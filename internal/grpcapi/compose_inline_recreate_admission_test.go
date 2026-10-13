package grpcapi

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// inlineStackServer is legacyGuardServer with a shared bridge network "lan"
// (10.0.0.0/24), on which VM "other" holds 10.0.0.7, and stack st's VM
// "web" on it, running image img-a with the given stored NIC.
func inlineStackServer(t *testing.T, nic string) *Server {
	t.Helper()
	s := legacyGuardServer(t)
	ctx := context.Background()
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "lan", Type: "bridge",
		Config: `{"Subnet":"10.0.0.0/24"}`}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "other", HostName: s.hostName, State: "stopped",
		Spec: `{"name":"other","uuid":"u-other"}`}, []corrosion.InterfaceRecord{{VMName: "other", NetworkName: "lan",
		MAC: "52:54:00:00:4e:09", IP: "10.0.0.7"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "web", StackName: "st", HostName: s.hostName,
		State: "running", CPUActual: 1, MemActual: 256,
		Spec: `{"name":"web","uuid":"u-web","image":"img-a","cpu":1,"memory_mib":256,"network":[` + nic + `]}`},
		[]corrosion.InterfaceRecord{{VMName: "web", NetworkName: "lan", MAC: legacyGuardMAC}}, nil); err != nil {
		t.Fatal(err)
	}
	return s
}

// Round 5, S1: the default (inline) compose re-create — an image change in a
// stack with no update strategy — makes, before it deletes the VM, every
// admission its create will make that the delete does not change. A guard
// the create would refuse (a mode that is not on or off), or an address
// another VM holds, leaves the VM as it was and says nothing was deleted.
func TestComposeInlineRecreate_AdmissionRunsBeforeTheDelete(t *testing.T) {
	for _, c := range []struct{ name, nic, want string }{
		{"invalid guard", `        spoof-guard: "enabled"`, "want on or off"},
		{"address another VM holds", `        ip: "10.0.0.7"`, "already used by other"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := inlineStackServer(t, `{"name":"lan"}`)
			createFakeImage(t, s, "img-b")
			yaml := "name: st\nnetworks:\n  lan:\n    external: true\nvms:\n  web:\n    image: img-b\n    cpu: 1\n" +
				"    memory: 256\n    network:\n      - name: lan\n" + c.nic + "\n"
			stream := &mockDeployStream{ctx: adminCtx()}
			err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: yaml}, stream)
			var lines []string
			for _, p := range stream.sent {
				lines = append(lines, p.Phase+" "+p.VmName+": "+p.Detail+" "+p.Error)
			}
			progress := strings.Join(lines, "\n")
			vm, _ := corrosion.GetVM(context.Background(), s.db, "web")
			if vm == nil {
				t.Fatalf("the deploy deleted the VM and then refused its create (err %v):\n%s", err, progress)
			}
			if !strings.Contains(vm.Spec, `"img-a"`) {
				t.Errorf("the VM was replaced: %s", vm.Spec)
			}
			if !strings.Contains(progress, "nothing was deleted") || !strings.Contains(progress, c.want) {
				t.Errorf("err %v; progress:\n%s\nwant a refusal before the delete naming %q", err, progress, c.want)
			}
		})
	}
}

// deployerCtx is user dee, who may create, delete and read VMs anywhere
// (Deployer at /) but holds no network.update.
func deployerCtx(t *testing.T, s *Server) context.Context {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "dee", "operator", "x"); err != nil {
		t.Fatal(err)
	}
	if err := auth.SeedBuiltinRoles(ctx, s.db); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertRole(ctx, s.db, corrosion.RoleRecord{
		Name: "Deployer", Verbs: []string{"vm.create", "vm.delete", "vm.read", "vm.start", "vm.stop"}}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
		ID: "dee-deploy", Path: "/", Role: "Deployer", Principal: "user:dee@local", Propagate: true}); err != nil {
		t.Fatal(err)
	}
	engine := auth.NewEngine(s.db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	s.SetAuthEngine(engine)
	return userCtx("dee", "operator")
}

// Round 5, S1: the inline re-create's create is a fresh create (it carries
// the VM it replaces only for a VM on an iSCSI LUN), so its guard admission
// is judged as one before the delete: a relaxation the file declares needs
// network.update even when the live record already has it. A preflight
// judged as a re-create would pass it, and the create would then refuse it
// with the VM gone.
func TestComposeInlineRecreate_GuardPreflightJudgesAsTheCreateWill(t *testing.T) {
	s := inlineStackServer(t, `{"name":"lan","spoof_guard":"off"}`)
	if err := corrosion.PutNICGuard(context.Background(), s.db, capabilities.GrantForTest(t, capabilities.FeatureNICGuards),
		corrosion.NICGuardRecord{VMName: "web", MAC: legacyGuardMAC, Mode: corrosion.NICGuardOff, VMUUID: "u-web", Network: "lan"},
		"admin"); err != nil {
		t.Fatal(err)
	}
	dee := deployerCtx(t, s)
	spec := &pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256, Network: []*pb.NetworkAttachment{{Name: "lan", SpoofGuard: "off"}}}
	a := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: s.hostName, Spec: spec}
	f := &compose.File{Name: "st"}
	err := s.recreateInline(dee, a, f, newDependsOnGate(s, f, []planner.VMAction{a}, nil))
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "nothing was deleted") ||
		!strings.Contains(err.Error(), "network.update") {
		t.Errorf("err = %v, want the relaxation refused before the delete", err)
	}
	if vm, _ := corrosion.GetVM(context.Background(), s.db, "web"); vm == nil {
		t.Errorf("the re-create was refused after the VM was deleted: %v", err)
	}
}

// Round 5 (re-review 4 nit): the guard preflight judges the spec the create
// will judge — a replayed spec without the settings it leaves out — so a
// stored guard on a direct NIC that the create would leave out is left out
// by the preflight too, never refused there, even when it is not well formed.
func TestRebuild_TheGuardPreflightLeavesOutWhatTheCreateLeavesOut(t *testing.T) {
	s := legacyGuardServer(t)
	insertStoredVM(t, s, "wan", `{"name":"web","uuid":"u-web","cpu":1,"memory_mib":256,"network":[{"name":"wan","spoof_guard":"enabled"}]}`)
	if _, err := s.RebuildVM(adminCtx(), &pb.RebuildVMRequest{Name: "web"}); err != nil {
		t.Fatalf("rebuild of a VM whose stored direct NIC carries a malformed, never-enforced guard: %v", err)
	}
	if vm, _ := corrosion.GetVM(context.Background(), s.db, "web"); vm == nil || strings.Contains(vm.Spec, "spoof_guard") {
		t.Errorf("rebuilt VM %v, want it present without the guard settings", vm)
	}
}

// Round 5 (re-review 4 nit): the warning that a create left guard settings
// out is recorded once the create has succeeded, never for a create that was
// then refused.
func TestCreate_TheNotEnforcedEventIsRecordedOnlyForACreateThatHappened(t *testing.T) {
	s := legacyGuardServer(t)
	insertStoredVM(t, s, "lan", `{"name":"web","uuid":"u-web"}`)
	ctx := peerHostCtx(t, s, "node-old")
	_, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256,
		Network: []*pb.NetworkAttachment{{Name: "wan", SpoofGuard: "on"}}}})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("a forwarded create of a name that is taken: %v, want AlreadyExists", err)
	}
	evs, _ := corrosion.ListVMEvents(context.Background(), s.db, "web", 0, "")
	for _, e := range evs {
		if e.Type == "vm.nic_guard.not_enforced" {
			t.Errorf("a refused create recorded that it left guard settings out: %+v", e)
		}
	}
}

// Round 5 (re-review 4 nit): the spec a failed re-create keeps is one
// lv run accepts: guard settings on a NIC whose network cannot enforce them
// are left out of it, as the create left them out; a bridge NIC's are kept.
func TestRecreateFailedAfterTeardown_KeepsASpecWithoutUnenforcedGuards(t *testing.T) {
	s := legacyGuardServer(t)
	spec := &pb.VMSpec{Name: "web", Network: []*pb.NetworkAttachment{
		{Name: "wan", SpoofGuard: "on", AllowedAddresses: []string{"10.0.0.5"}},
		{Name: "lan", SpoofGuard: "off"},
	}}
	err := s.recreateFailedAfterTeardown(adminCtx(), "rebuild", "web", s.hostName, spec, errors.New("boom"), false)
	msg := status.Convert(err).Message()
	path := msg[strings.LastIndex(msg, " at ")+len(" at "):]
	path = path[:strings.Index(path, "; re-create")]
	b, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("kept spec: %v (%s)", rerr, msg)
	}
	if strings.Contains(string(b), "10.0.0.5") || strings.Count(string(b), "spoofGuard") != 1 || !strings.Contains(string(b), `"off"`) {
		t.Errorf("kept spec %s: want the direct NIC's guard left out and the bridge NIC's kept", b)
	}
	if spec.GetNetwork()[0].GetSpoofGuard() != "on" {
		t.Errorf("the caller's spec was changed: %v", spec.GetNetwork()[0])
	}
}

// Round 5, S1: an inline re-create of a VM on an iSCSI LUN carries the VM it
// replaces into its create, so the create judges its guard as a re-create:
// a relaxation the VM already has is carried without network.update. The
// preflight judges it the same way, never refusing what the create passes.
func TestComposeInlineRecreate_OnALUNTheGuardPreflightIsARecreates(t *testing.T) {
	s := lunTestServer(t)
	if err := corrosion.UpsertNetwork(context.Background(), s.db, corrosion.NetworkRecord{Name: "lan", Type: "bridge",
		Config: `{"Subnet":"10.0.0.0/24"}`}); err != nil {
		t.Fatal(err)
	}
	req := lunVM("web", "lun0")
	req.Spec.Network = []*pb.NetworkAttachment{{Name: "lan", SpoofGuard: "off"}}
	if _, err := s.CreateVM(adminCtx(), req); err != nil {
		t.Fatalf("create: %v", err)
	}
	dee := deployerCtx(t, s)
	spec := lunVM("web", "lun0").Spec
	spec.Network = []*pb.NetworkAttachment{{Name: "lan", SpoofGuard: "off"}}
	a := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: s.hostName, Spec: spec}
	f := &compose.File{Name: "st"}
	if err := s.recreateInline(dee, a, f, newDependsOnGate(s, f, []planner.VMAction{a}, nil)); err != nil {
		t.Fatalf("an inline re-create on a LUN carrying the relaxation its NIC has: %v", err)
	}
	if vm, _ := corrosion.GetVM(context.Background(), s.db, "web"); vm == nil {
		t.Fatal("the VM is gone")
	}
}
