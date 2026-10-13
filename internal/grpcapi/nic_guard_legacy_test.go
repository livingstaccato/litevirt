package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

const legacyGuardMAC = "52:54:00:00:4e:01"

// legacyGuardServer is a guard-capable server with a fake hypervisor and a
// direct (macvtap) network "wan".
func legacyGuardServer(t *testing.T) *Server {
	t.Helper()
	s := guardServer(t, true)
	s.virt = libvirtfake.New()
	s.dataDir = t.TempDir()
	s.images = image.NewStore(s.dataDir)
	_ = s.images.Init()
	insertTestHost(t, context.Background(), s.db, s.hostName, "active")
	if err := corrosion.UpsertNetwork(context.Background(), s.db, corrosion.NetworkRecord{Name: "wan", Type: "direct",
		Config: `{"type":"direct","interface":"lo"}`}); err != nil {
		t.Fatal(err)
	}
	return s
}

// insertStoredVM is VM "web" on this host as a create on an older build
// stored it: spec is its stored spec, with one NIC on network.
func insertStoredVM(t *testing.T, s *Server, network, spec string) {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "web", HostName: s.hostName, State: "stopped",
		Spec: spec}, []corrosion.InterfaceRecord{{VMName: "web", NetworkName: network, MAC: legacyGuardMAC}}, nil); err != nil {
		t.Fatal(err)
	}
}

// Round 4, R1: a VM created before guards on a direct or SR-IOV NIC were
// refused stores the guard settings in its spec (they were never enforced).
// A rebuild, or a stack's re-create, replays that spec: it must leave the
// settings out with a warning, never refuse — least of all after the
// teardown, which would lose the VM.
func TestRecreate_ALegacyGuardOnADirectNICIsLeftOutNotRefused(t *testing.T) {
	ctx := adminCtx()
	const legacy = `{"name":"web","uuid":"u-web","cpu":1,"memory_mib":256,` +
		`"network":[{"name":"wan","spoof_guard":"on","allowed_addresses":["10.0.0.5"],"allow_vlan_tags":true}]}`
	for _, how := range []string{"rebuild", "recreate"} {
		t.Run(how, func(t *testing.T) {
			s := legacyGuardServer(t)
			insertStoredVM(t, s, "wan", legacy)
			var err error
			if how == "rebuild" {
				_, err = s.RebuildVM(ctx, &pb.RebuildVMRequest{Name: "web"})
			} else {
				var spec pb.VMSpec
				if jerr := json.Unmarshal([]byte(legacy), &spec); jerr != nil {
					t.Fatal(jerr)
				}
				spec.Uuid = ""
				err = (&serverOps{s: s}).RecreateVM(ctx, "web", &spec)
			}
			if err != nil {
				t.Fatalf("%s of a VM with a legacy guard on a direct NIC: %v", how, err)
			}
			vm, _ := corrosion.GetVM(context.Background(), s.db, "web")
			if vm == nil {
				t.Fatalf("the %s lost the VM", how)
			}
			var stored pb.VMSpec
			if err := json.Unmarshal([]byte(vm.Spec), &stored); err != nil {
				t.Fatal(err)
			}
			if n := stored.GetNetwork(); len(n) != 1 || nicGuardExplicit(n[0]) {
				t.Errorf("the re-created VM's spec still carries the unenforced guard: %v", n)
			}
			recs, _ := corrosion.ListNICGuards(context.Background(), s.db)
			for _, r := range recs {
				if r.VMName == "web" {
					t.Errorf("a guard record was written for a direct NIC: %+v", r)
				}
			}
			evs, _ := corrosion.ListVMEvents(context.Background(), s.db, "web", 0, "")
			found := false
			for _, e := range evs {
				if e.Type == "vm.nic_guard.not_enforced" && e.Severity == "warning" &&
					strings.Contains(e.Detail, "not enforced") && strings.Contains(e.Detail, "wan") {
					found = true
				}
			}
			if !found {
				t.Errorf("no warning event names the guard left out; events %+v", evs)
			}
		})
	}
}

// A guard on a direct NIC that a user asks for is still refused: the
// tolerance is for a spec being replayed, not for new input. That includes
// the on-node lv CLI (local root: the host certificate over loopback), which
// passes requirePeerCert but is not a peer's forward (round 5, S2).
func TestCreate_ANewGuardOnADirectNICIsStillRefused(t *testing.T) {
	s := legacyGuardServer(t)
	localRoot := localRootCtx(s.hostName)
	if err := s.requirePeerCert(localRoot); err != nil {
		t.Fatalf("the local-root fixture does not pass requirePeerCert, so it would not pin the peer-kind test: %v", err)
	}
	for name, ctx := range map[string]context.Context{"user": adminCtx(), "local root": localRoot} {
		t.Run(name, func(t *testing.T) {
			_, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "fresh", Cpu: 1, MemoryMib: 256,
				Network: []*pb.NetworkAttachment{{Name: "wan", SpoofGuard: "on"}}}})
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "protect nothing") {
				t.Fatalf("lv run with a guard on a direct NIC: %v, want the refusal", err)
			}
		})
	}
}

// The owner leg of a create its entry node admitted (a peer's forward — an
// older entry node accepted such a guard, as main did) leaves it out rather
// than refusing what the entry node already accepted.
func TestCreate_APeerForwardedLegacyGuardIsLeftOut(t *testing.T) {
	s := legacyGuardServer(t)
	ctx := peerHostCtx(t, s, "node-old")
	if _, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "fwd", Cpu: 1, MemoryMib: 256,
		Network: []*pb.NetworkAttachment{{Name: "wan", SpoofGuard: "on"}}}}); err != nil {
		t.Fatalf("a forwarded create with a guard on a direct NIC: %v", err)
	}
	vm, _ := corrosion.GetVM(context.Background(), s.db, "fwd")
	if vm == nil || strings.Contains(vm.Spec, "spoof_guard") {
		t.Errorf("stored spec %v, want the VM without the guard settings", vm)
	}
}

// Round 4, R1: every admission a rebuild's create would make that the
// teardown does not change is made before the teardown, so a refusal leaves
// the VM as it was. A stored guard the create would refuse (here a mode that
// is not on or off), a raw USB device an Operator may not pass through, and
// an address another VM holds are refused with the VM intact.
func TestRebuild_EveryAdmissionRunsBeforeTheTeardown(t *testing.T) {
	cases := []struct {
		name, spec, want string
		ctx              context.Context
	}{
		{"invalid guard", `{"name":"web","uuid":"u-web","cpu":1,"memory_mib":256,"network":[{"name":"lan","spoof_guard":"enabled"}]}`,
			"want on or off", adminCtx()},
		{"raw usb as operator", `{"name":"web","uuid":"u-web","cpu":1,"memory_mib":256,"network":[{"name":"lan"}],` +
			`"placement":{"host":"` + "%HOST%" + `"},"usb_devices":[{"vendor":"046d","product":"c52b"}]}`,
			"needs the admin role", context.WithValue(context.WithValue(context.Background(), ctxKeyUsername, "op"), ctxKeyRole, "operator")},
	}
	cases = append(cases, struct {
		name, spec, want string
		ctx              context.Context
	}{"address another VM holds", `{"name":"web","uuid":"u-web","cpu":1,"memory_mib":256,"network":[{"name":"lan","ip":"10.0.0.7"}]}`,
		"already used by other", adminCtx()})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := legacyGuardServer(t)
			if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "other", HostName: s.hostName, State: "stopped",
				Spec: `{"name":"other","uuid":"u-other"}`}, []corrosion.InterfaceRecord{{VMName: "other", NetworkName: "lan",
				MAC: "52:54:00:00:4e:09", IP: "10.0.0.7"}}, nil); err != nil {
				t.Fatal(err)
			}
			insertStoredVM(t, s, "lan", strings.ReplaceAll(c.spec, "%HOST%", s.hostName))
			_, err := s.RebuildVM(c.ctx, &pb.RebuildVMRequest{Name: "web"})
			if err == nil {
				t.Fatal("the rebuild succeeded; the fixture should be refused")
			}
			if !strings.Contains(err.Error(), "nothing was changed") || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want a refusal before the teardown", err)
			}
			if vm, _ := corrosion.GetVM(context.Background(), s.db, "web"); vm == nil {
				t.Errorf("the rebuild was refused after the VM was torn down: %v", err)
			}
		})
	}
}

// Round 4, R1: a stack's re-create makes the create's guard admission before
// it deletes the VM too, so a guard the create would refuse leaves the VM as
// it was.
func TestStackRecreate_GuardAdmissionRunsBeforeTheDelete(t *testing.T) {
	s := legacyGuardServer(t)
	insertStoredVM(t, s, "lan", `{"name":"web","uuid":"u-web","cpu":1,"memory_mib":256,"network":[{"name":"lan"}]}`)
	spec := &pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256, Network: []*pb.NetworkAttachment{{Name: "lan", SpoofGuard: "enabled"}}}
	err := (&serverOps{s: s}).RecreateVM(adminCtx(), "web", spec)
	if err == nil || !strings.Contains(err.Error(), "nothing was deleted") || !strings.Contains(err.Error(), "want on or off") {
		t.Errorf("err = %v, want the guard refused before the delete", err)
	}
	if vm, _ := corrosion.GetVM(context.Background(), s.db, "web"); vm == nil {
		t.Errorf("the re-create was refused after the VM was deleted: %v", err)
	}
}
