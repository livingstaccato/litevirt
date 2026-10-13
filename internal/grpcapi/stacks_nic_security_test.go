package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// insertNICSecVM records a running stack VM with one NIC per entry of nets,
// MACs 52:54:00:00:00:0<i+1>, as created with the given attachments.
func insertNICSecVM(t *testing.T, s *Server, atts ...*pb.NetworkAttachment) {
	t.Helper()
	ctx := context.Background()
	// The legacy table holds one NIC per network; a second NIC on a network
	// has only its vm_nics row, as one hot-attached after hardware_v2 does.
	var ifaces []corrosion.InterfaceRecord
	var extra []corrosion.NICRecord
	seen := map[string]bool{}
	for i, a := range atts {
		a.Mac = "52:54:00:00:00:0" + string(rune('1'+i))
		if seen[a.Name] {
			extra = append(extra, corrosion.NICRecord{VMName: "web", ID: corrosion.DeterministicNICID("web", a.Mac),
				NetworkName: a.Name, MAC: a.Mac, Ordinal: i})
			continue
		}
		seen[a.Name] = true
		ifaces = append(ifaces, corrosion.InterfaceRecord{VMName: "web", NetworkName: a.Name, MAC: a.Mac, Ordinal: i})
	}
	blob, _ := json.Marshal(&pb.VMSpec{Uuid: "u-1", Network: atts})
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "web", StackName: "st", HostName: s.hostName, State: "running", Spec: string(blob)},
		ifaces, nil); err != nil {
		t.Fatal(err)
	}
	for _, n := range extra {
		if err := corrosion.UpsertNIC(ctx, s.db, n); err != nil {
			t.Fatal(err)
		}
	}
}

// N2: an update whose plan carries a NIC's security-group binding and guard
// puts the file's back on the rows the firewall enforces from.
func TestApplyLiveMetadata_RestoresTheDeclaredNICSecurity(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	admin := adminCtxWithEngine(t, s)
	insertNICSecVM(t, s, &pb.NetworkAttachment{Name: "lan", SecurityGroups: []string{"web"}})
	// The operator's runtime changes: an isolation group, a bare guard.
	if _, err := s.BindSecurityGroups(admin, &pb.BindSecurityGroupsRequest{VmName: "web", NetworkName: "lan", SecurityGroups: []string{"isolate"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetNICGuard(admin, &pb.SetNICGuardRequest{VmName: "web", NetworkName: "lan", Mode: "on"}); err != nil {
		t.Fatal(err)
	}
	desired := &pb.VMSpec{Network: []*pb.NetworkAttachment{{Name: "lan", SecurityGroups: []string{"web"},
		SpoofGuard: "on", AllowedAddresses: []string{"10.0.0.250"}, AllowVlanTags: true}}}
	if err := s.applyLiveMetadata(withAllowWeaken(admin, true), "web", desired,
		[]string{compose.NICSecurityGroupsFieldPrefix + "0", compose.NICGuardFieldPrefix + "0"}); err != nil {
		t.Fatalf("applyLiveMetadata: %v", err)
	}
	live, err := corrosion.LiveNICSecurity(ctx, s.db, "web", "u-1")
	if err != nil || len(live) != 1 {
		t.Fatalf("LiveNICSecurity = %+v, %v", live, err)
	}
	if sgs := live[0].SecurityGroups; len(sgs) != 1 || sgs[0] != "web" {
		t.Errorf("binding = %v, want [web] restored", sgs)
	}
	if g := live[0].Guard; g == nil || g.Mode != "on" || len(g.Allowed) != 1 || g.Allowed[0] != "10.0.0.250" || !g.AllowVLANTags {
		t.Errorf("guard = %+v, want on, allowing 10.0.0.250 and VLAN tags", g)
	}
}

// A binding is written per network. When another NIC of the VM is on the same
// network and the file does not declare the same groups for it, a rebind would
// change that NIC too, so the update refuses rather than clobber it.
func TestApplyLiveMetadata_RefusesARebindThatWouldReachAnotherNIC(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	admin := adminCtxWithEngine(t, s)
	insertNICSecVM(t, s, &pb.NetworkAttachment{Name: "lan"}, &pb.NetworkAttachment{Name: "lan"})
	if _, err := s.BindSecurityGroups(admin, &pb.BindSecurityGroupsRequest{VmName: "web", NetworkName: "lan", SecurityGroups: []string{"isolate"}}); err != nil {
		t.Fatal(err)
	}
	desired := &pb.VMSpec{Network: []*pb.NetworkAttachment{{Name: "lan", SecurityGroups: []string{"web"}}, {Name: "lan"}}}
	err := s.applyLiveMetadata(withAllowWeaken(admin, true), "web", desired, []string{compose.NICSecurityGroupsFieldPrefix + "0"})
	if err == nil || !strings.Contains(err.Error(), "written per network") {
		t.Fatalf("err = %v, want a refusal naming the shared network", err)
	}
	live, _ := corrosion.LiveNICSecurity(ctx, s.db, "web", "u-1")
	for _, n := range live {
		if len(n.SecurityGroups) != 1 || n.SecurityGroups[0] != "isolate" {
			t.Errorf("NIC %s binding = %v, want isolate left in place", n.MAC, n.SecurityGroups)
		}
	}
	// Both NICs declaring the same groups is one binding, and is applied.
	desired.Network[1].SecurityGroups = []string{"web"}
	if err := s.applyLiveMetadata(withAllowWeaken(admin, true), "web", desired, []string{compose.NICSecurityGroupsFieldPrefix + "0", compose.NICSecurityGroupsFieldPrefix + "1"}); err != nil {
		t.Fatalf("applyLiveMetadata: %v", err)
	}
	live, _ = corrosion.LiveNICSecurity(ctx, s.db, "web", "u-1")
	for _, n := range live {
		if len(n.SecurityGroups) != 1 || n.SecurityGroups[0] != "web" {
			t.Errorf("NIC %s binding = %v, want web", n.MAC, n.SecurityGroups)
		}
	}
}

// I3: an Operator (no network.update) restores a declared guard that only
// tightens, as it could create it; a guard that loosens needs the authority
// SetNICGuard checks; a security-group rebind needs network.update on the VM.
// The plan's gate says the same before anything runs.
func TestNICSecurity_ADeployerWithoutNetworkUpdate(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	admin := adminCtxWithEngine(t, s)
	insertNICSecVM(t, s, &pb.NetworkAttachment{Name: "lan"})
	if _, err := s.SetNICGuard(admin, &pb.SetNICGuardRequest{VmName: "web", NetworkName: "lan", Mode: "off"}); err != nil {
		t.Fatal(err)
	}
	bob := boundAtCtx(t, s, "bob", "operator", "Operator", "/")
	field := []string{compose.NICGuardFieldPrefix + "0"}

	on := &pb.VMSpec{Network: []*pb.NetworkAttachment{{Name: "lan", SpoofGuard: "on"}}}
	if err := s.applyLiveMetadata(bob, "web", on, field); err != nil {
		t.Fatalf("a tightening restore by an Operator: %v", err)
	}
	if live, _ := corrosion.LiveNICSecurity(ctx, s.db, "web", "u-1"); live[0].Guard == nil || live[0].Guard.Mode != "on" {
		t.Fatalf("guard = %+v, want on", live[0].Guard)
	}
	loose := &pb.VMSpec{Network: []*pb.NetworkAttachment{{Name: "lan", SpoofGuard: "on", AllowedAddresses: []string{"10.0.0.250"}}}}
	if err := s.applyLiveMetadata(withAllowWeaken(bob, true), "web", loose, field); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "network.update") {
		t.Errorf("a loosening restore by an Operator: err = %v, want a refusal naming network.update", err)
	}

	gate := s.nicSecurityGate(bob, true)
	if gate.CheckBind("web") == nil {
		t.Error("the plan gate lets an Operator rebind security groups")
	}
	if gate.CheckGuardAuthority("lan") == nil {
		t.Error("the plan gate lets an Operator loosen a guard")
	}
	if gate.GuardsUnwritable != "" {
		t.Errorf("guards reported unwritable on an upgraded cluster: %s", gate.GuardsUnwritable)
	}
	adminGate := s.nicSecurityGate(admin, false)
	if adminGate.CheckBind("web") != nil || adminGate.CheckGuardAuthority("lan") != nil || adminGate.AllowWeaken {
		t.Errorf("admin gate = %+v", adminGate)
	}
}

// I4b: before the nic_guards release has latched, no guard record can be
// written, and the plan gate says so.
func TestNICSecurityGate_GuardsUnwritableBeforeTheRelease(t *testing.T) {
	s := guardServer(t, false)
	if g := s.nicSecurityGate(adminCtx(), false); !strings.Contains(g.GuardsUnwritable, "upgrade") {
		t.Errorf("GuardsUnwritable = %q, want the unfinished upgrade named", g.GuardsUnwritable)
	}
}

// I3: every field is checked before any is written, so a refused restore
// leaves nothing half-applied.
func TestApplyLiveMetadata_ARefusalWritesNothing(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	admin := adminCtxWithEngine(t, s)
	insertNICSecVM(t, s, &pb.NetworkAttachment{Name: "lan"}, &pb.NetworkAttachment{Name: "lan"})
	if _, err := s.BindSecurityGroups(admin, &pb.BindSecurityGroupsRequest{VmName: "web", NetworkName: "lan", SecurityGroups: []string{"isolate"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetNICGuard(admin, &pb.SetNICGuardRequest{VmName: "web", Mac: "52:54:00:00:00:01", Mode: "off"}); err != nil {
		t.Fatal(err)
	}
	desired := &pb.VMSpec{Network: []*pb.NetworkAttachment{{Name: "lan", SpoofGuard: "on", SecurityGroups: []string{"web"}}, {Name: "lan"}}}
	err := s.applyLiveMetadata(withAllowWeaken(admin, true), "web", desired,
		[]string{compose.NICGuardFieldPrefix + "0", compose.NICSecurityGroupsFieldPrefix + "0"})
	if err == nil {
		t.Fatal("a rebind reaching an undeclared NIC was applied")
	}
	if g, _ := corrosion.GetNICGuard(ctx, s.db, "web", "52:54:00:00:00:01"); g == nil || g.Mode != "off" {
		t.Errorf("guard = %+v, want it left off: the refusal must come before any write", g)
	}
}

// planAndApply plans one VM's NIC security restore from desired against the
// rows now, through the plan gate for ctx, and then runs the executor for
// every restore Classify found (as an executor handed a plan made under
// another gate would). It returns whether the gate withheld anything and the
// executor's error.
func planAndApply(t *testing.T, s *Server, ctx context.Context, desired *pb.VMSpec, allowWeaken bool) (withheld []string, execErr error) {
	t.Helper()
	vm, _ := corrosion.GetVM(context.Background(), s.db, "web")
	stored := &pb.VMSpec{}
	if err := json.Unmarshal([]byte(vm.Spec), stored); err != nil {
		t.Fatal(err)
	}
	live, err := corrosion.LiveNICSecurity(context.Background(), s.db, "web", stored.Uuid)
	if err != nil {
		t.Fatal(err)
	}
	overlaid := compose.OverlayLiveNICSecurity(stored, live)
	p := compose.Classify(desired, overlaid, nil)
	var fields []string
	for _, d := range p.MetadataChanges {
		fields = append(fields, d.Field)
	}
	gated := p
	withheld = compose.ApplyNICSecurityGate("web", &gated, desired, overlaid, live, s.nicSecurityGate(ctx, allowWeaken))
	if len(fields) == 0 {
		t.Fatalf("nothing to restore for %v over %+v", desired.Network, live)
	}
	return withheld, s.applyLiveMetadata(withAllowWeaken(ctx, allowWeaken), "web", desired, fields)
}

// Round 2, N1: the plan gate and the executor decide guard authority by one
// rule (compose.DeclaredGuardNeedsAuthority). For an Operator without
// network.update, a restore the plan does not withhold is applied, and one it
// withholds is refused, whatever the live guard was — including a declared
// guard with an allowance over no record (live unset), and one narrower than
// a wider live prefix.
func TestNICSecurity_PlanAndExecutorAgreeOnGuardAuthority(t *testing.T) {
	for _, c := range []struct {
		name     string
		live     *pb.SetNICGuardRequest // nil: no record
		declared *pb.NetworkAttachment
		applied  bool
	}{
		{"unset live, declared on with an allowance", nil,
			&pb.NetworkAttachment{Name: "lan", SpoofGuard: "on", AllowedAddresses: []string{"10.0.0.5"}}, false},
		{"wider live prefix, declared narrower", &pb.SetNICGuardRequest{Mode: "on", AllowedAddresses: []string{"10.0.0.0/24"}},
			&pb.NetworkAttachment{Name: "lan", SpoofGuard: "on", AllowedAddresses: []string{"10.0.0.5"}}, false},
		{"unset live, declared off", nil, &pb.NetworkAttachment{Name: "lan", SpoofGuard: "off"}, false},
		{"off live, declared plain on", &pb.SetNICGuardRequest{Mode: "off"}, &pb.NetworkAttachment{Name: "lan", SpoofGuard: "on"}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := guardServer(t, true)
			admin := adminCtxWithEngine(t, s)
			insertNICSecVM(t, s, &pb.NetworkAttachment{Name: "lan"})
			if c.live != nil {
				c.live.VmName, c.live.NetworkName = "web", "lan"
				if _, err := s.SetNICGuard(admin, c.live); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := corrosion.GetNICGuard(context.Background(), s.db, "web", "52:54:00:00:00:01")
			bob := boundAtCtx(t, s, "bob", "operator", "Operator", "/")
			withheld, err := planAndApply(t, s, bob, &pb.VMSpec{Network: []*pb.NetworkAttachment{c.declared}}, false)
			if (len(withheld) == 0) != (err == nil) {
				t.Fatalf("plan and executor disagree: plan withheld %q, executor err %v", withheld, err)
			}
			if (err == nil) != c.applied {
				t.Fatalf("applied = %v (err %v, withheld %q), want %v", err == nil, err, withheld, c.applied)
			}
			if !c.applied {
				if !strings.Contains(strings.Join(withheld, ";"), "network.update") {
					t.Errorf("withheld %q does not name the missing permission", withheld)
				}
				after, _ := corrosion.GetNICGuard(context.Background(), s.db, "web", "52:54:00:00:00:01")
				if (before == nil) != (after == nil) || (before != nil && before.AuditText() != after.AuditText()) {
					t.Errorf("a refused restore wrote the guard: %+v → %+v", before, after)
				}
			}
		})
	}
}

// N1: a deployer who may rebind the VM's groups (network.update on the VM) but
// not write a guard with allowances on the network: the refusal comes before
// any write, so the groups are not rebound either.
func TestApplyLiveMetadata_AnAuthorityRefusalWritesNothing(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	admin := adminCtxWithEngine(t, s)
	insertNICSecVM(t, s, &pb.NetworkAttachment{Name: "lan"})
	if _, err := s.BindSecurityGroups(admin, &pb.BindSecurityGroupsRequest{VmName: "web", NetworkName: "lan", SecurityGroups: []string{"isolate"}}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertRole(ctx, s.db, corrosion.RoleRecord{Name: "VMNetwork", Verbs: []string{"network.update"}}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{ID: "carol-vmnet", Path: vmRBACPathFor("", "web"),
		Role: "VMNetwork", Principal: "user:carol@local", Propagate: true}); err != nil {
		t.Fatal(err)
	}
	carol := boundAtCtx(t, s, "carol", "operator", "Operator", "/")
	if s.nicSecurityGate(carol, true).CheckBind("web") != nil {
		t.Fatal("setup: carol should be able to rebind web's groups")
	}
	desired := &pb.VMSpec{Network: []*pb.NetworkAttachment{{Name: "lan", SecurityGroups: []string{"web"},
		SpoofGuard: "on", AllowedAddresses: []string{"10.0.0.250"}}}}
	err := s.applyLiveMetadata(withAllowWeaken(carol, true), "web", desired,
		[]string{compose.NICSecurityGroupsFieldPrefix + "0", compose.NICGuardFieldPrefix + "0"})
	if err == nil || !strings.Contains(err.Error(), "network.update") {
		t.Fatalf("err = %v, want the guard refused for want of network.update", err)
	}
	if live, _ := corrosion.LiveNICSecurity(ctx, s.db, "web", "u-1"); len(live[0].SecurityGroups) != 1 || live[0].SecurityGroups[0] != "isolate" {
		t.Errorf("binding = %v, want isolate left: nothing may be written once a restore is refused", live[0].SecurityGroups)
	}
}

// Round 2, M2: the executor re-checks weakening against the rows as they are
// when it writes. A narrowing planned over [a,b] becomes a widening once an
// operator emptied the list in between; without --allow-weaken it is refused.
func TestApplyLiveMetadata_AWriteThatNowWeakensIsRefused(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	admin := adminCtxWithEngine(t, s)
	insertNICSecVM(t, s, &pb.NetworkAttachment{Name: "lan"})
	if _, err := s.SetNICGuard(admin, &pb.SetNICGuardRequest{VmName: "web", NetworkName: "lan", Mode: "on"}); err != nil {
		t.Fatal(err)
	}
	desired := &pb.VMSpec{Network: []*pb.NetworkAttachment{{Name: "lan", SpoofGuard: "on", AllowedAddresses: []string{"10.0.0.5"}}}}
	err := s.applyLiveMetadata(withAllowWeaken(admin, false), "web", desired, []string{compose.NICGuardFieldPrefix + "0"})
	if err == nil || !strings.Contains(err.Error(), "--allow-weaken") {
		t.Fatalf("err = %v, want a refusal naming --allow-weaken", err)
	}
	if g, _ := corrosion.GetNICGuard(ctx, s.db, "web", "52:54:00:00:00:01"); g == nil || len(g.Allowed) != 0 {
		t.Errorf("guard = %+v, want it left without allowances", g)
	}
	if err := s.applyLiveMetadata(withAllowWeaken(admin, true), "web", desired, []string{compose.NICGuardFieldPrefix + "0"}); err != nil {
		t.Errorf("with --allow-weaken: %v", err)
	}
}

// An Operator (no network.update anywhere) may restore a plain "on" guard but
// not rebind groups: with both in one restore, the rebind's refusal comes
// before the guard is written, whatever order the fields are in.
func TestApplyLiveMetadata_ARebindRefusalWritesNoGuard(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	admin := adminCtxWithEngine(t, s)
	insertNICSecVM(t, s, &pb.NetworkAttachment{Name: "lan"})
	if _, err := s.SetNICGuard(admin, &pb.SetNICGuardRequest{VmName: "web", NetworkName: "lan", Mode: "off"}); err != nil {
		t.Fatal(err)
	}
	bob := boundAtCtx(t, s, "bob", "operator", "Operator", "/")
	desired := &pb.VMSpec{Network: []*pb.NetworkAttachment{{Name: "lan", SpoofGuard: "on", SecurityGroups: []string{"web"}}}}
	err := s.applyLiveMetadata(withAllowWeaken(bob, true), "web", desired,
		[]string{compose.NICGuardFieldPrefix + "0", compose.NICSecurityGroupsFieldPrefix + "0"})
	if err == nil || !strings.Contains(err.Error(), "network.update") {
		t.Fatalf("err = %v, want the rebind refused for want of network.update", err)
	}
	if g, _ := corrosion.GetNICGuard(ctx, s.db, "web", "52:54:00:00:00:01"); g == nil || g.Mode != "off" {
		t.Errorf("guard = %+v, want it left off: the refusal must come before any write", g)
	}
}

// The executor never rebinds without the deploy's opt-in, even when handed a
// plan that names the rebind.
func TestApplyLiveMetadata_NoRebindWithoutAllowWeaken(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	admin := adminCtxWithEngine(t, s)
	insertNICSecVM(t, s, &pb.NetworkAttachment{Name: "lan"})
	if _, err := s.BindSecurityGroups(admin, &pb.BindSecurityGroupsRequest{VmName: "web", NetworkName: "lan", SecurityGroups: []string{"isolate"}}); err != nil {
		t.Fatal(err)
	}
	desired := &pb.VMSpec{Network: []*pb.NetworkAttachment{{Name: "lan", SecurityGroups: []string{"web"}}}}
	err := s.applyLiveMetadata(admin, "web", desired, []string{compose.NICSecurityGroupsFieldPrefix + "0"})
	if err == nil || !strings.Contains(err.Error(), "--allow-weaken") {
		t.Fatalf("err = %v, want a refusal naming --allow-weaken", err)
	}
	if live, _ := corrosion.LiveNICSecurity(ctx, s.db, "web", "u-1"); live[0].SecurityGroups[0] != "isolate" {
		t.Errorf("binding = %v, want isolate kept", live[0].SecurityGroups)
	}
}
