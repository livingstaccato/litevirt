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
	if err := s.applyLiveMetadata(admin, "web", desired,
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
	err := s.applyLiveMetadata(admin, "web", desired, []string{compose.NICSecurityGroupsFieldPrefix + "0"})
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
	if err := s.applyLiveMetadata(admin, "web", desired, []string{compose.NICSecurityGroupsFieldPrefix + "0", compose.NICSecurityGroupsFieldPrefix + "1"}); err != nil {
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
	if err := s.applyLiveMetadata(bob, "web", loose, field); status.Code(err) != codes.PermissionDenied {
		t.Errorf("a loosening restore by an Operator: err = %v, want PermissionDenied", err)
	}

	gate := s.nicSecurityGate(bob, true)
	if gate.CheckBind("web") == nil {
		t.Error("the plan gate lets an Operator rebind security groups")
	}
	if gate.CheckWeakenGuard("lan") == nil {
		t.Error("the plan gate lets an Operator loosen a guard")
	}
	if gate.GuardsUnwritable != "" {
		t.Errorf("guards reported unwritable on an upgraded cluster: %s", gate.GuardsUnwritable)
	}
	adminGate := s.nicSecurityGate(admin, false)
	if adminGate.CheckBind("web") != nil || adminGate.CheckWeakenGuard("lan") != nil || adminGate.AllowWeaken {
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
	err := s.applyLiveMetadata(admin, "web", desired,
		[]string{compose.NICGuardFieldPrefix + "0", compose.NICSecurityGroupsFieldPrefix + "0"})
	if err == nil {
		t.Fatal("a rebind reaching an undeclared NIC was applied")
	}
	if g, _ := corrosion.GetNICGuard(ctx, s.db, "web", "52:54:00:00:00:01"); g == nil || g.Mode != "off" {
		t.Errorf("guard = %+v, want it left off: the refusal must come before any write", g)
	}
}
