package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

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
	if err == nil || !strings.Contains(err.Error(), "same network") {
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
