package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// vmNICGroups is the security_groups of vmName's live vm_nics row with mac.
func vmNICGroups(t *testing.T, s *Server, vmName, mac string) (string, bool) {
	t.Helper()
	nics, err := corrosion.GetVMNICsRaw(context.Background(), s.db, "vm_nics", vmName)
	if err != nil {
		t.Fatalf("GetVMNICsRaw: %v", err)
	}
	for _, n := range nics {
		if n.MAC == mac && n.DeletedAt == "" {
			return n.SecurityGroups, true
		}
	}
	return "", false
}

// A NIC hot-attached after the hardware_v2 latch has a vm_nics row and no
// vm_interfaces row. The bind used to be a zero-row UPDATE of vm_interfaces
// that still answered OK and audited "ok" — the isolation lever doing nothing.
func TestBindSecurityGroups_PostLatchHotAttachedNIC(t *testing.T) {
	s := testServer(t)
	ctx := adminCtxWithEngine(t, s)
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name: "app", HostName: s.hostName, Spec: "{}", State: "running", Project: "_default",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	mac := "52:54:00:00:00:0a"
	if err := corrosion.UpsertNIC(context.Background(), s.db, corrosion.NICRecord{
		VMName: "app", ID: corrosion.DeterministicNICID("app", mac), NetworkName: "lan", MAC: mac,
		SecurityGroups: `["web"]`,
	}); err != nil {
		t.Fatalf("UpsertNIC: %v", err)
	}
	if _, err := s.BindSecurityGroups(ctx, &pb.BindSecurityGroupsRequest{
		VmName: "app", NetworkName: "lan", SecurityGroups: []string{"isolate"},
	}); err != nil {
		t.Fatalf("BindSecurityGroups: %v", err)
	}
	if got, _ := vmNICGroups(t, s, "app", mac); got != `["isolate"]` {
		t.Errorf("vm_nics security_groups after bind = %q, want [\"isolate\"]", got)
	}
	wantAudit(t, s, "sg.bind", "alice", "app", "network=lan before=[web] after=[isolate]")
}

// A NIC with both rows: the bind lands in vm_nics at once — the row the
// reconciler reads — not a bridge pass later, and the legacy row still gets it
// for peers on an older build.
func TestBindSecurityGroups_VMNICsBackedNICWithoutTheBridge(t *testing.T) {
	s := testServer(t)
	ctx := adminCtxWithEngine(t, s)
	mac := "52:54:00:00:00:0b"
	if err := corrosion.InsertVMWithHardware(context.Background(), s.db, corrosion.VMRecord{
		Name: "db", HostName: s.hostName, Spec: "{}", State: "running", Project: "_default",
	}, []corrosion.InterfaceRecord{{VMName: "db", NetworkName: "lan", MAC: mac, SecurityGroups: []string{"web"}}},
		nil, []corrosion.NICRecord{{VMName: "db", ID: corrosion.DeterministicNICID("db", mac), NetworkName: "lan",
			MAC: mac, SecurityGroups: `["web"]`}}, nil, true); err != nil {
		t.Fatalf("InsertVMWithHardware: %v", err)
	}
	if _, err := s.BindSecurityGroups(ctx, &pb.BindSecurityGroupsRequest{
		VmName: "db", NetworkName: "lan", SecurityGroups: []string{"isolate"},
	}); err != nil {
		t.Fatalf("BindSecurityGroups: %v", err)
	}
	if got, _ := vmNICGroups(t, s, "db", mac); got != `["isolate"]` {
		t.Errorf("vm_nics security_groups after bind = %q, want [\"isolate\"] without waiting for the bridge", got)
	}
	ifaces, _ := corrosion.GetVMInterfaces(context.Background(), s.db, "db")
	if len(ifaces) != 1 || len(ifaces[0].SecurityGroups) != 1 || ifaces[0].SecurityGroups[0] != "isolate" {
		t.Errorf("legacy vm_interfaces row must carry the bind for older peers, got %+v", ifaces)
	}
}

// A bind that matches no NIC changes nothing, so it must not answer OK, and
// the audit row must not say "ok".
func TestBindSecurityGroups_NoMatchingNICIsRefused(t *testing.T) {
	s := testServer(t)
	ctx := adminCtxWithEngine(t, s)
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name: "app", HostName: s.hostName, Spec: "{}", State: "running", Project: "_default",
	}, []corrosion.InterfaceRecord{{VMName: "app", NetworkName: "lan", MAC: "52:54:00:00:00:0c"}}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	_, err := s.BindSecurityGroups(ctx, &pb.BindSecurityGroupsRequest{
		VmName: "app", NetworkName: "no-such-net", SecurityGroups: []string{"isolate"},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("bind on a network the VM has no NIC on: got %v, want FailedPrecondition", err)
	}
	if got := lastAuditRow(t, s, "sg.bind"); !got.found || got.result == "ok" {
		t.Errorf("refused bind audit row = %+v, want a non-ok result", got)
	}
}
