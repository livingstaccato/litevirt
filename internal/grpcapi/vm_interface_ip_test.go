package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A discovered address is recorded on the NIC that holds the lease, by MAC,
// and only while that NIC is live (corrosion.UpdateVMInterfaceIP).

const (
	discNICX = "52:54:00:bb:00:01"
	discNICY = "52:54:00:bb:00:02"
)

func discoveryVM(t *testing.T, s *Server) {
	t.Helper()
	ctx := context.Background()
	cfg, _ := json.Marshal(compose.NetworkDef{Interface: "br-lan"})
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "lan", Type: "bridge", Config: string(cfg)}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "web", HostName: "test-host", State: "running", StackName: "prod",
	}, []corrosion.InterfaceRecord{
		{VMName: "web", NetworkName: "lan", MAC: discNICX},
	}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.UpsertNIC(ctx, s.db, corrosion.NICRecord{
		VMName: "web", ID: corrosion.DeterministicNICID("web", discNICX), NetworkName: "lan", MAC: discNICX,
	}); err != nil {
		t.Fatal(err)
	}
}

func mergedIPs(t *testing.T, s *Server) map[string]string {
	t.Helper()
	nics, err := corrosion.MergedVMNICs(context.Background(), s.db, "web")
	if err != nil {
		t.Fatalf("MergedVMNICs: %v", err)
	}
	out := map[string]string{}
	for _, n := range nics {
		out[strings.ToLower(n.MAC)] = n.IP
	}
	return out
}

// Two live NICs on one network, the legacy row naming X: an address
// discovered for Y is not written onto X's row, which is the network's legacy
// row. Y has no legacy row, so nothing records it (vm_nics is never written on
// the IP path).
func TestDiscovery_DoesNotRecordOnAnotherNICsRow(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	discoveryVM(t, s)
	if err := corrosion.UpsertNIC(ctx, s.db, corrosion.NICRecord{
		VMName: "web", ID: corrosion.DeterministicNICID("web", discNICY), NetworkName: "lan", MAC: discNICY, Ordinal: 1,
	}); err != nil {
		t.Fatal(err)
	}
	vm, err := corrosion.GetVM(ctx, s.db, "web")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %+v %v", vm, err)
	}
	if s.claimAndRecordDiscoveredVMIP(ctx, vm, "lan", discNICY, "10.0.60.9") {
		t.Error("an address discovered for Y was reported recorded")
	}
	if got := mergedIPs(t, s); got[discNICY] != "" || got[discNICX] != "" {
		t.Errorf("addresses after discovery for Y = %v, want none recorded", got)
	}
	// Discovered for X, it lands on X's row.
	if !s.claimAndRecordDiscoveredVMIP(ctx, vm, "lan", discNICX, "10.0.60.8") {
		t.Fatal("the discovered address of X was not recorded")
	}
	if got := mergedIPs(t, s); got[discNICX] != "10.0.60.8" || got[discNICY] != "" {
		t.Errorf("addresses after discovery for X = %v, want only X at 10.0.60.8", got)
	}
}

// The IP scanner walks the legacy rows, and after the hardware_v2 latch a
// detached NIC's legacy row stays live with no address. A lease still on file
// for its MAC must not bring it back, nor publish a DNS record for it.
func TestIPScanner_DoesNotReviveADetachedNIC(t *testing.T) {
	s := testServer(t)
	s.dnsDomain = "litevirt.local"
	ctx := context.Background()
	discoveryVM(t, s)
	if err := corrosion.TombstoneNIC(ctx, s.db, "web", corrosion.DeterministicNICID("web", discNICX)); err != nil {
		t.Fatal(err)
	}
	s.setNICIPDiscoveryOnBridge(func(mac, bridge string) string {
		if strings.EqualFold(mac, discNICX) {
			return "10.0.60.5"
		}
		return ""
	})
	NewIPScanner(s).scan(ctx)
	if got := mergedIPs(t, s); len(got) != 0 {
		t.Errorf("live NICs after the scan = %v, want none: the detached NIC came back", got)
	}
	if err := corrosion.BridgeVMNICs(ctx, s.db, "web"); err != nil {
		t.Fatal(err)
	}
	if got := mergedIPs(t, s); len(got) != 0 {
		t.Errorf("live NICs after the bridge = %v, want none", got)
	}
	rows, err := s.db.Query(ctx, `SELECT name FROM dns_records WHERE deleted_at IS NULL`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("a DNS record was published for the detached NIC's lease: %d rows", len(rows))
	}
}
