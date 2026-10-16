package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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
// discovered for Y lands on Y, not on whatever the network's legacy row names.
func TestDiscovery_RecordsOnTheNICThatHoldsTheLease(t *testing.T) {
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
	if !s.claimAndRecordDiscoveredVMIP(ctx, vm, "lan", discNICY, "10.0.60.9") {
		t.Fatal("the discovered address of a live NIC was not recorded")
	}
	if got := mergedIPs(t, s); got[discNICY] != "10.0.60.9" || got[discNICX] != "" {
		t.Errorf("addresses after discovery for Y = %v, want only Y at 10.0.60.9", got)
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

// vmNICsOnlyY adds NIC Y on wan to web as an attach after the latch does:
// vm_nics only.
func vmNICsOnlyY(t *testing.T, s *Server) string {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "wan", Type: "bridge", Config: `{"Interface":"br-wan"}`}); err != nil {
		t.Fatal(err)
	}
	id := corrosion.DeterministicNICID("web", discNICY)
	if err := corrosion.UpsertNIC(ctx, s.db, corrosion.NICRecord{VMName: "web", ID: id, NetworkName: "wan", MAC: discNICY, Ordinal: 1}); err != nil {
		t.Fatal(err)
	}
	return id
}

func nicRowStamp(t *testing.T, s *Server, id string) string {
	t.Helper()
	rows, err := s.db.Query(context.Background(), `SELECT updated_at FROM vm_nics WHERE vm_name = 'web' AND id = ?`, id)
	if err != nil || len(rows) != 1 {
		t.Fatalf("vm_nics %s: %d rows, %v", id, len(rows), err)
	}
	return rows[0].String("updated_at")
}

// On the owner, SetVMIP's read and writes run under the VM lock, so they wait
// for a detach (or any locked operation) in progress.
func TestSetVMIP_WaitsForTheVMLock(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	discoveryVM(t, s)
	vmNICsOnlyY(t, s)
	unlock := s.lockVM("web")
	done := make(chan error, 1)
	go func() {
		_, err := s.SetVMIP(ctx, &pb.SetVMIPRequest{Name: "web", Ip: "10.0.61.9", NetworkName: "wan"})
		done <- err
	}()
	select {
	case err := <-done:
		unlock()
		t.Fatalf("SetVMIP returned (%v) while the VM lock was held", err)
	case <-time.After(300 * time.Millisecond):
	}
	if got := mergedIPs(t, s)[discNICY]; got != "" {
		t.Errorf("Y's address was written while the VM lock was held: %q", got)
	}
	unlock()
	if err := <-done; err != nil {
		t.Fatalf("SetVMIP: %v", err)
	}
	if got := mergedIPs(t, s)[discNICY]; got != "10.0.61.9" {
		t.Errorf("Y's address after the lock was released = %q, want 10.0.61.9", got)
	}
}

// A discovery that cannot take the VM lock at once does not wait for it: it
// writes the legacy row only, so a vm_nics-only NIC is left as it is.
func TestDiscovery_WithoutTheVMLockWritesTheLegacyRowOnly(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	discoveryVM(t, s)
	id := vmNICsOnlyY(t, s)
	before := nicRowStamp(t, s, id)
	vm, err := corrosion.GetVM(ctx, s.db, "web")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %+v %v", vm, err)
	}
	unlock := s.lockVM("web")
	recorded := s.claimAndRecordDiscoveredVMIP(ctx, vm, "wan", discNICY, "10.0.61.10")
	unlock()
	if recorded {
		t.Error("a discovery without the VM lock recorded an address on a vm_nics-only NIC")
	}
	if got := nicRowStamp(t, s, id); got != before {
		t.Errorf("Y's vm_nics row was rewritten without the VM lock: %q, was %q", got, before)
	}
	// With the lock free, the owner writes it.
	if !s.claimAndRecordDiscoveredVMIP(ctx, vm, "wan", discNICY, "10.0.61.10") {
		t.Fatal("the owner did not record a discovered address with the VM lock free")
	}
	if got := mergedIPs(t, s)[discNICY]; got != "10.0.61.10" {
		t.Errorf("Y's address = %q, want 10.0.61.10", got)
	}
}
