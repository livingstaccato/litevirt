// Fleet scenarios for NIC guards (per-NIC anti-spoofing, docs/firewall.md).
//
// The guard is decided on one node — wherever the create, the attach or the
// operator's change lands — and enforced on another: the host that runs the
// VM renders it from its own replica. These scenarios pin that the record a
// create writes reaches the owning host over real replication and renders
// there, that a change made through a different node replaces it on the owner,
// and that a NIC created with no record is left unguarded.

package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
)

// renderOn renders node n's firewall from its own replica, with libvirt's
// taps from n's fake — exactly what n's reconciler would apply.
func renderOn(t *testing.T, n *Node) string {
	t.Helper()
	plan, err := firewall.CorrosionPlanLoader(n.DB, n.Name, firewall.Plan{}, firewall.LoaderOptions{
		RunningTaps: n.Virt.RunningDomainTaps,
		TapBridge:   func(string) string { return "" },
	})(context.Background())
	if err != nil {
		t.Fatalf("plan on %s: %v", n.Name, err)
	}
	out, err := firewall.Render(plan)
	if err != nil {
		t.Fatalf("render on %s: %v", n.Name, err)
	}
	return out
}

func TestFleet_NICGuard_CreateRecordsAndOwnerRenders(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	for _, n := range c.Nodes {
		n.DB.SetClusterPolicyGate(func() bool { return true })
		n.Server.SetBridgeEnsure(func(string) error { return nil })
	}
	owner, entry, other := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()

	// Created through another node, placed on owner: the guard is recorded
	// with the NIC, on by default.
	vm, err := c.SelfClient(entry).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "guarded", Cpu: 1, MemoryMib: 256,
		Placement: &pb.PlacementSpec{Host: owner.Name},
		Network:   []*pb.NetworkAttachment{{Name: "lan", Ip: "10.30.0.5"}},
	}})
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	nics, err := corrosion.MergedVMNICs(ctx, owner.DB, vm.Name)
	if err != nil || len(nics) != 1 {
		t.Fatalf("NICs on owner = %v, %v", nics, err)
	}
	mac := nics[0].MAC

	eventually(t, 10*time.Second, "the guard record to reach every node", func() bool {
		for _, n := range c.Nodes {
			rec, err := corrosion.GetNICGuard(ctx, n.DB, vm.Name, mac)
			if err != nil || rec == nil || !rec.Guarded() {
				return false
			}
		}
		return true
	})
	out := renderOn(t, owner)
	if !strings.Contains(out, "table bridge "+firewall.NICTableName) || !strings.Contains(out, "ip saddr != { 10.30.0.5 } drop") {
		t.Fatalf("the owner does not render the guard:\n%s", out)
	}

	// The operator relaxes it through a third node; the owner renders the
	// change from its replica.
	if _, err := c.SelfClient(other).SetNICGuard(ctx, &pb.SetNICGuardRequest{
		VmName: vm.Name, Mac: mac, Mode: "on", AllowedAddresses: []string{"10.30.0.250"},
	}); err != nil {
		t.Fatalf("SetNICGuard: %v", err)
	}
	eventually(t, 10*time.Second, "the relaxed guard to render on the owner", func() bool {
		return strings.Contains(renderOn(t, owner), "ip saddr != { 10.30.0.250, 10.30.0.5 } drop")
	})

	// Turned off: the owner renders no guard chain for it.
	if _, err := c.SelfClient(other).SetNICGuard(ctx, &pb.SetNICGuardRequest{VmName: vm.Name, Mac: mac, Mode: "off"}); err != nil {
		t.Fatalf("SetNICGuard off: %v", err)
	}
	eventually(t, 10*time.Second, "the guard to go from the owner", func() bool {
		return !strings.Contains(renderOn(t, owner), "chain guard_")
	})
}

// TestFleet_NICGuard_NoRecordWhileStoreClosed: before failover_scope_v1 has
// latched nothing can be recorded, so a NIC created with default settings is
// created unguarded, as every NIC was — and an explicit setting is refused
// rather than silently dropped.
func TestFleet_NICGuard_NoRecordWhileStoreClosed(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	n := c.Nodes[0]
	n.Server.SetBridgeEnsure(func(string) error { return nil })
	ctx := context.Background()
	if _, err := c.SelfClient(n).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "plain", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n.Name},
		Network: []*pb.NetworkAttachment{{Name: "lan", Ip: "10.30.0.6"}},
	}}); err != nil {
		t.Fatalf("CreateVM with default guard and the store closed: %v", err)
	}
	all, err := corrosion.ListNICGuards(ctx, n.DB)
	if err != nil || len(all) != 0 {
		t.Fatalf("records = %v, %v; want none", all, err)
	}
	if strings.Contains(renderOn(t, n), "chain guard_") {
		t.Fatal("a NIC with no record was guarded")
	}
	if _, err := c.SelfClient(n).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "explicit", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n.Name},
		Network: []*pb.NetworkAttachment{{Name: "lan", SpoofGuard: "off"}},
	}}); err == nil {
		t.Fatal("an explicit guard setting was accepted with nowhere to record it")
	}
}
