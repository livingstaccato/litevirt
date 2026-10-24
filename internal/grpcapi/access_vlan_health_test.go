package grpcapi

import (
	"context"
	"strings"
	"sync"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/network"
)

// fakeBridges is this host's bridges' VLAN filtering: bridge → on. A bridge
// not in the map does not exist here.
type fakeBridges struct {
	mu sync.Mutex
	on map[string]bool
}

func (f *fakeBridges) read(bridge string) (isBridge, on bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.on[bridge]
	return ok, v, nil
}

func (f *fakeBridges) set(bridge string, on bool) {
	f.mu.Lock()
	f.on[bridge] = on
	f.mu.Unlock()
}

// bridge_vlan_filtering_off is raised for a bridge of this host that does not
// filter VLANs while a VM of the cluster (on any host) has an access-port NIC
// on it — observed, then confirmed — naming the host, the bridge, the VM
// count and the fix; it resolves once the bridge filters, and again when no
// such VM is left. A bridge only a trunk NIC uses, and an access NIC's bridge
// that does not exist here, raise nothing.
//
// Mutations: raise for any trunk NIC (len(trunk) >= 1) — red (the trunk
// bridge is raised); judge a bridge that does not exist here — red; drop the
// resolve of a condition whose bridge is fine — red.
func TestReconcileAccessVLANBridges_RaisesAndResolves(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	acc, trk, absent := network.FlatBridgeName("accnet"), network.FlatBridgeName("trknet"), network.FlatBridgeName("elsewhere")
	br := &fakeBridges{on: map[string]bool{acc: false, trk: false}}
	s.SetBridgeVLANFiltering(br.read)
	insertTestVMWithSpec(t, ctx, s.db, "vm-acc", "other-host", "running", seedSpecJSON(t, &pb.VMSpec{
		Name: "vm-acc", Network: []*pb.NetworkAttachment{{Name: "accnet", Trunk: []int32{30}}},
	}))
	insertTestVMWithSpec(t, ctx, s.db, "vm-trk", "other-host", "running", seedSpecJSON(t, &pb.VMSpec{
		Name: "vm-trk", Network: []*pb.NetworkAttachment{{Name: "trknet", Trunk: []int32{100, 101}}},
	}))
	insertTestVMWithSpec(t, ctx, s.db, "vm-absent", "other-host", "running", seedSpecJSON(t, &pb.VMSpec{
		Name: "vm-absent", Network: []*pb.NetworkAttachment{{Name: "elsewhere", Trunk: []int32{40}}},
	}))
	cond := func(bridge string) (corrosion.HealthCondition, bool) {
		t.Helper()
		c, ok, err := corrosion.GetHealthCondition(ctx, s.db, health.AccessVLANEvaluator, health.CondBridgeVLANFilteringOff,
			"host", health.AccessVLANSubject(bridge, s.hostName))
		if err != nil {
			t.Fatal(err)
		}
		return c, ok
	}

	s.ReconcileAccessVLANBridges(ctx)
	c, ok := cond(acc)
	if !ok || c.Lifecycle != corrosion.ConditionObserved {
		t.Fatalf("after one pass the condition for %s is %+v (found %v), want observed", acc, c, ok)
	}
	for _, want := range []string{`"host":"test-host"`, `"bridge":"` + acc + `"`, `"vm_count":1`, "vm-acc",
		"ip link set dev " + acc + " type bridge vlan_filtering 1"} {
		if !strings.Contains(c.Evidence, want) {
			t.Errorf("evidence lacks %q:\n%s", want, c.Evidence)
		}
	}
	for _, b := range []string{trk, absent} {
		if c, ok := cond(b); ok {
			t.Errorf("a condition was raised for %s: %+v", b, c)
		}
	}
	s.ReconcileAccessVLANBridges(ctx)
	if c, _ := cond(acc); c.Lifecycle != corrosion.ConditionConfirmed {
		t.Fatalf("after two passes the condition is %s, want confirmed", c.Lifecycle)
	}
	unfit, err := health.AccessVLANUnfitHosts(ctx, s.db)
	if err != nil || !unfit[s.hostName][acc] || len(unfit) != 1 || len(unfit[s.hostName]) != 1 {
		t.Fatalf("AccessVLANUnfitHosts = %v (%v), want only %s on %s", unfit, err, acc, s.hostName)
	}

	br.set(acc, true)
	s.ReconcileAccessVLANBridges(ctx)
	if c, _ := cond(acc); c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("once %s filters VLANs the condition is %s, want resolved", acc, c.Lifecycle)
	}
	if unfit, _ := health.AccessVLANUnfitHosts(ctx, s.db); len(unfit) != 0 {
		t.Fatalf("AccessVLANUnfitHosts = %v after the resolve, want none", unfit)
	}

	br.set(acc, false)
	s.ReconcileAccessVLANBridges(ctx)
	if c, _ := cond(acc); c.Lifecycle != corrosion.ConditionObserved {
		t.Fatalf("filtering off again: the condition is %s, want observed", c.Lifecycle)
	}
	if err := corrosion.DeleteVM(ctx, s.db, "vm-acc"); err != nil {
		t.Fatal(err)
	}
	s.ReconcileAccessVLANBridges(ctx)
	if c, _ := cond(acc); c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("with no access-VLAN VM on %s left the condition is %s, want resolved", acc, c.Lifecycle)
	}
}
