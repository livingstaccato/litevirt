package firewall

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestReconciler_ArmResendsTheTable (re-review m9): a pass that arms a VM sends
// the per-NIC table even when it renders as last time: the kernel's copy may
// have been flushed out of band (an nftables.service reload), and a start must
// not be cleared by a cache.
func TestReconciler_ArmResendsTheTable(t *testing.T) {
	f := &fakeNft{}
	plan := Plan{NICs: []NICBinding{{NICDev: "lvt525400000001", VMName: "web", Guard: &NICGuard{MAC: "52:54:00:00:00:01"}}}}
	r := NewReconciler(func(context.Context) (Plan, error) { return plan, nil }, NewApplier(f), 0)
	r.SetArming(NewArming())
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := len(f.applies)
	if err := r.Arm(context.Background(), "web"); err != nil {
		t.Fatal(err)
	}
	if len(f.applies) <= before {
		t.Errorf("Arm sent nothing (%d applies before and after): a flushed kernel table would stay flushed", before)
	}
}

// TestReconciler_ArmCoalesces (re-review m3): many starts at once — an onboot,
// a failover — share passes instead of each running its own.
func TestReconciler_ArmCoalesces(t *testing.T) {
	var passes int32
	gate := make(chan struct{})
	loader := func(context.Context) (Plan, error) {
		if atomic.AddInt32(&passes, 1) == 1 {
			<-gate // the first pass is slow; the others pile up behind it
		}
		return Plan{}, nil
	}
	r := NewReconciler(loader, NewApplier(&fakeNft{}), 0)
	r.SetArming(NewArming())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = r.Arm(context.Background(), "vm0") }()
	for atomic.LoadInt32(&passes) == 0 {
		time.Sleep(time.Millisecond)
	}
	for i := 1; i <= 20; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); _ = r.Arm(context.Background(), "vm") }(i)
	}
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()
	if n := atomic.LoadInt32(&passes); n > 3 {
		t.Errorf("21 arms ran %d passes; waiting arms must share one", n)
	}
}

// TestReconciler_GuardsInForce (re-review m3): whether a VM's guarded NICs
// are in the per-NIC table last applied.
func TestReconciler_GuardsInForce(t *testing.T) {
	plan := Plan{NICs: []NICBinding{{NICDev: "lvt525400000001", VMName: "web", MAC: "52:54:00:00:00:01", Guard: &NICGuard{MAC: "52:54:00:00:00:01"}}}}
	r := NewReconciler(func(context.Context) (Plan, error) { return plan, nil }, NewApplier(&fakeNft{}), 0)
	if r.GuardsInForce("web", []string{"52:54:00:00:00:01"}) {
		t.Error("in force before any pass")
	}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !r.GuardsInForce("web", []string{"52:54:00:00:00:01"}) {
		t.Error("not in force after the pass")
	}
	if r.GuardsInForce("web", []string{"52:54:00:00:00:01", "52:54:00:00:00:02"}) {
		t.Error("a guarded NIC missing from the table counted as in force")
	}
}

// TestCorrosionPlanLoader_IgnoresAnotherIncarnationsRecord (re-review m1): a
// record left by an earlier VM under the same name and MAC — a live restore
// keeps MACs; a NIC decided "no record" writes none — guards nothing.
func TestCorrosionPlanLoader_IgnoresAnotherIncarnationsRecord(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "web", HostName: "host-a", State: "running",
		Spec: `{"name":"web","uuid":"u-2"}`},
		[]corrosion.InterfaceRecord{{VMName: "web", NetworkName: "lan", MAC: "52:54:00:00:00:01", IP: "10.0.0.5"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.PutNICGuard(ctx, db, capabilities.GrantForTest(t, capabilities.FeatureNICGuards), corrosion.NICGuardRecord{VMName: "web", MAC: "52:54:00:00:00:01",
		Mode: corrosion.NICGuardOn, VMUUID: "u-1"}, "t"); err != nil {
		t.Fatal(err)
	}
	plan, err := CorrosionPlanLoader(db, "host-a", Plan{}, liveTaps(map[string]map[string]string{"web": {"52:54:00:00:00:01": "vnet1"}}))(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.NICs) != 1 || plan.NICs[0].Guard != nil {
		t.Errorf("an earlier incarnation's record guarded the NIC: %+v", plan.NICs)
	}
}

// TestCorrosionPlanLoader_PendingContainerNICs (re-review m10): a container's
// NICs are rendered from what its create registered before the runtime brings
// its veth up — before its rows exist.
func TestCorrosionPlanLoader_PendingContainerNICs(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.SetClusterPolicyGate(func() bool { return true })
	owner := corrosion.ContainerGuardOwner("host-a", "web")
	if err := corrosion.PutNICGuard(ctx, db, capabilities.GrantForTest(t, capabilities.FeatureNICGuards), corrosion.NICGuardRecord{VMName: owner, MAC: "52:00:00:00:00:10", Mode: corrosion.NICGuardOn}, "t"); err != nil {
		t.Fatal(err)
	}
	arm := NewArming()
	arm.SetPendingContainer("web", []corrosion.ContainerInterfaceRecord{{HostName: "host-a", CtName: "web", NetworkName: "lan",
		MAC: "52:00:00:00:00:10", IP: "10.0.0.9", VethDevice: "lvc0abc"}})
	plan, err := CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{Arming: arm})(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.NICs) != 1 || plan.NICs[0].NICDev != "lvc0abc" || plan.NICs[0].Guard == nil {
		t.Fatalf("the container's pending NIC is not rendered guarded: %+v", plan.NICs)
	}
	arm.ClearPendingContainer("web")
	plan, _ = CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{Arming: arm})(ctx)
	if len(plan.NICs) != 0 {
		t.Errorf("rendered after its pending NICs were cleared: %+v", plan.NICs)
	}
}
