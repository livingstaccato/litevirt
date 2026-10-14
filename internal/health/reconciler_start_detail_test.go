package health

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// F-4. The reconciler's start recorded "started by reconciler after failover"
// whatever made it start the VM, so a start an operator re-armed with `lv start`
// after `lv stop --force`, or an onboot start, read as a failover that never
// happened. The detail names why the VM was started.
//
// Mutation: the detail is the failover text for every start — red.
func TestReconcilerStart_DetailNamesWhyTheVMWasStarted(t *testing.T) {
	for _, tc := range []struct {
		name, state, spec, detail, want, notWant string
		onboot                                   bool
	}{
		{name: "failover", state: "pending", spec: `{}`, want: "after failover"},
		{name: "re-armed operator start", state: "starting", spec: `{}`,
			detail: "operator start: the start cancelled earlier is made again",
			want:   "operator start", notWant: "failover"},
		{name: "self-heal restart", state: "running", spec: `{}`, want: "domain was not running", notWant: "failover"},
		{name: "onboot", state: "stopped", spec: `{"onboot":true}`, onboot: true,
			want: "onboot", notWant: "failover"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testReconcilerDB(t)
			ctx := context.Background()
			if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
				Name: "vm1", HostName: "node-a", Spec: tc.spec, State: tc.state, StateDetail: tc.detail}, nil, nil); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			fake := libvirtfake.New()
			r := NewReconciler("node-a", t.TempDir(), db, fake)
			if tc.onboot {
				r.StartOnbootVMs(ctx)
			} else {
				vm, _ := corrosion.GetVM(ctx, db, "vm1")
				r.startPendingVM(ctx, *vm)
			}
			vm, err := corrosion.GetVM(ctx, db, "vm1")
			if err != nil || vm == nil {
				t.Fatalf("GetVM: %v %v", vm, err)
			}
			if vm.State != "running" {
				t.Fatalf("state = %q (%q), want running", vm.State, vm.StateDetail)
			}
			if !strings.Contains(vm.StateDetail, tc.want) || (tc.notWant != "" && strings.Contains(vm.StateDetail, tc.notWant)) {
				t.Errorf("state_detail = %q, want it to name %q and not %q", vm.StateDetail, tc.want, tc.notWant)
			}
		})
	}
}

// F-4 as the lab saw it: the re-armed start is deferred once (storage still
// recovering), which rewrites the row's state_detail, and is made on the next
// pass. The reason comes from the open vm_start_cancelled record, which no
// deferral rewrites.
//
// Mutation: startedDetail reads only the row's detail text — red.
func TestReconcilerStart_ARearmedStartDeferredOnceStillSaysOperatorStart(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node-a", Spec: `{}`, State: "starting",
		StateDetail: "operator start: the start cancelled earlier is made again"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordStartCancelled(ctx, db, "node-a", "vm1", "starting", false, time.Now()); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})
	deferIt := true
	r.SetStartDeferral(func(_ context.Context, vm *corrosion.VMRecord) error {
		if deferIt {
			return deferredStartErr(vm.Name)
		}
		return nil
	})
	r.reconcile(ctx)
	// What deferStart writes when storage did not answer: the row's own detail
	// no longer says the start was re-armed.
	if err := corrosion.UpdateVMState(ctx, db, "vm1", "starting", "start deferred: storage did not answer"); err != nil {
		t.Fatal(err)
	}
	deferIt = false
	r.reconcile(ctx)
	vm, _ := corrosion.GetVM(ctx, db, "vm1")
	if vm == nil || vm.State != "running" || !strings.Contains(vm.StateDetail, "operator start") || strings.Contains(vm.StateDetail, "failover") {
		t.Fatalf("after a deferred re-armed start ran: %+v, want running with the operator-start detail", vm)
	}
}
