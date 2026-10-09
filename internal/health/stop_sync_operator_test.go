package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// An `lv stop` that completes while the reconciler is walking keeps its
// operator stop. The walk decided from a snapshot that said "running" and
// found the domain cleanly shut down, which classifies as guest-shutdown —
// a stop nobody asked for, which failover would restart elsewhere on shared
// storage. The sync must not overwrite the operator's stop with it.
//
// Mutation: make SyncVMStopIfRunning's precondition ignore the row's state —
// the stop is rewritten to guest-shutdown and the test goes red.
func TestStopSync_AnOperatorStopDuringTheWalkIsKept(t *testing.T) {
	db, r := stopSyncFixture(t)
	fake := r.virt.(*libvirtfake.Fake)
	fake.SetStateReason("vm1", "guest-shutdown")
	ctx := context.Background()
	r.stopSyncHook = func(ctx context.Context, name string) {
		if err := corrosion.UpdateVMState(ctx, db, name, "stopped", operatorStopDetail); err != nil {
			t.Errorf("record the operator stop: %v", err)
		}
	}
	r.ReconcileOnce(ctx)
	vm, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.State != "stopped" || vm.StateDetail != operatorStopDetail {
		t.Fatalf("vm1 after a stop sync that raced an lv stop = %s/%q, want stopped/%q", vm.State, vm.StateDetail, operatorStopDetail)
	}

	// Without the race the sync records the clean shutdown, as before.
	db2, r2 := stopSyncFixture(t)
	r2.virt.(*libvirtfake.Fake).SetStateReason("vm1", "guest-shutdown")
	r2.ReconcileOnce(ctx)
	if vm, _ := corrosion.GetVM(ctx, db2, "vm1"); vm == nil || vm.State != "stopped" || vm.StateDetail != guestShutdownDetail {
		t.Fatalf("vm1 after an unraced clean shutdown = %+v, want stopped/%q", vm, guestShutdownDetail)
	}
}
