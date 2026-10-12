package health

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Re-review 1, R1-I-1: a row the pre-boot check cannot read is a transient
// failure — the lab's own condition, where a stalled store timed the
// reconciler's queries out. A proof-less start (self-heal, onboot) must be
// retried on the next pass, never parked in "error": no pass re-drives
// "error", so the VM would stay down until an operator started it.
func TestStartPendingVM_RowUnreadableBeforeStartIsRetriedNotErrored(t *testing.T) {
	db, fake, r, vm := startRowGoneFixture(t, false)
	ctx := context.Background()
	faults := 1
	r.startRowReadFault = func(string) error {
		if faults > 0 {
			faults--
			return errors.New("injected: query: context deadline exceeded")
		}
		return nil
	}

	r.startPendingVM(ctx, vm)
	if startedVM1(fake) {
		t.Fatal("the reconciler booted vm1 although it could not re-read its row")
	}
	row, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || row == nil {
		t.Fatalf("GetVM: %v %v", row, err)
	}
	if row.State == "error" {
		t.Fatalf("a transient read failure parked vm1 in error (%q); nothing re-drives it", row.StateDetail)
	}
	if row.State != "starting" {
		t.Fatalf("vm1 reads %q after the refused start, want starting (re-driven next pass)", row.State)
	}

	// The next pass re-drives it through the walk's starting case.
	r.ReconcileOnce(ctx)
	if !startedVM1(fake) {
		t.Fatal("the next pass did not retry the start")
	}
	if st, _ := fake.DomainState("vm1"); st != "running" {
		t.Fatalf("vm1 domain %q after the retry, want running", st)
	}
	if row, _ := corrosion.GetVM(ctx, db, "vm1"); row == nil || row.State != "running" {
		t.Fatalf("vm1 row after the retry = %+v, want running", row)
	}
}

// With a proof the start is re-armed to pending, as every other retryable
// failure of a proof-gated start is — never error, never the proof failed.
func TestStartPendingVM_RowUnreadableBeforeStartRearmsAProof(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	proof := corrosion.ActionProof{ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm1", DestHost: "node-a", Coordinator: "node-a"}
	if err := corrosion.WriteVMRescheduleProof(ctx, db, proof, "vm1", "node-a"); err != nil {
		t.Fatalf("WriteVMRescheduleProof: %v", err)
	}
	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})
	r.startRowReadFault = func(string) error { return errors.New("injected: query: context deadline exceeded") }
	fresh, _ := corrosion.GetVM(ctx, db, "vm1")

	r.startPendingVM(ctx, *fresh)
	if startedVM1(fake) {
		t.Fatal("the reconciler booted vm1 although it could not re-read its row")
	}
	row, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || row == nil {
		t.Fatalf("GetVM: %v %v", row, err)
	}
	if row.State != "pending" {
		t.Fatalf("vm1 reads %q/%q after a transient read failure, want pending (re-armed)", row.State, row.StateDetail)
	}
}
