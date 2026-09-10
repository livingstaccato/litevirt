package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// startProofReadyToComplete builds the exact precondition CompleteVMStartProof
// needs: a VM pointing at a claimed, non-terminal proof.
func startProofReadyToComplete(t *testing.T, db *corrosion.Client, vm, host string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: vm, HostName: host, Spec: "{}", State: "starting",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.BackfillOwnerEpochs(ctx, db, host); err != nil {
		t.Fatalf("BackfillOwnerEpochs: %v", err)
	}
	if err := corrosion.WriteVMRescheduleProof(ctx, db, corrosion.ActionProof{
		ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm", TargetName: vm,
		DestHost: host, Coordinator: "coord-1", LeaseHolder: "coord-1",
		QuorumLive: 3, QuorumNeeded: 2,
	}, vm, host); err != nil {
		t.Fatalf("WriteVMRescheduleProof: %v", err)
	}
	if err := corrosion.ClaimActionProof(ctx, db, "p1", host); err != nil {
		t.Fatalf("ClaimActionProof: %v", err)
	}
}

// TestReconciler_CompletingAStartProofMarksTheRuntime closes a gap that was
// real, not hypothetical.
//
// CompleteVMStartProof sets state='running' AND vm_owner_epoch = vm_owner_epoch
// + 1 in one guarded batch. One of its two call sites wrote both markers by
// hand; the other — the already-running-domain retry — wrote NEITHER. A VM
// recovered through that branch ran at a fresh generation it could not prove
// until the next convergence sweep, and on a fleet with the default
// enforcement.owner_epoch=false the backfill that would fix it never runs.
func TestReconciler_CompletingAStartProofMarksTheRuntime(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)
	r := NewReconciler("node-a", dir, db, fake)
	startProofReadyToComplete(t, db, "vm1", "node-a")

	before, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || before == nil {
		t.Fatalf("GetVM = (%v, %v), want a row", before, err)
	}
	if before.OwnerEpoch != 1 {
		t.Fatalf("setup: epoch = %d, want 1", before.OwnerEpoch)
	}

	if err := r.publishRunningMinted(ctx, "vm1", func(ctx context.Context) error {
		return corrosion.CompleteVMStartProof(ctx, db, "p1", "vm1", "node-a")
	}); err != nil {
		t.Fatalf("publishRunningMinted: %v", err)
	}

	row, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || row == nil {
		t.Fatalf("GetVM = (%v, %v), want a row", row, err)
	}
	if row.State != "running" || row.OwnerEpoch != 2 {
		t.Fatalf("row = %q/epoch %d, want running/2 (the completion mints)", row.State, row.OwnerEpoch)
	}
	epoch, ok, rerr := ReadVMOwnerEpochMarker(dir, "vm1")
	if rerr != nil || !ok || epoch != 2 {
		t.Errorf("file marker = (%d,%v,%v), want (2,true,nil) — a completed start proof "+
			"leaves a running VM that must be able to prove its generation", epoch, ok, rerr)
	}
	if e, ok, _ := fake.GetDomainOwnerEpoch("vm1"); !ok || e != 2 {
		t.Errorf("domain marker = (%d,%v), want (2,true)", e, ok)
	}
}

// TestVMChecker_HealingToRunningMarksFirst.
//
// vmcheck heals a stale row toward libvirt reality. That write publishes the VM
// as running on this host, so it goes through the chokepoint like any other.
// Observed from inside the commit: the end state is identical either way.
func TestVMChecker_HealingToRunningMarksFirst(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node1", Spec: "{}", State: "stopped",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.BackfillOwnerEpochs(ctx, db, "node1"); err != nil {
		t.Fatal(err)
	}
	v := NewVMChecker("node1", dir, db, nil)

	var stateAtMark string
	err := v.publishRunning(ctx, "vm1", "running", func(ctx context.Context) error {
		if row, _ := corrosion.GetVM(ctx, db, "vm1"); row != nil {
			stateAtMark = row.State
		}
		return corrosion.UpdateVMStateStrict(ctx, db, "vm1", "running", "reconciled from libvirt")
	})
	if err != nil {
		t.Fatalf("publishRunning: %v", err)
	}
	if stateAtMark != "stopped" {
		t.Errorf("row was %q when the marker was written, want stopped", stateAtMark)
	}
	if epoch, ok, _ := ReadVMOwnerEpochMarker(dir, "vm1"); !ok || epoch != 1 {
		t.Errorf("file marker = (%d,%v), want (1,true) — a nil *lv.Client must not stop the "+
			"FILE marker from landing", epoch, ok)
	}
}

// TestVMChecker_ANilConcreteClientDoesNotPanic: v.virt is a *lv.Client, nil in
// nearly every test and on a host whose libvirt connection is down. Boxed into
// DomainEpochSetter it is a NON-nil interface holding a nil pointer.
func TestVMChecker_ANilConcreteClientDoesNotPanic(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node1", Spec: "{}", State: "stopped",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	v := NewVMChecker("node1", t.TempDir(), db, nil)
	committed := false
	if err := v.publishRunning(ctx, "vm1", "running", func(context.Context) error {
		committed = true
		return nil
	}); err != nil {
		t.Fatalf("a nil libvirt client must not fail the transition: %v", err)
	}
	if !committed {
		t.Error("a nil libvirt client blocked the transition")
	}
}

// TestVMChecker_AStopIsNotGatedOnMarkers: vmcheck writes "error" and
// "migrating" states through the same helper wherever it is wrapped uniformly.
// Those must never attempt a running-marker write.
func TestVMChecker_AStopIsNotGatedOnMarkers(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node1", Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.BackfillOwnerEpochs(ctx, db, "node1"); err != nil {
		t.Fatal(err)
	}
	v := NewVMChecker("node1", dir, db, nil)

	if err := v.publishRunning(ctx, "vm1", "error", func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", "error", "health check failed")
	}); err != nil {
		t.Fatalf("a non-running publish must not be gated on markers: %v", err)
	}
	if _, ok, _ := ReadVMOwnerEpochMarker(dir, "vm1"); ok {
		t.Error("a running marker was written for an error state")
	}
}
