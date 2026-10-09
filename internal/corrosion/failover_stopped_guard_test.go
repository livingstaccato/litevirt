package corrosion

import (
	"context"
	"errors"
	"testing"
)

// The failover writes re-read the workload's state inside their transaction
// and refuse a stopped one with ErrWorkloadStopped, writing nothing: a stop
// that lands after the coordinator chose the workload wins over the recovery
// (docs/migration-failover.md, "Stopped workloads"). Each case's mutation is
// the removal of that writer's stopped check; the write then lands and the
// case goes red.

func TestWriteVMRescheduleProof_StoppedRowWritesNothing(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	apInsertVM(t, c, "vm1", "host-a", "stopped")
	if err := InsertDisk(ctx, c, DiskRecord{VMName: "vm1", DiskName: "root", HostName: "host-a",
		Path: "/d/vm1-root", StorageType: "local"}); err != nil {
		t.Fatal(err)
	}

	err := WriteVMRescheduleProof(ctx, c, apProof("p1", "vm1", "host-b"), "vm1", "host-b")
	if !errors.Is(err, ErrWorkloadStopped) {
		t.Fatalf("WriteVMRescheduleProof on a stopped VM: err=%v, want ErrWorkloadStopped", err)
	}
	vm, _ := GetVM(ctx, c, "vm1")
	if vm == nil || vm.State != "stopped" || vm.HostName != "host-a" || vm.PendingActionID != "" {
		t.Fatalf("the stopped VM was rewritten: %+v", vm)
	}
	if _, ok, _ := GetActionProof(ctx, c, "p1"); ok {
		t.Error("a proof was written for a stopped VM")
	}
	if disks, _ := GetVMDisks(ctx, c, "vm1"); len(disks) != 1 || disks[0].HostName != "host-a" {
		t.Errorf("the stopped VM's disk rows moved: %+v", disks)
	}
}

func TestRescheduleVMHost_StoppedRowIsNotRescheduledPending(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	apInsertVM(t, c, "vm1", "host-a", "stopped")
	if err := InsertDisk(ctx, c, DiskRecord{VMName: "vm1", DiskName: "root", HostName: "host-a",
		Path: "/d/vm1-root", StorageType: "local"}); err != nil {
		t.Fatal(err)
	}

	if err := RescheduleVMHost(ctx, c, "vm1", "host-b", "pending"); !errors.Is(err, ErrWorkloadStopped) {
		t.Fatalf("RescheduleVMHost(pending) on a stopped VM: err=%v, want ErrWorkloadStopped", err)
	}
	if vm, _ := GetVM(ctx, c, "vm1"); vm == nil || vm.State != "stopped" || vm.HostName != "host-a" {
		t.Fatalf("the stopped VM was rewritten: %+v", vm)
	}
	if disks, _ := GetVMDisks(ctx, c, "vm1"); len(disks) != 1 || disks[0].HostName != "host-a" {
		t.Errorf("the stopped VM's disk rows moved: %+v", disks)
	}

	// A move that keeps it stopped is not a start, and is not refused.
	if err := RescheduleVMHost(ctx, c, "vm1", "host-b", "stopped"); err != nil {
		t.Fatalf("RescheduleVMHost(stopped) on a stopped VM: %v", err)
	}
	if vm, _ := GetVM(ctx, c, "vm1"); vm == nil || vm.State != "stopped" || vm.HostName != "host-b" {
		t.Fatalf("a stopped move did not land: %+v", vm)
	}

	// A running VM reschedules as before; a vanished one is reported.
	apInsertVM(t, c, "vm2", "host-a", "running")
	if err := RescheduleVMHost(ctx, c, "vm2", "host-b", "pending"); err != nil {
		t.Fatalf("RescheduleVMHost on a running VM: %v", err)
	}
	if vm, _ := GetVM(ctx, c, "vm2"); vm == nil || vm.State != "pending" || vm.HostName != "host-b" {
		t.Fatalf("the running VM was not rescheduled: %+v", vm)
	}
	if err := RescheduleVMHost(ctx, c, "ghost", "host-b", "pending"); !errors.Is(err, ErrNoRowsAffected) {
		t.Fatalf("RescheduleVMHost on a missing VM: err=%v, want ErrNoRowsAffected", err)
	}
}

func TestRelocateContainerWithToken_StoppedSourceIsNotRelocated(t *testing.T) {
	ctx := context.Background()
	for _, lifecycle := range []bool{false, true} {
		c := newTestDB(t)
		seedRelocatableContainer(t, c, "host-a", "web", lifecycle)
		if err := SetContainerStateDetail(ctx, c, "host-a", "web", "stopped", "operator-stop"); err != nil {
			t.Fatal(err)
		}
		if err := RelocateContainerWithToken(ctx, c, "host-a", "web", "host-b", "tok"); !errors.Is(err, ErrWorkloadStopped) {
			t.Fatalf("lifecycle=%v: relocate a stopped container: err=%v, want ErrWorkloadStopped", lifecycle, err)
		}
		if src, _ := GetContainer(ctx, c, "host-a", "web"); src == nil || src.State != "stopped" || src.StateDetail != "operator-stop" {
			t.Fatalf("lifecycle=%v: the stopped source was changed: %+v", lifecycle, src)
		}
		if dst, _ := GetContainer(ctx, c, "host-b", "web"); dst != nil {
			t.Fatalf("lifecycle=%v: a target row was written for a stopped container: %+v", lifecycle, dst)
		}
	}
}

// A container failover itself marked relocate-skipped is stopped by failover,
// not by intent: the removed-host pass still relocates it.
func TestRelocateContainerWithToken_RelocateSkippedSourceStillMoves(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedRelocatableContainer(t, c, "host-a", "web", true)
	if err := SetContainerStateDetail(ctx, c, "host-a", "web", "stopped", ContainerRelocateSkippedDetail); err != nil {
		t.Fatal(err)
	}
	if err := RelocateContainerWithToken(ctx, c, "host-a", "web", "host-b", "tok"); err != nil {
		t.Fatalf("relocate a relocate-skipped container: %v", err)
	}
	if dst, _ := GetContainer(ctx, c, "host-b", "web"); dst == nil || dst.State != "pending" {
		t.Fatalf("the relocate-skipped container did not move: %+v", dst)
	}
}

func TestMarkContainerRelocateRestore_StoppedRowIsNotMarked(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedRelocatableContainer(t, c, "host-a", "web", true)
	seedRelocatableContainer(t, c, "host-a", "api", true)
	if err := SetContainerStateDetail(ctx, c, "host-a", "web", "stopped", "operator-stop"); err != nil {
		t.Fatal(err)
	}

	if err := MarkContainerRelocateRestore(ctx, c, "host-a", "web", "host-b", "tok"); !errors.Is(err, ErrWorkloadStopped) {
		t.Fatalf("mark a stopped container: err=%v, want ErrWorkloadStopped", err)
	}
	if src, _ := GetContainer(ctx, c, "host-a", "web"); src == nil || src.State != "stopped" || src.StateDetail != "operator-stop" {
		t.Fatalf("the stopped container was marked: %+v", src)
	}

	if err := MarkContainerRelocateRestore(ctx, c, "host-a", "api", "host-b", "tok"); err != nil {
		t.Fatalf("mark a running container: %v", err)
	}
	src, _ := GetContainer(ctx, c, "host-a", "api")
	if target, token, ok := RelocateRestoreMarker(src.State, src.StateDetail); !ok || target != "host-b" || token != "tok" {
		t.Fatalf("the running container's marker = %q/%q (%v), want host-b/tok", src.State, src.StateDetail, ok)
	}
	if err := MarkContainerRelocateRestore(ctx, c, "host-a", "ghost", "host-b", "tok"); !errors.Is(err, ErrNoRowsAffected) {
		t.Fatalf("mark a missing container: err=%v, want ErrNoRowsAffected", err)
	}
}

func TestRecoverableOnHostFailure_StoppedIsNotACandidate(t *testing.T) {
	vm := VMRecord{Name: "vm1", State: "stopped", Spec: `{"on_host_failure":"restart-any"}`}
	if VMRecoverableOnHostFailure(vm, false) || VMRecoverableOnHostFailure(vm, true) {
		t.Error("a stopped VM is recoverable on host failure")
	}
	vm.State = "running"
	if !VMRecoverableOnHostFailure(vm, false) {
		t.Error("a running VM with restart-any is not recoverable")
	}
	ct := ContainerRecord{Name: "ct1", State: "stopped", StateDetail: "operator-stop", OnHostFailure: "image-recreate"}
	if ContainerRecoverableOnHostFailure(ct) {
		t.Error("a stopped container is recoverable on host failure")
	}
	ct.State, ct.StateDetail = "running", ""
	if !ContainerRecoverableOnHostFailure(ct) {
		t.Error("a running container with image-recreate is not recoverable")
	}
}
