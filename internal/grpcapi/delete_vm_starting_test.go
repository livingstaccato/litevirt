package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Whole-branch review I-1: a delete of a VM being started with no domain
// (pending/starting — a failover's start, or one re-armed after `lv stop
// --force`) removed some of its disks, failed on another, and returned with
// the row still pending. The reconciler then resumed that start, and a
// transfer start rebuilds a missing disk from its image: the VM the operator
// was deleting booted on a blank root disk. The delete now records the row
// stopped by its operator before it removes anything, so a failed delete
// leaves a row no start path starts.
//
// Mutation: the stop not recorded — the row is still pending after the failed
// delete: red.
func TestDeleteVM_AFailedDeleteOfAVMBeingStartedLeavesItUnstartable(t *testing.T) {
	refuse := standInBtrfsForDelete(t)
	root := t.TempDir()
	local := filepath.Join(t.TempDir(), "a-root.qcow2")
	if err := qcow2.Create(local, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	subvol := filepath.Join(root, "a-data")
	if err := os.MkdirAll(subvol, 0o755); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(subvol, "a-data.qcow2")
	if err := qcow2.Create(data, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	s, fake := deleteDiskServerWith(t, false,
		corrosion.DiskRecord{VMName: "a", DiskName: "root", Path: local, StorageType: "local", DeleteWithVM: true},
		corrosion.DiskRecord{VMName: "a", DiskName: "data", Path: data, SizeBytes: 1 << 20,
			StorageType: "btrfs", StorageVolume: "bt", DeleteWithVM: true})
	s.addStoragePoolRef("bt", StoragePoolRef{Driver: "btrfs", Source: root})
	ctx := context.Background()
	// A transfer onto this host, its start not made yet: no domain here.
	if err := corrosion.UpdateVMState(ctx, s.db, "a", "pending", ""); err != nil {
		t.Fatal(err)
	}

	_, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "a"})
	if err == nil {
		t.Fatal("the delete reported success with the data disk's subvolume left behind")
	}
	if !strings.Contains(err.Error(), "lv rm --keep-disks a") {
		t.Errorf("the failed delete does not name its escape (lv rm --keep-disks a): %v", err)
	}
	if exists(local) {
		t.Fatal("the root disk was not removed: the test proves nothing")
	}
	vm, _ := corrosion.GetVM(ctx, s.db, "a")
	if vm == nil {
		t.Fatal("the failed delete dropped the record")
	}
	if vm.State != "stopped" || !health.IsOperatorStop(vm.StateDetail) {
		t.Fatalf("the row of a VM whose delete failed after removing its disks: %s/%q, want stopped by its operator (no start path starts it)", vm.State, vm.StateDetail)
	}

	// A reconcile pass neither defines the VM nor rebuilds its root disk.
	health.NewReconciler(s.hostName, s.dataDir, s.db, fake).ReconcileOnce(ctx)
	if fake.DomainExists("a") {
		t.Fatal("the reconciler defined the VM whose delete failed")
	}
	if exists(local) {
		t.Fatal("the reconciler rebuilt the removed root disk")
	}

	// The retry finishes the delete.
	if err := os.Remove(refuse); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "a"}); err != nil {
		t.Fatalf("retried delete: %v", err)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "a"); vm != nil {
		t.Fatal("the retried delete kept the record")
	}
}
