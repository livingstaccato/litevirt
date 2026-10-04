package grpcapi

import (
	"slices"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The migrate_disks list names the host-local disks only (an untyped row
// counts as host-local, as it does for the target's stubs), and a copied disk
// that cannot be named is refused: libvirt reads an empty or short list as
// "copy every writable disk" or "leave this one behind".
//
// The shared-disk half is pinned end to end by
// TestFleet_StorageMigrationCopiesOnlyHostLocalDisks. Mutation: drop the
// TargetDev refusal (skip such a disk) — the second case goes red.
func TestStorageMigrationTargets(t *testing.T) {
	got, err := storageMigrationTargets("vm", []corrosion.DiskRecord{
		{DiskName: "root", Path: "/d/root", StorageType: "local", TargetDev: "vda"},
		{DiskName: "data", Path: "/nfs/data", StorageType: "nfs", TargetDev: "vdb"},
		{DiskName: "old", Path: "/d/old", StorageType: "", TargetDev: "vdc"},
		{DiskName: "dir", Path: "/d/dir", StorageType: "dir", TargetDev: "vdd"},
		{DiskName: "rbd", Path: "rbd/pool/x", StorageType: "ceph", TargetDev: "vde"},
	})
	if err != nil || !slices.Equal(got, []string{"vda", "vdc", "vdd"}) {
		t.Fatalf("targets = %v, %v; want [vda vdc vdd]", got, err)
	}

	_, err = storageMigrationTargets("vm", []corrosion.DiskRecord{
		{DiskName: "root", Path: "/d/root", StorageType: "local", TargetDev: "vda"},
		{DiskName: "data", Path: "/d/data", StorageType: "local"},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a copied disk with no target device: err = %v, want FailedPrecondition", err)
	}
}
