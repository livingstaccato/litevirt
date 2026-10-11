package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The move decisions (drain's live-or-cold choice, what a cold or storage copy
// carries, failback's skip) and the cluster's definition of shared storage
// (corrosion.DiskIsShared) must give one answer for every disk a move can copy.
// btrfs, which a clone or MoveVolume into a btrfs pool creates, used to be
// host-local to the one and not to the other.
//
// Mutation: drop the btrfs clause in isHostLocalDisk - the btrfs row fails.
func TestIsHostLocalDiskAgreesWithDiskIsShared(t *testing.T) {
	for _, st := range []string{"", "local", "dir", "btrfs", "BTRFS", "nfs", "ceph", "rbd", "iscsi"} {
		d := corrosion.DiskRecord{StorageType: st}
		want := !corrosion.DiskIsShared(d)
		if got := isHostLocalDisk(d); got != want {
			t.Errorf("storage_type %q: isHostLocalDisk = %v, DiskIsShared says shared = %v", st, got, !want)
		}
	}
	// Volumes, not files: no move here copies them, so they stay out of the
	// host-local set though they are not shared either.
	for _, st := range []string{"zfs", "lvm"} {
		if isHostLocalDisk(corrosion.DiskRecord{StorageType: st}) {
			t.Errorf("%s was taken for a copyable host-local file", st)
		}
	}
}
