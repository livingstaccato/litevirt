package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// snapDependentsFixture is a running VM "src" on host-a whose root disk is an
// external snapshot's overlay over its own base (both real qcow2 files), with
// one disk snapshot s1 recorded in corrosion and the fake.
type snapDependentsFixture struct {
	s             *Server
	fake          *libvirtfake.Fake
	dir           string
	base, overlay string
}

func newSnapDependentsFixture(t *testing.T) *snapDependentsFixture {
	t.Helper()
	needQemuImg(t)
	ctx := adminCtx()
	s, fake := newDiskPathTestServer(t)
	dir := t.TempDir()
	f := &snapDependentsFixture{s: s, fake: fake, dir: dir,
		base:    filepath.Join(dir, "src-root.qcow2"),
		overlay: filepath.Join(dir, "src-root.s1"),
	}
	runQemuImg(t, "create", "-q", "-f", "qcow2", f.base, "1M")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", f.base, f.overlay)
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "src", HostName: "host-a", State: "running"}, nil,
		[]corrosion.DiskRecord{{VMName: "src", DiskName: "root", HostName: "host-a", Path: f.overlay, StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{
		ID: "src-s1", VMName: "src", HostName: "host-a", Name: "s1", State: "ok", Type: "disk",
	}); err != nil {
		t.Fatalf("InsertSnapshot: %v", err)
	}
	if _, err := fake.CreateSnapshot("src", "s1"); err != nil {
		t.Fatalf("fake CreateSnapshot: %v", err)
	}
	return f
}

// cloneOn records a stopped VM "clone" on host-a whose disk file is a qcow2
// overlay of backsOn; recordedBacking is its vm_disks.backing_disk ("" for a
// clone whose record does not say, so only its header does).
func (f *snapDependentsFixture) cloneOn(t *testing.T, backsOn, recordedBacking string) {
	t.Helper()
	file := filepath.Join(f.dir, "clone-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", backsOn, file)
	if err := corrosion.InsertVM(adminCtx(), f.s.db,
		corrosion.VMRecord{Name: "clone", HostName: "host-a", State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "clone", DiskName: "root", HostName: "host-a", Path: file, StorageType: "local", BackingDisk: recordedBacking}},
	); err != nil {
		t.Fatalf("InsertVM clone: %v", err)
	}
}

func (f *snapDependentsFixture) deleteS1(t *testing.T) {
	t.Helper()
	if _, err := f.s.DeleteSnapshot(adminCtx(), &pb.DeleteSnapshotRequest{VmName: "src", SnapshotName: "s1"}); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
}

func (f *snapDependentsFixture) requireNotFlattened(t *testing.T) {
	t.Helper()
	for _, e := range f.fake.EventLog() {
		if e.Domain == "src" && e.Op == "snapshot-flatten" {
			t.Fatal("the snapshot's files back another VM's disk, yet the delete flattened them " +
				"(block-commit into the base and removal of the overlay): that VM's chain would be destroyed")
		}
	}
	for _, p := range []string{f.base, f.overlay} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s is gone: %v", p, err)
		}
	}
}

// Without anything else layered on the VM's files, deleting the last snapshot
// of a running VM still flattens (the existing behaviour is kept).
func TestDeleteSnapshot_NoDependentStillFlattens(t *testing.T) {
	f := newSnapDependentsFixture(t)
	f.deleteS1(t)
	if !hasOp(f.fake.EventLog(), "snapshot-flatten", "src") {
		t.Fatal("deleting the last snapshot of a running VM with nothing layered on it must still flatten")
	}
}

// lab-recheck-5 line 82: a linked clone made while its source had a
// snapshot backs on the source's snapshot overlay, recorded as its
// backing_disk.
func TestDeleteSnapshot_RecordedLinkedCloneKeepsTheFiles(t *testing.T) {
	f := newSnapDependentsFixture(t)
	f.cloneOn(t, f.overlay, f.overlay)
	f.deleteS1(t)
	f.requireNotFlattened(t)
	if !hasOp(f.fake.EventLog(), "snapshot-delete", "src") {
		t.Fatal("the snapshot must still be deleted (its metadata), keeping the files")
	}
	if snap, _ := corrosion.GetSnapshot(context.Background(), f.s.db, "src", "s1"); snap != nil {
		t.Fatal("the snapshot record must be removed")
	}
}

// A clone made before the snapshot backs on the layer UNDER the source's
// current disk: its record names the base, which is no longer the source's
// recorded path. The source's whole chain counts, not only its top file.
func TestDeleteSnapshot_LinkedCloneOfALowerLayerKeepsTheFiles(t *testing.T) {
	f := newSnapDependentsFixture(t)
	f.cloneOn(t, f.base, f.base)
	f.deleteS1(t)
	f.requireNotFlattened(t)
}

// A clone whose record names no backing (an earlier build's) is found by
// its disk's header, as a start judges its chain.
func TestDeleteSnapshot_UnrecordedCloneFoundByItsHeaderKeepsTheFiles(t *testing.T) {
	f := newSnapDependentsFixture(t)
	f.cloneOn(t, f.overlay, "")
	f.deleteS1(t)
	f.requireNotFlattened(t)
}
