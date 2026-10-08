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
	s.dataDir = t.TempDir()
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
	fake.SetDiskSource("src", "vda", f.base)
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

// Review M-6c: a disk on this host whose file is there but whose header
// cannot be read, and whose record names no backing, may be a clone of any
// layer: it counts as dependent, and nothing is merged or removed. (A disk
// whose file is not there at all has no header, so it backs on nothing —
// re-review 2, I-A.)
func TestDeleteSnapshot_ADiskWhoseHeaderCannotBeReadCountsAsDependent(t *testing.T) {
	f := newSnapDependentsFixture(t)
	bad := filepath.Join(f.dir, "clone-root.qcow2")
	// qcow2 magic, then a version no reader knows.
	if err := os.WriteFile(bad, append([]byte{'Q', 'F', 'I', 0xfb, 0, 0, 0, 99}, make([]byte, 504)...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(adminCtx(), f.s.db,
		corrosion.VMRecord{Name: "clone", HostName: "host-a", State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "clone", DiskName: "root", HostName: "host-a", Path: bad, StorageType: "local"}},
	); err != nil {
		t.Fatal(err)
	}
	f.deleteS1(t)
	f.requireNotFlattened(t)
}

// A VM that is itself a linked clone (its own disk backs on another VM's)
// still merges its snapshot layers — down to its own disk, never into the
// disk it shares.
func TestDeleteSnapshot_ALinkedCloneMergesDownToItsOwnDisk(t *testing.T) {
	needQemuImg(t)
	ctx := adminCtx()
	s, fake := newDiskPathTestServer(t)
	s.dataDir = t.TempDir()
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "tmpl-root.qcow2")
	own := filepath.Join(dir, "lc-root.qcow2")
	top := filepath.Join(dir, "lc-root.s1")
	runQemuImg(t, "create", "-q", "-f", "qcow2", tmpl, "1M")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", tmpl, own)
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", own, top)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "tmpl", HostName: "host-a", State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "tmpl", DiskName: "root", HostName: "host-a", Path: tmpl, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "lc", HostName: "host-a", State: "running"}, nil,
		[]corrosion.DiskRecord{{VMName: "lc", DiskName: "root", HostName: "host-a", Path: top, StorageType: "local", BackingDisk: tmpl}}); err != nil {
		t.Fatal(err)
	}
	fake.SetDiskSource("lc", "vda", own)
	if _, err := fake.CreateSnapshot("lc", "s1"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{ID: "lc-s1", VMName: "lc", HostName: "host-a", Name: "s1", State: "ok", Type: "disk"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "lc", SnapshotName: "s1"}); err != nil {
		t.Fatal(err)
	}
	srcs, _ := fake.DomainDiskSources("lc")
	if srcs["vda"] != own {
		t.Fatalf("the linked clone is on %s, want merged down onto its own disk %s (never into %s)", srcs["vda"], own, tmpl)
	}
}
