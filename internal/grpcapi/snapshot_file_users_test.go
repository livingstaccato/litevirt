package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// snapUsersFixture is VM "src" on host-a with one disk snapshot s1: real
// qcow2 files src-root.qcow2 (the disk s1 was taken of) and src-root.s1 (its
// overlay, now the VM's disk), in the fake and in corrosion.
type snapUsersFixture struct {
	s             *Server
	fake          *libvirtfake.Fake
	dir           string
	base, overlay string
}

func newSnapUsersFixture(t *testing.T, state string) *snapUsersFixture {
	t.Helper()
	needQemuImg(t)
	s, fake := newDiskPathTestServer(t)
	dir := t.TempDir()
	f := &snapUsersFixture{s: s, fake: fake, dir: dir,
		base:    filepath.Join(dir, "src-root.qcow2"),
		overlay: filepath.Join(dir, "src-root.s1"),
	}
	runQemuImg(t, "create", "-q", "-f", "qcow2", f.base, "1M")
	fake.SetDiskSource("src", "vda", f.base)
	if _, err := fake.CreateSnapshot("src", "s1"); err != nil {
		t.Fatal(err)
	}
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", f.base, f.overlay)
	if err := corrosion.InsertVM(adminCtx(), s.db,
		corrosion.VMRecord{Name: "src", HostName: "host-a", State: state}, nil,
		[]corrosion.DiskRecord{{VMName: "src", DiskName: "root", HostName: "host-a", Path: f.overlay, StorageType: "local"}},
	); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertSnapshot(adminCtx(), s.db, corrosion.SnapshotRecord{
		ID: "src-s1", VMName: "src", HostName: "host-a", Name: "s1", State: "ok", Type: "disk",
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

// vmOn records stopped VM name on host-a whose disk is a new qcow2 overlay
// of backsOn ("" for a standalone file), recorded with backing_disk
// recorded.
func (f *snapUsersFixture) vmOn(t *testing.T, name, backsOn, recorded string) string {
	t.Helper()
	file := filepath.Join(f.dir, name+"-root.qcow2")
	if backsOn == "" {
		runQemuImg(t, "create", "-q", "-f", "qcow2", file, "1M")
	} else {
		runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", backsOn, file)
	}
	if err := corrosion.InsertVM(adminCtx(), f.s.db,
		corrosion.VMRecord{Name: name, HostName: "host-a", State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: name, DiskName: "root", HostName: "host-a", Path: file, StorageType: "local", BackingDisk: recorded}},
	); err != nil {
		t.Fatal(err)
	}
	return file
}

func (f *snapUsersFixture) deleteS1() error {
	_, err := f.s.DeleteSnapshot(adminCtx(), &pb.DeleteSnapshotRequest{VmName: "src", SnapshotName: "s1"})
	return err
}

func (f *snapUsersFixture) libvirtDeleted() bool {
	for _, e := range f.fake.EventLog() {
		if e.Domain == "src" && (e.Op == "snapshot-delete" || e.Op == "snapshot-flatten") {
			return true
		}
	}
	return false
}

func (f *snapUsersFixture) requireRefusedFor(t *testing.T, err error, vm string) {
	t.Helper()
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("the delete returned %v; another VM backs on the snapshot's files, so it must be refused", err)
	}
	if !strings.Contains(err.Error(), vm) {
		t.Errorf("the refusal does not name %s: %v", vm, err)
	}
	if f.libvirtDeleted() {
		t.Fatal("libvirt was asked to delete the snapshot, which merges and removes the files the other VM backs on")
	}
	for _, p := range []string{f.base, f.overlay} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s is gone: %v", p, err)
		}
	}
	if snap, _ := corrosion.GetSnapshot(adminCtx(), f.s.db, "src", "s1"); snap == nil {
		t.Fatal("the snapshot's record was removed though the delete was refused")
	}
}

// Scenario 3 (sr10c): a linked clone of the stopped source backs on the
// snapshot's overlay. libvirt merged the overlay into the base and deleted
// it, and the clone could never start again.
func TestDeleteSnapshot_RefusedWhileALinkedCloneBacksOnItsOverlay(t *testing.T) {
	f := newSnapUsersFixture(t, "stopped")
	f.vmOn(t, "sr10c", f.overlay, f.overlay)
	f.requireRefusedFor(t, f.deleteS1(), "sr10c")
}

// A clone whose record does not say what it backs on (an earlier build's)
// is found by its qcow2 header.
func TestDeleteSnapshot_RefusedWhileAnUnrecordedCloneBacksOnItsOverlay(t *testing.T) {
	f := newSnapUsersFixture(t, "stopped")
	f.vmOn(t, "old-clone", f.overlay, "")
	f.requireRefusedFor(t, f.deleteS1(), "old-clone")
}

// The merge writes into the disk the snapshot was taken of: a clone made of
// the source before the snapshot backs on it, and would read the merged
// blocks as its own base.
func TestDeleteSnapshot_RefusedWhileACloneBacksOnTheBase(t *testing.T) {
	f := newSnapUsersFixture(t, "stopped")
	f.vmOn(t, "early-clone", f.base, f.base)
	f.requireRefusedFor(t, f.deleteS1(), "early-clone")
}

// The running source's last disk snapshot takes litevirt's own flatten
// (commit into the base, overlay removed), as on main: the same guard.
func TestDeleteSnapshot_FlattenRefusedWhileACloneBacksOnTheBase(t *testing.T) {
	f := newSnapUsersFixture(t, "running")
	f.vmOn(t, "early-clone", f.base, "")
	f.requireRefusedFor(t, f.deleteS1(), "early-clone")
}

// VMs that use none of the snapshot's files do not stop the delete: one on
// its own file, and one whose disk cannot be read on this host.
func TestDeleteSnapshot_UnrelatedVMsDoNotStopIt(t *testing.T) {
	f := newSnapUsersFixture(t, "stopped")
	f.vmOn(t, "own", "", "")
	if err := corrosion.InsertVM(adminCtx(), f.s.db,
		corrosion.VMRecord{Name: "elsewhere", HostName: "host-b", State: "running"}, nil,
		[]corrosion.DiskRecord{{VMName: "elsewhere", DiskName: "root", HostName: "host-b",
			Path: filepath.Join(f.dir, "not-here", "elsewhere-root.qcow2"), StorageType: "local"}},
	); err != nil {
		t.Fatal(err)
	}
	if err := f.deleteS1(); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	if !f.libvirtDeleted() {
		t.Fatal("the snapshot was not deleted in libvirt")
	}
}

// A clone whose file this host cannot read (on another host's mount of
// shared storage) is found by its record.
func TestDeleteSnapshot_RefusedWhileARecordedCloneElsewhereBacksOnIt(t *testing.T) {
	f := newSnapUsersFixture(t, "stopped")
	if err := corrosion.InsertVM(adminCtx(), f.s.db,
		corrosion.VMRecord{Name: "far-clone", HostName: "host-b", State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "far-clone", DiskName: "root", HostName: "host-b",
			Path: filepath.Join(f.dir, "not-here", "far-clone-root.qcow2"), StorageType: "local", BackingDisk: f.overlay}},
	); err != nil {
		t.Fatal(err)
	}
	f.requireRefusedFor(t, f.deleteS1(), "far-clone")
}

func (f *snapUsersFixture) restoreS1() error {
	_, err := f.s.RestoreSnapshot(adminCtx(), &pb.RestoreSnapshotRequest{VmName: "src", SnapshotName: "s1"})
	return err
}

func (f *snapUsersFixture) reverted() bool {
	for _, e := range f.fake.EventLog() {
		if e.Domain == "src" && (e.Op == "revert" || e.Op == "revert-live") {
			return true
		}
	}
	return false
}

// Review C-1: a restore resets the VM's live overlay — removes it and
// creates an empty file in its place — and starts the VM on it. A linked
// clone of the stopped source backs on that very file (scenario 3's
// setup): its clusters would then sit over a different, empty base that the
// source writes into, and the clone's disk is silently corrupt. The restore
// is refused, naming the clone, before anything is torn down.
func TestRestoreSnapshot_RefusedWhileALinkedCloneBacksOnTheLiveOverlay(t *testing.T) {
	for _, recorded := range []bool{true, false} {
		t.Run(map[bool]string{true: "recorded", false: "header only"}[recorded], func(t *testing.T) {
			f := newSnapUsersFixture(t, "stopped")
			rec := ""
			if recorded {
				rec = f.overlay
			}
			f.vmOn(t, "sr10c", f.overlay, rec)
			err := f.restoreS1()
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "sr10c") {
				t.Fatalf("RestoreSnapshot = %v, want FailedPrecondition naming sr10c", err)
			}
			if f.reverted() {
				t.Fatal("the revert ran: it resets the overlay the clone backs on")
			}
		})
	}
}

// A clone of the disk the snapshot was taken of is not touched by a
// restore (the base is only read), so the restore goes ahead as on main.
func TestRestoreSnapshot_ACloneOfTheBaseDoesNotStopIt(t *testing.T) {
	f := newSnapUsersFixture(t, "stopped")
	f.vmOn(t, "early-clone", f.base, f.base)
	if err := f.restoreS1(); err != nil {
		t.Fatalf("RestoreSnapshot: %v", err)
	}
	if !f.reverted() {
		t.Fatal("the revert did not run")
	}
}

// A guest controls the bytes of a raw disk, header included (re-review
// R1-M1). A raw disk holding a fake qcow2 header that names the source's
// overlay — on its own, or as the raw base of a real qcow2 disk — is not a
// user of that file: it stops neither the source's snapshot delete nor its
// restore.
func TestSnapshotFileUsers_ARawLayerIsNeverParsed(t *testing.T) {
	for _, tc := range []string{"a raw disk", "the raw base of a qcow2 disk"} {
		t.Run(tc, func(t *testing.T) {
			for _, op := range []string{"delete", "restore"} {
				t.Run(op, func(t *testing.T) {
					f := newSnapUsersFixture(t, "stopped")
					// Guest-written bytes that parse as a qcow2 header naming
					// the source's overlay.
					fake := filepath.Join(f.dir, "evil-data.raw")
					runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", f.overlay, fake)
					disk := fake
					if tc != "a raw disk" {
						disk = filepath.Join(f.dir, "evil-root.qcow2")
						runQemuImg(t, "create", "-q", "-u", "-f", "qcow2", "-F", "raw", "-b", fake, disk, "1M")
					}
					if err := corrosion.InsertVM(adminCtx(), f.s.db, corrosion.VMRecord{Name: "evil", HostName: "host-a", State: "stopped"}, nil,
						[]corrosion.DiskRecord{{VMName: "evil", DiskName: "root", HostName: "host-a", Path: disk, StorageType: "local"}}); err != nil {
						t.Fatal(err)
					}
					// Its domain on this host says what each disk is.
					format := "raw"
					if disk != fake {
						format = "qcow2"
					}
					defineDiskDomain(t, f.fake, "evil", disk, format)
					var err error
					if op == "delete" {
						err = f.deleteS1()
					} else {
						err = f.restoreS1()
					}
					if err != nil {
						t.Fatalf("%s refused over a raw layer's guest-written header: %v", op, err)
					}
				})
			}
		})
	}
}

// defineDiskDomain defines domain name in the fake with one disk on file,
// whose libvirt driver type is format.
func defineDiskDomain(t *testing.T, fake *libvirtfake.Fake, name, file, format string) {
	t.Helper()
	x := "<domain type='kvm'><name>" + name + "</name><devices><disk type='file' device='disk'><driver name='qemu' type='" + format +
		"'/><source file='" + file + "'/><target dev='vda' bus='virtio'/></disk></devices></domain>"
	if err := fake.DefineDomain(x); err != nil {
		t.Fatal(err)
	}
}

// Re-review R2-C2: a linked clone whose record does not say what it backs
// on, now running on a top layer named neither .qcow2 nor after a current
// snapshot — a restore-older overlay, or one whose snapshot was deleted
// metadata-only — is still found by its header: its domain says the disk is
// qcow2, or nothing says otherwise. It stops the source's snapshot delete and
// restore, and its source's VM delete keeps what it backs on.
func TestSnapshotFileUsers_AnUnrecordedCloneOnANonQcow2NamedTop(t *testing.T) {
	for _, defined := range []bool{true, false} {
		t.Run(map[bool]string{true: "domain says qcow2", false: "no domain here"}[defined], func(t *testing.T) {
			for _, op := range []string{"delete", "restore"} {
				t.Run(op, func(t *testing.T) {
					f := newSnapUsersFixture(t, "stopped")
					top := filepath.Join(f.dir, "old-root.s7-r1700000000")
					runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", f.overlay, top)
					if err := corrosion.InsertVM(adminCtx(), f.s.db, corrosion.VMRecord{Name: "old", HostName: "host-a", State: "stopped"}, nil,
						[]corrosion.DiskRecord{{VMName: "old", DiskName: "root", HostName: "host-a", Path: top, StorageType: "local"}}); err != nil {
						t.Fatal(err)
					}
					if defined {
						defineDiskDomain(t, f.fake, "old", top, "qcow2")
					}
					var err error
					if op == "delete" {
						err = f.deleteS1()
					} else {
						err = f.restoreS1()
					}
					if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "old") {
						t.Fatalf("%s = %v, want refused naming the clone old", op, err)
					}
				})
			}
		})
	}
}
