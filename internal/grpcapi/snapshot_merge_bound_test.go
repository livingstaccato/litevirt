package grpcapi

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// The merge bound (controller ruling, round 4): a snapshot delete merges
// only layers of THIS VM's own snapshot overlays. The target is never below
// the VM's own disk file (its record's file, by stem, after symlink
// resolution on both sides), never its recorded backing_disk or an image or
// template base, and every frozen layer of any other snapshot — recorded by
// litevirt or not — stops it. On main (libvirt 10) deleting the current
// snapshot merged its overlay into its parent: the VM's own disk, or the
// previous snapshot's layer.

// mergeFixture is one VM on host-a with its domain on active (vda) and its
// record naming recPath.
type mergeFixture struct {
	s    *Server
	fake *libvirtfake.Fake
	vm   string
}

func newMergeFixture(t *testing.T, vm, state, active string, rec corrosion.DiskRecord) *mergeFixture {
	t.Helper()
	needQemuImg(t)
	s, fake := newDiskPathTestServer(t)
	s.dataDir = t.TempDir()
	rec.VMName, rec.DiskName, rec.HostName, rec.TargetDev = vm, "root", "host-a", "vda"
	if rec.Path == "" {
		rec.Path = active
	}
	if rec.StorageType == "" {
		rec.StorageType = "local"
	}
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: vm, HostName: "host-a", State: state}, nil,
		[]corrosion.DiskRecord{rec}); err != nil {
		t.Fatal(err)
	}
	fake.SetDiskSource(vm, "vda", active)
	return &mergeFixture{s: s, fake: fake, vm: vm}
}

// snap takes snapshot name as libvirt does: an overlay <stem>.<name> over the
// active layer (named in its header by the path the domain gives it), the
// domain and the record cut over to it. recorded: litevirt has a record.
func (f *mergeFixture) snap(t *testing.T, name string, recorded bool) string {
	t.Helper()
	srcs, _ := f.fake.DomainDiskSources(f.vm)
	active := srcs["vda"]
	overlay := strings.TrimSuffix(active, filepath.Ext(active)) + "." + name
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", active, overlay)
	if _, err := f.fake.CreateSnapshot(f.vm, name); err != nil {
		t.Fatal(err)
	}
	if recorded {
		if err := corrosion.InsertSnapshot(adminCtx(), f.s.db, corrosion.SnapshotRecord{
			ID: f.vm + "-" + name, VMName: f.vm, HostName: "host-a", Name: name, State: "ok", Type: "disk"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.UpdateVMDiskPath(adminCtx(), f.s.db, f.vm, "root", overlay); err != nil {
		t.Fatal(err)
	}
	return overlay
}

func (f *mergeFixture) rm(t *testing.T, name string) {
	t.Helper()
	if _, err := f.s.DeleteSnapshot(adminCtx(), &pb.DeleteSnapshotRequest{VmName: f.vm, SnapshotName: name}); err != nil {
		t.Fatalf("DeleteSnapshot %s: %v", name, err)
	}
}

func (f *mergeFixture) on(t *testing.T) string {
	t.Helper()
	srcs, _ := f.fake.DomainDiskSources(f.vm)
	return srcs["vda"]
}

func (f *mergeFixture) requireNeverMergedInto(t *testing.T, file, what string) {
	t.Helper()
	for _, b := range f.fake.FlattenBases {
		if resolvedOr(b["vda"]) == resolvedOr(file) {
			t.Fatalf("merged into %s, %s: a file this VM must never write", file, what)
		}
	}
}

func sumOf(t *testing.T, p string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return sha256.Sum256(b)
}

// Review C-1. On main 3e4ba50b a root disk created in a storage pool backed
// on the pool's image by BARE name: vm.go set sourceImage = spec.Image, and
// storage/local.go CreateDisk made <pooldir>/<vm>-<disk>.qcow2 with
// qcow2.CreateWithBacking(path, opts.SourceImage, ...). So a main-era pool VM
// is an overlay on <pooldir>/<image>, a file every VM in that pool made from
// that image shares by name. As the image's only user here, the merge must
// still stop at the VM's own disk: the pool image is never written and the
// VM's own disk never given up.
func TestDeleteSnapshot_AMainEraPoolVMNeverMergesIntoThePoolImage(t *testing.T) {
	needQemuImg(t)
	pool := t.TempDir()
	img := filepath.Join(pool, "debian-12.qcow2")
	own := filepath.Join(pool, "pv-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", img, "1M")
	// As main made it: the backing named relative, by the image's bare name.
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", "debian-12.qcow2", own)
	f := newMergeFixture(t, "pv", "stopped", own, corrosion.DiskRecord{
		BackingImage: "debian-12.qcow2", StorageType: "local", StorageVolume: "pool1"})
	before := sumOf(t, img)
	top := f.snap(t, "s1", true)
	f.rm(t, "s1")
	f.requireNeverMergedInto(t, img, "the pool's shared image")
	if _, err := os.Stat(top); !os.IsNotExist(err) {
		t.Fatalf("the merged overlay %s is still there (%v)", top, err)
	}
	if got := f.on(t); got != own {
		t.Fatalf("the domain is on %s, want merged down onto its own disk %s", got, own)
	}
	if _, err := os.Stat(own); err != nil {
		t.Fatalf("the VM's own disk is gone: %v", err)
	}
	if sumOf(t, img) != before {
		t.Fatal("the pool image changed")
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), f.s.db, "pv")
	if len(disks) != 1 || disks[0].Path != own {
		t.Fatalf("record %+v, want it on %s", disks, own)
	}
}

// Review I-1. A VM promoted with --no-localize runs on
// <target>-promoted-<stem>.qcow2 over the replica, with backing_disk naming
// the replica. The replica is never a merge target, raw or qcow2.
func TestDeleteSnapshot_APromotedVMNeverMergesIntoItsReplica(t *testing.T) {
	for _, format := range []string{"raw", "qcow2"} {
		t.Run(format, func(t *testing.T) {
			needQemuImg(t)
			replicas, disks := t.TempDir(), t.TempDir()
			replica := filepath.Join(replicas, "src-root-20261001-101010."+format)
			runQemuImg(t, "create", "-q", "-f", format, replica, "1M")
			promoted := filepath.Join(disks, "tgt-promoted-src-root-20261001-101010.qcow2")
			runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", format, "-b", replica, promoted)
			f := newMergeFixture(t, "tgt", "stopped", promoted, corrosion.DiskRecord{BackingDisk: replica})
			before := sumOf(t, replica)
			f.snap(t, "s1", true)
			f.rm(t, "s1")
			f.requireNeverMergedInto(t, replica, "the VM's replica (its backing_disk)")
			if got := f.on(t); got != promoted {
				t.Fatalf("the domain is on %s, want merged down onto %s", got, promoted)
			}
			if sumOf(t, replica) != before {
				t.Fatal("the replica changed")
			}
		})
	}
}

// Review I-2. libvirt holds an unrecorded snapshot "orphan" (its DB insert
// failed) taken after the recorded s2. Deleting orphan must not pass through
// s2's frozen layer: s2 would still list and revert, but to later data.
func TestDeleteSnapshot_AnUnrecordedSnapshotsDeleteKeepsARecordedOnesFrozenLayer(t *testing.T) {
	needQemuImg(t)
	dir := t.TempDir()
	root := filepath.Join(dir, "or-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", root, "1M")
	f := newMergeFixture(t, "or", "running", root, corrosion.DiskRecord{})
	a := f.snap(t, "s2", true)
	f.snap(t, "orphan", false)
	f.rm(t, "orphan")
	f.requireNeverMergedInto(t, root, "the frozen layer of recorded snapshot s2")
	if got := f.on(t); got != a {
		t.Fatalf("the domain is on %s, want merged into its parent %s (s2's overlay) and no further", got, a)
	}
}

// Review I-4. With data_dir or a pool target reached through a symlink, the
// merge repoints the domain by the path its chain spells, and the record
// names the same file as the domain afterwards.
func TestDeleteSnapshot_ASymlinkedDirKeepsTheDomainAndTheRecordOnOneFile(t *testing.T) {
	for _, tc := range []struct{ name, volume string }{{"data_dir", ""}, {"pool_target", "pool1"}} {
		t.Run(tc.name, func(t *testing.T) {
			needQemuImg(t)
			real := t.TempDir()
			link := filepath.Join(t.TempDir(), "via-link")
			if err := os.Symlink(real, link); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(link, "sl-root.qcow2")
			runQemuImg(t, "create", "-q", "-f", "qcow2", root, "1M")
			f := newMergeFixture(t, "sl", "stopped", root, corrosion.DiskRecord{StorageVolume: tc.volume})
			f.snap(t, "s1", true)
			f.rm(t, "s1")
			if got := f.on(t); got != root {
				t.Fatalf("the domain is on %s, want %s as its chain spells it", got, root)
			}
			disks, _ := corrosion.GetVMDisks(context.Background(), f.s.db, "sl")
			if len(disks) != 1 || resolvedOr(disks[0].Path) != resolvedOr(f.on(t)) {
				t.Fatalf("record %+v names another file than the domain (%s)", disks, f.on(t))
			}
		})
	}
}

// Review I-3. A linked clone of an NFS VM lives on its source host's local
// disk, but an earlier build recorded it "nfs" (with no storage pool). On
// every other host its row must not stop every merge: its recorded
// backing_disk is what it uses.
func TestDeleteSnapshot_AnotherHostsCloneRecordedNFSDoesNotStopMerging(t *testing.T) {
	needQemuImg(t)
	dir := t.TempDir()
	root := filepath.Join(dir, "m-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", root, "1M")
	f := newMergeFixture(t, "m", "running", root, corrosion.DiskRecord{})
	if err := corrosion.InsertVM(adminCtx(), f.s.db, corrosion.VMRecord{Name: "nfsclone", HostName: "host-b", State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "nfsclone", DiskName: "root", HostName: "host-b",
			Path: filepath.Join(dir, "not-on-this-host", "nfsclone-root.qcow2"), StorageType: "nfs",
			BackingDisk: "/mnt/nfs/nfsvm-root.qcow2"}}); err != nil {
		t.Fatal(err)
	}
	f.snap(t, "s1", true)
	f.rm(t, "s1")
	if got := f.on(t); got != root {
		t.Fatalf("the domain is on %s: another host's clone stopped the merge", got)
	}
}
