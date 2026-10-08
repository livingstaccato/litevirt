package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Re-review 2, I-A. A merge writes and removes only this VM's own snapshot
// layers, so a disk this host cannot read is no reason to stop it unless it
// could back on them: an ordinary VM on another host's NFS pool (never
// mounted here, no backing_disk) and a VM here whose disk was never made
// must not stop merges of an unrelated VM. Twenty create/rm cycles later
// the VM's chain is as deep as it was, and a start accepts it.
func TestDeleteSnapshot_DisksThatCannotBeReadHereDoNotStopAnUnrelatedVMsMerges(t *testing.T) {
	needQemuImg(t)
	dir := t.TempDir()
	root := filepath.Join(dir, "ia-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", root, "1M")
	f := newMergeFixture(t, "ia", "running", root, corrosion.DiskRecord{})
	if err := corrosion.InsertVM(adminCtx(), f.s.db, corrosion.VMRecord{Name: "nfsvm", HostName: "host-b", State: "running"}, nil,
		[]corrosion.DiskRecord{{VMName: "nfsvm", DiskName: "root", HostName: "host-b",
			Path: filepath.Join(dir, "nfs-not-mounted-here", "nfsvm-root.qcow2"), StorageType: "nfs", StorageVolume: "nfs1",
			BackingImage: "debian-12"}}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(adminCtx(), f.s.db, corrosion.VMRecord{Name: "errvm", HostName: "host-a", State: "error"}, nil,
		[]corrosion.DiskRecord{{VMName: "errvm", DiskName: "root", HostName: "host-a",
			Path: filepath.Join(dir, "errvm-root.qcow2"), StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("c%d", i)
		f.snap(t, name, true)
		f.rm(t, name)
	}
	if got := f.on(t); got != root {
		t.Errorf("after 20 cycles the domain is on %s, not back on %s", got, root)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), f.s.db, "ia")
	if len(disks) != 1 {
		t.Fatalf("disks %+v", disks)
	}
	if err := f.s.verifyDiskChainForStart(adminCtx(), &corrosion.VMRecord{Name: "ia", HostName: "host-a"}, disks[0], disks[0].Path); err != nil {
		t.Fatalf("a start after 20 cycles is refused: %v", err)
	}
}

// Re-review 2, m-1: the layout the family rule alone guards. On main
// 3e4ba50b, promote --no-localize built the live disk in the pool directory
// next to the replica — promote.go:712 replicaPath := filepath.Join(poolDir,
// replica) (a replica named "%s-%s-%s.qcow2" of VM, disk and time by
// replication_runner.go:194/222), :886-887 livePath :=
// filepath.Join(poolDir, fmt.Sprintf("%s-promoted-%s.qcow2", targetName,
// ts)) with ts the replica's name less its extension, and :902
// qcow2.CreateWithBackingFormat(livePath, replicaPath, ...) — and it
// recorded no backing_disk (promote.go:976-979). The replica is qcow2, no
// other row names it, and the VM has no backing image: only the family rule
// keeps the merge off it.
func TestDeleteSnapshot_AMainEraPromotedVMOverAQcow2ReplicaInItsPoolStaysOnItsOwnDisk(t *testing.T) {
	needQemuImg(t)
	pool := t.TempDir()
	replica := filepath.Join(pool, "src-root-20261001-101010.qcow2")
	live := filepath.Join(pool, "tgt-promoted-src-root-20261001-101010.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", replica, "1M")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", replica, live)
	f := newMergeFixture(t, "tgt", "stopped", live, corrosion.DiskRecord{StorageType: "local", StorageVolume: "pool1"})
	before := sumOf(t, replica)
	f.snap(t, "s1", true)
	f.rm(t, "s1")
	f.requireNeverMergedInto(t, replica, "the replica a main-era promotion backs on")
	if got := f.on(t); got != live {
		t.Fatalf("the domain is on %s, want %s", got, live)
	}
	if sumOf(t, replica) != before {
		t.Fatal("the replica changed")
	}
}

// Re-review 2, m-5. A merge that failed after libvirt's metadata was gone
// leaves the overlay <stem>.<snap> with nothing naming it; libvirt will not
// create an external snapshot over an existing file, so the name could
// never be used again. Such a leftover — marked as one by the merge that
// left it, and used by nothing — is removed before the snapshot is taken.
func TestCreateSnapshot_AnUnusedLeftoverOverlayDoesNotBlockTheName(t *testing.T) {
	needQemuImg(t)
	dir := t.TempDir()
	root := filepath.Join(dir, "lo-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", root, "1M")
	f := newMergeFixture(t, "lo", "stopped", root, corrosion.DiskRecord{})
	leftover := filepath.Join(dir, "lo-root.s1")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", root, leftover)
	// A merge marks what it leaves behind (re-review 3, I-2).
	if err := os.WriteFile(leftover+".lv-leftover", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.CreateSnapshot(adminCtx(), &pb.CreateSnapshotRequest{VmName: "lo", Name: "s1"}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Fatalf("the leftover %s is still there (%v): libvirt would refuse to create the overlay over it", leftover, err)
	}
}

// A file of the overlay's name that something uses (here another VM's
// recorded backing) is never removed: the create is refused, naming it.
func TestCreateSnapshot_AnOverlayNameSomethingUsesIsKept(t *testing.T) {
	needQemuImg(t)
	dir := t.TempDir()
	root := filepath.Join(dir, "lo-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", root, "1M")
	f := newMergeFixture(t, "lo", "stopped", root, corrosion.DiskRecord{})
	used := filepath.Join(dir, "lo-root.s1")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", root, used)
	clone := filepath.Join(dir, "other-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", used, clone)
	if err := corrosion.InsertVM(adminCtx(), f.s.db, corrosion.VMRecord{Name: "other", HostName: "host-a", State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "other", DiskName: "root", HostName: "host-a", Path: clone, StorageType: "local", BackingDisk: used}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.CreateSnapshot(adminCtx(), &pb.CreateSnapshotRequest{VmName: "lo", Name: "s1"}); err == nil {
		t.Fatal("the create went ahead over a file another VM backs on")
	}
	if _, err := os.Stat(used); err != nil {
		t.Fatalf("the used file is gone: %v", err)
	}
}

// Re-review 2, m-6. On main 3e4ba50b an auto-mode clone was linked when
// every source disk was recorded shared (templates.go:162
// cloneMode(req.Mode, allDisksShared(srcDisks))), and a clone's row copied
// its source's storage type (templates.go:221 StorageType: d.StorageType),
// so a clone of a clone of an NFS VM was linked too. This build records the
// clone local (its file is), and keeps that clone-of-a-clone linked: the
// family bound keeps any layer a clone backs on.
func TestCloneVM_AnAutoCloneOfAnNFSVMsCloneIsLinkedAsOnMain(t *testing.T) {
	s := cloneSourceTemplate(t)
	ctx := adminCtx()
	src := filepath.Join(t.TempDir(), "nfsvm-root.qcow2")
	if err := qcow2.Create(src, 64*1024*1024, nil); err != nil {
		t.Fatal(err)
	}
	specJSON, _ := json.Marshal(&pb.VMSpec{Name: "nfsvm", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "nfsvm", HostName: "test-host", State: "stopped", Spec: string(specJSON)}, nil,
		[]corrosion.DiskRecord{{VMName: "nfsvm", DiskName: "root", HostName: "test-host", Path: src,
			SizeBytes: 64 * 1024 * 1024, StorageType: "nfs", StorageVolume: "nfs1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "nfsvm", Target: "c1"}); err != nil {
		t.Fatalf("CloneVM c1: %v", err)
	}
	if _, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "c1", Target: "c2"}); err != nil {
		t.Fatalf("CloneVM c2: %v", err)
	}
	c1, _ := corrosion.GetVMDisks(ctx, s.db, "c1")
	c2, _ := corrosion.GetVMDisks(ctx, s.db, "c2")
	if len(c1) != 1 || len(c2) != 1 {
		t.Fatalf("disks c1=%v c2=%v", c1, c2)
	}
	if c2[0].BackingDisk != c1[0].Path {
		t.Fatalf("the clone of a clone is backed by %q, want linked to %s as on main", c2[0].BackingDisk, c1[0].Path)
	}
}
