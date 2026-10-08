package grpcapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Review I-3. A linked clone (auto mode) of an NFS VM writes its overlay to
// <data_dir>/disks on the source host's own disk. Its row must say so —
// local, on this host, in no pool — not copy the source's "nfs".
func TestCloneVM_ALinkedCloneOfAnNFSVMIsRecordedWhereItLives(t *testing.T) {
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
	if _, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "nfsvm", Target: "nfsclone"}); err != nil {
		t.Fatalf("CloneVM: %v", err)
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, "nfsclone")
	if err != nil || len(disks) != 1 {
		t.Fatalf("clone disks = %v, %v", disks, err)
	}
	d := disks[0]
	if d.BackingDisk != src {
		t.Fatalf("not a linked clone (backing %q) — this test does not exercise the auto-linked path", d.BackingDisk)
	}
	if d.StorageType != "local" || d.StorageVolume != "" || d.HostName != "test-host" {
		t.Fatalf("clone recorded as %q in pool %q on %q; its file %s is this host's local disk",
			d.StorageType, d.StorageVolume, d.HostName, d.Path)
	}
}

// Review M-1. A linked clone backs on its source's current layer, created
// before the clone's row exists. A snapshot delete of the source (which
// holds the source's lock) must not run in that window, so CloneVM takes
// the source's lock too.
func TestCloneVM_WaitsForTheSourcesLock(t *testing.T) {
	s := cloneSourceTemplate(t)
	unlock := s.lockVM("tpl")
	done := make(chan error, 1)
	go func() {
		_, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl", Target: "lk1", Mode: "linked"})
		done <- err
	}()
	select {
	case err := <-done:
		unlock()
		t.Fatalf("CloneVM finished (%v) while the source's lock was held", err)
	case <-time.After(500 * time.Millisecond):
	}
	unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("CloneVM: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("CloneVM did not finish after the lock was released")
	}
	if _, err := os.Stat(s.images.DiskPath("lk1", "root")); err != nil {
		t.Fatalf("clone disk: %v", err)
	}
}
