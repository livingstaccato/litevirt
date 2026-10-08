package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Main-era (3e4ba50b) disks still start on this build after their image is
// refreshed here, and the chains main wrote that this build's start judges
// (I-4) are the ones main started.

// refreshImageHere refreshes image name on this build as an import does
// (ImportImage, imageops.go): new content published as a version
// <name>@<sha>.qcow2 with <name>.current pointed at it, then the prune that
// follows a refresh, run to completion. It returns the new current file.
func refreshImageHere(t *testing.T, s *Server, name string) string {
	t.Helper()
	ctx := context.Background()
	tmp := filepath.Join(s.dataDir, "images", "import-refresh.tmp")
	if err := qcow2.Create(tmp, 2<<20, nil); err != nil {
		t.Fatal(err)
	}
	digest, err := image.FileDigest(tmp)
	if err != nil {
		t.Fatal(err)
	}
	s.recordImageProvenance(ctx, name)
	pub, err := s.images.Publish(name, tmp, digest)
	if err != nil {
		t.Fatalf("refresh %s: %v", name, err)
	}
	if _, _, err := s.pruneImageVersions(ctx, name, false); err != nil {
		t.Fatalf("prune after refreshing %s: %v", name, err)
	}
	return pub.Path
}

// A root disk main built on an image in the store — <data_dir>/disks/
// <vm>-<disk>.qcow2 (image/store.go:66-70 at 3e4ba50b), an overlay whose
// header names <data_dir>/images/<image>.qcow2 by its absolute path
// (store.go:39-41 and :113), its row recording the image's name
// (grpcapi/vm.go:449-461) — starts after the image is refreshed here: the
// refresh leaves the file the header names, the prune keeps it, and the start
// judges it as the image-store base it is.
func TestStart_AMainEraDiskStartsAfterItsImageIsRefreshed(t *testing.T) {
	s := testServerWithLocks(t)
	s.dataDir = t.TempDir()
	s.images = image.NewStore(s.dataDir)
	if err := s.images.Init(); err != nil {
		t.Fatal(err)
	}
	ctx := adminCtx()
	base := filepath.Join(s.dataDir, "images", "ubuntu.qcow2")
	if err := qcow2.Create(base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(s.dataDir, "disks", "web-root.qcow2")
	if err := qcow2.CreateWithBacking(disk, base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	insertTestVM(t, ctx, s.db, "web", s.hostName, "stopped")
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "web", DiskName: "root", HostName: s.hostName, Path: disk, SizeBytes: 1 << 20,
		BackingImage: "ubuntu", StorageType: "local", TargetDev: "vda", Bus: "virtio",
	}); err != nil {
		t.Fatal(err)
	}

	cur := refreshImageHere(t, s, "ubuntu")
	if cur == base || s.images.ImagePath("ubuntu") != cur {
		t.Fatalf("the refresh did not publish a new version: current %q, first content %q", cur, base)
	}
	if _, err := os.Stat(base); err != nil {
		t.Fatalf("the image file the main-era disk is built on is gone after the refresh and its prune: %v", err)
	}
	if info, err := qcow2.Info(disk); err != nil || info.BackingFile != base {
		t.Fatalf("the main-era disk's header names %q (%v), want %q", info.BackingFile, err, base)
	}

	if err := s.verifyImageBasesForStart(ctx, vmRecord(t, s, "web")); err != nil {
		t.Fatalf("the start's chain check refuses the main-era disk after a refresh: %v", err)
	}
	s.virt = libvirtfake.New()
	if err := s.virt.DefineDomain("<domain><name>web</name></domain>"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "web"}); err != nil {
		t.Fatalf("starting the main-era VM after its image was refreshed: %v", err)
	}
	if _, err := os.Stat(base); err != nil {
		t.Fatalf("the base is gone after the start: %v", err)
	}
}

// A linked clone main made of a main-era VM (templates.go:184-200 at
// 3e4ba50b: <data_dir>/disks/<clone>-<disk>.qcow2, an overlay naming the
// source disk's file, backing_disk recorded) whose own root disk names its
// image by the bare relative name its spec gave (storage/local.go:25-36 at
// 3e4ba50b) starts: qemu reads the clone, the source disk and the image beside
// it, as it did on main. So does a clone this build makes of it into a pool.
func TestStart_ALinkedCloneOfAMainEraPoolDiskStarts(t *testing.T) {
	for _, c := range []struct{ name, src, clone string }{
		{"source in its project's pool", "pa", "disks"},
		{"source in <data_dir>/disks", "disks", "disks"},
		{"clone in a pool", "disks", "pa"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newStartChainFixture(t)
			src := f.mainEraLinkedSource(t, c.src)
			vm := f.linkedClone(t, "web", "a", src, c.clone)
			startAllowed(t, f.s, vm, "a linked clone of a main-era pool disk")
		})
	}
}

// The source's base is still judged as its own start judges it: a file
// beside it under its image's name that is another project's VM disk is not
// read through a clone.
func TestStart_ALinkedCloneDoesNotReadAnotherProjectsDiskAsItsSourcesBase(t *testing.T) {
	f := newStartChainFixture(t)
	src := f.mainEraLinkedSource(t, "disks")
	f.insertVM(t, "ubuntu-vm", "b", filepath.Join(f.s.dataDir, "disks", "ubuntu"), "", "")
	startRefused(t, f.s, f.linkedClone(t, "web", "a", src, "disks"), "a clone whose source's base is b's disk")
}

// mainEraLinkedSource is project a's main-era VM "tmpl" whose root disk, in
// <data_dir>/disks or pool pa, names its image "ubuntu" beside it, present.
func (f *startChainFixture) mainEraLinkedSource(t *testing.T, where string) string {
	t.Helper()
	dir, pool := f.pa, "pa"
	if where == "disks" {
		dir, pool = filepath.Join(f.s.dataDir, "disks"), ""
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	vm := f.mainEraVM(t, "tmpl", dir, pool)
	if err := qcow2.Create(filepath.Join(dir, "ubuntu"), 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	startAllowed(t, f.s, vm, "the main-era source VM")
	return filepath.Join(dir, "tmpl-root.qcow2")
}

// linkedClone records project's VM name whose root disk, in <data_dir>/disks
// or pool pa, is an overlay naming src, with backing_disk recorded.
func (f *startChainFixture) linkedClone(t *testing.T, name, project, src, where string) *corrosion.VMRecord {
	t.Helper()
	dir, pool, storage := filepath.Join(f.s.dataDir, "disks"), "", "local"
	if where == "pa" {
		dir, pool, storage = f.pa, "pa", "dir"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	clone := filepath.Join(dir, name+"-root.qcow2")
	if err := qcow2.CreateWithBacking(clone, src, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: name, Project: project, Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(context.Background(), f.s.db,
		corrosion.VMRecord{Name: name, HostName: f.s.hostName, State: "stopped", Project: project, Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{{VMName: name, DiskName: "root", HostName: f.s.hostName, Path: clone, SizeBytes: 1 << 20,
			StorageType: storage, StorageVolume: pool, BackingDisk: src}}); err != nil {
		t.Fatal(err)
	}
	return vmRecord(t, f.s, name)
}

// Main cloned a stopped VM that had an external snapshot (templates.go:101
// at 3e4ba50b): its disk row had moved to the snapshot's overlay
// <vm>-<disk>.<snapshot> (reconcileDiskPaths, snapshot_diskpath.go:32), so
// the clone is built on that overlay, which is built on the VM's original
// disk, which is built on its image. That clone starts here too.
func TestStart_ALinkedCloneOfASnapshottedMainEraVMStarts(t *testing.T) {
	for _, base := range []string{"an image in the store", "its image beside it"} {
		t.Run(base, func(t *testing.T) {
			f := newStartChainFixture(t)
			disks := filepath.Join(f.s.dataDir, "disks")
			if err := os.MkdirAll(disks, 0o755); err != nil {
				t.Fatal(err)
			}
			orig := filepath.Join(disks, "tmpl-root.qcow2")
			var vm *corrosion.VMRecord
			if base == "its image beside it" {
				vm = f.mainEraVM(t, "tmpl", disks, "")
				if err := qcow2.Create(filepath.Join(disks, "ubuntu"), 1<<20, nil); err != nil {
					t.Fatal(err)
				}
			} else {
				img := filepath.Join(f.s.dataDir, "images", "ubuntu.qcow2")
				if err := os.MkdirAll(filepath.Dir(img), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := qcow2.Create(img, 1<<20, nil); err != nil {
					t.Fatal(err)
				}
				if err := qcow2.CreateWithBacking(orig, img, 1<<20, nil); err != nil {
					t.Fatal(err)
				}
				vm = f.insertVM(t, "tmpl", "a", orig, "", "ubuntu")
			}
			overlay := filepath.Join(disks, "tmpl-root.snap1")
			if err := qcow2.CreateWithBacking(overlay, orig, 1<<20, nil); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.UpdateVMDiskPath(context.Background(), f.s.db, "tmpl", "root", overlay); err != nil {
				t.Fatal(err)
			}
			startAllowed(t, f.s, vm, "the snapshotted main-era source VM")
			startAllowed(t, f.s, f.linkedClone(t, "web", "a", overlay, "disks"), "a linked clone of a snapshotted main-era VM")
		})
	}
}
