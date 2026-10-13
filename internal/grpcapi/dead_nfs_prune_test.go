package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/storage"
)

// Lab 2 N-6: with the image store's directory symlinked onto an NFS mount
// whose server does not answer, a prune hung in an unbounded listing of the
// store (image.Store.StoreFiles), before its bounded scan, and never said
// "nothing is pruned".

// dirGate blocks the prune's listing of one directory while it is on, until
// the test ends, as a listing on a hard NFS mount whose server does not
// answer does.
type dirGate struct {
	mu      sync.Mutex
	on      bool
	release chan struct{}
}

func (g *dirGate) set(on bool) {
	g.mu.Lock()
	g.on = on
	g.mu.Unlock()
}

func (g *dirGate) blocking() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.on
}

func gateDirRead(t *testing.T, s *Server, dir string, on bool) *dirGate {
	t.Helper()
	g := &dirGate{on: on, release: make(chan struct{})}
	t.Cleanup(func() { close(g.release) })
	s.imagePrune.readDir = func(d string) ([]os.DirEntry, error) {
		if d == dir && g.blocking() {
			<-g.release
		}
		return os.ReadDir(d)
	}
	return g
}

// prunableStore is a store with image "ubuntu" in three versions: old (no
// disk is built on it: a prune removes it), used (a stopped VM's disk is
// built on it) and the current one.
func prunableStore(t *testing.T) (s *Server, old, used string) {
	t.Helper()
	s = pruneServer(t)
	old = publishVersion(t, s, "ubuntu", "OLD ", "")
	used = publishVersion(t, s, "ubuntu", "USED ", "")
	publishVersion(t, s, "ubuntu", "CURRENT ", "")
	disks := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(disks, "web-root.qcow2")
	if err := qcow2.CreateWithBacking(disk, used, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	insertTestVM(t, context.Background(), s.db, "web", s.hostName, "stopped")
	if err := corrosion.InsertDisk(context.Background(), s.db, corrosion.DiskRecord{
		VMName: "web", DiskName: "root", HostName: s.hostName, Path: disk, SizeBytes: 1 << 20,
		BackingImage: "ubuntu", StorageType: "local", TargetDev: "vda", Bus: "virtio",
	}); err != nil {
		t.Fatal(err)
	}
	return s, old, used
}

func wantNothingPruned(t *testing.T, s *Server, what string, files ...string) {
	t.Helper()
	type res struct {
		resp *pb.PruneImagesResponse
		err  error
	}
	got := within(t, 10*time.Second, what, func() res {
		resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
		return res{resp, err}
	})
	if got.err == nil || !strings.Contains(got.err.Error(), "nothing is pruned") || !strings.Contains(got.err.Error(), "does its server answer") {
		t.Fatalf("%s: %v (response %v); want a refusal saying nothing is pruned because storage does not answer", what, got.err, got.resp)
	}
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("%s: %s is gone: %v", what, f, err)
		}
	}
}

// The store's listing does not answer before the scan (the listing of
// which images have files here), during it (the kept files' own chains) or
// after it (the candidates): every one refuses within the bound, with
// "nothing is pruned", and nothing is removed. The prune's own deadline is
// two minutes: the refusal comes from the listing's bound.
//
// Mutations, each red in its window: "the first listing unbounded",
// "the scan's listing unbounded", "the removal's listing unbounded".
func TestPruneImages_AStoreListingThatDoesNotAnswerPrunesNothing(t *testing.T) {
	for _, when := range []string{"before the scan", "during the scan", "after the scan"} {
		t.Run(when, func(t *testing.T) {
			s, old, used := prunableStore(t)
			t.Cleanup(storage.OverrideFSCallBoundForTest(200 * time.Millisecond))
			g := gateDirRead(t, s, s.images.ImageDir(), when == "before the scan")
			// Each window is the listing's alone: the store answers again
			// after it, so only that listing's bound can refuse the prune.
			switch when {
			case "before the scan":
				s.imagePrune.afterCatalog = func() { g.set(false) }
			case "during the scan":
				s.imagePrune.afterCatalog = func() { g.set(true) }
				s.imagePrune.afterScan = func() { g.set(false) }
			case "after the scan":
				s.imagePrune.afterScan = func() { g.set(true) }
			}
			wantNothingPruned(t, s, "a prune while the image store's listing does not answer", old, used)
		})
	}
}

// A pool directory whose listing does not answer refuses the prune within
// the listing's bound, not the scan's two-minute deadline. An nfs pool at
// its mount point is known mounted from the mount table: no stat of it (lab
// 2: the scan was found in that stat, isMountpoint).
//
// Mutations: "the pool listing unbounded" — waits for the deadline: red.
// "the nfs mount judged by stat" — the stat is made: red.
func TestPruneImages_APoolDirectoryThatDoesNotAnswerRefusesWithinTheBound(t *testing.T) {
	for _, driver := range []string{"dir", "nfs"} {
		t.Run(driver, func(t *testing.T) {
			s, old, used := prunableStore(t)
			t.Cleanup(storage.OverrideFSCallBoundForTest(200 * time.Millisecond))
			dir := t.TempDir()
			source := ""
			if driver == "nfs" {
				source = "nas:/vm"
				overrideMounts(t, "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw", nfsMountLine(dir, source))
			}
			registerPool(t, s, "stuck", driver, source, dir, "")
			gateDirRead(t, s, dir, true)
			var statted []string
			var mu sync.Mutex
			release := make(chan struct{})
			t.Cleanup(func() { close(release) })
			s.imagePrune.mounted = func(d string) (bool, error) {
				mu.Lock()
				statted = append(statted, d)
				mu.Unlock()
				<-release // a stat of the dead mount point
				return true, nil
			}
			wantNothingPruned(t, s, "a prune while a "+driver+" pool's directory does not answer", old, used)
			mu.Lock()
			defer mu.Unlock()
			if len(statted) != 0 {
				t.Fatalf("the nfs pool's mount point was stat'ed: %v", statted)
			}
		})
	}
}

// Lab 2 N-7 (triage): with the image store on a network filesystem, an old
// version of an image that is NOT deleted was judged by this host's disks
// alone. Another host sharing the store may have a disk built on it, on its
// own local storage, which this host cannot see: removing the version would
// leave that disk without its base. The rule a deleted image's files already
// had applies to every version: on a network store, a version no disk here
// is built on is kept, with the reason.
//
// Mutation "the network-store keep only for deleted images" — the old
// version is removed: red.
func TestPruneImages_AVersionOnANetworkStoreIsKept(t *testing.T) {
	s, old, used := prunableStore(t)
	s.imagePrune.storeFS = func(string) (string, error) { return "nfs", nil }
	resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if len(resp.Removed) != 0 {
		t.Fatalf("removed %v from a store other hosts may share", resp.Removed)
	}
	for _, f := range []string{old, used} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("%s is gone: %v", f, err)
		}
	}
	var why string
	for _, k := range resp.Kept {
		if k.Path == old {
			why = k.Reason
		}
	}
	if !strings.Contains(why, "network filesystem") {
		t.Fatalf("the old version is not reported kept for the store's filesystem: kept %v", resp.Kept)
	}

	// A store whose filesystem cannot be told keeps it too.
	s.imagePrune.storeFS = func(string) (string, error) { return "", os.ErrPermission }
	resp, err = s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil || len(resp.Removed) != 0 {
		t.Fatalf("prune with the store's filesystem unknown: removed %v, %v", resp.GetRemoved(), err)
	}

	// On a local store the same version is removed, as before.
	s.imagePrune.storeFS = func(string) (string, error) { return "", nil }
	resp, err = s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil || len(resp.Removed) != 1 || resp.Removed[0] != old {
		t.Fatalf("prune on a local store: removed %v, %v; want only %s", resp.GetRemoved(), err, old)
	}
}
