package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Post-breaker fix (diskiso-breaker-fix-brief.md): the prune keeps a layered
// image's base (I-A), never hangs a refresh and prunes nothing on a partial
// view (I-B, n-2), and keeps a version a backup manifest or a btrfs disk with
// no row yet names (n-1, n-3).

// pruneServer is a server with an empty image store.
func pruneServer(t *testing.T) *Server {
	t.Helper()
	needQemuImg(t)
	s := testServer(t)
	s.dataDir = t.TempDir()
	s.images = image.NewStore(s.dataDir)
	_ = s.images.Init()
	t.Cleanup(s.waitImagePrunes)
	return s
}

// publishVersion publishes a new version of image name holding fill (or, with
// base set, an overlay on base) and returns its file.
func publishVersion(t *testing.T, s *Server, name, fill, base string) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), "v.qcow2")
	if base != "" {
		if err := qcow2.CreateWithBacking(src, base, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
	} else {
		filledQcow2(t, src, fill)
	}
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(s.images.ImageDir(), "import-"+name+fill+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	pub, err := s.images.Publish(name, tmp, sha256Hex(b))
	if err != nil {
		t.Fatal(err)
	}
	return pub.Path
}

func importVersion(t *testing.T, s *Server, name, fill string) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "n.qcow2")
	filledQcow2(t, src, fill)
	b, _ := os.ReadFile(src)
	if err := s.ImportImage(&mockImportImageStream{ctx: adminCtx(), msgs: []*pb.ImportImageRequest{{Name: name, Format: "qcow2", Chunk: b}}}); err != nil {
		t.Fatal(err)
	}
	s.waitImagePrunes()
}

// waitImagePrunes waits for the background prunes refreshes started.
func (s *Server) waitImagePrunes() { s.imagePrune.bg.Wait() }

// I-A: image "upper" is built on lower's version X. A refresh of lower, then
// a prune, keeps X: the current file of upper names it.
func TestPruneImages_KeepsALayeredImagesBase(t *testing.T) {
	s := pruneServer(t)
	importVersion(t, s, "lower", "X ")
	x := s.images.ImagePath("lower")
	publishVersion(t, s, "upper", "U", x)
	importVersion(t, s, "lower", "Y ")
	importVersion(t, s, "lower", "Z ")
	s.waitImagePrunes()
	if _, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{}); err != nil {
		t.Fatal(err)
	}
	if !exists(x) {
		t.Fatalf("lower's version %s was pruned: the current file of upper is built on it", x)
	}
	if got := guestView(t, s.images.ImagePath("upper")); len(got) == 0 || got[0] != 'X' {
		t.Error("upper no longer reads its base")
	}
}

// I-B: a refresh never waits on a pool directory: one whose read blocks (a
// hung hard-mounted share) does not hang the import.
func TestImportImage_ARefreshDoesNotWaitOnABlockedPoolDir(t *testing.T) {
	s := pruneServer(t)
	stuck := blockDirRead(t, s)
	registerPool(t, s, "stuck", "dir", "", stuck, "")
	importVersion(t, s, "ubuntu", "A ")
	done := make(chan error, 1)
	src := filepath.Join(t.TempDir(), "n.qcow2")
	filledQcow2(t, src, "B ")
	b, _ := os.ReadFile(src)
	go func() {
		done <- s.ImportImage(&mockImportImageStream{ctx: adminCtx(), msgs: []*pb.ImportImageRequest{{Name: "ubuntu", Format: "qcow2", Chunk: b}}})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the refresh is still waiting on a blocked pool directory read")
	}
}

// blockDirRead makes a directory whose read, through s's prune, blocks until
// the test ends — as a read of a hung hard-mounted share does.
func blockDirRead(t *testing.T, s *Server) string {
	t.Helper()
	dir := t.TempDir()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	s.imagePrune.readDir = func(d string) ([]os.DirEntry, error) {
		if d == dir {
			<-release
		}
		return os.ReadDir(d)
	}
	return dir
}

// n-2: a disk file that carries the qcow2 magic but whose header does not
// parse might name any version: nothing is pruned.
func TestPruneImages_AnUnreadableHeaderPrunesNothing(t *testing.T) {
	s := pruneServer(t)
	a := publishVersion(t, s, "ubuntu", "A ", "")
	publishVersion(t, s, "ubuntu", "B ", "")
	disks := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(disks, "x-root.qcow2"), []byte("QFI\xfbgarbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"}); err == nil {
		t.Error("the prune went ahead on a disk header it could not read")
	}
	if !exists(a) {
		t.Fatal("a version was pruned while a disk header could not be read")
	}
}

// n-2: an nfs pool whose share is not mounted reads as an empty directory; the
// disks on it are unseen, so nothing is pruned.
func TestPruneImages_AnUnmountedSharePrunesNothing(t *testing.T) {
	s := pruneServer(t)
	a := publishVersion(t, s, "ubuntu", "A ", "")
	publishVersion(t, s, "ubuntu", "B ", "")
	registerPool(t, s, "share", "nfs", "nas:/export", t.TempDir(), "")
	if _, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"}); err == nil {
		t.Error("the prune went ahead with an nfs share unmounted")
	}
	if !exists(a) {
		t.Fatal("a version was pruned while a share was unmounted")
	}
}

// n-1: a backup records the base it was taken on; the version stays while a
// manifest names it, though no disk is built on it any more.
func TestPruneImages_KeepsAVersionABackupManifestNames(t *testing.T) {
	s := pruneServer(t)
	a := publishVersion(t, s, "ubuntu", "A ", "")
	b := publishVersion(t, s, "ubuntu", "B ", "")
	publishVersion(t, s, "ubuntu", "C ", "")
	root := filepath.Join(t.TempDir(), "repo")
	repo, err := pbsstore.Init(root)
	if err != nil {
		t.Fatal(err)
	}
	s.SetBackupRepos(map[string]string{"r": root})
	disk := filepath.Join(t.TempDir(), "gone-root.qcow2")
	if err := qcow2.CreateWithBacking(disk, a, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := pbsstore.PushFile(context.Background(), repo, disk, pbsstore.PushOptions{
		VMName: "gone", DiskName: "root", Timestamp: "2026-10-05T10:00:00Z",
		ContentFormat: pbsstore.ContentDiskFile, BaseIdentity: overlayBaseIdentity(disk),
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(disk); err != nil { // the VM is gone; only the backup names a
		t.Fatal(err)
	}
	resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if !exists(a) {
		t.Fatal("the version a backup was taken on was pruned")
	}
	if !slices.Equal(resp.Removed, []string{b}) {
		t.Errorf("removed %v, want only %s", resp.Removed, b)
	}
}

// n-3: a btrfs pool disk lives in a per-disk subvolume; one with no row yet is
// still seen, and its base kept.
func TestPruneImages_KeepsAVersionUnderABtrfsDiskWithNoRow(t *testing.T) {
	s := pruneServer(t)
	a := publishVersion(t, s, "ubuntu", "A ", "")
	publishVersion(t, s, "ubuntu", "B ", "")
	root := t.TempDir()
	registerPool(t, s, "bt", "btrfs", root, "", "")
	sub := filepath.Join(root, "new-root")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBacking(filepath.Join(sub, "new-root.qcow2"), a, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"}); err != nil {
		t.Fatal(err)
	}
	if !exists(a) {
		t.Fatal("the version a btrfs disk is built on was pruned")
	}
}

// I-B: lv image prune is bounded too: past the deadline it removes nothing
// and says why; while that scan is still blocked, the next prune does not
// pile up behind it; once the read returns, prunes work again.
func TestPruneImages_ABlockedScanPrunesNothingWithinTheDeadline(t *testing.T) {
	s := pruneServer(t)
	a := publishVersion(t, s, "ubuntu", "A ", "")
	publishVersion(t, s, "ubuntu", "B ", "")
	dir := t.TempDir()
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	s.imagePrune.readDir = func(d string) ([]os.DirEntry, error) {
		if d == dir {
			<-release
		}
		return os.ReadDir(d)
	}
	registerPool(t, s, "stuck", "dir", "", dir, "")
	s.imagePrune.deadline.Store(int64(300 * time.Millisecond))
	for i := 0; i < 2; i++ {
		start := time.Now()
		_, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
		if err == nil || !strings.Contains(err.Error(), "nothing is pruned") {
			t.Fatalf("prune %d: got %v, want a refusal past the deadline", i, err)
		}
		if d := time.Since(start); d > 10*time.Second {
			t.Fatalf("prune %d took %s", i, d)
		}
		if !exists(a) {
			t.Fatal("a version was pruned on a scan that did not finish")
		}
	}
	unblock()
	s.imagePrune.deadline.Store(int64(30 * time.Second))
	if _, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"}); err != nil {
		t.Fatalf("prune after the read returned: %v", err)
	}
	if exists(a) {
		t.Error("the unused version was not pruned once the scan could finish")
	}
}

// n-3: a disk create on an image holds it: until its row is written, no prune
// removes a file of the image.
func TestPruneImages_AnInFlightCreateHoldsItsImage(t *testing.T) {
	s := pruneServer(t)
	a := publishVersion(t, s, "ubuntu", "A ", "")
	b := publishVersion(t, s, "ubuntu", "B ", "")
	publishVersion(t, s, "ubuntu", "C ", "")
	release := s.holdImage("ubuntu")
	if _, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"}); err != nil {
		t.Fatal(err)
	}
	if !exists(a) || !exists(b) {
		t.Fatal("a version was pruned while a disk create on the image was in flight")
	}
	release()
	release() // idempotent
	if _, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"}); err != nil {
		t.Fatal(err)
	}
	if exists(a) || exists(b) {
		t.Error("the unused versions were not pruned once the create finished")
	}
}
