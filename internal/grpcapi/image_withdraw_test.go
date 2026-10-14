package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// A copy of older content than the image's record is withdrawn from being
// current (image.Store.Withdraw), and nothing is pruned on the spot: a disk
// create that resolved the copy's file while it was current, and writes its
// overlay after a prune's scan, keeps its backing file. The withdrawn file is
// left for the next prune, which sees the disk.
func TestImportImage_AStaleCopysFileKeepsADiskCreatedOnIt(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	ctx := context.Background()

	var staleFile string
	s.SetImageRecordHookForTest(func(name string) {
		if staleFile != "" {
			return
		}
		staleFile = s.images.ImagePath(name)
		// A refresh elsewhere, begun after the copy, recorded first.
		if res, err := corrosion.RecordImage(ctx, s.db, corrosion.ImageRecord{Name: name, Format: "qcow2", Checksum: "sha256:new"}, true, "", corrosion.ReserveImageClocks(s.db)); err != nil || res.Outcome != corrosion.ImageRecordWritten {
			t.Errorf("the refresh's record: %+v err=%v", res, err)
		}
	})
	t.Cleanup(func() { s.SetImageRecordHookForTest(nil) })

	disk := s.images.DiskPath("late", "root")
	created := false
	create := func() {
		if created {
			return
		}
		created = true
		release := s.holdImage("ubuntu")
		defer release()
		if err := os.MkdirAll(filepath.Dir(disk), 0o755); err != nil {
			t.Error(err)
		}
		if err := qcow2.CreateWithBacking(disk, staleFile, 0, nil); err != nil {
			t.Error(err)
		}
	}
	// A create that resolved the copy's file before it was withdrawn writes
	// its overlay after any prune's scan.
	s.imagePrune.afterScan = create

	src := filepath.Join(t.TempDir(), "old.qcow2")
	filledQcow2(t, src, "B ")
	b, _ := os.ReadFile(src)
	copyCtx := metadata.NewIncomingContext(adminCtx(), metadata.Pairs(imageCopyMDKey, "push"))
	err := s.ImportImage(&mockImportImageStream{ctx: copyCtx, msgs: []*pb.ImportImageRequest{{Name: "ubuntu", Format: "qcow2", Chunk: b}}})
	if status.Code(err) != codes.Aborted || !isStaleImageCopy(err) {
		t.Fatalf("a copy overtaken by other content: %v, want a stale-copy Aborted", err)
	}
	s.waitImagePrunes()
	create() // no prune scanned: the create finishes now
	if staleFile == "" || !exists(staleFile) {
		t.Fatalf("the withdrawn copy's file %q is gone under the disk created on it", staleFile)
	}
	if got := guestView(t, disk); len(got) == 0 || got[0] != 'B' {
		t.Fatal("the disk created on the withdrawn file lost its base")
	}

	// The next prune sees the disk and keeps the file for it.
	s.imagePrune.afterScan = nil
	if _, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"}); err != nil {
		t.Fatal(err)
	}
	if !exists(staleFile) {
		t.Fatal("removed once the scan could see the disk built on it")
	}
}

// A Publish that lands after a stale copy began and before the copy's own
// Publish (an operator's import of newer content) is the file the copy's
// withdrawal points the name back to: the copy is withdrawn to what its own
// Publish superseded, read under the name's lock, not to what was current
// when the copy began.
func TestImportImage_AStaleCopyIsWithdrawnToThePublishBeforeIt(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	importVersion(t, s, "ubuntu", "A ")
	old := s.images.ImagePath("ubuntu")

	var newer string
	s.imagePrune.prePublish = func(name string) {
		if newer != "" {
			return
		}
		newer = "pending"
		// Begun after the copy, so its record supersedes the copy's.
		importVersion(t, s, name, "N ")
		newer = s.images.ImagePath(name)
	}
	t.Cleanup(func() { s.imagePrune.prePublish = nil })

	src := filepath.Join(t.TempDir(), "stale.qcow2")
	filledQcow2(t, src, "S ")
	b, _ := os.ReadFile(src)
	copyCtx := metadata.NewIncomingContext(adminCtx(), metadata.Pairs(imageCopyMDKey, "push"))
	err := s.ImportImage(&mockImportImageStream{ctx: copyCtx, msgs: []*pb.ImportImageRequest{{Name: "ubuntu", Format: "qcow2", Chunk: b}}})
	if status.Code(err) != codes.Aborted || !isStaleImageCopy(err) {
		t.Fatalf("a copy overtaken by an import of other content: %v, want a stale-copy Aborted", err)
	}
	s.waitImagePrunes()
	if newer == "" || newer == "pending" || newer == old {
		t.Fatalf("the import during the copy did not publish a new version (%q)", newer)
	}
	if got := s.images.ImagePath("ubuntu"); got != newer {
		t.Fatalf("after the stale copy's withdrawal, ImagePath = %s, want the import's %s (the version before it: %s)", got, newer, old)
	}
	if !exists(newer) {
		t.Fatalf("the import's file %s is gone", newer)
	}
}

// While a stale copy is briefly the image's current file, the file it would
// be withdrawn to (its Published.Prev) is not removed by a prune: the
// withdrawal lands on it, and it stays.
func TestImportImage_APruneWhileAStaleCopyIsCurrentKeepsItsPrev(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	importVersion(t, s, "ubuntu", "A ")

	var newer string
	s.imagePrune.prePublish = func(name string) {
		if newer != "" {
			return
		}
		newer = "pending"
		importVersion(t, s, name, "N ") // its record supersedes the copy's
		newer = s.images.ImagePath(name)
	}
	pruned := false
	s.SetImageRecordHookForTest(func(name string) {
		if pruned || newer == "" || newer == "pending" {
			return
		}
		pruned = true
		if s.images.ImagePath(name) == newer {
			t.Errorf("the copy is not current at its record")
		}
		// An operator's prune lands while the copy is current: newer is
		// not current, kept by no list, and nothing is built on it.
		if _, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: name}); err != nil {
			t.Errorf("prune: %v", err)
		}
	})
	t.Cleanup(func() {
		s.imagePrune.prePublish = nil
		s.SetImageRecordHookForTest(nil)
	})

	src := filepath.Join(t.TempDir(), "stale.qcow2")
	filledQcow2(t, src, "S ")
	b, _ := os.ReadFile(src)
	copyCtx := metadata.NewIncomingContext(adminCtx(), metadata.Pairs(imageCopyMDKey, "push"))
	err := s.ImportImage(&mockImportImageStream{ctx: copyCtx, msgs: []*pb.ImportImageRequest{{Name: "ubuntu", Format: "qcow2", Chunk: b}}})
	if status.Code(err) != codes.Aborted || !isStaleImageCopy(err) {
		t.Fatalf("a copy overtaken by an import of other content: %v, want a stale-copy Aborted", err)
	}
	s.waitImagePrunes()
	if !pruned {
		t.Fatal("no prune ran while the copy was current")
	}
	if !exists(newer) {
		t.Fatalf("the file the copy is withdrawn to, %s, was removed while the copy was current", newer)
	}
	if got := s.images.ImagePath("ubuntu"); got != newer {
		t.Fatalf("after the withdrawal, ImagePath = %s, want %s", got, newer)
	}
}
