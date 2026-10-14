package grpcapi

import (
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// m-6: the failover reconciler's rebuild of a missing disk (RecreateOverlayDisk)
// resolves the image's current file and then writes an overlay on it. A
// refresh that supersedes that file and a prune that runs between the two
// removed it: the scan saw no disk built on it yet, and nothing held the
// image. The overlay was then written on a file that was gone, and the VM
// started on a disk with no base.
//
// Mutation: drop the hold in RecreateOverlayDisk — the superseded version is
// removed and the recreated disk has no base.
func TestRecreateOverlayDisk_HoldsTheImageAgainstAPrune(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	importVersion(t, s, "ubuntu", "A ")
	older := s.images.ImagePath("ubuntu")

	fired := false
	defer s.images.SetOverlayResolvedForTest(func(backing string) {
		if fired {
			return
		}
		fired = true
		if backing != older {
			t.Errorf("the recreate resolved %s, want the current version %s", backing, older)
		}
		// Between the resolve and the overlay: a refresh supersedes the
		// file, and a prune runs.
		publishVersion(t, s, "ubuntu", "B ", "")
		if s.images.ImagePath("ubuntu") == older {
			t.Error("the second version is not current")
		}
		if _, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"}); err != nil {
			t.Error(err)
		}
	})()

	disk, err := s.RecreateOverlayDisk("web", "root", "ubuntu", "1048576")
	if err != nil {
		t.Fatalf("RecreateOverlayDisk: %v", err)
	}
	if !fired {
		t.Fatal("the seam never ran: the recreate did not resolve the image")
	}
	if !exists(older) {
		t.Fatal("the version the recreated disk is built on was removed by a prune during the recreate")
	}
	if got := guestView(t, disk); len(got) == 0 || got[0] != 'A' {
		t.Error("the recreated disk lost its base")
	}
	// Released once the overlay is there: the next prune sees the disk
	// and keeps the version for it, and nothing is held any more.
	s.imagePrune.mu.Lock()
	n := s.imagePrune.holds["ubuntu"]
	s.imagePrune.mu.Unlock()
	if n != 0 {
		t.Errorf("%d holds left on the image after the recreate returned", n)
	}
	if _, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"}); err != nil {
		t.Fatal(err)
	}
	if !exists(older) {
		t.Fatal("removed once the scan could see the disk built on it")
	}
}

// m-4: a prune holds the hold lock across an unlink, which on an image store
// that does not answer does not return. The reconciler's rebuild waits for
// the lock only so long, then fails transiently (a later pass retries),
// instead of stalling the reconciler's whole pass; it builds nothing.
//
// Mutation: take the hold unbounded (holdImage) — the rebuild waits until
// the lock is let go: red.
func TestRecreateOverlayDisk_DoesNotWaitOnAStuckPrune(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	importVersion(t, s, "ubuntu", "A ")
	prev := recreateHoldWait
	recreateHoldWait = 100 * time.Millisecond
	t.Cleanup(func() { recreateHoldWait = prev })

	s.imagePrune.mu.Lock() // a prune stuck in an unlink
	unlocked := false
	defer func() {
		if !unlocked {
			s.imagePrune.mu.Unlock()
		}
	}()
	err := within(t, 5*time.Second, "a rebuild while a prune holds the lock", func() error {
		_, err := s.RecreateOverlayDisk("web", "root", "ubuntu", "1048576")
		return err
	})
	if err == nil {
		t.Fatal("the rebuild went ahead without the image's hold")
	}
	if exists(s.images.DiskPath("web", "root")) {
		t.Error("a rebuild that did not get the hold built a disk")
	}
	s.imagePrune.mu.Unlock()
	unlocked = true
	if _, err := s.RecreateOverlayDisk("web", "root", "ubuntu", "1048576"); err != nil {
		t.Fatalf("the rebuild once the prune let go: %v", err)
	}
}
