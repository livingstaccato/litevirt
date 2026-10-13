package grpcapi

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pitoverlay"
)

// A directory whose walk does not end (a hung NFS mount) holds at most one
// goroutine, however many scans ask for it: each upgrade or preflight joins
// the walk still running instead of starting another, and still reports the
// directory unanswered within its bound. Once the walk ends, a later scan
// walks afresh, and finds what is there.
//
// Mutation "a walk per scan" (pitOverlayWalkOf never joins) — the hung
// directory is walked once per scan: red.
func TestPITOverlayScan_AHungDirectoryHoldsOneWalk(t *testing.T) {
	s, dir := upgradeTestServer(t)
	s.dataDir = filepath.Join(dir, "data")
	hung := filepath.Join(dir, "nfs")
	if err := os.MkdirAll(hung, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "nfs", Driver: "nfs", Target: hung, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(hung, ".vm-root.qcow2"+pitoverlay.Suffix)
	if err := os.WriteFile(overlay, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	released := false
	t.Cleanup(func() {
		if !released {
			close(release)
		}
	})
	var hungWalks atomic.Int32
	prevWalk, prevTimeout := walkForOverlays, pitOverlayScanTimeout
	walkForOverlays = func(root string, fn fs.WalkDirFunc) error {
		if root == hung {
			hungWalks.Add(1)
			<-release
		}
		return filepath.WalkDir(root, fn)
	}
	pitOverlayScanTimeout = 200 * time.Millisecond
	t.Cleanup(func() { walkForOverlays, pitOverlayScanTimeout = prevWalk, prevTimeout })

	for i := 0; i < 3; i++ {
		t0 := time.Now()
		_, unanswered := s.pitOverlayScan(context.Background())
		if !slices.Contains(unanswered, hung) || time.Since(t0) > 2*time.Second {
			t.Fatalf("scan %d: unanswered %v after %v; want %s within the bound", i, unanswered, time.Since(t0), hung)
		}
	}
	if n := hungWalks.Load(); n != 1 {
		t.Fatalf("the hung directory was walked %d times by 3 scans, want once", n)
	}

	close(release)
	released = true
	deadline := time.Now().Add(5 * time.Second)
	for {
		files, unanswered := s.pitOverlayScan(context.Background())
		if len(unanswered) == 0 && slices.Contains(files, overlay) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the directory answers: files %v unanswered %v; want %s found", files, unanswered, overlay)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
