package grpcapi

// Lab 2 F-1: the startup sweeps read every pool directory, and one on an NFS
// mount whose server does not answer blocks its listing in the kernel. These
// tests stand that in with a directory listing that blocks until released.

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/storage"
)

// F-1: the staging sweep reads every pool directory. One that does not
// answer is given up on within the bound, and the others are still swept.
//
// Mutation "no bound" (each directory swept directly) — the sweep hangs: red.
func TestSweepStaleStaging_ADirectoryThatDoesNotAnswerHoldsNothingElse(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	good := replicaPoolDir(t, s, "good")
	dead := replicaPoolDir(t, s, "dead")
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	t.Cleanup(storage.OverrideFSCallBoundForTest(300 * time.Millisecond))
	prev := stagingReadDir
	stagingReadDir = func(dir string) ([]os.DirEntry, error) {
		if pathWithin(dead, dir) {
			<-release
		}
		return os.ReadDir(dir)
	}
	t.Cleanup(func() { stagingReadDir = prev })
	stale := filepath.Join(good, ".upload-123.tmp")
	if err := os.WriteFile(stale, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	within(t, 10*time.Second, "the staging sweep", func() struct{} {
		s.SweepStaleStaging(context.Background())
		return struct{}{}
	})
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("the answering pool's stale temp was not swept: %v", err)
	}
}

// F-1: the cold migration scratch sweep runs before the daemon serves. A
// root that does not answer is skipped within the bound, the others are
// swept, and nothing is removed from the skipped root once it answers: only
// a listing that finished before the daemon served is acted on.
//
// Mutations: "no bound" — the sweep hangs: red. "remove inside the bounded
// call" — the skipped root's scratch is removed after it answers: red.
func TestSweepColdMigrationScratch_ARootThatDoesNotAnswerIsSkipped(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	good, dead := t.TempDir(), t.TempDir()
	s.SetStoragePoolsByName(map[string]StoragePoolRef{
		"good": {Driver: "dir", Target: good},
		"dead": {Driver: "dir", Target: dead},
	})
	const name = ".os1-root.qcow2.receiving-123456"
	for _, d := range []string{good, dead} {
		if err := os.WriteFile(filepath.Join(d, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	release := make(chan struct{})
	released := false
	t.Cleanup(func() {
		if !released {
			close(release)
		}
	})
	t.Cleanup(storage.OverrideFSCallBoundForTest(300 * time.Millisecond))
	prev := coldScratchReadDir
	var listedDead atomic.Bool
	coldScratchReadDir = func(dir string) ([]os.DirEntry, error) {
		if dir == dead {
			<-release
			listedDead.Store(true)
		}
		return os.ReadDir(dir)
	}
	t.Cleanup(func() { coldScratchReadDir = prev })
	within(t, 10*time.Second, "the cold migration scratch sweep", func() struct{} {
		s.SweepColdMigrationScratch()
		return struct{}{}
	})
	if _, err := os.Stat(filepath.Join(good, name)); !os.IsNotExist(err) {
		t.Fatalf("the answering root's scratch was not swept: %v", err)
	}
	close(release) // the server answers again
	released = true
	deadline := time.Now().Add(5 * time.Second)
	for !listedDead.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(dead, name)); err != nil {
		t.Fatalf("a scratch file was removed from a root after the sweep gave up on it: %v", err)
	}
}

// hangingMounts makes a `mount` hang until released (or its context ends),
// as one against a server that does not answer does, then fail or succeed.
