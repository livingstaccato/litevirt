//go:build linux

package lxc

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// startIn starts a long-lived process with its working directory in dir.
func startIn(t *testing.T, dir string) (*exec.Cmd, chan struct{}) {
	t.Helper()
	c := exec.Command("sleep", "30")
	c.Dir = dir
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = c.Wait(); close(done) }()
	t.Cleanup(func() { _ = c.Process.Kill(); <-done })
	return c, done
}

// A worker that forks a child after the sweep read /proc (so the child is in
// no snapshot it took) is stopped too: the sweep scans again until a scan
// finds nobody in the stage, and only then is the stage removed. A process
// outside the stage is left alone.
func TestSweepStopsAWorkerForkedAfterTheScan(t *testing.T) {
	store := t.TempDir()
	stage := filepath.Join(store, fetchDirName, "web", "web", "rootfs")
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	_, firstDone := startIn(t, stage)
	_, outsideDone := startIn(t, t.TempDir())
	var forked chan struct{}
	prev := afterProcScan
	t.Cleanup(func() { afterProcScan = prev })
	afterProcScan = func() {
		if forked == nil { // once: a child appears after the first snapshot
			_, forked = startIn(t, stage)
		}
	}
	if err := (&LxcRunner{Lxcpath: store}).SweepFetchDir(); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	for name, done := range map[string]chan struct{}{"the worker": firstDone, "its late child": forked} {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s was left running in the stage", name)
		}
	}
	select {
	case <-outsideDone:
		t.Fatal("a process outside the stage was stopped")
	default:
	}
	if _, err := os.Stat(filepath.Join(store, fetchDirName)); err == nil {
		t.Fatal("the stage was not removed after it went quiet")
	}
}

// When the sweep cannot prove a worker stopped (no pidfd here), it keeps
// the stage and says so, rather than removing it under a live writer.
func TestSweepKeepsTheStageWhenItCannotStopAWorker(t *testing.T) {
	store := t.TempDir()
	stage := filepath.Join(store, fetchDirName, "web", "web", "rootfs")
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	startIn(t, stage)
	prev := pidfdOpen
	t.Cleanup(func() { pidfdOpen = prev })
	pidfdOpen = func(int, int) (int, error) { return -1, errors.New("pidfd unsupported") }
	if err := (&LxcRunner{Lxcpath: store}).SweepFetchDir(); err == nil {
		t.Fatal("the sweep reported success with a worker it could not stop")
	}
	if _, err := os.Stat(stage); err != nil {
		t.Fatal("the stage was removed under a live worker")
	}
}

// A stage the start-up sweep kept (a worker it could not stop) stays kept:
// the name's next fetch refuses rather than rebuild it under that worker.
func TestFetchImage_KeepsAStageAWorkerMayStillWorkIn(t *testing.T) {
	store := t.TempDir()
	fakeLxcCreate(t, 0)
	stage := filepath.Join(store, fetchDirName, "web", "web", "rootfs")
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	startIn(t, stage)
	prev := pidfdOpen
	t.Cleanup(func() { pidfdOpen = prev })
	pidfdOpen = func(int, int) (int, error) { return -1, errors.New("pidfd unsupported") }
	err := (&LxcRunner{Lxcpath: store}).FetchImage(context.Background(),
		CreateOpts{Name: "web", Template: "download", Distro: "alpine", Release: "3.22", Arch: "amd64"})
	if err == nil {
		t.Fatal("the fetch rebuilt a stage a worker may still work in")
	}
	if _, err := os.Stat(stage); err != nil {
		t.Fatal("the stage was removed under a live worker")
	}
}

// So does what an interrupted pull left of an item: its next pull refuses
// rather than recover the entries under that worker.
func TestRecoverItem_KeepsEntriesAWorkerMayStillWorkIn(t *testing.T) {
	lib := t.TempDir()
	entry := filepath.Join(lib, unpackDirName, "web+abc", "rootfs")
	if err := os.MkdirAll(entry, 0o755); err != nil {
		t.Fatal(err)
	}
	startIn(t, entry)
	prev := pidfdOpen
	t.Cleanup(func() { pidfdOpen = prev })
	pidfdOpen = func(int, int) (int, error) { return -1, errors.New("pidfd unsupported") }
	if err := recoverItem(filepath.Join(lib, "web")); err == nil {
		t.Fatal("recovery went ahead with a worker it could not stop")
	}
	if _, err := os.Stat(entry); err != nil {
		t.Fatal("the entry was removed under a live worker")
	}
}
