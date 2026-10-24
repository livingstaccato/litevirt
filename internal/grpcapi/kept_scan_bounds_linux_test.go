package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// keptScanOpened records every path the scan is about to open, for the
// test's life.
func keptScanOpened(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var got []string
	prev := keptScanOpenHook
	keptScanOpenHook = func(p string) {
		mu.Lock()
		got = append(got, p)
		mu.Unlock()
	}
	t.Cleanup(func() { keptScanOpenHook = prev })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
}

// createWithin runs a create of web on pool ssd and fails the test, rather
// than hang it, when it has not returned within d.
func createWithin(t *testing.T, s *Server, d time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := s.CreateVM(adminCtx(), poolCreateRequest("web", "ssd"))
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		t.Fatalf("the create has not returned after %s: the kept-collision scan hangs", d)
		return nil
	}
}

// While kept-disks.json cannot be read, a symlink below a scanned root that
// names a pseudo-filesystem (/proc, /sys, or a file on one: /proc/kmsg is a
// regular file whose read blocks) is neither listed nor read, judged by the
// filesystem's type: the create goes ahead, and the scan opened nothing
// there. An overlay in the pool is opened, so the hook is seen to work.
//
// Mutation: drop the pseudo-filesystem checks (the statfs skip before a
// directory is listed and in keptScanFollow): red, the scan walks /proc.
func TestCreateVM_KeptScanNeverReadsAPseudoFilesystem(t *testing.T) {
	s, _ := provableCreateServer(t)
	dir := filepath.Join(t.TempDir(), "ssd")
	writePathsDirPool(t, s, "ssd", dir)
	ov := filepath.Join(dir, "db-snap1.qcow2")
	overlayOn(t, ov, filepath.Join(t.TempDir(), "elsewhere.raw"))
	for name, target := range map[string]string{"proc": "/proc", "sys": "/sys", "kmsg": "/proc/kmsg", "self": "/proc/self"} {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	unreadableKeptRegistry(t, s)
	opened := keptScanOpened(t)
	if err := createWithin(t, s, 60*time.Second); err != nil {
		t.Fatalf("create web beside links to /proc and /sys, while kept-disks.json cannot be read: %v", err)
	}
	got := opened()
	sawOverlay := false
	for _, p := range got {
		if strings.HasPrefix(p, "/proc") || strings.HasPrefix(p, "/sys") {
			t.Fatalf("the scan opened %s, on a pseudo-filesystem", p)
		}
		sawOverlay = sawOverlay || p == ov
	}
	if !sawOverlay {
		t.Fatalf("the scan opened %v, not the overlay %s: this proves nothing", got, ov)
	}
}

// While kept-disks.json cannot be read, a FIFO is never opened by the scan,
// however it is reached: in the pool itself, through a symlink in the pool,
// or as the backing file of an overlay there. A blocking open of one is the
// hang. The create goes ahead.
//
// Mutation: drop the regular-file checks before an open (walkKeptChainIn's
// and keptScanBudget.open's stat) and open without O_NONBLOCK: red, the
// create does not return in time (or refuses as storage not answering).
func TestCreateVM_KeptScanNeverOpensAFIFO(t *testing.T) {
	s, _ := provableCreateServer(t)
	dir := filepath.Join(t.TempDir(), "ssd")
	writePathsDirPool(t, s, "ssd", dir)
	elsewhere := t.TempDir()
	fifo := filepath.Join(elsewhere, "pipe")
	inPool := filepath.Join(dir, "pipe-here")
	for _, p := range []string{fifo, inPool} {
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(fifo, filepath.Join(dir, "pipe-link")); err != nil {
		t.Fatal(err)
	}
	ov := filepath.Join(dir, "db-snap1.qcow2")
	overlayOn(t, ov, fifo)
	unreadableKeptRegistry(t, s)
	opened := keptScanOpened(t)
	if err := createWithin(t, s, 30*time.Second); err != nil {
		t.Fatalf("create web beside FIFOs, while kept-disks.json cannot be read: %v", err)
	}
	got := opened()
	sawOverlay := false
	for _, p := range got {
		if p == fifo || p == inPool || strings.HasSuffix(p, "pipe-link") {
			t.Fatalf("the scan opened the FIFO %s", p)
		}
		sawOverlay = sawOverlay || p == ov
	}
	if !sawOverlay {
		t.Fatalf("the scan opened %v, not the overlay %s: this proves nothing", got, ov)
	}
}

// A scan past its budget of files, bytes read or time refuses the write,
// naming the budget; within it, the same create goes ahead.
//
// Mutation: make look and charge never fail: the three refusals red.
func TestCreateVM_KeptScanRefusesPastItsBudget(t *testing.T) {
	setup := func(t *testing.T) *Server {
		s, _ := provableCreateServer(t)
		dir := filepath.Join(t.TempDir(), "ssd")
		writePathsDirPool(t, s, "ssd", dir)
		for _, n := range []string{"a", "b", "c", "d"} {
			overlayOn(t, filepath.Join(dir, n+"-snap.qcow2"), filepath.Join(t.TempDir(), n+".raw"))
		}
		unreadableKeptRegistry(t, s)
		return s
	}
	set := func(t *testing.T, files, bytes int64, d time.Duration) {
		pf, pb, pd := keptScanMaxFiles, keptScanMaxBytes, keptScanMaxTime
		keptScanMaxFiles, keptScanMaxBytes, keptScanMaxTime = files, bytes, d
		t.Cleanup(func() { keptScanMaxFiles, keptScanMaxBytes, keptScanMaxTime = pf, pb, pd })
	}
	t.Run("within it", func(t *testing.T) {
		s := setup(t)
		if err := createWithin(t, s, 30*time.Second); err != nil {
			t.Fatalf("create web within the scan budget: %v", err)
		}
	})
	for _, c := range []struct {
		name, want   string
		files, bytes int64
		d            time.Duration
	}{
		{"files", "more than 3 files", 3, 4 << 30, time.Minute},
		{"bytes", "more than 100 bytes read", 250_000, 100, time.Minute},
		{"time", "more than 1ns", 250_000, 4 << 30, time.Nanosecond},
	} {
		t.Run("past its "+c.name, func(t *testing.T) {
			s := setup(t)
			set(t, c.files, c.bytes, c.d)
			err := createWithin(t, s, 30*time.Second)
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "past its budget") ||
				!strings.Contains(err.Error(), c.want) {
				t.Fatalf("create web = %v; want FailedPrecondition naming the budget (%q)", err, c.want)
			}
		})
	}
}
