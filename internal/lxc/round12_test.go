//go:build linux

package lxc

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A first pull that fails leaves no item directory (it created one, still
// empty) and no lock file behind; a directory it did not create is kept.
func TestPullOCI_AFailedFirstPullLeavesNothing(t *testing.T) {
	fakeOCITools(t, true)
	parent := t.TempDir()
	dest := filepath.Join(parent, "web")
	if err := PullOCI(context.Background(), PullOCIOptions{Image: "alpine:3.21", Dest: dest}); err == nil {
		t.Fatal("a failing unpack reported success")
	}
	if _, err := os.Stat(dest); err == nil {
		t.Error("the failed first pull left the item directory")
	}
	if _, err := os.Stat(filepath.Join(parent, unpackDirName, "web"+lockSuffix)); err == nil {
		t.Error("the failed first pull left its lock file")
	}
	mine := filepath.Join(parent, "mine")
	if err := os.MkdirAll(mine, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = PullOCI(context.Background(), PullOCIOptions{Image: "alpine:3.21", Dest: mine})
	if _, err := os.Stat(mine); err != nil {
		t.Error("a failed pull removed a directory it did not create")
	}
}

// Start-up recovery removes the lock file of an item that no longer
// exists, unless another process holds it; an existing item's lock stays.
func TestRecoverOCILibrary_RemovesLocksOfGoneItems(t *testing.T) {
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("flock(1) not installed")
	}
	lib := t.TempDir()
	dir := filepath.Join(lib, unpackDirName)
	if err := os.MkdirAll(filepath.Join(lib, "keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"gone", "keep", "held"} {
		if err := os.WriteFile(filepath.Join(dir, n+lockSuffix), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ready := filepath.Join(t.TempDir(), "ready")
	c := exec.Command("flock", filepath.Join(dir, "held"+lockSuffix), "sh", "-c", "touch "+ready+" && exec sleep 30")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
	for i := 0; i < 250; i++ {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := RecoverOCILibrary(lib); err != nil {
		t.Fatal(err)
	}
	for n, want := range map[string]bool{"gone": false, "keep": true, "held": true} {
		_, err := os.Stat(filepath.Join(dir, n+lockSuffix))
		if (err == nil) != want {
			t.Errorf("%s%s present = %v, want %v", n, lockSuffix, err == nil, want)
		}
	}
}

// A lock taken on a lock file that was removed and created again while the
// taker waited is not the item's lock: the taker locks the file now at the
// path.
func TestLockItemFile_FollowsAReplacedLockFile(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "web")
	release, err := lockItemFile(context.Background(), dest)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(dest), unpackDirName, "web"+lockSuffix)
	got := make(chan func(), 1)
	go func() {
		r, err := lockItemFile(context.Background(), dest)
		if err != nil {
			t.Error(err)
		}
		got <- r
	}()
	time.Sleep(200 * time.Millisecond) // the waiter has the old file open
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	release() // the old file's lock is free; the path holds no file now
	r2 := <-got
	defer r2()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("the waiter holds no lock file at the path: %v", err)
	}
	defer f.Close()
	if ok, _ := flockTry(f); ok {
		t.Fatal("the lock file at the path is free while the waiter thinks it holds the item's lock")
	}
}

// The start-up sweep says what it did: each process it stopped (pid, name,
// why) and each stage it removed.
func TestStartupSweepLogsWhatItDoes(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	store := t.TempDir()
	work := filepath.Join(store, fetchDirName, "web", "web", "rootfs")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	w := exec.Command("sleep", "30")
	w.Dir = work
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = w.Wait(); close(done) }()
	t.Cleanup(func() { _ = w.Process.Kill(); <-done })
	if err := (&LxcRunner{Lxcpath: store}).SweepFetchDir(); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"pid=" + strconv.Itoa(w.Process.Pid), "comm=sleep", "why=", "removed", fetchDirName} {
		if !strings.Contains(out, want) {
			t.Errorf("the sweep's log lacks %q:\n%s", want, out)
		}
	}
}

// The runtime's refusals of a source are typed, so the daemon can answer
// them as a refusal rather than an internal error.
func TestSourceRefusalsAreTyped(t *testing.T) {
	base := t.TempDir()
	fifo := filepath.Join(base, "x.tar")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"docker-daemon:x", "-x", "docker-archive:" + fifo, "dir:" + fifo, "oci:" + filepath.Join(base, "missing") + ":v1"} {
		src, err := ParseOCISource(ref)
		if err == nil {
			_, err = openLocalSource(src, nil)
		}
		if !errors.Is(err, ErrSourceRefused) {
			t.Errorf("%s: %v, want an ErrSourceRefused", ref, err)
		}
	}
	prev := stagingSpace
	t.Cleanup(func() { stagingSpace = prev })
	stagingSpace = func(string) (uint64, uint64, error) { return 10, 100 << 30, nil }
	if err := checkStagingSpace(base, 4096, "oci-archive"); !errors.Is(err, ErrStagingSpace) {
		t.Errorf("space refusal %v, want an ErrStagingSpace", err)
	}
}

// Retaking a lock file that keeps being replaced under the taker honours
// the caller's cancel: the taker does not spin past it.
func TestLockItemFile_TheRetakeHonoursCancel(t *testing.T) {
	prev := lockAtPath
	t.Cleanup(func() { lockAtPath = prev })
	lockAtPath = func(*os.File, string) bool { return false } // replaced every time
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	got := make(chan error, 1)
	go func() {
		r, err := lockItemFile(ctx, filepath.Join(t.TempDir(), "web"))
		if r != nil {
			r()
		}
		got <- err
	}()
	select {
	case err := <-got:
		if err == nil {
			t.Fatal("the taker reported a lock it never held")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a cancelled taker kept retaking")
	}
}

// A source the host cannot read for reasons of its own (an I/O error) is a
// failure, not a refusal of what the caller named; a missing one is.
func TestSourceIOErrorsAreNotRefusals(t *testing.T) {
	prev := openSourceRef
	t.Cleanup(func() { openSourceRef = prev })
	src := OCISource{Transport: "docker-archive", Path: "/x/img.tar", Local: true}
	openSourceRef = func(string, bool) (*os.File, error) {
		return nil, &os.PathError{Op: "open", Path: "/x/img.tar", Err: syscall.EIO}
	}
	if _, err := openLocalSource(src, nil); err == nil || errors.Is(err, ErrSourceRefused) {
		t.Errorf("an I/O error: %v, want a plain failure", err)
	}
	openSourceRef = func(string, bool) (*os.File, error) {
		return nil, &os.PathError{Op: "open", Path: "/x/img.tar", Err: syscall.ENOENT}
	}
	if _, err := openLocalSource(src, nil); !errors.Is(err, ErrSourceRefused) {
		t.Errorf("a missing source: %v, want a refusal", err)
	}
}

// A first pull whose unpack fails after writing leaves no item behind: it
// unpacks beside the item and puts it in place only when it succeeds.
func TestPullOCI_AFailedFirstPullLeavesNoPartialItem(t *testing.T) {
	fakeOCITools(t, false)
	bin := t.TempDir()
	// An umoci that writes part of the bundle, then fails.
	umoci := `#!/bin/sh
for a in "$@"; do bundle="$a"; done
mkdir -p "$bundle/rootfs/etc" && echo partial > "$bundle/rootfs/etc/image"
echo "umoci: write failed" >&2; exit 1
`
	if err := os.WriteFile(filepath.Join(bin, "umoci"), []byte(umoci), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	parent := t.TempDir()
	dest := filepath.Join(parent, "web")
	if err := PullOCI(context.Background(), PullOCIOptions{Image: "alpine:3.21", Dest: dest}); err == nil {
		t.Fatal("a failing unpack reported success")
	}
	if _, err := os.Stat(dest); err == nil {
		t.Fatal("a failed first pull left a partial item")
	}
	// An item directory that existed before the pull is never removed.
	mine := filepath.Join(parent, "mine")
	if err := os.MkdirAll(mine, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = PullOCI(context.Background(), PullOCIOptions{Image: "alpine:3.21", Dest: mine})
	if _, err := os.Stat(mine); err != nil {
		t.Fatal("a failed pull removed a directory that existed before it")
	}
}

// An empty item directory (an older build's failed first pull left one) is
// treated as no item: the pull unpacks beside it and renames over it only on
// success, so a failure partway leaves it empty, not a partial item.
func TestPullOCI_AnEmptyDestIsTreatedAsMissing(t *testing.T) {
	fakeOCITools(t, false)
	bin := t.TempDir()
	umoci := `#!/bin/sh
for a in "$@"; do bundle="$a"; done
mkdir -p "$bundle/rootfs/etc" && echo partial > "$bundle/rootfs/etc/image"
echo "umoci: write failed" >&2; exit 1
`
	if err := os.WriteFile(filepath.Join(bin, "umoci"), []byte(umoci), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	dest := filepath.Join(t.TempDir(), "admdarchbad")
	if err := os.MkdirAll(dest, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := PullOCI(context.Background(), PullOCIOptions{Image: "alpine:3.21", Dest: dest}); err == nil {
		t.Fatal("a failing unpack reported success")
	}
	if ents, err := os.ReadDir(dest); err == nil && len(ents) != 0 {
		t.Fatalf("a failed pull into an empty item directory left a partial item: %v", ents)
	}
	// A pull that succeeds there puts the bundle in place.
	fakeOCITools(t, false)
	if err := PullOCI(context.Background(), PullOCIOptions{Image: "alpine:3.21", Dest: dest}); err != nil {
		t.Fatal(err)
	}
	if got := imageIn(t, dest); got != "3.21" {
		t.Fatalf("the item holds %q", got)
	}
}
