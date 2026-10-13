package storage

import (
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// Each check reads the mount table once, and its bounded calls judge every
// path against that read.
//
// Mutation "boundedCall ignores the table it is given" — red.
func TestBoundedChecks_ReadTheMountTableOncePerCall(t *testing.T) {
	var n atomic.Int64
	t.Cleanup(OverrideMountInfoForTest(func() ([]byte, error) {
		n.Add(1)
		return []byte("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"), nil
	}))
	a, b := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	for _, c := range []struct {
		name string
		fn   func()
	}{
		{"EvalSymlinksBounded", func() { _, _ = EvalSymlinksBounded(a) }},
		{"DirsOverlap", func() { _, _ = DirsOverlap(a, b) }},
		{"CheckWriteRoot", func() { _ = CheckWriteRoot(a, "/var/lib/litevirt", "/etc/litevirt/pki") }},
		{"IsDataDirDisksErr", func() { _, _ = IsDataDirDisksErr(a, "/var/lib/litevirt") }},
		{"PrimeBounded", func() { PrimeBounded(a, b, filepath.Join(b, "c")) }},
	} {
		n.Store(0)
		c.fn()
		if got := n.Load(); got != 1 {
			t.Errorf("%s read the mount table %d times, want 1", c.name, got)
		}
	}
}

// A path is judged by the mount table of the operation it is part of. Within
// it, a dead mount lazily unmounted since the table was read still fails the
// next call under it at once (the latch is that mount's, by its ID); the next
// operation reads the table again, finds the mount gone, and is not failed by
// that latch.
func TestBoundedIn_JudgesAPathByItsOperationsMountTable(t *testing.T) {
	root := t.TempDir()
	installDeadNFS(t, root)
	snap, err := ReadMountTable()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolveBounded(&snap, filepath.Join(root, "a")); !IsFSNoAnswer(err) {
		t.Fatalf("a path under the dead mount: %v, want an FSNoAnswerError", err)
	}
	t.Cleanup(OverrideMountInfoForTest(func() ([]byte, error) {
		return []byte("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"), nil
	}))

	var e *FSNoAnswerError
	t0 := time.Now()
	_, err = resolveBounded(&snap, filepath.Join(root, "b"))
	if !errors.As(err, &e) || !e.Earlier || e.Mount != root {
		t.Fatalf("another path under the dead mount, same operation: %v, want it failed at once by %s's latch", err, root)
	}
	if d := time.Since(t0); d > 100*time.Millisecond {
		t.Errorf("same operation waited %v, want it failed at once", d)
	}

	fresh, err := ReadMountTable()
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolveBounded(&fresh, filepath.Join(root, "c"))
	if !errors.As(err, &e) || e.Earlier || e.Mount != "" {
		t.Fatalf("a path there in the next operation, the mount gone: %v, want it waited for and judged on no network mount", err)
	}
}
