package storage

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// deadNFS fakes a mount table holding one NFS mount at root, and makes every
// path resolution under root block until the test ends, as a stat on a hard
// NFS mount whose server does not answer does.
type deadNFS struct {
	root    string
	release chan struct{}
	calls   atomic.Int32
}

func installDeadNFS(t *testing.T, root string) *deadNFS {
	t.Helper()
	d := &deadNFS{root: root, release: make(chan struct{})}
	t.Cleanup(func() { close(d.release) })
	t.Cleanup(OverrideMountInfoForTest(func() ([]byte, error) {
		return []byte(fmt.Sprintf("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"+
			"40 1 0:60 / %s %s - nfs4 nas:/export rw\n", root, hardenedFlags)), nil
	}))
	t.Cleanup(OverrideFSCallBoundForTest(200 * time.Millisecond))
	t.Cleanup(OverridePathResolverForTest(func(p string) string {
		if within(d.root, p) {
			d.calls.Add(1)
			<-d.release
		}
		return resolveExisting(p)
	}))
	return d
}

// returnsWithin fails the test when fn has not returned within limit.
func returnsWithin(t *testing.T, limit time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("%s did not return within %v", what, limit)
	}
}

// Bounded gives up on a call that does not return; an identical call while
// it still runs is not started again and fails at once; and once a call
// under a network mount has gone unanswered, another path under that mount
// fails at once too. When the first call returns, calls are made again.
//
// Mutations: "no join" (an identical call starts again), "no stuck mount"
// (a call under the unanswered mount is attempted) — red.
func TestBounded_ACallThatDoesNotReturnCostsOneBoundPerMount(t *testing.T) {
	root := t.TempDir()
	installDeadNFS(t, root)
	release := make(chan struct{})
	var started atomic.Int32
	block := func() (int, error) {
		started.Add(1)
		<-release
		return 1, nil
	}
	// A path on no network mount: only the join keeps a second call from
	// waiting (and leaking a goroutine) again.
	local := filepath.Join(t.TempDir(), "x")
	t0 := time.Now()
	if _, err := Bounded("stat", local, block); !IsFSNoAnswer(err) {
		t.Fatalf("a call that does not return: %v, want an FSNoAnswerError", err)
	}
	if d := time.Since(t0); d < 150*time.Millisecond || d > 2*time.Second {
		t.Fatalf("gave up after %v, want about the bound", d)
	}
	t0 = time.Now()
	_, err := Bounded("stat", local, block)
	var nae *FSNoAnswerError
	if !errors.As(err, &nae) || !nae.Earlier || time.Since(t0) > 100*time.Millisecond {
		t.Fatalf("the same call again: %v after %v; want an immediate 'earlier call' error", err, time.Since(t0))
	}
	if n := started.Load(); n != 1 {
		t.Fatalf("%d calls were started, want 1", n)
	}
	// Under the network mount: once one path has gone unanswered, another
	// is not attempted.
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	if _, err := Bounded("stat", a, block); !IsFSNoAnswer(err) {
		t.Fatalf("a call that does not return: %v, want an FSNoAnswerError", err)
	}
	t0 = time.Now()
	_, err = Bounded("stat", b, block)
	if !errors.As(err, &nae) || !nae.Earlier || nae.Mount != root || time.Since(t0) > 100*time.Millisecond {
		t.Fatalf("another path under the unanswered mount: %v after %v; want an immediate error naming the mount", err, time.Since(t0))
	}
	if n := started.Load(); n != 2 {
		t.Fatalf("%d calls were started, want 2", n)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if v, err := Bounded("stat", b, func() (int, error) { return 7, nil }); err == nil && v == 7 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("calls under the mount still fail after the stuck call returned")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// F-2: an NFS pool's mount point is judged with no system call on it — the
// mount table has it, and a mount point is its own resolution — so a
// directory beside it is decided not to overlap while its server does not
// answer.
//
// Mutation "no mount-point shortcut" — the resolution blocks, the overlap
// cannot be verified: red.
func TestDirsOverlap_AnNFSMountPointNeedsNoSystemCall(t *testing.T) {
	root := t.TempDir()
	d := installDeadNFS(t, root)
	other := t.TempDir()
	var overlap bool
	var err error
	returnsWithin(t, 5*time.Second, "DirsOverlap", func() { overlap, err = DirsOverlap(other, root) })
	if err != nil || overlap {
		t.Fatalf("DirsOverlap(%s, NFS mount point) = %v, %v; want false, nil", other, overlap, err)
	}
	if n := d.calls.Load(); n != 0 {
		t.Fatalf("the dead mount was stat'ed %d times", n)
	}
}

// F-2, fail closed: an overlap that can only be decided by resolving a path
// on the dead mount is an error within the bound — never "no overlap" — and
// one that shows as written needs no resolution at all.
//
// Mutations: "a timed-out resolution is no overlap" (DirsOverlap returns
// false, nil) — red; "unbounded" — the call hangs: red; "no lexical test
// first" — the as-written overlap waits on the dead mount: red.
func TestDirsOverlap_AnUnresolvablePathIsAnErrorNeverNoOverlap(t *testing.T) {
	root := t.TempDir()
	d := installDeadNFS(t, root)
	inner := filepath.Join(root, "pool")
	other := t.TempDir()
	var overlap bool
	var err error
	returnsWithin(t, 5*time.Second, "DirsOverlap", func() { overlap, err = DirsOverlap(inner, filepath.Join(inner, "sub")) })
	if !overlap || err != nil {
		t.Fatalf("DirsOverlap of a path and one inside it = %v, %v; want true, nil", overlap, err)
	}
	if d.calls.Load() != 0 {
		t.Fatal("an overlap shown as written waited on the dead mount")
	}
	returnsWithin(t, 5*time.Second, "DirsOverlap", func() { overlap, err = DirsOverlap(other, inner) })
	if err == nil || overlap || !IsFSNoAnswer(err) || !strings.Contains(err.Error(), "cannot verify") {
		t.Fatalf("DirsOverlap(%s, a path on the dead mount) = %v, %v; want an error saying it cannot verify", other, overlap, err)
	}
}

// NFSBackingOf a directory that cannot be resolved in time is an error, not
// "on no NFS mount" (which a pool check would read as local storage), and
// SharedStoreOf such a directory is shared, with no identity.
//
// Mutations: "NFSBackingOf ignores the error" — nil, nil: red; "SharedStoreOf
// ignores the error" — judged by its written form, an ID: red.
func TestNFSBackingOf_AnUnresolvableDirectoryIsAnError(t *testing.T) {
	root := t.TempDir()
	installDeadNFS(t, root)
	inner := filepath.Join(root, "pool")
	mt, err := ReadMountTable()
	if err != nil {
		t.Fatal(err)
	}
	var b *NFSBacking
	returnsWithin(t, 5*time.Second, "NFSBackingOf", func() { b, err = mt.NFSBackingOf(inner) })
	if err == nil || !IsFSNoAnswer(err) || b != nil {
		t.Fatalf("NFSBackingOf(a path on the dead mount) = %v, %v; want an error", b, err)
	}
	var st SharedStore
	returnsWithin(t, 5*time.Second, "SharedStoreOf", func() { st = mt.SharedStoreOf(inner) })
	if !st.Shared || st.ID != "" {
		t.Fatalf("SharedStoreOf(a path on the dead mount) = %+v; want shared with no identity", st)
	}
	// The mount point itself is judged with no system call.
	returnsWithin(t, 5*time.Second, "NFSBackingOf", func() { b, err = mt.NFSBackingOf(root) })
	if err != nil || b == nil || b.Export.String() != "nas:/export" {
		t.Fatalf("NFSBackingOf(the mount point) = %+v, %v; want nas:/export", b, err)
	}
}

// CheckWriteRoot of a pool directory below the dead mount refuses within the
// bound, as a directory that cannot be checked; the mount point itself is
// checked with no call on it.
//
// Mutation "unbounded" (CheckWriteRoot resolves with pathForms) — the check
// hangs: red.
func TestCheckWriteRoot_ADirectoryOnADeadMountIsRefusedNotWaitedOn(t *testing.T) {
	root := t.TempDir()
	d := installDeadNFS(t, root)
	var err error
	returnsWithin(t, 5*time.Second, "CheckWriteRoot", func() { err = CheckWriteRoot(root, "/var/lib/litevirt-test", "") })
	if err != nil || d.calls.Load() != 0 {
		t.Fatalf("CheckWriteRoot(the mount point) = %v after %d calls on the dead mount; want nil after none", err, d.calls.Load())
	}
	returnsWithin(t, 5*time.Second, "CheckWriteRoot", func() { err = CheckWriteRoot(filepath.Join(root, "pool"), "/var/lib/litevirt-test", "") })
	if err == nil || !IsFSNoAnswer(err) || !strings.Contains(err.Error(), "cannot be checked") {
		t.Fatalf("CheckWriteRoot(a directory on the dead mount) = %v; want a refusal saying it cannot be checked", err)
	}
}

// IsMountPoint reads the mount table only.
func TestIsMountPoint(t *testing.T) {
	root := t.TempDir()
	installDeadNFS(t, root)
	if !IsMountPoint(root) || !IsMountPoint(root+"/") {
		t.Fatalf("%s is in the mount table", root)
	}
	if IsMountPoint(filepath.Join(root, "x")) || IsMountPoint(t.TempDir()) {
		t.Fatal("a path the mount table does not have is not a mount point")
	}
}
