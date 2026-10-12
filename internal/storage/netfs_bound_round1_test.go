package storage

import (
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// R1 I-1: a call with another result type, on the same op and path, is not
// joined to one still running: it runs on its own and returns its own value.
// Joined, it got the other call's value as a zero of its own type, with no
// error (a statfs for capacity reading a CephFS fsid "", say).
//
// Mutation "join by op and path only" — the string call returns "", nil: red.
func TestBounded_ACallOfAnotherResultTypeIsNotJoined(t *testing.T) {
	t.Cleanup(OverrideFSCallBoundForTest(2 * time.Second))
	p := filepath.Join(t.TempDir(), "pool")
	release := make(chan struct{})
	first := make(chan struct{})
	go func() {
		_, _ = Bounded("statfs", p, func() (uint32, error) {
			close(first)
			<-release
			return 7, nil
		})
	}()
	<-first
	defer close(release)
	got, err := Bounded("statfs", p, func() (string, error) { return "fsid-1", nil })
	if err != nil || got != "fsid-1" {
		t.Fatalf("a string call beside a uint32 one in flight = %q, %v; want its own value", got, err)
	}
}

// R1 M-1: the latch on a network mount whose call went unanswered is the
// mount's own (its mount ID), not its directory's: a new mount at the same
// directory — after a lazy unmount of the dead one, whose stuck call never
// returns — is used, not failed at once.
//
// Mutation "latch by directory" — the call on the new mount fails at once: red.
func TestBounded_ANewMountAtTheSameDirectoryIsNotLatched(t *testing.T) {
	root := t.TempDir()
	var mountID atomic.Int32
	mountID.Store(40)
	t.Cleanup(OverrideMountInfoForTest(func() ([]byte, error) {
		return []byte(fmt.Sprintf("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"+
			"%d 1 0:60 / %s %s - nfs4 nas:/export rw\n", mountID.Load(), root, hardenedFlags)), nil
	}))
	t.Cleanup(OverrideFSCallBoundForTest(200 * time.Millisecond))
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	a := filepath.Join(root, "a")
	if _, err := Bounded("stat", a, func() (int, error) { <-release; return 0, nil }); !IsFSNoAnswer(err) {
		t.Fatalf("a call that does not return: %v", err)
	}
	if _, err := Bounded("stat", filepath.Join(root, "b"), func() (int, error) { return 1, nil }); !IsFSNoAnswer(err) {
		t.Fatalf("the same mount after an unanswered call: %v; want an immediate error", err)
	}
	mountID.Store(41) // umount -l, and a new mount at the same directory
	v, err := Bounded("stat", filepath.Join(root, "b"), func() (int, error) { return 1, nil })
	if err != nil || v != 1 {
		t.Fatalf("a call on the new mount at the same directory = %d, %v; want it made", v, err)
	}
}

// R1 I-2: SharedStoreOfErr reports a store that does not answer as an error,
// for a writer; SharedStoreOf keeps the conservative "shared, no identity"
// for a reader.
//
// Mutation "SharedStoreOfErr maps the timeout to no identity" — red.
func TestSharedStoreOfErr_AStoreThatDoesNotAnswerIsAnError(t *testing.T) {
	root := t.TempDir()
	installDeadNFS(t, root)
	inner := filepath.Join(root, "pool")
	var st SharedStore
	var err error
	returnsWithin(t, 5*time.Second, "SharedStoreOfErr", func() { st, err = SharedStoreOfErr(inner) })
	if !IsFSNoAnswer(err) {
		t.Fatalf("SharedStoreOfErr(a dead store) = %+v, %v; want an FSNoAnswerError", st, err)
	}
	if got := SharedStoreOf(inner); !got.Shared || got.ID != "" {
		t.Fatalf("SharedStoreOf(a dead store) = %+v; want shared with no identity", got)
	}
	if st, err := SharedStoreOfErr(root); err != nil || st.ID != "nfs:nas:/export" {
		t.Fatalf("SharedStoreOfErr(the mount point) = %+v, %v; want its identity", st, err)
	}
}
