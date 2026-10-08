package lxc

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// Test hooks for packages that drive the real runtime without root. They are
// not used by the daemon.

// Cleanuper is the part of testing.TB the hooks need.
type Cleanuper interface{ Cleanup(func()) }

// OwnershipOverlay records the owners chown would have set, and answers the
// shift's owner lookups from them, so a test can run (and interrupt) a real
// ownership shift as an unprivileged user.
type OwnershipOverlay struct {
	mu        sync.Mutex
	owners    map[string][2]int
	failAfter int
	failErr   error
}

// UseOwnershipOverlayForTest routes the runtime's chown and owner lookups
// through a fresh overlay until t's cleanup.
func UseOwnershipOverlayForTest(t Cleanuper) *OwnershipOverlay {
	o := &OwnershipOverlay{owners: map[string][2]int{}, failAfter: -1}
	oldC, oldL := lchown, lookupOwner
	lchown = o.chown
	lookupOwner = func(p string, fi fs.FileInfo) (int, int) { return o.lookup(p, fi) }
	t.Cleanup(func() { lchown, lookupOwner = oldC, oldL })
	return o
}

// FailAfter makes the chown after the next n succeed fail with err; n < 0
// never fails.
func (o *OwnershipOverlay) FailAfter(n int, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.failAfter, o.failErr = n, err
}

// Of returns p's owner as the overlay sees it.
func (o *OwnershipOverlay) Of(p string) (int, int) {
	fi, err := os.Lstat(p)
	if err != nil {
		return -1, -1
	}
	return o.lookup(p, fi)
}

func (o *OwnershipOverlay) chown(p string, uid, gid int) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.failAfter == 0 {
		return fmt.Errorf("chown %s: %w", p, o.failErr)
	}
	if o.failAfter > 0 {
		o.failAfter--
	}
	o.owners[filepath.Clean(p)] = [2]int{uid, gid}
	return nil
}

func (o *OwnershipOverlay) lookup(p string, fi fs.FileInfo) (int, int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if v, ok := o.owners[filepath.Clean(p)]; ok {
		return v[0], v[1]
	}
	return ownerOf(fi)
}

// UseSubIDFilesForTest points root's subordinate-id files at dir (as if the
// host hands out ranges) until t's cleanup.
func UseSubIDFilesForTest(t Cleanuper, dir string) {
	oldU, oldG, oldW := subUIDPath, subGIDPath, subIDsWanted
	subUIDPath, subGIDPath = filepath.Join(dir, "subuid"), filepath.Join(dir, "subgid")
	subIDsWanted = func() bool { return true }
	subIDsMu.Lock()
	subIDsEnsured = map[int64]bool{}
	subIDsMu.Unlock()
	t.Cleanup(func() { subUIDPath, subGIDPath, subIDsWanted = oldU, oldG, oldW })
}
