package storage

import (
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// The mount table cache.
//
// Every pool file open (OpenPoolFile), and every pool check, judges a path
// against this host's mount table. Reading /proc/self/mountinfo for each of
// them made a replication run read it once per file it opened, and the
// replication pool check up to four times. The table is now read again only
// when the kernel says it changed: an open /proc/self/mountinfo is marked
// (POLLPRI) by every mount, unmount and remount in the daemon's mount
// namespace, a bind remount that drops nosymfollow included. Each use polls
// that mark first, and reads the table again when it is set, so no use is
// judged against a table older than the last change the kernel had made when
// the use began: the same moment a fresh read would have shown. When the mark
// cannot be watched, every use reads the table, as before.

// procMountInfo reads this host's mount table text; tests replace it.
var procMountInfo = newTestHook(func() ([]byte, error) { return os.ReadFile("/proc/self/mountinfo") })

// mountTableChanged reports whether the table may have changed since the
// last call; tests replace it.
var mountTableChanged = newTestHook(func() bool { return procWatch.changed() })

var procWatch = &procMountWatch{}

var mountCache struct {
	mu    sync.Mutex
	all   []mountEntry
	valid bool
}

// cachedMounts is the mount table, read again only when it changed.
func cachedMounts() ([]mountEntry, error) {
	mountCache.mu.Lock()
	defer mountCache.mu.Unlock()
	// The mark is taken BEFORE the read: a change after it is marked again,
	// and seen by the next use.
	if mountTableChanged.get()() || !mountCache.valid {
		data, err := procMountInfo.get()()
		if err != nil {
			mountCache.all, mountCache.valid = nil, false
			return nil, err
		}
		mountCache.all, mountCache.valid = parseMountInfo(data), true
	}
	return mountCache.all, nil
}

// resetMountCache drops the cached table (tests).
func resetMountCache() {
	mountCache.mu.Lock()
	mountCache.all, mountCache.valid = nil, false
	mountCache.mu.Unlock()
}

// procMountWatch holds /proc/self/mountinfo open for its change mark. Used
// under mountCache.mu only.
type procMountWatch struct {
	f *os.File
}

// changed reports whether the mount table changed since the previous call:
// true on the first call, and whenever the mark cannot be read.
func (w *procMountWatch) changed() bool {
	if w.f == nil {
		f, err := os.Open("/proc/self/mountinfo")
		if err != nil {
			return true
		}
		w.f = f
		return true
	}
	// Polling consumes the mark (the kernel records the event as seen). The
	// file always polls readable; only POLLPRI (with POLLERR) is the mark.
	fds := []unix.PollFd{{Fd: int32(w.f.Fd()), Events: unix.POLLPRI}}
	n, err := unix.Poll(fds, 0)
	if err != nil {
		return true
	}
	return n > 0 && fds[0].Revents&(unix.POLLPRI|unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0
}

func (w *procMountWatch) close() {
	if w.f != nil {
		w.f.Close()
		w.f = nil
	}
}

// OverrideMountTableSourceForTest serves the mount table through the cache
// from read, with changed standing for the kernel's change mark, for tests in
// other packages. It returns the restore function.
func OverrideMountTableSourceForTest(read func() ([]byte, error), changed func() bool) func() {
	r1 := readMountInfo.set(nil)
	r2 := procMountInfo.set(read)
	r3 := mountTableChanged.set(changed)
	resetMountCache()
	return func() {
		r3()
		r2()
		r1()
		resetMountCache()
	}
}
