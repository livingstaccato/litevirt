package storage

import (
	"os"
	"sync"
	"time"

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
//
// The watch's descriptor is opened outside the Go runtime's netpoller: an
// epoll instance watching mountinfo runs the kernel's mounts_poll on its
// epoll_wait, which consumes the mark before the watch polls for it. And a
// table older than mountTableMaxAge is read again whatever the mark says, so
// a mark missed for any other reason cannot leave the table stale for long.

// procMountInfo reads this host's mount table text; tests replace it.
var procMountInfo = newTestHook(func() ([]byte, error) { return os.ReadFile("/proc/self/mountinfo") })

// mountTableChanged reports whether the table may have changed since the
// last call; tests replace it.
var mountTableChanged = newTestHook(func() bool { return procWatch.changed() })

var procWatch = &procMountWatch{}

// mountTableMaxAge bounds how long a table is used without reading it again.
// It is a third of the NFS mount reconcile interval (grpcapi's
// NFSMountReconcileInterval, 30s): nfs_mount_missing is raised only when a
// pass sees the export missing and the next pass confirms it, so with a
// missed mark the confirming pass still reads a table taken after the first
// one, and a pool is never held "not mounted" by a stale table.
const mountTableMaxAge = 10 * time.Second

// mountTableNow is the clock the table's age is judged by; tests replace it.
var mountTableNow = newTestHook(time.Now)

var mountCache struct {
	mu     sync.Mutex
	all    []mountEntry
	valid  bool
	readAt time.Time // taken before the read
}

// cachedMounts is the mount table, read again when it changed or is older
// than mountTableMaxAge.
func cachedMounts() ([]mountEntry, error) {
	mountCache.mu.Lock()
	defer mountCache.mu.Unlock()
	// The mark is taken BEFORE the read: a change after it is marked again,
	// and seen by the next use. It is polled on every use, so a mark is
	// consumed even when the table is read for its age.
	now := mountTableNow.get()()
	changed := mountTableChanged.get()()
	if changed || !mountCache.valid || now.Sub(mountCache.readAt) >= mountTableMaxAge {
		data, err := procMountInfo.get()()
		if err != nil {
			mountCache.all, mountCache.valid = nil, false
			return nil, err
		}
		mountCache.all, mountCache.valid, mountCache.readAt = parseMountInfo(data), true, now
	}
	return mountCache.all, nil
}

// invalidateMountCache drops the cached table, so the next use reads it.
// litevirt calls it right after each of its own mount and umount commands:
// the check that follows one must see it whatever the kernel's mark says
// (bug B1 showed there, and a table that young is inside the age bound).
func invalidateMountCache() {
	mountCache.mu.Lock()
	mountCache.all, mountCache.valid, mountCache.readAt = nil, false, time.Time{}
	mountCache.mu.Unlock()
}

// resetMountCache drops the cached table (tests).
func resetMountCache() { invalidateMountCache() }

// procMountWatch holds /proc/self/mountinfo open for its change mark. Used
// under mountCache.mu only.
//
// The descriptor is a raw one, never an *os.File: os.Open registers a
// pollable file with the runtime's netpoller (epoll), and the netpoller's
// epoll_wait then consumes the mark (bug B1: every mount was missed on the
// lab, and an NFS pool read as not mounted for hours).
type procMountWatch struct {
	fd    int
	valid bool
}

// changed reports whether the mount table changed since the previous call:
// true on the first call, and whenever the mark cannot be read.
func (w *procMountWatch) changed() bool {
	if !w.valid {
		fd, err := unix.Open("/proc/self/mountinfo", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return true
		}
		w.fd, w.valid = fd, true
		return true
	}
	// Polling consumes the mark (the kernel records the event as seen). The
	// file always polls readable; only POLLPRI (with POLLERR) is the mark.
	fds := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLPRI}}
	n, err := unix.Poll(fds, 0)
	if err != nil {
		return true
	}
	if n > 0 && fds[0].Revents&unix.POLLNVAL != 0 {
		// The descriptor is no longer open (closed under us): forget it,
		// without closing a number that may now be someone else's, and
		// open a new one at the next use.
		w.valid = false
		return true
	}
	return n > 0 && fds[0].Revents&(unix.POLLPRI|unix.POLLERR|unix.POLLHUP) != 0
}

func (w *procMountWatch) close() {
	if w.valid {
		unix.Close(w.fd)
		w.valid = false
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
