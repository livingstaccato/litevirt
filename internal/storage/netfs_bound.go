package storage

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"
)

// System calls on a path that a network filesystem may hold (lab 2 F-1, F-2).
// On a hard NFS mount whose server does not answer, a stat, open or readdir
// under the mount blocks in the kernel until the server answers again, for
// ever if it never does, and nothing in Go can interrupt it. Bounded runs such
// a call in a goroutine and stops waiting for it after fsCallBound: the caller
// gets an *FSNoAnswerError and goes on, and the goroutine finishes, or not, on
// its own.
//
// Two things keep a server that never answers from costing more than that:
//
//   - an identical call (the same op on the same path) still running is
//     joined, not started again, so each path has at most one stuck goroutine;
//   - once a call under a network mount has gone unanswered, every later call
//     under that mount (judged from the path as written against the mount
//     table, with no system call) fails at once, until that call returns. A
//     caller is delayed once per mount, not once per path or per pass.

// fsCallBound is how long Bounded waits; tests shorten it.
var fsCallBound = 5 * time.Second

// FSNoAnswerError is a call Bounded stopped waiting for.
type FSNoAnswerError struct {
	Op   string
	Path string
	// Mount is the network filesystem's mount point the path lies on, when
	// the mount table names one.
	Mount string
	Bound time.Duration
	// Earlier: not waited for at all, because an earlier call on that path or
	// mount has gone unanswered and has not returned yet.
	Earlier bool
}

func (e *FSNoAnswerError) Error() string {
	where := ""
	if e.Mount != "" {
		where = fmt.Sprintf(" (on the network filesystem mounted at %s)", e.Mount)
	}
	if e.Earlier {
		return fmt.Sprintf("%s %s%s: not attempted, because an earlier call there has not returned (does its server answer?)", e.Op, e.Path, where)
	}
	return fmt.Sprintf("%s %s%s did not return within %v (does its server answer?)", e.Op, e.Path, where, e.Bound)
}

// IsFSNoAnswer reports whether err is, or wraps, an *FSNoAnswerError.
func IsFSNoAnswer(err error) bool {
	var e *FSNoAnswerError
	return errors.As(err, &e)
}

type fsCall struct {
	done chan struct{}
	val  any
	err  error
	// Under fsMu.
	finished bool
	timedOut bool
}

var (
	fsCalls sync.Map // op + "\x00" + path -> *fsCall
	fsMu    sync.Mutex
	fsStuck = map[string]int{} // network mount point -> its unanswered calls still running
)

// Bounded runs fn, an operation op on path, and returns what it returns, or
// an *FSNoAnswerError when it has not returned within the bound (see above).
func Bounded[T any](op, path string, fn func() (T, error)) (T, error) {
	v, err := boundedCall(op, path, func() (any, error) { return fn() })
	t, _ := v.(T)
	return t, err
}

func boundedCall(op, path string, fn func() (any, error)) (any, error) {
	bound := fsCallBound
	path = filepath.Clean(path)
	mount := networkMountOf(path)
	if mount != "" && mountUnanswered(mount) {
		return nil, &FSNoAnswerError{Op: op, Path: path, Mount: mount, Earlier: true}
	}
	key := op + "\x00" + path
	c := &fsCall{done: make(chan struct{})}
	if v, running := fsCalls.LoadOrStore(key, c); running {
		c = v.(*fsCall)
		fsMu.Lock()
		gaveUp := c.timedOut
		fsMu.Unlock()
		if gaveUp {
			return nil, &FSNoAnswerError{Op: op, Path: path, Mount: mount, Earlier: true}
		}
	} else {
		go func() {
			val, err := fn()
			fsMu.Lock()
			c.val, c.err, c.finished = val, err, true
			if c.timedOut && mount != "" {
				if fsStuck[mount]--; fsStuck[mount] <= 0 {
					delete(fsStuck, mount)
				}
			}
			fsMu.Unlock()
			fsCalls.CompareAndDelete(key, c)
			close(c.done)
		}()
	}
	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case <-c.done:
		return c.val, c.err
	case <-timer.C:
	}
	fsMu.Lock()
	if c.finished {
		fsMu.Unlock()
		<-c.done
		return c.val, c.err
	}
	if !c.timedOut {
		c.timedOut = true
		if mount != "" {
			fsStuck[mount]++
		}
	}
	fsMu.Unlock()
	return nil, &FSNoAnswerError{Op: op, Path: path, Mount: mount, Bound: bound}
}

func mountUnanswered(mount string) bool {
	fsMu.Lock()
	defer fsMu.Unlock()
	return fsStuck[mount] > 0
}

// networkMountOf is the mount point of the network filesystem path lies on
// (the deepest mount containing it, as written), or "" when it lies on none
// or the mount table cannot be read. No system call touches path.
func networkMountOf(path string) string {
	t, err := ReadMountTable()
	if err != nil {
		return ""
	}
	return t.networkMountOf(path)
}

func (t MountTable) networkMountOf(path string) string {
	var under mountEntry
	for _, e := range t.all {
		if within(e.dir, path) && len(e.dir) >= len(under.dir) {
			under = e
		}
	}
	if under.dir != "" && isNetworkFstype(under.fstype) {
		return under.dir
	}
	return ""
}

// isNetworkFstype reports a filesystem whose calls a remote server answers.
func isNetworkFstype(t string) bool {
	switch {
	case isNFSFstype(t), t == "ceph", t == "cifs", t == "smb3", t == "glusterfs", t == "fuse.glusterfs":
		return true
	}
	return networkFstype(t)
}

// IsMountPoint reports whether the mount table has dir, as written, as a
// mount point. No system call touches dir: an existing directory a mount
// table names needs no stat to be known to exist.
func IsMountPoint(dir string) bool {
	t, err := ReadMountTable()
	if err != nil {
		return false
	}
	return t.isMountPoint(filepath.Clean(dir))
}

func (t MountTable) isMountPoint(dir string) bool {
	for _, e := range t.all {
		if e.dir == dir {
			return true
		}
	}
	return false
}

// resolvePathFn is how a path's symlinks are resolved; tests replace it.
var resolvePathFn = resolveExisting

// resolveBounded is resolveExisting without letting a network filesystem
// that does not answer hold the caller. A path the mount table has as a mount
// point is its own resolution — the mount table's paths are the kernel's,
// with no symlink in them — and is answered with no system call: that is an
// NFS pool's mount point, whose stat is what blocked on lab 2. Any other path
// is resolved under Bounded.
func resolveBounded(t *MountTable, p string) (string, error) {
	clean := filepath.Clean(p)
	if t == nil || t.Empty() {
		if mt, err := ReadMountTable(); err == nil {
			t = &mt
		}
	}
	if t != nil && t.isMountPoint(clean) {
		return clean, nil
	}
	resolve := resolvePathFn
	return Bounded("resolve the symlinks of", clean, func() (string, error) { return resolve(clean), nil })
}

// pathFormsBounded is pathForms under resolveBounded: p cleaned, plus what it
// resolves to when that differs. On an error the cleaned form is still
// returned, alone.
func pathFormsBounded(t *MountTable, p string) ([]string, error) {
	clean := filepath.Clean(p)
	r, err := resolveBounded(t, clean)
	if err != nil {
		return []string{clean}, err
	}
	if r != clean {
		return []string{clean, r}, nil
	}
	return []string{clean}, nil
}

// OverrideFSCallBoundForTest sets how long Bounded waits, for tests in other
// packages. It returns the restore function.
func OverrideFSCallBoundForTest(d time.Duration) func() {
	prev := fsCallBound
	fsCallBound = d
	return func() { fsCallBound = prev }
}

// OverridePathResolverForTest replaces how a path's symlinks are resolved by
// the bounded checks (DirsOverlap, NFSBackingOf, SharedStoreOf,
// IsDataDirDisks), for tests in other packages. It returns the restore
// function.
func OverridePathResolverForTest(resolve func(string) string) func() {
	prev := resolvePathFn
	resolvePathFn = resolve
	return func() { resolvePathFn = prev }
}
