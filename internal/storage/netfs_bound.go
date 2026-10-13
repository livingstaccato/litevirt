package storage

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
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
//   - an identical call (the same op on the same path, with the same result
//     type) still running is joined, not started again, so each path has at
//     most one stuck goroutine per op;
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
	fsCalls sync.Map // op, result type and path -> *fsCall
	fsMu    sync.Mutex
	// fsStuck counts, per network mount, its unanswered calls still running.
	// It is keyed by the mount itself (its mount ID), not its directory: a
	// call stuck on a mount that was lazily unmounted stays in the kernel on
	// that detached mount, and must not fail calls on a new mount made at the
	// same directory. A daemon restart clears it.
	fsStuck = map[string]int{}
)

// Bounded runs fn, an operation op on path, and returns what it returns, or
// an *FSNoAnswerError when it has not returned within the bound (see above).
// Only a call of the same op, on the same path, with the same result type T
// is joined: a joined call returns exactly what that call returns.
func Bounded[T any](op, path string, fn func() (T, error)) (T, error) {
	return boundedFor(fsCallBound, op, path, fn)
}

// BoundedOuter is Bounded for a call that itself makes bounded calls (a VM
// start's chain check resolves every pool directory of the host): it waits
// four bounds, so the calls inside it give up, and it goes on past them,
// before it does.
func BoundedOuter[T any](op, path string, fn func() (T, error)) (T, error) {
	return boundedFor(4*fsCallBound, op, path, fn)
}

func boundedFor[T any](bound time.Duration, op, path string, fn func() (T, error)) (T, error) {
	typ := reflect.TypeFor[T]().String()
	v, err := boundedCall(bound, op, typ, path, func() (any, error) { return fn() })
	if err != nil {
		var zero T
		if t, ok := v.(T); ok {
			return t, err
		}
		return zero, err
	}
	t, ok := v.(T)
	if !ok && v != nil {
		return t, fmt.Errorf("%s %s: a call returned %T, not %s", op, path, v, typ)
	}
	return t, nil
}

func boundedCall(bound time.Duration, op, typ, path string, fn func() (any, error)) (any, error) {
	path = filepath.Clean(path)
	mount := networkMountOf(path)
	if mount.key != "" && mountUnanswered(mount.key) {
		return nil, &FSNoAnswerError{Op: op, Path: path, Mount: mount.dir, Earlier: true}
	}
	// The mount is in the key too: a call stuck on a lazily unmounted dead
	// mount must not be joined by a call on a new mount at the same path.
	key := op + "\x00" + typ + "\x00" + mount.key + "\x00" + path
	c := &fsCall{done: make(chan struct{})}
	if v, running := fsCalls.LoadOrStore(key, c); running {
		c = v.(*fsCall)
		fsMu.Lock()
		gaveUp := c.timedOut
		fsMu.Unlock()
		if gaveUp {
			return nil, &FSNoAnswerError{Op: op, Path: path, Mount: mount.dir, Earlier: true}
		}
	} else {
		go func() {
			val, err := fn()
			fsMu.Lock()
			c.val, c.err, c.finished = val, err, true
			if c.timedOut && mount.key != "" {
				if fsStuck[mount.key]--; fsStuck[mount.key] <= 0 {
					delete(fsStuck, mount.key)
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
		if mount.key != "" {
			fsStuck[mount.key]++
		}
	}
	fsMu.Unlock()
	return nil, &FSNoAnswerError{Op: op, Path: path, Mount: mount.dir, Bound: bound}
}

func mountUnanswered(mount string) bool {
	fsMu.Lock()
	defer fsMu.Unlock()
	return fsStuck[mount] > 0
}

// networkMountOf is the mount point of the network filesystem path lies on
// (the deepest mount containing it, as written), or "" when it lies on none
// or the mount table cannot be read. No system call touches path.
func networkMountOf(path string) netMount {
	t, err := ReadMountTable()
	if err != nil {
		return netMount{}
	}
	return t.networkMountOf(path)
}

// netMount is a network mount a path lies on: its directory (for messages)
// and its key, the mount ID plus the directory (for the latch).
type netMount struct{ dir, key string }

func (t MountTable) networkMountOf(path string) netMount {
	var under mountEntry
	for _, e := range t.all {
		if within(e.dir, path) && len(e.dir) >= len(under.dir) {
			under = e
		}
	}
	if under.dir != "" && isNetworkFstype(under.fstype) {
		return netMount{dir: under.dir, key: under.id + "@" + under.dir}
	}
	return netMount{}
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

// evalSymlinksFn is filepath.EvalSymlinks; tests replace it.
var evalSymlinksFn = filepath.EvalSymlinks

// EvalSymlinksBounded is filepath.EvalSymlinks without letting a network
// filesystem that does not answer hold the caller (lab 2 N-1: every VM start
// resolved every pool directory of the host, the nfs pool's mount point
// included, and hung while its server did not answer). A path the mount
// table has as a mount point is its own resolution, with no system call; any
// other is evaluated under Bounded, and an *FSNoAnswerError when it does not
// finish in time.
func EvalSymlinksBounded(p string) (string, error) {
	clean := filepath.Clean(p)
	if t, err := ReadMountTable(); err == nil && t.isMountPoint(clean) {
		return clean, nil
	}
	eval := evalSymlinksFn
	return Bounded("evaluate the symlinks of", clean, func() (string, error) { return eval(clean) })
}

// PrimeBounded resolves every path at once — as EvalSymlinksBounded does and
// as the bounded checks (DirsOverlap, CheckWriteRoot, NFSBackingOf,
// SharedStoreOf, IsDataDirDisks) do — each under its own bound, and returns
// when all have answered or been given up on. A caller about to make those
// calls one path after another primes the paths first: a path that does not
// answer is then already given up on (its mount latched, or its call joined
// as unanswered), and the calls that follow fail on it at once, so several
// dead mounts cost one bound in all, not one bound each.
func PrimeBounded(paths ...string) {
	var t *MountTable
	if mt, err := ReadMountTable(); err == nil {
		t = &mt
	}
	var wg sync.WaitGroup
	seen := map[string]bool{}
	for _, p := range paths {
		if p == "" || !filepath.IsAbs(p) || seen[filepath.Clean(p)] {
			continue
		}
		seen[filepath.Clean(p)] = true
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = EvalSymlinksBounded(p) }()
		go func() { defer wg.Done(); _, _ = resolveBounded(t, p) }()
	}
	wg.Wait()
}

// OverrideEvalSymlinksForTest replaces how EvalSymlinksBounded evaluates a
// path, for tests in other packages. It returns the restore function.
func OverrideEvalSymlinksForTest(eval func(string) (string, error)) func() {
	prev := evalSymlinksFn
	evalSymlinksFn = eval
	return func() { evalSymlinksFn = prev }
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
