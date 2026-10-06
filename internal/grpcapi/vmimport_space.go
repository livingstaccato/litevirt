package grpcapi

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Imports on one host run side by side, and each writes into filesystems
// others may write into too: the import directory (usually the one state.db
// is on) and the target pool. A free-space glance alone would let two imports
// that glanced together each claim the same bytes, so each import reserves
// what it is about to write before writing it, and every check counts the
// other imports' reservations on the same filesystem less what they have
// already written — written bytes are already gone from the free space, so
// counting them again would refuse imports that fit.
//
// "Already written" is credited conservatively. A file's allocated blocks are
// measured, the file is then flushed, and only then is the free space read:
// a filesystem may count dirty data in a file's blocks before it takes it
// from its free space (btrfs does), and a byte counted in neither place would
// be admitted twice. The credit is also never more than the free space has
// fallen since the phase began.

// importSpaceRefreshEvery is how often an import re-measures the files it
// writes, so the part of its reservation already written stops counting
// against other imports.
const importSpaceRefreshEvery = time.Second

// importStatfsTimeout bounds the free-space glance a reservation takes under
// the ledger's lock: a pool on a hung mount refuses its own import rather
// than holding every other import's reservation on the host.
const importStatfsTimeout = 10 * time.Second

// importSpaceLedger holds this host's running imports' reservations, and the
// names of the VMs being imported. Zero value ready.
type importSpaceLedger struct {
	mu    sync.Mutex
	held  map[*importReservation]struct{}
	names map[string]struct{}
}

// claimImportName refuses a second import of a VM name already being imported
// on this host: both would write the same files into the pool. The release is
// safe to call more than once.
func (s *Server) claimImportName(name string) (func(), error) {
	l := &s.importSpace
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, busy := l.names[name]; busy {
		return nil, status.Errorf(codes.AlreadyExists,
			"VM %q is already being imported on %s; wait for that import to finish, or choose a different --name", name, s.hostName)
	}
	if l.names == nil {
		l.names = map[string]struct{}{}
	}
	l.names[name] = struct{}{}
	return sync.OnceFunc(func() {
		l.mu.Lock()
		delete(l.names, name)
		l.mu.Unlock()
	}), nil
}

// spaceShare is one import's claim on one filesystem in its current phase.
type spaceShare struct {
	need      uint64 // bytes reserved this phase
	baseAlloc uint64 // its files' blocks there when the phase began
	baseAvail uint64 // the filesystem's free space when the phase began
	alloc     uint64 // its files' blocks there, last measured and flushed
	avail     uint64 // the free space read after that flush
}

func sub0(a, b uint64) uint64 { return a - min(a, b) }

// written is what the phase has written there and the free space shows gone.
func (sh *spaceShare) written() uint64 {
	return min(sub0(sh.alloc, sh.baseAlloc), sub0(sh.baseAvail, sh.avail))
}

func (sh *spaceShare) outstanding() uint64 { return sub0(sh.need, sh.written()) }

// importReservation is one import's claim on disk space for its current write
// phase: the upload, an extraction, or one disk's private copy and
// conversion. It is kept per filesystem.
type importReservation struct {
	s   *Server
	dir string // the import directory, walked

	// refreshMu makes measurements one at a time, so an older one is never
	// stored over a newer one. It guards files and dirKeys too.
	refreshMu sync.Mutex
	files     []string // files it writes outside dir, each stat'd
	dirKeys   map[string]fsKey

	// Guarded by the ledger's mu.
	shares   map[fsKey]*spaceShare
	released bool

	stop    chan struct{}
	release func()
}

// reserveImportSpace starts an empty reservation for an import writing into
// importDir. The caller releases it when it stops writing, whether it
// succeeded or not; releasing it twice is safe.
func (s *Server) reserveImportSpace(importDir string) *importReservation {
	r := &importReservation{s: s, dir: importDir, stop: make(chan struct{}), dirKeys: map[string]fsKey{}}
	l := &s.importSpace
	l.mu.Lock()
	if l.held == nil {
		l.held = map[*importReservation]struct{}{}
	}
	r.shares = map[fsKey]*spaceShare{}
	l.held[r] = struct{}{}
	l.mu.Unlock()
	r.begin()
	r.release = sync.OnceFunc(func() {
		l.mu.Lock()
		delete(l.held, r)
		r.released = true
		l.mu.Unlock()
		close(r.stop)
	})
	go func() {
		t := time.NewTicker(importSpaceRefreshEvery)
		defer t.Stop()
		for {
			select {
			case <-r.stop:
				return
			case <-t.C:
				r.refresh()
			}
		}
	}()
	return r
}

// track adds a file the import is about to write outside its import
// directory — a conversion's scratch file in the pool — to what is measured.
// Only a file the import itself created is tracked: another file's blocks
// would be credited as this import's writing.
func (r *importReservation) track(path string) {
	r.refreshMu.Lock()
	r.files = append(r.files, path)
	r.refreshMu.Unlock()
}

// keyLocked is dir's filesystem, looked up once. refreshMu is held.
func (r *importReservation) keyLocked(dir string) fsKey {
	if k, ok := r.dirKeys[dir]; ok {
		return k
	}
	k := r.s.importFSKey(dir)
	r.dirKeys[dir] = k
	return k
}

type spaceMeasure struct{ alloc, avail uint64 }

// measureLocked reads the blocks the import's files occupy, per filesystem,
// flushing each file after reading it, and then each filesystem's free space.
// Only the import's own goroutines measure its files: a stat that hangs on a
// dead mount stalls the import that writes there, never another import's
// check. refreshMu is held.
func (r *importReservation) measureLocked() map[fsKey]spaceMeasure {
	type acc struct {
		dir   string
		alloc uint64
	}
	byKey := map[fsKey]*acc{}
	add := func(dir string, n uint64) {
		k := r.keyLocked(dir)
		a := byKey[k]
		if a == nil {
			a = &acc{dir: dir}
			byKey[k] = a
		}
		a.alloc += n
	}
	add(r.dir, 0)
	_ = filepath.WalkDir(r.dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			add(r.dir, flushedAllocated(p))
		}
		return nil
	})
	for _, p := range r.files {
		add(filepath.Dir(p), flushedAllocated(p))
	}
	out := map[fsKey]spaceMeasure{}
	for k, a := range byKey {
		avail, _, err := r.s.diskSpace(a.dir)
		if err != nil {
			// Unreadable: credit nothing new on it.
			continue
		}
		out[k] = spaceMeasure{alloc: a.alloc, avail: avail}
	}
	return out
}

// flushedAllocated is the blocks p occupies, read before p is flushed: once
// the flush returns, every byte counted has been taken from the free space.
// A file that cannot be opened or flushed counts as nothing written.
func flushedAllocated(p string) uint64 {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return 0
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	n := uint64(st.Blocks) * 512
	if f.Sync() != nil {
		return 0
	}
	return n
}

// refresh credits what the import's files have written since the phase
// began.
func (r *importReservation) refresh() {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	m := r.measureLocked()
	l := &r.s.importSpace
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, v := range m {
		if sh := r.shares[k]; sh != nil {
			sh.alloc, sh.avail = v.alloc, v.avail
		}
	}
}

// begin starts a new write phase: what earlier phases reserved and did not
// write, they never will, so it stops counting against anyone at once —
// before the measurement that sets the new phase's base, which may be slow.
func (r *importReservation) begin() {
	l := &r.s.importSpace
	l.mu.Lock()
	for _, sh := range r.shares {
		sh.need = 0
	}
	l.mu.Unlock()
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	m := r.measureLocked()
	l.mu.Lock()
	defer l.mu.Unlock()
	r.shares = map[fsKey]*spaceShare{}
	for k, v := range m {
		r.shares[k] = &spaceShare{baseAlloc: v.alloc, baseAvail: v.avail, alloc: v.alloc, avail: v.avail}
	}
}

// fsKey names a filesystem's free space; "" is a filesystem that could not be
// identified, which is counted as the same as every other.
type fsKey string

func sameSpace(a, b fsKey) bool { return a == "" || b == "" || a == b }

// reserve claims n more bytes for the current phase to write into dir. It
// refuses when dir's filesystem, less the headroom a cold migration also
// keeps, cannot hold what the imports on this host have reserved there and
// not yet written, this one included, plus n. The other imports' outstanding
// bytes are read before the glance, so a write they make meanwhile is counted
// in both and never in neither.
func (r *importReservation) reserve(dir string, n uint64, what string) error {
	r.refreshMu.Lock()
	key := r.keyLocked(dir)
	r.refreshMu.Unlock()
	l := &r.s.importSpace
	l.mu.Lock()
	defer l.mu.Unlock()
	if r.released {
		return status.Errorf(codes.Internal, "%s: the import's space reservation was already released", what)
	}
	var others, mine uint64
	for o := range l.held {
		for k, sh := range o.shares {
			if !sameSpace(k, key) {
				continue
			}
			if o == r {
				mine = satAdd(mine, sh.outstanding())
			} else {
				others = satAdd(others, sh.outstanding())
			}
		}
	}
	avail, fsTotal, err := r.s.diskSpaceWithin(dir, importStatfsTimeout)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "%s: cannot read the free space on %s: %v", what, r.s.hostName, err)
	}
	headroom := coldDiskHeadroom(fsTotal)
	if avail < satAdd(satAdd(headroom, others), satAdd(mine, n)) {
		return status.Errorf(codes.FailedPrecondition,
			"%s needs %d MiB more on %s, which has %d MiB free there, of which imports writing to the same filesystem have reserved %d MiB (%d MiB of them by other imports); "+
				"an import leaves at least %d MiB free there",
			what, n>>20, r.s.hostName, avail>>20, satAdd(others, mine)>>20, others>>20, headroom>>20)
	}
	sh := r.shares[key]
	if sh == nil {
		sh = &spaceShare{baseAvail: avail, avail: avail}
		r.shares[key] = sh
	}
	sh.need = satAdd(sh.need, n)
	return nil
}

// totals adapts reserve to an extraction that names its running total.
func (r *importReservation) totals(dir, what string) func(total uint64) error {
	var reserved uint64
	return func(total uint64) error {
		if total <= reserved {
			return nil
		}
		if err := r.reserve(dir, total-reserved, what); err != nil {
			return err
		}
		reserved = total
		return nil
	}
}

// syncFile flushes p's data to its filesystem.
func syncFile(p string) error {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func satAdd(a, b uint64) uint64 {
	if a+b < a {
		return ^uint64(0)
	}
	return a + b
}

// diskSpaceWithin is diskSpace that gives up after d. A statfs on a hung mount
// does not return, and is left to finish on its own.
func (s *Server) diskSpaceWithin(dir string, d time.Duration) (avail, total uint64, err error) {
	type answer struct {
		avail, total uint64
		err          error
	}
	ch := make(chan answer, 1)
	go func() {
		a, t, e := s.diskSpace(dir)
		ch <- answer{a, t, e}
	}()
	select {
	case a := <-ch:
		return a.avail, a.total, a.err
	case <-time.After(d):
		return 0, 0, fmt.Errorf("its filesystem did not answer within %s", d)
	}
}
