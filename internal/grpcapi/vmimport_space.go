package grpcapi

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Imports on one host run side by side, and each writes into filesystems the
// others write into too: the import directory (usually the one state.db is
// on) and the target pool. A free-space glance alone would let two imports
// that glanced together each claim the same bytes, so each import reserves
// what a write phase will need before it writes, and every check counts the
// other imports' reservations less what they have already written — written
// bytes are already gone from the filesystem's free space, so counting them
// again would refuse imports that fit.

// importSpaceRefreshEvery is how often an import re-measures the files it
// writes, so the part of its reservation already written stops counting
// against other imports.
const importSpaceRefreshEvery = time.Second

// importStatfsTimeout bounds the free-space glance a reservation takes under
// the ledger's lock: a pool on a hung mount refuses its own import rather
// than holding every other import's reservation on the host.
const importStatfsTimeout = 10 * time.Second

// importSpaceLedger holds this host's running imports' reservations. Zero
// value ready.
type importSpaceLedger struct {
	mu   sync.Mutex
	held map[*importReservation]struct{}
}

// importReservation is one import's claim on disk space for its current write
// phase: an extraction, or one disk's private copy and conversion. What is
// outstanding is what it reserved less what the files it writes have
// allocated since the phase began, so the claim shrinks as it is used.
type importReservation struct {
	s   *Server
	dir string // the import directory, walked

	filesMu sync.Mutex
	files   []string // files it writes outside dir, each stat'd

	// need and base are guarded by the ledger's mu.
	need uint64 // bytes reserved for the current phase
	base uint64 // its files' allocation when the phase began

	alloc   atomic.Uint64 // its files' allocation, last measured
	stop    chan struct{}
	release func()
}

// reserveImportSpace starts an empty reservation for an import writing into
// importDir. What importDir already holds (the staged source) is the base the
// first phase is measured from. The caller releases it when it stops writing,
// whether it succeeded or not; releasing it twice is safe.
func (s *Server) reserveImportSpace(importDir string) *importReservation {
	r := &importReservation{s: s, dir: importDir, stop: make(chan struct{})}
	r.refresh()
	l := &s.importSpace
	l.mu.Lock()
	if l.held == nil {
		l.held = map[*importReservation]struct{}{}
	}
	r.base = r.alloc.Load()
	l.held[r] = struct{}{}
	l.mu.Unlock()
	r.release = sync.OnceFunc(func() {
		l.mu.Lock()
		delete(l.held, r)
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
// directory — a conversion's output in the pool — to what is measured.
func (r *importReservation) track(path string) {
	r.filesMu.Lock()
	r.files = append(r.files, path)
	r.filesMu.Unlock()
}

// refresh measures the blocks the import's files occupy. Only the import's
// own goroutines measure its files: a stat that hangs on a dead mount stalls
// the import that writes there, never another import's check.
func (r *importReservation) refresh() {
	var sum uint64
	_ = filepath.WalkDir(r.dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if n, e := fileAllocated(p); e == nil {
				sum += n
			}
		}
		return nil
	})
	r.filesMu.Lock()
	files := append([]string(nil), r.files...)
	r.filesMu.Unlock()
	for _, p := range files {
		if n, e := fileAllocated(p); e == nil {
			sum += n
		}
	}
	r.alloc.Store(sum)
}

// outstandingLocked is what the current phase reserved and has not written.
// The ledger's mu is held.
func (r *importReservation) outstandingLocked() uint64 {
	return r.need - min(r.need, r.writtenLocked())
}

// writtenLocked is what the import's files have grown by since the phase
// began. The ledger's mu is held.
func (r *importReservation) writtenLocked() uint64 {
	a := r.alloc.Load()
	return a - min(a, r.base)
}

// begin starts a new write phase: what earlier phases reserved and did not
// write, they never will, so it no longer counts against anyone.
func (r *importReservation) begin() {
	r.refresh()
	l := &r.s.importSpace
	l.mu.Lock()
	r.base, r.need = r.alloc.Load(), 0
	l.mu.Unlock()
}

// reserve claims room for the current phase to have written total bytes into
// dir. It refuses when dir's filesystem, less the headroom a cold migration
// also keeps, cannot hold what the other imports on this host have reserved
// and not yet written plus what this phase has still to write. The other
// imports' outstanding bytes are read before the glance, so a write they make
// meanwhile is counted in both and never in neither.
func (r *importReservation) reserve(dir string, total uint64, what string) error {
	r.refresh()
	l := &r.s.importSpace
	l.mu.Lock()
	defer l.mu.Unlock()
	var others uint64
	for o := range l.held {
		if o != r {
			others = satAdd(others, o.outstandingLocked())
		}
	}
	avail, fsTotal, err := r.s.diskSpaceWithin(dir, importStatfsTimeout)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "%s: cannot read the free space on %s: %v", what, r.s.hostName, err)
	}
	left := total - min(total, r.writtenLocked())
	headroom := coldDiskHeadroom(fsTotal)
	if avail < satAdd(satAdd(headroom, others), left) {
		return status.Errorf(codes.FailedPrecondition,
			"%s needs %d MiB on %s, which has %d MiB free, of which other imports there have reserved %d MiB; "+
				"an import leaves at least %d MiB free there",
			what, left>>20, r.s.hostName, avail>>20, others>>20, headroom>>20)
	}
	r.need = max(r.need, total)
	return nil
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
