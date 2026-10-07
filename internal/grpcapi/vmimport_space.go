package grpcapi

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/randid"
)

// Imports on one host run side by side, and each writes into filesystems
// others may write into too: the import directory (usually the one state.db
// is on) and the target pool. A free-space glance alone would let two imports
// that glanced together each claim the same bytes, so each import reserves
// what it is about to write before writing it, and every check counts what
// the imports writing to the same filesystem have reserved and not yet
// written.
//
// "Already written" is credited per filesystem, for all of its imports
// together: never more than the free space has fallen since the first of
// them began, and never more than their files have grown. A filesystem may
// count a file's blocks before it takes them from its free space (btrfs does,
// until its transaction commits, flush or not), so one import's growth is not
// proof that its bytes are gone from the free space; the fall in free space
// is, and one fall is credited once however many imports grew. Space another
// writer frees does not take a credit back, or grow it.

// importSpaceRefreshEvery is how often an import re-measures the files it
// writes, so the part of its reservation already written stops counting
// against other imports.
const importSpaceRefreshEvery = time.Second

// importStatfsTimeout bounds the free-space glance a reservation takes under
// the ledger's lock: a pool on a hung mount refuses its own import rather
// than holding every other import's reservation on the host.
const importStatfsTimeout = 10 * time.Second

// importUploadStep is how much of an upload is reserved at a time: at most
// this much is held, unwritten, while the import waits for the client's next
// chunk.
const importUploadStep = 64 << 20

// importSpaceLedger holds this host's running imports' reservations, what
// each filesystem has been credited, and the names of the VMs being imported.
// Zero value ready.
type importSpaceLedger struct {
	mu   sync.Mutex
	held map[*importReservation]struct{}
	keys map[fsKey]*keySpace

	// namesMu guards names on its own: judging whether a file is a running
	// import's never waits on mu, which a reservation holds across a
	// free-space read of a pool that may be slow to answer.
	namesMu sync.Mutex
	names   map[string]string // name → import id
}

// keySpace is one filesystem's credit: what the free space shows its running
// imports have written.
type keySpace struct {
	// baseAvail is the free space when the first running import began on it,
	// less what imports that have since finished wrote there. It can go
	// below the free space (a finished import's bytes not yet shown), which
	// holds the credit back until they show.
	baseAvail int64
	avail     uint64 // the free space last read
	credit    uint64 // bytes credited as written, all imports together
}

// claimImportName refuses a second import of a VM name already being imported
// on this host: both would write the same files into the pool. importID names
// the import in the origin of the files it writes. The release is safe to
// call more than once.
func (s *Server) claimImportNameAs(name, importID string) (func(), error) {
	l := &s.importSpace
	l.namesMu.Lock()
	defer l.namesMu.Unlock()
	if _, busy := l.names[name]; busy {
		return nil, status.Errorf(codes.AlreadyExists,
			"VM %q is already being imported on %s; wait for that import to finish, or choose a different --name", name, s.hostName)
	}
	if l.names == nil {
		l.names = map[string]string{}
	}
	l.names[name] = importID
	return sync.OnceFunc(func() {
		l.namesMu.Lock()
		delete(l.names, name)
		l.namesMu.Unlock()
	}), nil
}

// claimImportName is claimImportNameAs under a fresh import id.
func (s *Server) claimImportName(name string) (func(), error) {
	return s.claimImportNameAs(name, randid.New())
}

// importNamesInFlight is the names this host is importing now.
func (s *Server) importNamesInFlight() []string {
	l := &s.importSpace
	l.namesMu.Lock()
	defer l.namesMu.Unlock()
	out := make([]string, 0, len(l.names))
	for n := range l.names {
		out = append(out, n)
	}
	return out
}

// importRunning reports whether this process is running the import importID.
func (s *Server) importRunning(importID string) bool {
	_, ok := s.importNameRunning(importID)
	return ok
}

// importNameRunning is the VM name the running import importID imports.
func (s *Server) importNameRunning(importID string) (string, bool) {
	l := &s.importSpace
	l.namesMu.Lock()
	defer l.namesMu.Unlock()
	for n, id := range l.names {
		if id == importID {
			return n, true
		}
	}
	return "", false
}

// spaceShare is one import's claim on one filesystem.
type spaceShare struct {
	dir       string // a directory on it, for a flush
	need      uint64 // bytes reserved
	baseAlloc uint64 // its files' blocks there when the share began
	alloc     uint64 // its files' blocks there, last measured
}

func sub0(a, b uint64) uint64 { return a - min(a, b) }

// grown is what the share's files have grown by.
func (sh *spaceShare) grown() uint64 { return sub0(sh.alloc, sh.baseAlloc) }

// importReservation is one import's claim on disk space, kept per filesystem.
type importReservation struct {
	s   *Server
	dir string // the import directory, walked

	// refreshMu makes measurements one at a time, so an older one is never
	// stored over a newer one. It guards files and dirKeys too.
	refreshMu sync.Mutex
	files     []string // files it writes outside dir, each stat'd
	dirKeys   map[string]fsKey
	// flushed is, on btrfs, each file's blocks when it was last flushed: a
	// file is flushed again only once it has grown.
	flushed map[string]uint64
	// flushFailed is whether the last measurement failed to flush a file.
	flushFailed bool

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
	r.refreshMu.Lock()
	m := r.measureLocked()
	l.mu.Lock()
	if l.held == nil {
		l.held = map[*importReservation]struct{}{}
	}
	r.shares = map[fsKey]*spaceShare{}
	for k, v := range m {
		l.ensureKeyLocked(k, v.avail)
		r.shares[k] = &spaceShare{dir: v.dir, baseAlloc: v.alloc, alloc: v.alloc}
	}
	l.held[r] = struct{}{}
	l.mu.Unlock()
	r.refreshMu.Unlock()
	r.release = sync.OnceFunc(func() { r.finish() })
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

// finish releases the reservation. What it wrote becomes ordinary used space:
// its filesystems' baselines drop by it, so its bytes, shown in the free space
// or not yet, are never credited to another import. On btrfs the transaction
// is committed first, so the bytes show before nothing counts them.
func (r *importReservation) finish() {
	l := &r.s.importSpace
	l.mu.Lock()
	var btrfs []string
	for k, sh := range r.shares {
		if strings.HasPrefix(string(k), "btrfs:") && sh.grown() > 0 {
			btrfs = append(btrfs, sh.dir)
		}
	}
	l.mu.Unlock()
	for _, d := range btrfs {
		_ = syncFilesystem(d)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.held, r)
	r.released = true
	for k, sh := range r.shares {
		ks := l.keys[k]
		if ks == nil {
			continue
		}
		ks.baseAvail -= int64(sh.grown())
		l.recreditLocked(k)
	}
	l.dropIdleKeysLocked()
	close(r.stop)
}

// ensureKeyLocked starts a filesystem's credit at the free space now, when no
// running import is on it yet.
func (l *importSpaceLedger) ensureKeyLocked(k fsKey, avail uint64) {
	if l.keys == nil {
		l.keys = map[fsKey]*keySpace{}
	}
	if l.keys[k] == nil {
		l.keys[k] = &keySpace{baseAvail: int64(avail), avail: avail}
	}
}

// grownLocked is what the running imports' files on k have grown by, each
// counted no further than it reserved.
func (l *importSpaceLedger) grownLocked(k fsKey) (grown, need uint64) {
	for o := range l.held {
		if sh := o.shares[k]; sh != nil {
			grown = satAdd(grown, min(sh.grown(), sh.need))
			need = satAdd(need, sh.need)
		}
	}
	return grown, need
}

// observeLocked takes a fresh reading of k's free space. The credit follows
// the fall since the baseline, up to what the imports grew; a rise (space
// freed by something else) leaves the credit where it was, moving the
// baseline instead.
func (l *importSpaceLedger) observeLocked(k fsKey, avail uint64) {
	ks := l.keys[k]
	if ks == nil {
		return
	}
	ks.avail = avail
	grown, _ := l.grownLocked(k)
	drop := ks.baseAvail - int64(avail)
	if drop < int64(ks.credit) {
		keep := min(ks.credit, grown)
		ks.baseAvail = int64(avail) + int64(keep)
		ks.credit = keep
		return
	}
	ks.credit = uint64(max(0, min(int64(grown), drop)))
}

// recreditLocked re-derives k's credit from its baseline and last reading,
// after a baseline moved down or an import left.
func (l *importSpaceLedger) recreditLocked(k fsKey) {
	ks := l.keys[k]
	grown, _ := l.grownLocked(k)
	drop := ks.baseAvail - int64(ks.avail)
	ks.credit = uint64(max(0, min(int64(grown), drop)))
}

// dropIdleKeysLocked forgets a filesystem no running import is on.
func (l *importSpaceLedger) dropIdleKeysLocked() {
	for k := range l.keys {
		used := false
		for o := range l.held {
			if o.shares[k] != nil {
				used = true
				break
			}
		}
		if !used {
			delete(l.keys, k)
		}
	}
}

// outstandingLocked is what the running imports on k have reserved and the
// free space does not yet show written.
func (l *importSpaceLedger) outstandingLocked(k fsKey) uint64 {
	_, need := l.grownLocked(k)
	credit := uint64(0)
	if ks := l.keys[k]; ks != nil {
		credit = ks.credit
	}
	return sub0(need, credit)
}

// track adds a file the import is about to write outside its import
// directory — a conversion's scratch file in the pool — to what is measured.
// Only a file the import itself created is tracked: another file's blocks
// would be counted as this import's writing.
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

type spaceMeasure struct {
	dir          string
	alloc, avail uint64
}

// measureLocked reads the blocks the import's files occupy and the free
// space, per filesystem. Only the import's own goroutines measure its files:
// a stat that hangs on a dead mount stalls the import that writes there, never
// another import's check. refreshMu is held.
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
	// On btrfs a file's blocks count before its free space falls, so only
	// bytes flushed there are counted as written. A file is flushed once per
	// growth, not on every measurement; one that cannot be flushed counts
	// what it held when it last was.
	r.flushFailed = false
	alloc := func(dir, p string) uint64 {
		n := lstatAllocated(p)
		if n == 0 || !strings.HasPrefix(string(r.keyLocked(dir)), "btrfs:") {
			return n
		}
		if f, ok := r.flushed[p]; ok && f == n {
			return n
		}
		if flushForCredit(p) != nil {
			r.flushFailed = true
			return min(r.flushed[p], n)
		}
		if r.flushed == nil {
			r.flushed = map[string]uint64{}
		}
		r.flushed[p] = n
		return n
	}
	add(r.dir, 0)
	_ = filepath.WalkDir(r.dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			add(r.dir, alloc(r.dir, p))
		}
		return nil
	})
	for _, p := range r.files {
		add(filepath.Dir(p), alloc(filepath.Dir(p), p))
	}
	out := map[fsKey]spaceMeasure{}
	for k, a := range byKey {
		avail, _, err := r.s.diskSpace(a.dir)
		if err != nil {
			continue // unreadable: nothing new is credited on it
		}
		out[k] = spaceMeasure{dir: a.dir, alloc: a.alloc, avail: avail}
	}
	return out
}

// lstatAllocated is the blocks the file at p occupies; a file that is gone
// occupies none.
func lstatAllocated(p string) uint64 {
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return 0
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Blocks) * 512
	}
	return 0
}

// refresh records what the import's files have grown by, and what the free
// space shows.
func (r *importReservation) refresh() {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	r.refreshLocked(false)
}

// refreshLocked is refresh with refreshMu held; with endPhase it also drops
// what the phase reserved and did not write (see begin).
func (r *importReservation) refreshLocked(endPhase bool) {
	m := r.measureLocked()
	l := &r.s.importSpace
	l.mu.Lock()
	defer l.mu.Unlock()
	if r.released {
		return
	}
	for k, v := range m {
		if sh := r.shares[k]; sh != nil {
			sh.alloc = v.alloc
			l.observeLocked(k, v.avail)
		}
	}
	// A file that could not be flushed may hold more than it counts; what
	// the phase reserved stays reserved until a measurement sees it all.
	if !endPhase || r.flushFailed {
		return
	}
	for _, sh := range r.shares {
		sh.need = min(sh.need, sh.grown())
	}
}

// begin ends a write phase: what it reserved and did not write (a sparse
// disk, the rest of an upload step) it never will, so it stops counting.
// What it wrote stays counted until the free space shows it.
func (r *importReservation) begin() {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	r.refreshLocked(true)
}

// fsKey names a filesystem's free space; "" is a filesystem that could not be
// identified, which is counted as the same as every other.
type fsKey string

func sameSpace(a, b fsKey) bool { return a == "" || b == "" || a == b }

// reserve claims n more bytes for the import to write into dir. It refuses
// when dir's filesystem cannot hold what the imports on this host have
// reserved there and the free space does not yet show written, this one
// included, plus n. It keeps no margin beyond that: main (3e4ba50b) checked
// no free space for an import at all (vmimport.go:201-240 reserved project
// quota and host cpu/mem only), so an import that fits — however full the
// filesystem is otherwise — was imported, and is admitted here.
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
	avail, _, err := r.s.diskSpaceWithin(dir, importStatfsTimeout)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "%s: cannot read the free space on %s: %v", what, r.s.hostName, err)
	}
	l.ensureKeyLocked(key, avail)
	l.observeLocked(key, avail)
	var outstanding uint64
	for k := range l.keys {
		if sameSpace(k, key) {
			outstanding = satAdd(outstanding, l.outstandingLocked(k))
		}
	}
	if avail < satAdd(outstanding, n) {
		return status.Errorf(codes.FailedPrecondition,
			"%s needs %d MiB more on %s, which has %d MiB free there, of which running imports writing to the same filesystem have reserved %d MiB not yet written",
			what, n>>20, r.s.hostName, avail>>20, outstanding>>20)
	}
	sh := r.shares[key]
	if sh == nil {
		sh = &spaceShare{dir: dir}
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

// flushForCredit flushes a file before its blocks are counted as written on
// btrfs; a variable so a test can watch it.
var flushForCredit = syncFile

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
