package libvirt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// The health conditions about a host's flusher: its evaluator, and the code of
// a failed vars fsync (raised by the daemon, resolvable by an admin's
// acknowledgement).
const (
	NvramFlushEvaluator  = "uefi-vars"
	CondNvramFlushFailed = "nvram_flush_failed"
)

// NvramFlushInterval is how often the daemon flushes UEFI vars files that
// changed: about the longest a guest's UEFI variable write waits in the host
// page cache before it is on disk.
const NvramFlushInterval = time.Second

// nvramMtimeTick bounds the coarseness of file timestamps (the kernel's
// coarse clock, a jiffy). A write within this of the start of a file's last
// fsync may carry the same mtime as the data that fsync flushed.
const nvramMtimeTick = 50 * time.Millisecond

// nvramBlockedAfter: a vars file that has not been openable for this long is
// reported as blocked (NvramFlusher.Blocked).
const nvramBlockedAfter = time.Minute

// nvramOpenFail is an episode of a vars file failing to open.
type nvramOpenFail struct {
	NvramFlushFailure
	since     time.Time
	escalated bool
}

// nvramStallAfter: a sweep still running after this is reported.
const nvramStallAfter = 10 * time.Second

// errNvramEntryChanged: the directory entry no longer names the regular file
// the listing saw.
var errNvramEntryChanged = errors.New("the entry is no longer the regular file listed")

// NvramFlushStateFile is where, in the daemon's data directory, a host keeps
// its failed vars files across a restart (NvramFlusher.LoadState).
const NvramFlushStateFile = "nvram-flush-failures.json"

// NvramFlushFailure is a vars file whose fsync failed. It stays failed until
// the file is removed or replaced, or an admin acknowledges that episode.
// The failure is the file's, not its name's: renamed, the file keeps it.
// After a writeback error the kernel reports it to one fsync and marks the
// lost pages clean, and qemu writes back only the sectors a later guest write
// changes, so no later fsync, after a guest write or not, puts the lost pages
// back on disk.
type NvramFlushFailure struct {
	Path  string `json:"path"`
	VM    string `json:"vm,omitempty"`
	Error string `json:"error"`
	At    string `json:"at"`
	Dev   uint64 `json:"dev"`
	Ino   uint64 `json:"ino"`
	// Mtime is the file's mtime when its fsync failed (evidence only).
	Mtime time.Time `json:"mtime"`
	// Episode names this failed fsync: each one gets a new one, and an
	// acknowledgement covers only the episode it names.
	Episode string `json:"episode,omitempty"`
}

type nvramFlushed struct {
	mtime     time.Time // the file's mtime when its last fsync started
	syncStart time.Time // when its last fsync started
	ino       uint64    // the file flushed
	size      int64     // its size then
}

// NvramFlusher fsyncs the UEFI vars (pflash) files in its directories that
// changed since it last flushed them, and a directory when its set of files
// changed.
//
// qemu writes a guest's UEFI variable store with no flush, and libvirt has no
// cache mode for <nvram> or <loader>, so without this a write waits in the
// host page cache until writeback (vm.dirty_expire_centisecs, 30 s by
// default) and a host power cut loses it.
type NvramFlusher struct {
	dirs []string
	// sync fsyncs path: the regular file want (as listed) or, with want nil,
	// a directory.
	sync      func(path string, want os.FileInfo) error
	now       func() time.Time
	entryInfo func(e os.DirEntry) (os.FileInfo, error)

	stallAfter time.Duration
	onStall    func(path string, elapsed time.Duration)
	current    atomic.Value // string: the path being fsynced

	flushed map[string]nvramFlushed
	listed  map[string]map[string]uint64 // dir → files (path → inode) it held at its last fsync
	warned  map[string]bool              // directory or odd entry already logged

	// statePath is where the failures are kept across a restart (LoadState);
	// "" keeps them in memory only. Set before Run, read-only after.
	statePath   string
	stateMu     sync.Mutex // serialises writes of the state file
	stateWarned bool       // under stateMu: a failed write was logged

	mu       sync.Mutex
	failed   map[string]NvramFlushFailure // by failKey: the file's identity
	dirty    bool                         // failed changed since the state file was last written
	missing  map[string]int               // by failKey: consecutive sweeps that found the failed file nowhere
	openFail map[string]nvramOpenFail     // episodes, by file path or dirReadKey/dirFsyncKey
	stall    *NvramFlushFailure           // the sweep stuck in an fsync, if one is
	sweepGen uint64                       // changes at each watched sweep's start and end (beginSweep, endSweep)

	done chan struct{}
}

// NewNvramFlusher flushes the vars files in dirs. A directory that does not
// exist is skipped until it does.
func NewNvramFlusher(dirs ...string) *NvramFlusher {
	f := &NvramFlusher{
		dirs:       dirs,
		sync:       fsyncListed,
		entryInfo:  os.DirEntry.Info,
		now:        time.Now,
		stallAfter: nvramStallAfter,
		flushed:    map[string]nvramFlushed{},
		listed:     map[string]map[string]uint64{},
		warned:     map[string]bool{},
		failed:     map[string]NvramFlushFailure{},
		missing:    map[string]int{},
		openFail:   map[string]nvramOpenFail{},
		done:       make(chan struct{}),
	}
	f.onStall = func(path string, elapsed time.Duration) {
		slog.Warn("UEFI vars flush is stalled; until it returns, no vars file on this host is flushed",
			"path", path, "elapsed", elapsed)
	}
	return f
}

// Run sweeps every interval until ctx ends, and once more then; Done closes
// after that last sweep.
func (f *NvramFlusher) Run(ctx context.Context, interval time.Duration) {
	defer close(f.done)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		f.watchedSweep()
		select {
		case <-ctx.Done():
			f.watchedSweep()
			return
		case <-t.C:
		}
	}
}

// watchedSweep is Sweep, reported if it takes longer than stallAfter.
func (f *NvramFlusher) watchedSweep() {
	start := time.Now()
	gen := f.beginSweep()
	timer := time.AfterFunc(f.stallAfter, func() {
		p, _ := f.current.Load().(string)
		f.markStalled(gen, p, time.Since(start))
	})
	f.Sweep()
	f.endSweep()
	if !timer.Stop() {
		slog.Info("UEFI vars flush finished after a stall", "elapsed", time.Since(start))
	}
}

// Failures lists the vars files whose fsync failed, by path.
func (f *NvramFlusher) Failures() []NvramFlushFailure {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]NvramFlushFailure, 0, len(f.failed))
	for _, v := range f.failed {
		out = append(out, v)
	}
	sortFailures(out)
	return out
}

func sortFailures(out []NvramFlushFailure) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Ino < out[j].Ino
	})
}

// settled: the file's data as of its mtime was flushed: it is the same file
// (inode) at the same size, and a write can share the mtime of the data an
// fsync flushed only if it came within a timestamp tick of that fsync's
// start; an mtime further from it either way (an older write, or a future
// mtime that any new write would replace) needs no repeat.
func (s nvramFlushed) settled(info os.FileInfo) bool {
	_, ino := fileIdentity(info)
	mt := info.ModTime()
	return s.ino == ino && s.size == info.Size() && s.mtime.Equal(mt) &&
		(mt.Before(s.syncStart.Add(-nvramMtimeTick)) || mt.After(s.syncStart.Add(nvramMtimeTick)))
}

// nvramListing is what one sweep found in its directories.
type nvramListing struct {
	// byPath is every regular file listed; nil for one that could not be
	// looked at (an lstat error other than "no such file").
	byPath  map[string]os.FileInfo
	read    map[string]bool // the directories read
	unknown bool            // some entry could not be looked at
	// raced: directories an entry left between their listing and its lstat,
	// so their listing may miss a name it moved to.
	raced map[string]bool
}

// Sweep flushes, once, every file that changed since its last flush.
func (f *NvramFlusher) Sweep() {
	l := nvramListing{byPath: map[string]os.FileInfo{}, read: map[string]bool{}, raced: map[string]bool{}}
	perDir := make([][]string, len(f.dirs))
	for i, dir := range f.dirs {
		entries, err := os.ReadDir(dir)
		switch {
		case os.IsNotExist(err):
			f.episodeRecovered(dirReadKey(dir), "UEFI vars directory is gone; it is no longer read")
			continue
		case err != nil:
			f.episodeFailed(dirReadKey(dir), dir, "UEFI vars directory could not be read", err)
			continue
		}
		f.episodeRecovered(dirReadKey(dir), "UEFI vars directory readable again")
		l.read[dir] = true
		for _, e := range entries {
			if !e.Type().IsRegular() {
				continue
			}
			p := filepath.Join(dir, e.Name())
			info, err := f.entryInfo(e) // lstat
			switch {
			case errors.Is(err, fs.ErrNotExist):
				// Removed or renamed since the listing, which may then miss
				// its new name.
				l.raced[dir] = true
				continue
			case err != nil:
				// Still there as far as anyone knows, and not flushed: a
				// failure it has stays, and it is reported if this lasts.
				l.byPath[p], l.unknown = nil, true
				f.openFailed(p, err)
			case !info.Mode().IsRegular():
				continue // replaced by something else since the listing
			default:
				l.byPath[p] = info
			}
			perDir[i] = append(perDir[i], p)
		}
	}
	f.reconcileFailures(l)
	for i, dir := range f.dirs {
		if !l.read[dir] {
			continue
		}
		present := map[string]uint64{}
		for _, p := range perDir[i] {
			info := l.byPath[p]
			if info == nil {
				present[p] = f.listed[dir][p] // not looked at: no change by itself
				continue
			}
			_, present[p] = fileIdentity(info)
			f.flushFile(p, info)
		}
		f.syncDirIfChanged(dir, present)
	}
	f.persist()
}

// flushFile fsyncs the regular file p (as listed) unless it is settled.
func (f *NvramFlusher) flushFile(p string, info os.FileInfo) {
	if last, ok := f.flushed[p]; ok && last.settled(info) {
		return
	}
	start := f.now()
	f.current.Store(p)
	err := f.sync(p, info)
	f.current.Store("")
	var syncErr *nvramSyncError
	switch {
	case err == nil:
		_, ino := fileIdentity(info)
		f.flushed[p] = nvramFlushed{mtime: info.ModTime(), syncStart: start, ino: ino, size: info.Size()}
		f.openRecovered(p)
		delete(f.warned, p)
	case errors.As(err, &syncErr):
		f.fail(p, info, err)
	case os.IsNotExist(err):
		// Gone since the listing; the next sweep sees it gone.
	case errors.Is(err, errNvramEntryChanged) || errors.Is(err, syscall.ELOOP):
		f.warnOnce(p, "UEFI vars entry changed under the flusher; skipped", err)
	default:
		// Not opened, so nothing was flushed and nothing is known lost:
		// retried on the next sweep, and reported if it lasts.
		f.openFailed(p, err)
	}
}

// syncDirIfChanged fsyncs dir when its files (by name and inode) changed
// since its last fsync.
func (f *NvramFlusher) syncDirIfChanged(dir string, present map[string]uint64) {
	prev := f.listed[dir]
	changed := len(prev) != len(present)
	for p, ino := range prev {
		cur, ok := present[p]
		if !ok {
			changed = true
			f.forget(p)
			continue
		}
		if cur != ino {
			changed = true // another file at the name
		}
	}
	if !changed {
		// Nothing pending: a directory-fsync episode for a change since
		// undone is over.
		f.episodeRecovered(dirFsyncKey(dir), "UEFI vars directory needs no fsync any more")
		return
	}
	f.current.Store(dir)
	err := f.sync(dir, nil)
	f.current.Store("")
	if err != nil {
		f.episodeFailed(dirFsyncKey(dir), dir, "UEFI vars directory fsync failed", fmt.Errorf("fsync: %w", err))
		return // the next sweep sees the change again
	}
	f.listed[dir] = present
	f.episodeRecovered(dirFsyncKey(dir), "UEFI vars directory fsync succeeded again")
}

// reconcileFailures follows each failed file to where it is now. A failure
// is its file's (inode's): renamed within or between the watched directories,
// the file keeps it under its new name. It is dropped only once two sweeps in
// a row found its inode in no watched directory, with its own directory read,
// no entry of it renamed away mid-listing, and every listed entry looked at:
// a rename racing one listing (a replacement's cutover) is seen by the next.
func (f *NvramFlusher) reconcileFailures(l nvramListing) {
	byIno := map[uint64][]string{}
	for p, info := range l.byPath {
		if info != nil {
			_, ino := fileIdentity(info)
			byIno[ino] = append(byIno[ino], p)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	next := make(map[string]NvramFlushFailure, len(f.failed))
	missing := make(map[string]int, len(f.missing))
	for k, v := range f.failed {
		w, keep := locateFailed(v, l, byIno)
		switch {
		case !keep && l.raced[filepath.Dir(v.Path)]:
			w = v // this listing may have missed its new name
		case !keep && f.missing[k]+1 < 2:
			missing[k] = f.missing[k] + 1
			w = v // confirmed only by the next, fresh, listing
		case !keep:
			f.dirty = true
			slog.Info("UEFI vars file whose flush failed was removed or replaced", "path", v.Path, "vm", v.VM)
			continue
		case w.Path != v.Path:
			slog.Warn("UEFI vars file whose flush failed was renamed; its failure goes with it",
				"from", v.Path, "to", w.Path, "vm", w.VM)
		}
		if w != v {
			f.dirty = true
		}
		if _, dup := next[failKey(w)]; dup {
			f.dirty = true
			continue
		}
		next[failKey(w)] = w
	}
	f.failed, f.missing = next, missing
}

// locateFailed is failure v as of listing l, and whether it is kept.
func locateFailed(v NvramFlushFailure, l nvramListing, byIno map[uint64][]string) (NvramFlushFailure, bool) {
	if v.Ino == 0 {
		return v, true // names no file to look for (the state file's own failure)
	}
	info, present := l.byPath[v.Path]
	if present && info == nil {
		return v, true // cannot be looked at
	}
	if present {
		if dev, ino := fileIdentity(info); ino == v.Ino {
			v.Dev = dev // the device number can change across a reboot: kept current
			return v, true
		}
	}
	if cands := byIno[v.Ino]; len(cands) > 0 {
		sort.Strings(cands)
		at := cands[0]
		for _, c := range cands {
			if dev, _ := fileIdentity(l.byPath[c]); dev == v.Dev {
				at = c
				break
			}
		}
		v.Dev, _ = fileIdentity(l.byPath[at])
		v.Path, v.VM = at, nvramVMName(at)
		return v, true
	}
	if !l.read[filepath.Dir(v.Path)] || l.unknown {
		return v, true
	}
	return v, false
}

// failKey is a failure's key in NvramFlusher.failed: its file's identity,
// or its path for one that names no inode.
func failKey(v NvramFlushFailure) string {
	if v.Ino == 0 {
		return "path\x00" + v.Path
	}
	return fmt.Sprintf("ino\x00%d\x00%d", v.Dev, v.Ino)
}

// newNvramEpisode names a failure episode.
func newNvramEpisode() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// fail records a failed fsync of p: a new episode of its file's failure,
// written to the state file before it is visible (recordFailure).
func (f *NvramFlusher) fail(p string, info os.FileInfo, err error) {
	dev, ino := fileIdentity(info)
	v := NvramFlushFailure{
		Path: p, VM: nvramVMName(p), Error: err.Error(),
		At:  f.now().UTC().Format(time.RFC3339),
		Dev: dev, Ino: ino, Mtime: info.ModTime(),
		Episode: newNvramEpisode(),
	}
	if already := f.recordFailure(v); !already {
		slog.Error("UEFI vars flush failed: the guest's UEFI variable writes may not be on disk, "+
			"and stopping the VM does not write them out again; see the nvram_flush_failed condition",
			"path", p, "vm", nvramVMName(p), "error", err)
	}
}

// forget drops what the flusher knows of a name that left its directory. A
// failure is its file's, not the name's: reconcileFailures follows it.
func (f *NvramFlusher) forget(p string) {
	delete(f.flushed, p)
	delete(f.warned, p)
	f.mu.Lock()
	delete(f.openFail, p)
	f.mu.Unlock()
}

func (f *NvramFlusher) warnOnce(key, msg string, err error) {
	if f.warned[key] {
		return
	}
	f.warned[key] = true
	slog.Warn(msg, "path", key, "error", err)
}

// nvramVMName is the VM a vars file belongs to, by libvirt's and litevirt's
// naming (<vm>_VARS.fd), or "" for another name.
func nvramVMName(p string) string {
	name, ok := strings.CutSuffix(filepath.Base(p), "_VARS.fd")
	if !ok {
		return ""
	}
	return name
}

// fsyncListed fsyncs path. With want nil it is a directory, opened without
// following a link. Otherwise it must still be the regular file want was
// listed as: opened without following a link, without blocking (a FIFO put
// in its place) and never as a controlling terminal, and confirmed by fstat
// to be that same file. Only an error of the fsync itself is an
// *nvramSyncError.
func fsyncListed(path string, want os.FileInfo) error {
	if want == nil {
		d, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		defer d.Close()
		return d.Sync()
	}
	fh, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return err
	}
	defer fh.Close()
	got, err := fh.Stat()
	if err != nil {
		return err
	}
	if !got.Mode().IsRegular() || !os.SameFile(got, want) {
		return fmt.Errorf("%s: %w", path, errNvramEntryChanged)
	}
	if err := fh.Sync(); err != nil {
		return &nvramSyncError{err}
	}
	return nil
}

// Seed carries failures over from before a restart (the state file, the host
// condition's evidence). It fails closed. A failure whose file is at its path
// is kept, with the file's current device number (it can change across a
// reboot). One whose path is gone, or holds another file, is kept when the
// path is in a watched directory, for the next sweep to look for its inode
// (the file may have been renamed), and is dropped, and logged, otherwise. A
// file that cannot be looked at keeps its failure, and so does a failure that
// names no inode.
func (f *NvramFlusher) Seed(failures []NvramFlushFailure) {
	f.mu.Lock()
	for _, v := range failures {
		if v.Ino != 0 {
			info, err := os.Lstat(v.Path)
			switch {
			case err == nil && info.Mode().IsRegular() && sameInode(info, v.Ino):
				v.Dev, _ = fileIdentity(info)
			case err != nil && !os.IsNotExist(err):
				slog.Warn("carried-over UEFI vars flush failure kept: its file cannot be looked at", "path", v.Path, "vm", v.VM, "error", err)
			case f.watches(filepath.Dir(v.Path)):
				// Gone from its name, or another file is there: the next
				// sweep looks for its inode.
			default:
				slog.Info("carried-over UEFI vars flush failure dropped: the file is gone, or another file is at the path", "path", v.Path, "vm", v.VM)
				continue
			}
		}
		if _, ok := f.failed[failKey(v)]; !ok {
			f.failed[failKey(v)] = v
			f.dirty = true
		}
	}
	f.mu.Unlock()
	f.persist()
}

func sameInode(info os.FileInfo, ino uint64) bool {
	_, got := fileIdentity(info)
	return got == ino
}

// watches reports whether dir is one of the flusher's directories.
func (f *NvramFlusher) watches(dir string) bool {
	for _, d := range f.dirs {
		if filepath.Clean(d) == filepath.Clean(dir) {
			return true
		}
	}
	return false
}

// LoadState makes path the flusher's state file. The failures it holds are
// carried over (Seed), and from then on every change to them is written there
// by the end of the sweep or call that made it, so a failure survives a
// restart whatever the replicated condition row says (a stale resolve can
// overwrite that with fewer files). A missing state file holds nothing. One
// that cannot be read or parsed is itself a failure: what it held is not
// known, so it is kept until an admin acknowledges it. Call it before Run.
func (f *NvramFlusher) LoadState(path string) {
	b, err := os.ReadFile(path)
	var held []NvramFlushFailure
	if err == nil {
		err = json.Unmarshal(b, &held)
	}
	f.statePath = path
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		v := NvramFlushFailure{Path: path,
			Error:   "the record of this host's failed UEFI vars flushes cannot be read, so the failures it held are not known: " + err.Error(),
			At:      f.now().UTC().Format(time.RFC3339),
			Episode: newNvramEpisode()}
		slog.Error("the UEFI vars flush failures recorded on this host cannot be read; raised as a failure of their own",
			"path", path, "error", err)
		f.mu.Lock()
		f.failed[failKey(v)] = v
		f.dirty = true
		f.mu.Unlock()
		f.persist()
	default:
		f.Seed(held)
	}
}

// persist writes the failures to the state file if they changed since it was
// last written. A failed write is logged once and retried at the next sweep.
func (f *NvramFlusher) persist() {
	if f.statePath == "" {
		return
	}
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	f.mu.Lock()
	if !f.dirty {
		f.mu.Unlock()
		return
	}
	out := f.snapshotLocked(nil)
	f.dirty = false
	f.mu.Unlock()
	if !f.writeStateLocked(out) {
		f.mu.Lock()
		f.dirty = true
		f.mu.Unlock()
	}
}

// recordFailure makes failure v visible (Failures, and through it the
// condition and an acknowledgement) only once the state file holds it, so no
// replicated write can be its only record: a tick could otherwise publish it,
// a stale resolve overwrite that row, and a restart lose it. If the state
// file cannot be written it is made visible anyway, and the write retried.
// It reports whether the file already had a failure.
func (f *NvramFlusher) recordFailure(v NvramFlushFailure) (already bool) {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	f.mu.Lock()
	_, already = f.failed[failKey(v)]
	var out []NvramFlushFailure
	if f.statePath != "" {
		out = f.snapshotLocked(&v)
	}
	f.mu.Unlock()
	written := f.statePath == "" || f.writeStateLocked(out)
	f.mu.Lock()
	f.failed[failKey(v)] = v
	if !written {
		f.dirty = true
	}
	f.mu.Unlock()
	return already
}

// snapshotLocked is the failures, with add among them if it is not nil. The
// caller holds mu.
func (f *NvramFlusher) snapshotLocked(add *NvramFlushFailure) []NvramFlushFailure {
	out := make([]NvramFlushFailure, 0, len(f.failed)+1)
	for k, v := range f.failed {
		if add == nil || k != failKey(*add) {
			out = append(out, v)
		}
	}
	if add != nil {
		out = append(out, *add)
	}
	sortFailures(out)
	return out
}

// writeStateLocked writes out to the state file, logging a failure once.
// The caller holds stateMu.
func (f *NvramFlusher) writeStateLocked(out []NvramFlushFailure) bool {
	if err := writeNvramState(f.statePath, out); err != nil {
		if !f.stateWarned {
			f.stateWarned = true
			slog.Error("could not record this host's failed UEFI vars flushes; retried every sweep, "+
				"and a restart until then keeps only those the nvram_flush_failed condition names",
				"path", f.statePath, "error", err)
		}
		return false
	}
	if f.stateWarned {
		f.stateWarned = false
		slog.Info("this host's failed UEFI vars flushes are recorded again", "path", f.statePath)
	}
	return true
}

// writeNvramState replaces path with failures, durably: the data and the
// rename are on disk when it returns nil.
func writeNvramState(path string, failures []NvramFlushFailure) error {
	b, err := json.Marshal(failures)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp")
	fh, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, err = fh.Write(b)
	if err == nil {
		err = fh.Sync()
	}
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return fsyncPath(dir)
}

// fileIdentity is a file's device and inode numbers.
func fileIdentity(info os.FileInfo) (dev, ino uint64) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev), st.Ino
	}
	return 0, 0
}

// nvramSyncError is an error from the fsync itself, as opposed to the open:
// only it can mean written data was lost.
type nvramSyncError struct{ err error }

func (e *nvramSyncError) Error() string { return "fsync: " + e.err.Error() }
func (e *nvramSyncError) Unwrap() error { return e.err }

// Done closes once Run has made its last sweep.
func (f *NvramFlusher) Done() <-chan struct{} { return f.done }

// Blocked lists what has kept vars files from being flushed for longer than
// nvramBlockedAfter (a file that cannot be opened, a directory that cannot be
// read or fsynced), and a sweep stuck in an fsync for longer than
// stallAfter, by path. Nothing is known lost for them, but nothing they cover
// is being flushed either.
func (f *NvramFlusher) Blocked() []NvramFlushFailure {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []NvramFlushFailure{}
	for _, v := range f.openFail {
		if v.escalated {
			out = append(out, v.NvramFlushFailure)
		}
	}
	if f.stall != nil {
		out = append(out, *f.stall)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// SetClock replaces the flusher's clock; for tests that drive it past
// nvramBlockedAfter.
func (f *NvramFlusher) SetClock(now func() time.Time) { f.now = now }

// episodeFailed records a failure under key (a file that cannot be opened, a
// directory that cannot be read or fsynced) for path: logged when an episode
// starts, and at error once it has lasted nvramBlockedAfter, when Blocked
// lists it.
func (f *NvramFlusher) episodeFailed(key, path, startMsg string, err error) {
	now := f.now()
	f.mu.Lock()
	v, ok := f.openFail[key]
	if !ok {
		v = nvramOpenFail{since: now}
		v.Path, v.VM = path, nvramVMName(path)
		v.At = now.UTC().Format(time.RFC3339)
	}
	v.Error = err.Error()
	escalate := !v.escalated && now.Sub(v.since) >= nvramBlockedAfter
	if escalate {
		v.escalated = true
	}
	f.openFail[key] = v
	f.mu.Unlock()
	switch {
	case !ok:
		slog.Warn(startMsg+"; retried every sweep", "path", path, "vm", v.VM, "error", err)
	case escalate:
		slog.Error("UEFI vars have not been flushed since: "+startMsg+"; the guests' UEFI variable writes are not being made durable",
			"path", path, "vm", v.VM, "since", v.At, "error", err)
	}
}

// episodeRecovered ends key's episode, if it had one.
func (f *NvramFlusher) episodeRecovered(key, msg string) {
	f.mu.Lock()
	v, ok := f.openFail[key]
	delete(f.openFail, key)
	f.mu.Unlock()
	if ok {
		slog.Info(msg, "path", v.Path, "vm", v.VM, "since", v.At)
	}
}

func (f *NvramFlusher) openFailed(p string, err error) {
	f.episodeFailed(p, p, "UEFI vars file could not be opened to flush it", err)
}

func (f *NvramFlusher) openRecovered(p string) {
	f.episodeRecovered(p, "UEFI vars file flushed again after it could not be opened")
}

// Episode keys of a directory's read and fsync.
func dirReadKey(dir string) string  { return "read\x00" + dir }
func dirFsyncKey(dir string) string { return "fsync\x00" + dir }

// Acknowledge drops the failures an admin acknowledged (the host condition
// resolved by hand, accepting that those vars stores may be stale): each
// failure episode named, matched on path, inode and episode. A later failed
// fsync of the same file is another episode, which it does not cover.
func (f *NvramFlusher) Acknowledge(failures []NvramFlushFailure) {
	f.mu.Lock()
	for _, v := range failures {
		for k, cur := range f.failed {
			if cur.Path == v.Path && cur.Ino == v.Ino && cur.Episode == v.Episode {
				delete(f.failed, k)
				f.dirty = true
				slog.Warn("UEFI vars flush failure acknowledged by an admin; the vars store may be stale",
					"path", v.Path, "vm", v.VM, "episode", v.Episode)
			}
		}
	}
	f.mu.Unlock()
	f.persist()
}

// beginSweep starts a watched sweep and returns its generation.
func (f *NvramFlusher) beginSweep() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweepGen++
	return f.sweepGen
}

// endSweep ends the watched sweep: its stall, if any, is over, and a stall
// timer that fires from now on belongs to a finished sweep.
func (f *NvramFlusher) endSweep() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweepGen++
	f.stall = nil
}

// markStalled records that sweep gen is stuck in an fsync of p, unless that
// sweep has already returned.
func (f *NvramFlusher) markStalled(gen uint64, p string, elapsed time.Duration) {
	f.mu.Lock()
	if gen != f.sweepGen {
		f.mu.Unlock()
		return
	}
	f.stall = &NvramFlushFailure{Path: p, VM: nvramVMName(p),
		Error: fmt.Sprintf("fsync has not returned for %s; no vars file on this host is flushed until it does", elapsed.Round(time.Second)),
		At:    time.Now().UTC().Format(time.RFC3339)}
	f.mu.Unlock()
	f.onStall(p, elapsed)
}
