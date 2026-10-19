package libvirt

import (
	"context"
	"errors"
	"fmt"
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

// NvramFlushFailure is a vars file whose fsync failed. It stays failed until
// the file is removed or replaced. After a writeback error the kernel reports
// it to one fsync and marks the lost pages clean, and qemu writes back only
// the sectors a later guest write changes, so no later fsync, after a guest
// write or not, puts the lost pages back on disk.
type NvramFlushFailure struct {
	Path  string `json:"path"`
	VM    string `json:"vm,omitempty"`
	Error string `json:"error"`
	At    string `json:"at"`
	Dev   uint64 `json:"dev"`
	Ino   uint64 `json:"ino"`
	// Mtime is the file's mtime when its fsync failed (evidence only).
	Mtime time.Time `json:"mtime"`
}

type nvramFlushed struct {
	mtime     time.Time // the file's mtime when its last fsync started
	syncStart time.Time // when its last fsync started
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
	sync func(path string, want os.FileInfo) error
	now  func() time.Time

	stallAfter time.Duration
	onStall    func(path string, elapsed time.Duration)
	current    atomic.Value // string: the path being fsynced

	flushed map[string]nvramFlushed
	listed  map[string]map[string]bool // dir → files it held at its last fsync
	warned  map[string]bool            // directory or odd entry already logged

	mu       sync.Mutex
	failed   map[string]NvramFlushFailure
	openFail map[string]nvramOpenFail // episodes, by file path or dirReadKey/dirFsyncKey
	stall    *NvramFlushFailure       // the sweep stuck in an fsync, if one is

	done chan struct{}
}

// NewNvramFlusher flushes the vars files in dirs. A directory that does not
// exist is skipped until it does.
func NewNvramFlusher(dirs ...string) *NvramFlusher {
	f := &NvramFlusher{
		dirs:       dirs,
		sync:       fsyncListed,
		now:        time.Now,
		stallAfter: nvramStallAfter,
		flushed:    map[string]nvramFlushed{},
		listed:     map[string]map[string]bool{},
		warned:     map[string]bool{},
		failed:     map[string]NvramFlushFailure{},
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
	timer := time.AfterFunc(f.stallAfter, func() {
		p, _ := f.current.Load().(string)
		elapsed := time.Since(start)
		f.mu.Lock()
		f.stall = &NvramFlushFailure{Path: p, VM: nvramVMName(p),
			Error: fmt.Sprintf("fsync has not returned for %s; no vars file on this host is flushed until it does", elapsed.Round(time.Second)),
			At:    time.Now().UTC().Format(time.RFC3339)}
		f.mu.Unlock()
		f.onStall(p, elapsed)
	})
	f.Sweep()
	f.mu.Lock()
	f.stall = nil
	f.mu.Unlock()
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
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// settled: the file's data as of its mtime was flushed. A write can share
// the mtime of the data an fsync flushed only if it came within a timestamp
// tick of that fsync's start; an mtime further from it either way (an older
// write, or a future mtime that any new write would replace) needs no repeat.
func (s nvramFlushed) settled(mt time.Time) bool {
	return s.mtime.Equal(mt) &&
		(mt.Before(s.syncStart.Add(-nvramMtimeTick)) || mt.After(s.syncStart.Add(nvramMtimeTick)))
}

// Sweep flushes, once, every file that changed since its last flush.
func (f *NvramFlusher) Sweep() {
	for _, dir := range f.dirs {
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
		present := map[string]bool{}
		for _, e := range entries {
			if !e.Type().IsRegular() {
				continue
			}
			p := filepath.Join(dir, e.Name())
			info, err := e.Info() // lstat
			if err != nil || !info.Mode().IsRegular() {
				continue // removed or replaced since the listing
			}
			present[p] = true
			if f.replaced(p, info) {
				f.forget(p)
			}
			mt := info.ModTime()
			if last, ok := f.flushed[p]; ok && last.settled(mt) {
				continue
			}
			start := f.now()
			f.current.Store(p)
			err = f.sync(p, info)
			f.current.Store("")
			var syncErr *nvramSyncError
			switch {
			case err == nil:
				f.flushed[p] = nvramFlushed{mtime: mt, syncStart: start}
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
		prev := f.listed[dir]
		changed := len(prev) != len(present)
		for p := range prev {
			if !present[p] {
				changed = true
				f.forget(p)
			}
		}
		if !changed {
			continue
		}
		f.current.Store(dir)
		err = f.sync(dir, nil)
		f.current.Store("")
		if err != nil {
			f.episodeFailed(dirFsyncKey(dir), dir, "UEFI vars directory fsync failed", fmt.Errorf("fsync: %w", err))
			continue // the next sweep sees the change again
		}
		f.listed[dir] = present
		f.episodeRecovered(dirFsyncKey(dir), "UEFI vars directory fsync succeeded again")
	}
}

func (f *NvramFlusher) fail(p string, info os.FileInfo, err error) {
	dev, ino := fileIdentity(info)
	f.mu.Lock()
	_, already := f.failed[p]
	f.failed[p] = NvramFlushFailure{
		Path: p, VM: nvramVMName(p), Error: err.Error(),
		At:  f.now().UTC().Format(time.RFC3339),
		Dev: dev, Ino: ino, Mtime: info.ModTime(),
	}
	f.mu.Unlock()
	if !already {
		slog.Error("UEFI vars flush failed: the guest's UEFI variable writes may not be on disk, "+
			"and stopping the VM does not write them out again; see the nvram_flush_failed condition",
			"path", p, "vm", nvramVMName(p), "error", err)
	}
}

// forget drops what the flusher knows of a file that left its directory or
// was replaced, sticky failure included: a later file at that name is another
// file.
func (f *NvramFlusher) forget(p string) {
	delete(f.flushed, p)
	delete(f.warned, p)
	f.mu.Lock()
	_, was := f.failed[p]
	delete(f.failed, p)
	delete(f.openFail, p)
	f.mu.Unlock()
	if was {
		slog.Info("UEFI vars file whose flush failed was removed or replaced", "path", p)
	}
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

// Seed carries failures over from before a restart (the host condition's
// evidence). It fails closed: a failure is dropped, and logged, only when its
// file is gone or is positively another file (another inode at the path).
// The device number is not compared, since it can change across a reboot;
// a kept failure takes the file's current one. A file that cannot be looked
// at keeps its failure.
func (f *NvramFlusher) Seed(failures []NvramFlushFailure) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, v := range failures {
		info, err := os.Lstat(v.Path)
		switch {
		case os.IsNotExist(err):
			slog.Info("carried-over UEFI vars flush failure dropped: the file is gone", "path", v.Path, "vm", v.VM)
			continue
		case err != nil:
			slog.Warn("carried-over UEFI vars flush failure kept: its file cannot be looked at", "path", v.Path, "vm", v.VM, "error", err)
		case !info.Mode().IsRegular():
			slog.Info("carried-over UEFI vars flush failure dropped: the path is no longer a regular file", "path", v.Path, "vm", v.VM)
			continue
		default:
			dev, ino := fileIdentity(info)
			if ino != v.Ino {
				slog.Info("carried-over UEFI vars flush failure dropped: another file is at the path", "path", v.Path, "vm", v.VM)
				continue
			}
			v.Dev = dev
		}
		if _, ok := f.failed[v.Path]; !ok {
			f.failed[v.Path] = v
		}
	}
}

// fileIdentity is a file's device and inode numbers.
func fileIdentity(info os.FileInfo) (dev, ino uint64) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev), st.Ino
	}
	return 0, 0
}

// replaced reports whether the failed file at p has been replaced by another:
// another inode at the path. The device number is not compared (it can change
// across a reboot) but is kept current.
func (f *NvramFlusher) replaced(p string, info os.FileInfo) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.failed[p]
	if !ok {
		return false
	}
	dev, ino := fileIdentity(info)
	if ino != v.Ino {
		return true
	}
	if dev != v.Dev { // the same file under a device number changed since: keep it current
		v.Dev = dev
		f.failed[p] = v
	}
	return false
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
// resolved by hand, accepting that those vars stores may be stale): each one
// whose file is still the one named.
func (f *NvramFlusher) Acknowledge(failures []NvramFlushFailure) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, v := range failures {
		if cur, ok := f.failed[v.Path]; ok && cur.Ino == v.Ino {
			delete(f.failed, v.Path)
			slog.Warn("UEFI vars flush failure acknowledged by an admin; the vars store may be stale",
				"path", v.Path, "vm", v.VM)
		}
	}
}
