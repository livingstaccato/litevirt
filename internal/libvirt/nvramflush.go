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

// NvramFlushInterval is how often the daemon flushes UEFI vars files that
// changed: about the longest a guest's UEFI variable write waits in the host
// page cache before it is on disk.
const NvramFlushInterval = time.Second

// nvramMtimeTick bounds the coarseness of file timestamps (the kernel's
// coarse clock, a jiffy). A write within this of the start of a file's last
// fsync may carry the same mtime as the data that fsync flushed.
const nvramMtimeTick = 50 * time.Millisecond

// nvramStallAfter: a sweep still running after this is reported.
const nvramStallAfter = 10 * time.Second

// errNvramEntryChanged: the directory entry no longer names the regular file
// the listing saw.
var errNvramEntryChanged = errors.New("the entry is no longer the regular file listed")

// NvramFlushFailure is a vars file whose fsync failed. It stays failed until
// the file is removed or replaced: after a writeback error the kernel reports it to one
// fsync, and a later fsync returns 0 although the data never reached disk.
type NvramFlushFailure struct {
	Path  string `json:"path"`
	VM    string `json:"vm,omitempty"`
	Error string `json:"error"`
	At    string `json:"at"`
	Dev   uint64 `json:"dev"`
	Ino   uint64 `json:"ino"`
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

	mu     sync.Mutex
	failed map[string]NvramFlushFailure
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
	}
	f.onStall = func(path string, elapsed time.Duration) {
		slog.Warn("UEFI vars flush is stalled; until it returns, no vars file on this host is flushed",
			"path", path, "elapsed", elapsed)
	}
	return f
}

// Run sweeps every interval until ctx ends, and once more then.
func (f *NvramFlusher) Run(ctx context.Context, interval time.Duration) {
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
		f.onStall(p, time.Since(start))
	})
	f.Sweep()
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
		if err != nil {
			if !os.IsNotExist(err) {
				f.warnOnce(dir, "UEFI vars directory could not be read", err)
			}
			continue
		}
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
			switch {
			case errors.Is(err, errNvramEntryChanged) || errors.Is(err, syscall.ELOOP):
				f.warnOnce(p, "UEFI vars entry changed under the flusher; skipped", err)
			case err != nil:
				f.fail(p, info, err)
			default:
				f.flushed[p] = nvramFlushed{mtime: mt, syncStart: start}
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
			f.warnOnce(dir, "UEFI vars directory flush failed; retried on the next sweep", err)
			continue // the next sweep sees the change again
		}
		f.listed[dir] = present
		if f.warned[dir] {
			delete(f.warned, dir)
			slog.Info("UEFI vars directory flush recovered", "dir", dir)
		}
	}
}

func (f *NvramFlusher) fail(p string, info os.FileInfo, err error) {
	dev, ino := fileIdentity(info)
	f.mu.Lock()
	_, already := f.failed[p]
	f.failed[p] = NvramFlushFailure{
		Path: p, VM: nvramVMName(p), Error: err.Error(),
		At:  f.now().UTC().Format(time.RFC3339),
		Dev: dev, Ino: ino,
	}
	f.mu.Unlock()
	if !already {
		slog.Error("UEFI vars flush failed: the guest's UEFI variable writes may not be on disk; "+
			"qemu still holds them in memory, so once the disk is healthy stop the VM cleanly to write them out",
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
// listed as: opened without following a link and without blocking (a FIFO
// put in its place), and confirmed by fstat to be that same file.
func fsyncListed(path string, want os.FileInfo) error {
	if want == nil {
		d, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		defer d.Close()
		return d.Sync()
	}
	fh, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
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
	return fh.Sync()
}

// Seed carries failures over from before a restart (the host condition's
// evidence). One whose file is gone, or is another file now, is dropped.
func (f *NvramFlusher) Seed(failures []NvramFlushFailure) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, v := range failures {
		info, err := os.Lstat(v.Path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if dev, ino := fileIdentity(info); dev != v.Dev || ino != v.Ino {
			continue
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

// replaced reports whether the failed file at p has been replaced by another.
func (f *NvramFlusher) replaced(p string, info os.FileInfo) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.failed[p]
	if !ok {
		return false
	}
	dev, ino := fileIdentity(info)
	return dev != v.Dev || ino != v.Ino
}
