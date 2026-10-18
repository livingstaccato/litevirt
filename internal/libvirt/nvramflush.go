package libvirt

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// NvramFlushInterval is how often the daemon flushes UEFI vars files that
// changed: the longest a guest's UEFI variable write waits in the host page
// cache before it is on disk.
const NvramFlushInterval = time.Second

// nvramRecentWindow: a file whose mtime is this recent is flushed again on
// every sweep. File timestamps are coarse, so a write landing in the same
// timestamp tick as the one already flushed leaves the mtime unchanged and
// would otherwise never be flushed.
const nvramRecentWindow = 2 * time.Second

// NvramFlusher fsyncs the UEFI vars (pflash) files in its directories that
// changed since it last looked, and the directory when its set of files
// changed.
//
// qemu writes a guest's UEFI variable store with no flush, and libvirt has no
// cache mode for <nvram> or <loader>, so without this a write waits in the
// host page cache until writeback (vm.dirty_expire_centisecs, 30 s by
// default) and a host power cut loses it.
type NvramFlusher struct {
	dirs []string
	sync func(path string) error
	now  func() time.Time

	flushed map[string]time.Time       // file → mtime it was last flushed at
	listed  map[string]map[string]bool // dir → files it held at the last flush
	failing map[string]bool            // file or dir whose last fsync failed (logged once)
}

// NewNvramFlusher flushes the vars files in dirs. A directory that does not
// exist is skipped until it does.
func NewNvramFlusher(dirs ...string) *NvramFlusher {
	return &NvramFlusher{
		dirs:    dirs,
		sync:    fsyncPath,
		now:     time.Now,
		flushed: map[string]time.Time{},
		listed:  map[string]map[string]bool{},
		failing: map[string]bool{},
	}
}

// Run sweeps every interval until ctx ends.
func (f *NvramFlusher) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		f.Sweep()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Sweep flushes, once, every file that changed since the last sweep.
func (f *NvramFlusher) Sweep() {
	now := f.now()
	for _, dir := range f.dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if !os.IsNotExist(err) {
				f.report(dir, err)
			}
			continue
		}
		present := map[string]bool{}
		for _, e := range entries {
			if !e.Type().IsRegular() {
				continue
			}
			p := filepath.Join(dir, e.Name())
			info, err := e.Info()
			if err != nil {
				continue // removed since the listing
			}
			present[p] = true
			mt := info.ModTime()
			if last, ok := f.flushed[p]; ok && last.Equal(mt) && now.Sub(mt) > nvramRecentWindow {
				continue
			}
			if err := f.sync(p); err != nil {
				delete(f.flushed, p)
				f.report(p, err)
				continue
			}
			f.flushed[p] = mt
			f.recovered(p)
		}
		prev := f.listed[dir]
		changed := len(prev) != len(present)
		for p := range prev {
			if !present[p] {
				changed = true
				delete(f.flushed, p)
			}
		}
		if !changed {
			continue
		}
		if err := f.sync(dir); err != nil {
			f.report(dir, err)
			continue // the next sweep sees the change again
		}
		f.listed[dir] = present
		f.recovered(dir)
	}
}

func (f *NvramFlusher) report(path string, err error) {
	if f.failing[path] {
		return
	}
	f.failing[path] = true
	slog.Warn("UEFI vars flush failed; a host power cut can lose the guest's recent UEFI variable writes",
		"path", path, "error", err)
}

func (f *NvramFlusher) recovered(path string) {
	if f.failing[path] {
		delete(f.failing, path)
		slog.Info("UEFI vars flush recovered", "path", path)
	}
}
