package libvirt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// recordingFlusher is a NvramFlusher whose syncs are recorded, not performed,
// at a clock the test sets.
func recordingFlusher(t *testing.T, dirs ...string) (*NvramFlusher, *[]string, *time.Time) {
	t.Helper()
	var synced []string
	now := time.Now()
	f := NewNvramFlusher(dirs...)
	f.sync = func(p string, _ os.FileInfo) error { synced = append(synced, p); return nil }
	f.now = func() time.Time { return now }
	return f, &synced, &now
}

func writeAt(t *testing.T, p string, data string, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func sorted(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

// A vars file qemu has written since the last sweep is fsynced, and a file
// new to the directory gets the directory fsynced too, so its entry survives
// a power cut as well as its data.
func TestNvramFlusher_SyncsChangedFilesAndNewEntries(t *testing.T) {
	dir := t.TempDir()
	f, synced, now := recordingFlusher(t, dir)
	old := now.Add(-time.Hour)
	vars := filepath.Join(dir, "vm1_VARS.fd")
	writeAt(t, vars, "v1", old)

	f.Sweep()
	if got, want := sorted(*synced), sorted([]string{vars, dir}); !slices.Equal(got, want) {
		t.Fatalf("first sweep synced %v, want %v", got, want)
	}

	// Unchanged since: nothing to flush.
	*synced = nil
	f.Sweep()
	if len(*synced) != 0 {
		t.Fatalf("unchanged file was synced again: %v", *synced)
	}

	// The guest wrote a variable: the file is flushed, the directory is not
	// (no entry changed).
	*synced = nil
	writeAt(t, vars, "v2", old.Add(time.Minute))
	f.Sweep()
	if got := *synced; !slices.Equal(got, []string{vars}) {
		t.Fatalf("modified file: synced %v, want [%s]", got, vars)
	}
}

// Timestamps are coarse: a second write inside the same timestamp tick as an
// fsync that already started leaves the mtime unchanged. A file whose mtime is
// that close to the start of its last fsync is flushed once more, then left
// alone.
func TestNvramFlusher_MtimeAtTheLastFsyncIsFlushedOnceMore(t *testing.T) {
	dir := t.TempDir()
	f, synced, now := recordingFlusher(t, dir)
	vars := filepath.Join(dir, "vm1_VARS.fd")
	writeAt(t, vars, "v1", *now)

	f.Sweep()
	*synced = nil
	*now = now.Add(time.Second)
	f.Sweep()
	if got := *synced; !slices.Equal(got, []string{vars}) {
		t.Fatalf("mtime at the last fsync's start: synced %v, want [%s]", got, vars)
	}
	*synced = nil
	*now = now.Add(time.Second)
	f.Sweep()
	if len(*synced) != 0 {
		t.Fatalf("flushed again after a flush that started past its mtime: %v", *synced)
	}
}

// A slow sweep (many VMs writing at once, a slow disk) does not let a
// same-tick write escape: the decision rests on when the last fsync started,
// not on how long ago the clock says the write was.
func TestNvramFlusher_SameTickWriteSurvivesASlowSweep(t *testing.T) {
	dir := t.TempDir()
	f, synced, now := recordingFlusher(t, dir)
	vars := filepath.Join(dir, "vm1_VARS.fd")
	writeAt(t, vars, "v1", *now)

	f.Sweep()
	*synced = nil
	*now = now.Add(10 * time.Second) // the next sweep came late
	f.Sweep()
	if got := *synced; !slices.Equal(got, []string{vars}) {
		t.Fatalf("after a late sweep: synced %v, want [%s]", got, vars)
	}
}

// An mtime in the future (a clock stepped back) is flushed once, not on every
// sweep until the clock passes it: any later write sets a different mtime.
func TestNvramFlusher_FutureMtimeIsFlushedOnce(t *testing.T) {
	dir := t.TempDir()
	f, synced, now := recordingFlusher(t, dir)
	vars := filepath.Join(dir, "vm1_VARS.fd")
	writeAt(t, vars, "v1", now.Add(time.Hour))

	f.Sweep()
	*synced = nil
	*now = now.Add(time.Second)
	f.Sweep()
	if len(*synced) != 0 {
		t.Fatalf("future mtime flushed again: %v", *synced)
	}
}

// An fsync error on a vars file is sticky. After a writeback EIO the kernel
// reports the error once, and a later fsync on a fresh fd returns 0 with the
// data still lost, so a later success proves nothing. The failure stays,
// named by file and VM, until the file is removed.
func TestNvramFlusher_FsyncErrorIsStickyUntilTheFileGoes(t *testing.T) {
	dir := t.TempDir()
	f, _, now := recordingFlusher(t, dir)
	vars := filepath.Join(dir, "vm1_VARS.fd")
	writeAt(t, vars, "v1", now.Add(-time.Hour))

	var tries []string
	fail := true
	f.sync = func(p string, _ os.FileInfo) error {
		tries = append(tries, p)
		if fail && p == vars {
			return &nvramSyncError{syscall.EIO}
		}
		return nil
	}
	f.Sweep()
	fail = false
	tries = nil
	f.Sweep()
	if !slices.Contains(tries, vars) {
		t.Fatalf("file whose fsync failed was not tried again: %v", tries)
	}
	got := f.Failures()
	if len(got) != 1 || got[0].Path != vars || got[0].VM != "vm1" || got[0].Error == "" {
		t.Fatalf("after EIO then a clean retry, failures = %+v; want vm1's file, still failed", got)
	}

	if err := os.Remove(vars); err != nil {
		t.Fatal(err)
	}
	f.Sweep()
	if got := f.Failures(); len(got) != 0 {
		t.Fatalf("removed file still listed as failed: %+v", got)
	}
}

// A file that leaves the directory (a rename to a new name, a delete) has its
// directory fsynced, so the rename is as durable as the data; a missing
// directory is not an error, and nothing but regular files is flushed.
func TestNvramFlusher_RemovalSyncsDirAndOddEntriesAreSkipped(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(t.TempDir(), "absent")
	f, synced, now := recordingFlusher(t, dir, missing)
	old := now.Add(-time.Hour)
	a := filepath.Join(dir, "a_VARS.fd")
	writeAt(t, a, "a", old)
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(a, filepath.Join(dir, "link_VARS.fd")); err != nil {
		t.Fatal(err)
	}
	f.Sweep()
	if got, want := sorted(*synced), sorted([]string{a, dir}); !slices.Equal(got, want) {
		t.Fatalf("first sweep synced %v, want %v", got, want)
	}

	// A rename keeps the count of files: the entry itself changed.
	*synced = nil
	b := filepath.Join(dir, "b_VARS.fd")
	if err := os.Rename(a, b); err != nil {
		t.Fatal(err)
	}
	f.Sweep()
	if got, want := sorted(*synced), sorted([]string{b, dir}); !slices.Equal(got, want) {
		t.Fatalf("after a rename synced %v, want %v", got, want)
	}

	*synced = nil
	if err := os.Remove(b); err != nil {
		t.Fatal(err)
	}
	f.Sweep()
	if got := *synced; !slices.Equal(got, []string{dir}) {
		t.Fatalf("after a removal synced %v, want [%s]", got, dir)
	}
}

// The real fsync opens only the file the listing saw. The directory may be
// writable by the qemu user, so between the listing and the open an entry can
// be swapped for a FIFO (a plain open would block forever), a symlink (the
// daemon would open whatever it names, as root) or another file.
func TestNvramFlusher_DefaultSyncOpensOnlyTheListedRegularFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x_VARS.fd")
	writeAt(t, p, "x", time.Now())
	listed, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	f := NewNvramFlusher(dir)
	if err := f.sync(p, listed); err != nil {
		t.Fatalf("fsync of the listed regular file: %v", err)
	}
	if err := f.sync(dir, nil); err != nil {
		t.Fatalf("fsync of a directory: %v", err)
	}

	within := func(name string, fn func() error) error {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- fn() }()
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the fsync blocked", name)
			return nil
		}
	}

	// Swapped for a FIFO: must neither block nor succeed.
	fifo := filepath.Join(dir, "fifo_VARS.fd")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := within("fifo", func() error { return f.sync(fifo, listed) }); err == nil {
		t.Fatal("a FIFO in the listed file's place was fsynced")
	}

	// Swapped for a symlink to the very file listed: still refused, the link
	// is not followed.
	link := filepath.Join(dir, "link_VARS.fd")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if err := within("symlink", func() error { return f.sync(link, listed) }); err == nil {
		t.Fatal("a symlink in the listed file's place was followed")
	}

	// Swapped for another regular file: refused.
	other := filepath.Join(dir, "other")
	writeAt(t, other, "o", time.Now())
	if err := os.Rename(other, p); err != nil {
		t.Fatal(err)
	}
	if err := within("swapped", func() error { return f.sync(p, listed) }); !errors.Is(err, errNvramEntryChanged) {
		t.Fatalf("a different file in the listed file's place: err %v, want errNvramEntryChanged", err)
	}
}

// A sweep stuck in one fsync is reported, with the file it is stuck on.
func TestNvramFlusher_StalledSweepIsReported(t *testing.T) {
	dir := t.TempDir()
	f, _, now := recordingFlusher(t, dir)
	vars := filepath.Join(dir, "vm1_VARS.fd")
	writeAt(t, vars, "v1", now.Add(-time.Hour))

	release := make(chan struct{})
	f.sync = func(p string, _ os.FileInfo) error {
		if p == vars {
			<-release
		}
		return nil
	}
	f.stallAfter = 20 * time.Millisecond
	var stalledOn atomic.Value
	f.onStall = func(path string, _ time.Duration) { stalledOn.Store(path) }

	done := make(chan struct{})
	go func() { f.watchedSweep(); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for stalledOn.Load() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(release)
	<-done
	if got, _ := stalledOn.Load().(string); got != vars {
		t.Fatalf("stall reported on %q, want %q", got, vars)
	}
}

// Run sweeps once more when it is told to stop, so a write since the last
// tick is flushed before the daemon exits.
func TestNvramFlusher_RunSweepsOnceMoreAtShutdown(t *testing.T) {
	dir := t.TempDir()
	f := NewNvramFlusher(dir)
	var mu sync.Mutex
	var synced []string
	f.sync = func(p string, _ os.FileInfo) error {
		mu.Lock()
		defer mu.Unlock()
		synced = append(synced, p)
		return nil
	}
	writeAt(t, filepath.Join(dir, "early_VARS.fd"), "e", time.Now().Add(-time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.Run(ctx, time.Hour); close(done) }()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if f.current.Load() != nil || time.Now().After(deadline) {
			break // the first sweep has run (it stores the path it is on)
		}
	}
	time.Sleep(50 * time.Millisecond)
	vars := filepath.Join(dir, "late_VARS.fd")
	writeAt(t, vars, "v", time.Now().Add(-time.Hour))
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if !slices.Contains(synced, vars) {
		t.Fatalf("a file written before shutdown was not flushed by Run's last sweep: %v", synced)
	}
}

// A failed file replaced by another (a firmware restore renames a new file
// into place) is another file: its failure goes with the old one. A failure
// carried over from before a restart is kept while the same file is there.
func TestNvramFlusher_FailureFollowsTheFileNotTheName(t *testing.T) {
	dir := t.TempDir()
	f, _, now := recordingFlusher(t, dir)
	vars := filepath.Join(dir, "vm1_VARS.fd")
	writeAt(t, vars, "v1", now.Add(-time.Hour))
	f.sync = func(p string, _ os.FileInfo) error {
		if p == vars {
			return &nvramSyncError{syscall.EIO}
		}
		return nil
	}
	f.Sweep()
	carried := f.Failures()
	if len(carried) != 1 || carried[0].Ino == 0 {
		t.Fatalf("failure does not identify its file: %+v", carried)
	}

	// After a restart: the same file is still failed, a stale entry for a
	// file that is gone is not.
	other := filepath.Join(dir, "other_VARS.fd")
	writeAt(t, other, "o", now.Add(-time.Hour))
	g, _, _ := recordingFlusher(t, dir)
	g.Seed(append(carried,
		NvramFlushFailure{Path: filepath.Join(dir, "gone_VARS.fd"), Error: "EIO", Dev: 1, Ino: 1},
		NvramFlushFailure{Path: other, Error: "EIO", Dev: 1, Ino: 1}, // another file at the name now
	))
	if got := g.Failures(); len(got) != 1 || got[0].Path != vars {
		t.Fatalf("seeded failures = %+v; want only %s", got, vars)
	}
	g.Sweep()
	if got := g.Failures(); len(got) != 1 || got[0].Path != vars {
		t.Fatalf("after a restart, failures = %+v; want only %s", got, vars)
	}

	// The file is replaced: the failure is cleared and the new file flushed.
	next := filepath.Join(dir, "next")
	writeAt(t, next, "v2", now.Add(-time.Minute))
	if err := os.Rename(next, vars); err != nil {
		t.Fatal(err)
	}
	g.Sweep()
	if got := g.Failures(); len(got) != 0 {
		t.Fatalf("a replaced file is still failed: %+v", got)
	}
}

// Only an error from the fsync itself means data may be lost. A failure to
// open the file (it went away between the listing and the open, too many
// open files, a socket in its place) means nothing was flushed yet: it is
// not a failure of the file, and the next sweep tries again.
func TestNvramFlusher_OnlyAnFsyncErrorIsSticky(t *testing.T) {
	dir := t.TempDir()
	f, _, now := recordingFlusher(t, dir)
	vars := filepath.Join(dir, "vm1_VARS.fd")
	writeAt(t, vars, "v1", now.Add(-time.Hour))

	for _, openErr := range []error{
		&os.PathError{Op: "open", Path: vars, Err: syscall.EMFILE},
		&os.PathError{Op: "open", Path: vars, Err: syscall.ENOENT},
		&os.PathError{Op: "open", Path: vars, Err: syscall.ENXIO},
	} {
		var tries int
		f.sync = func(p string, _ os.FileInfo) error {
			if p == vars {
				tries++
				return openErr
			}
			return nil
		}
		f.Sweep()
		f.Sweep()
		if got := f.Failures(); len(got) != 0 {
			t.Fatalf("open error %v recorded as a flush failure: %+v", openErr, got)
		}
		if tries != 2 {
			t.Fatalf("after open error %v the file was tried %d times in two sweeps, want 2", openErr, tries)
		}
	}
}

// The default fsync tells an open failure from an fsync failure.
func TestNvramFlusher_DefaultSyncOpenErrorIsNotAnFsyncError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x_VARS.fd")
	writeAt(t, p, "x", time.Now())
	listed, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	err = NewNvramFlusher(dir).sync(p, listed)
	var se *nvramSyncError
	if err == nil || errors.As(err, &se) || !os.IsNotExist(err) {
		t.Fatalf("open of a vanished file: err %v; want a not-exist error that is not an fsync error", err)
	}
}

// A failed file the guest has written since its failure, and that has then
// been fsynced, is clear: the store is on disk as the guest last wrote it. A
// successful fsync with nothing written since proves nothing.
func TestNvramFlusher_RewrittenAndFlushedClearsTheFailure(t *testing.T) {
	dir := t.TempDir()
	f, _, now := recordingFlusher(t, dir)
	vars := filepath.Join(dir, "vm1_VARS.fd")
	at := now.Add(-time.Hour)
	writeAt(t, vars, "v1", at)
	failing := true
	f.sync = func(p string, _ os.FileInfo) error {
		if failing && p == vars {
			return &nvramSyncError{syscall.EIO}
		}
		return nil
	}
	f.Sweep()
	failing = false
	f.Sweep()
	if len(f.Failures()) != 1 {
		t.Fatalf("a clean fsync with nothing rewritten cleared the failure")
	}
	writeAt(t, vars, "v2", at.Add(time.Minute))
	f.Sweep()
	if got := f.Failures(); len(got) != 0 {
		t.Fatalf("rewritten and flushed, still failed: %+v", got)
	}

	// Carried over a restart, the same holds.
	failing = true
	writeAt(t, vars, "v3", at.Add(2*time.Minute))
	f.Sweep()
	carried := f.Failures()
	g, _, _ := recordingFlusher(t, dir)
	g.Seed(carried)
	g.Sweep()
	if len(g.Failures()) != 1 {
		t.Fatalf("seeded failure cleared by a clean fsync with nothing rewritten")
	}
	writeAt(t, vars, "v4", at.Add(3*time.Minute))
	g.Sweep()
	if got := g.Failures(); len(got) != 0 {
		t.Fatalf("seeded failure, rewritten and flushed, still failed: %+v", got)
	}
}

// Done closes once Run has made its last sweep.
func TestNvramFlusher_DoneClosesAfterTheLastSweep(t *testing.T) {
	dir := t.TempDir()
	f := NewNvramFlusher(dir)
	vars := filepath.Join(dir, "late_VARS.fd")
	release := make(chan struct{})
	var swept atomic.Bool
	f.sync = func(p string, _ os.FileInfo) error {
		if p == vars {
			<-release
			swept.Store(true)
		}
		return nil
	}
	writeAt(t, filepath.Join(dir, "early_VARS.fd"), "e", time.Now().Add(-time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	go f.Run(ctx, time.Hour)
	for deadline := time.Now().Add(5 * time.Second); f.current.Load() == nil && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond) // until the first sweep has run
	}
	time.Sleep(50 * time.Millisecond)
	writeAt(t, vars, "v", time.Now().Add(-time.Hour))
	cancel()
	select {
	case <-f.Done():
		t.Fatal("Done closed before the last sweep finished")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-f.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done never closed")
	}
	if !swept.Load() {
		t.Fatal("Done closed without the last sweep")
	}
}

// A failure recorded before failures carried the file's mtime is judged by
// when it was recorded: a clean fsync of a file not written since keeps it.
func TestNvramFlusher_SeededFailureWithoutMtimeUsesItsTime(t *testing.T) {
	dir := t.TempDir()
	f, _, now := recordingFlusher(t, dir)
	vars := filepath.Join(dir, "vm1_VARS.fd")
	writeAt(t, vars, "v1", now.Add(-2*time.Hour))
	info, err := os.Lstat(vars)
	if err != nil {
		t.Fatal(err)
	}
	dev, ino := fileIdentity(info)
	f.Seed([]NvramFlushFailure{{Path: vars, Error: "EIO", At: now.Add(-time.Hour).UTC().Format(time.RFC3339), Dev: dev, Ino: ino}})
	f.Sweep()
	if len(f.Failures()) != 1 {
		t.Fatal("a failure recorded after the file's last write was cleared by a clean fsync")
	}
}
