package libvirt

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

// A clean fsync after the guest wrote the file again does not clear a
// failure. qemu writes back only the sectors a guest write changed, and
// OVMF appends records, so the pages lost to the failed fsync stay stale on
// disk whatever the guest writes later. Only removing or replacing the file
// clears it.
func TestNvramFlusher_GuestRewriteAndCleanFsyncDoNotClearTheFailure(t *testing.T) {
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
	writeAt(t, vars, "v2", at.Add(time.Minute))
	f.Sweep()
	got := f.Failures()
	if len(got) != 1 || got[0].Path != vars {
		t.Fatalf("a guest rewrite and a clean fsync cleared the failure: %+v", got)
	}
	if !got[0].Mtime.Equal(at) {
		t.Fatalf("failure records mtime %v, want the mtime at the failed fsync %v", got[0].Mtime, at)
	}

	// Carried over a restart, the same holds.
	g, _, _ := recordingFlusher(t, dir)
	g.Seed(got)
	writeAt(t, vars, "v3", at.Add(2*time.Minute))
	g.Sweep()
	if len(g.Failures()) != 1 {
		t.Fatal("a seeded failure was cleared by a guest rewrite and a clean fsync")
	}
}

// A vars file that keeps failing to open is never flushed: past a bound it
// is reported as blocked (and logged at error), and when it is flushed again
// that is logged and it is no longer blocked.
func TestNvramFlusher_PersistentOpenFailureIsReportedAndRecovers(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	dir := t.TempDir()
	f, _, now := recordingFlusher(t, dir)
	vars := filepath.Join(dir, "vm1_VARS.fd")
	writeAt(t, vars, "v1", now.Add(-time.Hour))
	blocked := true
	f.sync = func(p string, _ os.FileInfo) error {
		if blocked && p == vars {
			return &os.PathError{Op: "open", Path: p, Err: syscall.EACCES}
		}
		return nil
	}
	f.Sweep()
	if got := f.Blocked(); len(got) != 0 {
		t.Fatalf("blocked at once: %+v", got)
	}
	*now = now.Add(nvramBlockedAfter + time.Second)
	f.Sweep()
	got := f.Blocked()
	if len(got) != 1 || got[0].Path != vars || got[0].VM != "vm1" || got[0].Error == "" {
		t.Fatalf("blocked past the bound = %+v; want vm1's file", got)
	}
	if !strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("no error logged for a file blocked past the bound:\n%s", logs.String())
	}
	if got := f.Failures(); len(got) != 0 {
		t.Fatalf("an open failure became a flush failure: %+v", got)
	}

	blocked = false
	f.Sweep()
	if got := f.Blocked(); len(got) != 0 {
		t.Fatalf("still blocked after it was flushed: %+v", got)
	}
	if !strings.Contains(logs.String(), "flushed again") {
		t.Fatalf("recovery not logged:\n%s", logs.String())
	}

	// A second episode is reported again, not swallowed by the first one's
	// warning.
	logs.Reset()
	blocked = true
	writeAt(t, vars, "v2", now.Add(-time.Minute))
	f.Sweep()
	if !strings.Contains(logs.String(), "could not be opened") {
		t.Fatalf("a second open failure was not logged:\n%s", logs.String())
	}
}

// The failure log gives the same advice as the condition: stopping the VM
// does not write the store out again.
func TestNvramFlusher_FailureLogDoesNotAdviseAStop(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	dir := t.TempDir()
	f, _, now := recordingFlusher(t, dir)
	vars := filepath.Join(dir, "vm1_VARS.fd")
	writeAt(t, vars, "v1", now.Add(-time.Hour))
	f.sync = func(p string, _ os.FileInfo) error { return &nvramSyncError{syscall.EIO} }
	f.Sweep()
	out := logs.String()
	if strings.Contains(out, "stop the VM") || !strings.Contains(out, "stopping the VM does not") {
		t.Fatalf("failure log advice does not match the remedy:\n%s", out)
	}
}

// A carried-over failure survives a reboot that renumbered the device: on
// seed the file is matched by path and inode, and the failure takes the
// device number it has now, so the next sweep does not see it as replaced.
func TestNvramFlusher_SeedMatchesByInodeAcrossADeviceRenumber(t *testing.T) {
	dir := t.TempDir()
	vars := filepath.Join(dir, "vm1_VARS.fd")
	writeAt(t, vars, "v1", time.Now().Add(-time.Hour))
	info, err := os.Lstat(vars)
	if err != nil {
		t.Fatal(err)
	}
	dev, ino := fileIdentity(info)
	f, _, _ := recordingFlusher(t, dir)
	f.Seed([]NvramFlushFailure{{Path: vars, VM: "vm1", Error: "EIO", Dev: dev + 7, Ino: ino}})
	f.Sweep()
	if got := f.Failures(); len(got) != 1 || got[0].Dev != dev {
		t.Fatalf("after a device renumber the carried-over failure is %+v; want it kept, with device %d", got, dev)
	}
}

// A carried-over failure whose file cannot be looked at (anything but "it is
// gone") is kept, not dropped: the seed fails closed. A dropped one is
// logged.
func TestNvramFlusher_SeedFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 000 directory")
	}
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	locked := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	vars := filepath.Join(locked, "vm1_VARS.fd")
	writeAt(t, vars, "v1", time.Now().Add(-time.Hour))
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	gone := filepath.Join(t.TempDir(), "gone_VARS.fd")

	f := NewNvramFlusher()
	f.Seed([]NvramFlushFailure{
		{Path: vars, VM: "vm1", Error: "EIO", Dev: 1, Ino: 1},
		{Path: gone, VM: "gone", Error: "EIO", Dev: 1, Ino: 1},
	})
	got := f.Failures()
	if len(got) != 1 || got[0].Path != vars {
		t.Fatalf("seed = %+v; want the unreadable file's failure kept and the gone one dropped", got)
	}
	if !strings.Contains(logs.String(), "gone_VARS.fd") {
		t.Fatalf("the dropped carried-over failure was not logged:\n%s", logs.String())
	}

	// Kept with the device number it was recorded with; once the directory
	// can be read, the same file (by inode) is still the failed one.
	if err := os.Chmod(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(vars)
	if err != nil {
		t.Fatal(err)
	}
	_, ino := fileIdentity(info)
	g, _, _ := recordingFlusher(t, locked)
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	g.Seed([]NvramFlushFailure{{Path: vars, VM: "vm1", Error: "EIO", Dev: 1, Ino: ino}})
	if err := os.Chmod(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	g.Sweep()
	if got := g.Failures(); len(got) != 1 || got[0].Path != vars {
		t.Fatalf("a kept failure was dropped once its file could be read: %+v", got)
	}
}

// A vars directory that cannot be read is an episode as a file is: logged
// when it starts, blocked past the bound, logged when it recovers, and
// logged again when it recurs.
func TestNvramFlusher_UnreadableDirectoryIsReportedAndRecovers(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 000 directory")
	}
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	dir := filepath.Join(t.TempDir(), "nvram")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	f, _, now := recordingFlusher(t, dir)
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	f.Sweep()
	if !strings.Contains(logs.String(), "could not be read") {
		t.Fatalf("an unreadable directory was not logged:\n%s", logs.String())
	}
	*now = now.Add(nvramBlockedAfter + time.Second)
	f.Sweep()
	if got := f.Blocked(); len(got) != 1 || got[0].Path != dir {
		t.Fatalf("blocked = %+v; want the directory", got)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f.Sweep()
	if got := f.Blocked(); len(got) != 0 {
		t.Fatalf("still blocked once readable: %+v", got)
	}
	if !strings.Contains(logs.String(), "readable again") {
		t.Fatalf("recovery not logged:\n%s", logs.String())
	}
	logs.Reset()
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	f.Sweep()
	if !strings.Contains(logs.String(), "could not be read") {
		t.Fatalf("a second episode was not logged:\n%s", logs.String())
	}
}

// A directory fsync that keeps failing is an episode too.
func TestNvramFlusher_FailingDirectoryFsyncIsReportedAndRecovers(t *testing.T) {
	dir := t.TempDir()
	f, _, now := recordingFlusher(t, dir)
	writeAt(t, filepath.Join(dir, "vm1_VARS.fd"), "v1", now.Add(-time.Hour))
	failing := true
	f.sync = func(p string, want os.FileInfo) error {
		if want == nil && failing {
			return syscall.EIO
		}
		return nil
	}
	f.Sweep()
	*now = now.Add(nvramBlockedAfter + time.Second)
	f.Sweep()
	if got := f.Blocked(); len(got) != 1 || got[0].Path != dir || !strings.Contains(got[0].Error, "fsync") {
		t.Fatalf("blocked = %+v; want the directory's fsync", got)
	}
	failing = false
	f.Sweep()
	if got := f.Blocked(); len(got) != 0 {
		t.Fatalf("still blocked after the directory fsync succeeded: %+v", got)
	}
}

// A sweep stuck in an fsync is reported as blocked, naming the file it is
// stuck on, while it is stuck, and no longer once it returns.
func TestNvramFlusher_StalledSweepIsBlocked(t *testing.T) {
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
	f.onStall = func(string, time.Duration) {}
	done := make(chan struct{})
	go func() { f.watchedSweep(); close(done) }()
	var got []NvramFlushFailure
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if got = f.Blocked(); len(got) > 0 {
			break
		}
	}
	close(release)
	<-done
	if len(got) != 1 || got[0].Path != vars || !strings.Contains(got[0].Error, "has not returned") {
		t.Fatalf("blocked while stalled = %+v; want the stuck file", got)
	}
	if got := f.Blocked(); len(got) != 0 {
		t.Fatalf("still blocked after the sweep returned: %+v", got)
	}
}

// A directory-fsync episode ends when nothing is pending any more: the
// listing went back to the one last fsynced (a file added, then removed).
func TestNvramFlusher_DirectoryFsyncEpisodeEndsWhenTheChangeIsUndone(t *testing.T) {
	dir := t.TempDir()
	f, _, now := recordingFlusher(t, dir)
	a := filepath.Join(dir, "a_VARS.fd")
	writeAt(t, a, "a", now.Add(-time.Hour))
	f.Sweep() // fsyncs the listing [a]
	failing := true
	f.sync = func(p string, want os.FileInfo) error {
		if want == nil && failing {
			return syscall.EIO
		}
		return nil
	}
	b := filepath.Join(dir, "b_VARS.fd")
	writeAt(t, b, "b", now.Add(-time.Hour))
	f.Sweep()
	*now = now.Add(nvramBlockedAfter + time.Second)
	f.Sweep()
	if len(f.Blocked()) != 1 {
		t.Fatalf("setup: blocked = %+v", f.Blocked())
	}
	if err := os.Remove(b); err != nil {
		t.Fatal(err)
	}
	f.Sweep()
	if got := f.Blocked(); len(got) != 0 {
		t.Fatalf("the directory-fsync episode outlived the change: %+v", got)
	}
}

// A stall timer that fires after its sweep returned marks nothing.
func TestNvramFlusher_LateStallTimerMarksNothing(t *testing.T) {
	f := NewNvramFlusher(t.TempDir())
	gen := f.beginSweep()
	f.endSweep()
	f.markStalled(gen, "/x/vm1_VARS.fd", time.Minute)
	if got := f.Blocked(); len(got) != 0 {
		t.Fatalf("a late stall timer left %+v", got)
	}
}
