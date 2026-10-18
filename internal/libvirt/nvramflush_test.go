package libvirt

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
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
	f.sync = func(p string) error { synced = append(synced, p); return nil }
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

// Timestamps are coarse: a second write inside the same timestamp tick as the
// one a sweep flushed leaves the mtime unchanged. A file whose mtime is
// recent is therefore flushed again on the next sweep, whatever it read last
// time, until its mtime is old enough that no write can hide behind it.
func TestNvramFlusher_RecentMtimeIsFlushedAgain(t *testing.T) {
	dir := t.TempDir()
	f, synced, now := recordingFlusher(t, dir)
	vars := filepath.Join(dir, "vm1_VARS.fd")
	writeAt(t, vars, "v1", *now)

	f.Sweep()
	*synced = nil
	f.Sweep()
	if got := *synced; !slices.Equal(got, []string{vars}) {
		t.Fatalf("recent, unchanged mtime: synced %v, want [%s]", got, vars)
	}

	*synced = nil
	*now = now.Add(nvramRecentWindow + time.Millisecond)
	f.Sweep()
	if len(*synced) != 0 {
		t.Fatalf("mtime older than the window was flushed again: %v", *synced)
	}
}

// A failed fsync is not recorded as done: the next sweep tries again.
func TestNvramFlusher_FailedSyncIsRetried(t *testing.T) {
	dir := t.TempDir()
	f, _, now := recordingFlusher(t, dir)
	vars := filepath.Join(dir, "vm1_VARS.fd")
	writeAt(t, vars, "v1", now.Add(-time.Hour))

	var tries []string
	fail := true
	f.sync = func(p string) error {
		tries = append(tries, p)
		if fail && p == vars {
			return errors.New("EIO")
		}
		return nil
	}
	f.Sweep()
	fail = false
	tries = nil
	f.Sweep()
	if !slices.Contains(tries, vars) {
		t.Fatalf("file whose fsync failed was not retried: %v", tries)
	}
	tries = nil
	f.Sweep()
	if len(tries) != 0 {
		t.Fatalf("after a successful retry it was synced again: %v", tries)
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

// The real fsync is what the flusher uses unless a test replaces it.
func TestNvramFlusher_DefaultSyncFsyncsTheFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x_VARS.fd")
	writeAt(t, p, "x", time.Now())
	f := NewNvramFlusher(dir)
	if err := f.sync(p); err != nil {
		t.Fatalf("fsync of a regular file: %v", err)
	}
	if err := f.sync(dir); err != nil {
		t.Fatalf("fsync of a directory: %v", err)
	}
}
