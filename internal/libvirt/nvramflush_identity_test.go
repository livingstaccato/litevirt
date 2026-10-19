package libvirt

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"
)

// failingFlusher is a recordingFlusher whose fsync of the files in failing
// fails with EIO.
func failingFlusher(t *testing.T, failing map[string]bool, dirs ...string) (*NvramFlusher, *time.Time) {
	t.Helper()
	f, _, now := recordingFlusher(t, dirs...)
	f.sync = func(p string, _ os.FileInfo) error {
		if failing[p] {
			return &nvramSyncError{syscall.EIO}
		}
		return nil
	}
	return f, now
}

// Codex I1: only "no such file" says a failed vars file is gone. A listed
// entry that cannot be looked at (lstat EIO) may still be the same file with
// the same lost pages, so its failure is kept, and the entry is reported as
// blocked once that lasts.
//
// Mutation: treat any lstat error as absence (skip the entry) and the
// failure is dropped on the first such sweep.
func TestNvramFlusher_AnEntryThatCannotBeLookedAtKeepsItsFailure(t *testing.T) {
	dir := t.TempDir()
	vars := filepath.Join(dir, "vm1_VARS.fd")
	failing := map[string]bool{vars: true}
	f, now := failingFlusher(t, failing, dir)
	writeAt(t, vars, "v1", now.Add(-time.Hour))
	f.Sweep()
	if len(f.Failures()) != 1 {
		t.Fatal("setup: no failure")
	}
	delete(failing, vars)

	var lookErr error = syscall.EIO
	f.entryInfo = func(e os.DirEntry) (os.FileInfo, error) {
		if e.Name() == "vm1_VARS.fd" && lookErr != nil {
			return nil, &fs.PathError{Op: "lstat", Path: vars, Err: lookErr}
		}
		return e.Info()
	}
	for range 3 {
		f.Sweep()
	}
	if got := f.Failures(); len(got) != 1 || got[0].Path != vars {
		t.Fatalf("after lstat EIO, failures = %+v; want %s kept", got, vars)
	}
	*now = now.Add(2 * time.Minute)
	f.Sweep()
	if b := f.Blocked(); len(b) != 1 || b[0].Path != vars {
		t.Fatalf("an entry that cannot be looked at for minutes: blocked = %+v; want %s", b, vars)
	}

	// An lstat that says no such file leaves the listing in doubt (the file
	// may have moved to a name it missed): the failure stays.
	lookErr = syscall.ENOENT
	for range 3 {
		f.Sweep()
	}
	if got := f.Failures(); len(got) != 1 {
		t.Fatalf("after an ENOENT lstat of a listed entry, failures = %+v; want it kept", got)
	}
	// Removed: two fresh listings without it, and the failure goes.
	lookErr = nil
	if err := os.Remove(vars); err != nil {
		t.Fatal(err)
	}
	f.Sweep()
	f.Sweep()
	if got := f.Failures(); len(got) != 0 {
		t.Fatalf("after the removal, failures = %+v; want none", got)
	}
}

// Codex I2: a failed vars file renamed (a replacement's cutover renames the
// temporary VM's vars file to the replaced VM's name, the same inode) keeps
// its failure under its new name, in its directory or the other watched one.
// Its lost pages went with it. Only once that inode is in no watched
// directory is the failure dropped.
//
// Mutation: drop a failure whose path left the directory without looking
// for its inode and the renamed file is clean.
func TestNvramFlusher_AFailedFileRenamedStaysFailed(t *testing.T) {
	dir, other := t.TempDir(), t.TempDir()
	tmpName := filepath.Join(dir, "web-1-replace_VARS.fd")
	f, now := failingFlusher(t, map[string]bool{tmpName: true}, dir, other)
	writeAt(t, tmpName, "v1", now.Add(-time.Hour))
	f.Sweep()
	before := f.Failures()
	if len(before) != 1 {
		t.Fatal("setup: no failure")
	}

	final := filepath.Join(dir, "web-1_VARS.fd")
	if err := os.Rename(tmpName, final); err != nil {
		t.Fatal(err)
	}
	f.Sweep()
	f.Sweep()
	got := f.Failures()
	if len(got) != 1 || got[0].Path != final || got[0].VM != "web-1" || got[0].Ino != before[0].Ino ||
		got[0].Episode != before[0].Episode {
		t.Fatalf("after the rename, failures = %+v; want %s (vm web-1), same inode and episode as %+v", got, final, before[0])
	}

	moved := filepath.Join(other, "web-1_VARS.fd")
	if err := os.Rename(final, moved); err != nil {
		t.Fatal(err)
	}
	f.Sweep()
	if got := f.Failures(); len(got) != 1 || got[0].Path != moved {
		t.Fatalf("after a move to the other directory, failures = %+v; want %s", got, moved)
	}

	if err := os.Remove(moved); err != nil {
		t.Fatal(err)
	}
	f.Sweep()
	f.Sweep()
	if got := f.Failures(); len(got) != 0 {
		t.Fatalf("after the removal, failures = %+v; want none", got)
	}
}

// Codex I3: an acknowledgement covers the failure episode the admin saw:
// its path, inode and episode. A later failed fsync of the same file is a
// new episode, with writes the admin never saw, and needs its own.
//
// Mutation: match an acknowledgement on path and inode only and the later
// episode is dropped.
func TestNvramFlusher_AnAcknowledgementCoversOnlyItsEpisode(t *testing.T) {
	dir := t.TempDir()
	vars := filepath.Join(dir, "vm1_VARS.fd")
	f, now := failingFlusher(t, map[string]bool{vars: true}, dir)
	writeAt(t, vars, "v1", now.Add(-time.Hour))
	f.Sweep()
	seen := f.Failures()
	if len(seen) != 1 || seen[0].Episode == "" {
		t.Fatalf("a failure names no episode: %+v", seen)
	}
	f.Sweep() // the next fsync of the same file fails too
	cur := f.Failures()
	if len(cur) != 1 || cur[0].Episode == seen[0].Episode {
		t.Fatalf("a second failed fsync kept the episode: %+v then %+v", seen, cur)
	}
	f.Acknowledge(seen)
	if got := f.Failures(); len(got) != 1 {
		t.Fatalf("an acknowledgement of the earlier episode dropped the later one: %+v", got)
	}
	elsewhere := cur[0]
	elsewhere.Path = filepath.Join(dir, "vm2_VARS.fd")
	f.Acknowledge([]NvramFlushFailure{elsewhere})
	if got := f.Failures(); len(got) != 1 {
		t.Fatalf("an acknowledgement naming another path dropped the failure: %+v", got)
	}
	f.Acknowledge(cur)
	if got := f.Failures(); len(got) != 0 {
		t.Fatalf("the acknowledged episode is still failed: %+v", got)
	}
}

// Codex I3: failures survive a restart in a host-local state file, whatever
// the replicated condition row says (a stale resolve can overwrite it with
// fewer files). An acknowledgement is written there too. A state file that
// cannot be read is itself a failure, kept until an admin acknowledges it.
//
// Mutation: do not write the state file and the restarted flusher holds
// nothing.
func TestNvramFlusher_FailuresSurviveARestartInTheStateFile(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(t.TempDir(), "nvram-flush-failures.json")
	a, b := filepath.Join(dir, "a_VARS.fd"), filepath.Join(dir, "b_VARS.fd")
	f, now := failingFlusher(t, map[string]bool{a: true, b: true}, dir)
	f.LoadState(state)
	writeAt(t, a, "a", now.Add(-time.Hour))
	writeAt(t, b, "b", now.Add(-time.Hour))
	f.Sweep()
	want := f.Failures()
	if len(want) != 2 {
		t.Fatalf("setup: failures %+v", want)
	}

	restarted := func() *NvramFlusher {
		g, _, _ := recordingFlusher(t, dir)
		g.LoadState(state)
		return g
	}
	g := restarted()
	if got := g.Failures(); !slices.EqualFunc(got, want, sameEpisode) {
		t.Fatalf("after a restart, failures = %+v; want %+v", got, want)
	}
	g.Acknowledge(want[:1])
	if got := restarted().Failures(); len(got) != 1 || !sameEpisode(got[0], want[1]) {
		t.Fatalf("after an acknowledgement and a restart, failures = %+v; want %+v", got, want[1])
	}

	if err := os.WriteFile(state, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := restarted()
	got := h.Failures()
	if len(got) != 1 || got[0].Path != state || got[0].Episode == "" {
		t.Fatalf("an unreadable state file: failures = %+v; want one naming %s", got, state)
	}
	h.Sweep()
	if got := restarted().Failures(); len(got) != 1 || got[0].Path != state {
		t.Fatalf("the unreadable-state failure did not survive a restart: %+v", got)
	}
	h.Acknowledge(got)
	if got := restarted().Failures(); len(got) != 0 {
		t.Fatalf("after its acknowledgement: %+v", got)
	}
}

func sameEpisode(x, y NvramFlushFailure) bool {
	return x.Path == y.Path && x.Ino == y.Ino && x.Episode == y.Episode
}

// Codex M1: the clean cache names the file, not just its mtime. A vars file
// replaced at the same path by another (a restore that keeps the timestamp)
// is flushed, and so is the directory its new entry is in; so is the same
// file truncated with its mtime put back.
//
// Mutation: compare the mtime alone and the replacement is never flushed.
func TestNvramFlusher_ASamePathReplacementKeepingTheMtimeIsFlushed(t *testing.T) {
	dir := t.TempDir()
	f, synced, now := recordingFlusher(t, dir)
	vars := filepath.Join(dir, "vm1_VARS.fd")
	mt := now.Add(-time.Hour)
	writeAt(t, vars, "v1", mt)
	f.Sweep()

	*synced = nil
	tmp := filepath.Join(t.TempDir(), "restore")
	writeAt(t, tmp, "v2", mt)
	if err := os.Rename(tmp, vars); err != nil {
		t.Fatal(err)
	}
	f.Sweep()
	if got, want := sorted(*synced), sorted([]string{vars, dir}); !slices.Equal(got, want) {
		t.Fatalf("after a same-path replacement synced %v, want %v", got, want)
	}

	*synced = nil
	if err := os.Truncate(vars, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(vars, mt, mt); err != nil {
		t.Fatal(err)
	}
	f.Sweep()
	if got := *synced; !slices.Equal(got, []string{vars}) {
		t.Fatalf("after a truncation keeping the mtime synced %v, want [%s]", got, vars)
	}
}

// Codex incoming-9 I1: the cutover renames OLD to NEW while a sweep is
// between its listing and its lstat of OLD. The listing names OLD but not
// NEW, and OLD's lstat says no such file. That listing proves nothing, so
// the failure is kept, and the next sweep finds its inode under NEW. A
// failure is dropped only once two sweeps in a row found its inode nowhere.
//
// Mutation: drop a failure the first time a listing does not hold its inode
// and it is gone after the racing sweep.
func TestNvramFlusher_ARenameDuringTheSweepKeepsTheFailure(t *testing.T) {
	dir := t.TempDir()
	oldp := filepath.Join(dir, "web-1-replace_VARS.fd")
	newp := filepath.Join(dir, "web-1_VARS.fd")
	f, now := failingFlusher(t, map[string]bool{oldp: true}, dir)
	writeAt(t, oldp, "v1", now.Add(-time.Hour))
	f.Sweep()
	before := f.Failures()
	if len(before) != 1 {
		t.Fatal("setup: no failure")
	}

	f.entryInfo = func(e os.DirEntry) (os.FileInfo, error) {
		if e.Name() == filepath.Base(oldp) {
			if err := os.Rename(oldp, newp); err != nil {
				t.Fatal(err)
			}
		}
		return e.Info()
	}
	f.Sweep()
	f.entryInfo = os.DirEntry.Info
	if got := f.Failures(); len(got) != 1 || got[0].Ino != before[0].Ino {
		t.Fatalf("after a rename during the sweep, failures = %+v; want %+v kept", got, before[0])
	}
	f.Sweep()
	if got := f.Failures(); len(got) != 1 || got[0].Path != newp || got[0].Episode != before[0].Episode {
		t.Fatalf("the next sweep: failures = %+v; want the failure under %s", got, newp)
	}

	if err := os.Remove(newp); err != nil {
		t.Fatal(err)
	}
	f.Sweep()
	if got := f.Failures(); len(got) != 1 {
		t.Fatalf("one sweep without the file dropped its failure: %+v", got)
	}
	f.Sweep()
	if got := f.Failures(); len(got) != 0 {
		t.Fatalf("two sweeps without the file: failures = %+v; want none", got)
	}
}

// Codex incoming-9 I2: a failed fsync is in the state file before anyone
// can see it (Failures, and so the condition row and an acknowledgement).
// Otherwise a tick could publish it, a stale resolve overwrite that row, and
// a restart before the sweep's end leave it in neither.
//
// Mutation: record the failure in memory first and persist it at the end of
// the sweep, and the state file lacks it while the sweep is still running.
func TestNvramFlusher_AFailureIsRecordedBeforeItIsVisible(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(t.TempDir(), NvramFlushStateFile)
	a, b := filepath.Join(dir, "a_VARS.fd"), filepath.Join(dir, "b_VARS.fd")
	f, _, now := recordingFlusher(t, dir)
	f.LoadState(state)
	writeAt(t, a, "a", now.Add(-time.Hour))
	writeAt(t, b, "b", now.Add(-time.Hour))

	var checked bool
	f.sync = func(p string, _ os.FileInfo) error {
		if p == a {
			return &nvramSyncError{syscall.EIO}
		}
		if p == b {
			// The sweep is still running (a later fsync, perhaps a slow
			// one): whatever is visible now must already be on disk.
			visible := f.Failures()
			g, _, _ := recordingFlusher(t, dir)
			g.LoadState(state)
			if len(visible) != 1 || !slices.EqualFunc(g.Failures(), visible, sameEpisode) {
				t.Errorf("mid-sweep: visible %+v, recorded %+v", visible, g.Failures())
			}
			checked = true
		}
		return nil
	}
	f.Sweep()
	if !checked {
		t.Fatal("the second file was never flushed")
	}
}
