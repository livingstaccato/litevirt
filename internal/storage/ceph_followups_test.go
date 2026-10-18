package storage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// R-7. A `rbd trash mv` that exits 16 is settled by the image's id like any
// other failure: when the image did move, its purge is tracked, never
// forgotten and left in the trash untracked.
//
// Mutation "busy forgets" (the exit-16 branch forgets the record and returns
// busy, as before): red.
func TestCephTrashMove_ABusyExitIsSettledByID(t *testing.T) {
	resetCephPurges(t)
	f := newFakeCeph()
	f.installSleep(t)
	f.images["lv/a-root"] = map[string]bool{}
	f.trash = map[string]fakeTrashed{}
	f.before["trash mv"] = func() {
		f.trash["lv/"+f.idOf("lv/a-root")] = fakeTrashed{name: "a-root", source: "USER"}
		delete(f.images, "lv/a-root")
		f.fail["trash mv"] = rbdExit(16)
		delete(f.before, "trash mv")
	}
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
	if err := d.DeleteDisk(context.Background(), "rbd:lv/a-root"); err != nil {
		t.Fatalf("DeleteDisk of an image the move did move: %v", err)
	}
	if p := CephPendingPurges(); len(p) != 1 || p[0].State != CephPurgeQueued {
		t.Fatalf("pending %+v, want the moved image's purge queued", p)
	}
	attemptCephPurges()
	if len(f.trash) != 0 {
		t.Fatalf("trash %v: the moved image was left in the trash", f.trash)
	}
}

// R-8. A claimed entry (an interrupted `rbd rm` left it, source REMOVING) that
// `rbd trash rm` refuses because a client has it open is held, as a moved
// one is: it may be a running VM's disk, and is never retried into a purge.
//
// Mutation "claimed retries" (the hold skips claimed entries): red.
func TestCephPurge_AClaimedWatchedEntryIsHeld(t *testing.T) {
	resetCephPurges(t)
	f := newFakeCeph()
	f.trash = map[string]fakeTrashed{"lv/0abc": {name: "a-root", source: "REMOVING", watchedUntil: time.Hour}}
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
	d.queuePurge("lv", "0abc", "a-root", true)
	attemptCephPurges()
	p := CephPendingPurges()
	if len(p) != 1 || p[0].State != CephPurgeHeld {
		t.Fatalf("pending %+v, want the claimed entry held", p)
	}
	for k, e := range f.trash {
		e.watchedUntil = 0 // the client closes
		f.trash[k] = e
	}
	attemptCephPurges()
	if len(f.trash) != 1 || f.called("trash rm") != 1 {
		t.Fatalf("trash %v calls %v: a held claimed entry was purged", f.trash, f.calls)
	}
}

// R-5. A queue file that cannot be read nor moved aside is still named
// (CephPurgeQueueSetAside, which ceph_trash_leftover lists), and nothing
// is saved over it.
//
// Mutation "only returned" (the error path does not record it): red.
func TestResumeCephPurges_AnUnmovableUnreadableQueueIsNamed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root renames in a read-only directory")
	}
	resetCephPurges(t)
	dir := t.TempDir()
	path := filepath.Join(dir, cephPurgeStateFile)
	if err := os.WriteFile(path, []byte(`[{"pool":"lv","id":"1000`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := ResumeCephPurges(dir); err == nil || !strings.Contains(err.Error(), "nor moved aside") {
		t.Fatalf("ResumeCephPurges: %v, want the unreadable, unmovable queue reported", err)
	}
	if got := CephPurgeQueueSetAside(); len(got) != 1 || got[0] != path {
		t.Fatalf("named %q, want the unreadable queue file %s", got, path)
	}
	if raw, _ := os.ReadFile(path); string(raw) != `[{"pool":"lv","id":"1000` {
		t.Fatalf("the unreadable queue was overwritten: %q", raw)
	}
}
