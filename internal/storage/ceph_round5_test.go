package storage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// m1. `rbd trash ls --format json` prints `source` only with --long (lab 2,
// 19.2.3). The trash is listed with it, so an entry's source is read rather
// than always "". The output is the lab's, verbatim.
func TestCephTrashList_ReadsTheSourceFromTheLongListing(t *testing.T) {
	var args []string
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: func(_ context.Context, _ string, a ...string) ([]byte, error) {
		args = a
		if slices.Contains(a, "--long") {
			return []byte(`[{"id":"3976e7557657","name":"lab-c2","source":"USER","deleted_at":"Fri Oct 10 22:56:08 2026","status":"expired at Fri Oct 10 22:56:08 2026"}]`), nil
		}
		return []byte(`[{"id":"3976e7557657","name":"lab-c2"}]`), nil
	}}
	entries, err := d.trashList(context.Background(), "lv")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != "3976e7557657" || entries[0].Source != "USER" {
		t.Fatalf("entries %+v (args %q), want the source read", entries, args)
	}
}

// m2 (lab 2: `rbd trash mv` does not refuse an open image). A client that
// opens the image between the watcher check and the move keeps it open in the
// trash. The move is checked against the trashed image's watchers; one that
// has them is put back under its name, and the delete is refused as in use.
// Nothing is ever purged.
func TestCephDeleteDisk_OpenedAsItWasMovedIsRestored(t *testing.T) {
	resetCephPurges(t)
	f := newFakeCeph()
	f.images["lv/a-root"] = map[string]bool{}
	f.before["trash mv"] = func() {
		f.watched = map[string]time.Duration{"lv/a-root": time.Hour} // a VM started on it
	}
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
	err := d.DeleteDisk(context.Background(), "rbd:lv/a-root")
	var inUse *cephInUseError
	if !errors.As(err, &inUse) || !strings.Contains(err.Error(), "10.78.0.13") {
		t.Fatalf("got %v, want an in-use refusal naming the watcher", err)
	}
	if !f.has("lv/a-root") || len(f.trash) != 0 {
		t.Fatalf("image %v trash %v: an open image was left in the trash", f.has("lv/a-root"), f.trash)
	}
	attemptCephPurges()
	if p := CephPendingPurges(); len(p) != 0 || f.called("trash rm") != 0 {
		t.Fatalf("pending %+v calls %v: an open image was queued for a purge", p, f.calls)
	}
}

// m2. When the move cannot be checked (no rados here, say), the purge is the
// guard: `rbd trash rm` refuses a watched image (exit 16, lab 2), and such an
// entry is HELD, never purged automatically, and named for an operator. A
// later attempt does not purge it once the client closes.
func TestCephPurge_AWatchedTrashEntryIsHeldNotPurged(t *testing.T) {
	resetCephPurges(t)
	f := newFakeCeph()
	f.images["lv/a-root"] = map[string]bool{}
	f.fail["rados"] = errors.New(`exec: "rados": executable file not found in $PATH`)
	f.before["trash mv"] = func() {
		f.watched = map[string]time.Duration{"lv/a-root": time.Hour}
	}
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
	if err := d.DeleteDisk(context.Background(), "rbd:lv/a-root"); err != nil {
		t.Fatalf("DeleteDisk: %v", err)
	}
	attemptCephPurges()
	p := CephPendingPurges()
	if len(p) != 1 || p[0].State != CephPurgeHeld || !strings.Contains(p[0].LastError, "watchers") {
		t.Fatalf("pending %+v, want the entry held with rbd's refusal", p)
	}
	for k, e := range f.trash {
		e.watchedUntil = 0 // the client closes
		f.trash[k] = e
	}
	attemptCephPurges()
	if len(f.trash) != 1 || f.called("trash rm") != 1 {
		t.Fatalf("trash %v calls %v: a held entry was purged", f.trash, f.calls)
	}
}

// m3. An `rbd status` answer that cannot be read is "in use" (fail closed):
// the image is never moved on a guess.
func TestCephDeleteDisk_UnreadableStatusIsInUse(t *testing.T) {
	resetCephPurges(t)
	f := newFakeCeph()
	f.installSleep(t)
	f.images["lv/a-root"] = map[string]bool{}
	f.failOut["status"] = struct {
		out []byte
		err error
	}{[]byte("2026-10-10T22:56:08.660+0000 7f monclient: something odd"), nil}
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
	err := d.DeleteDisk(context.Background(), "rbd:lv/a-root")
	var inUse *cephInUseError
	if !errors.As(err, &inUse) {
		t.Fatalf("got %v, want an in-use refusal", err)
	}
	if !f.has("lv/a-root") || f.called("trash mv") != 0 {
		t.Fatalf("an image whose status was unreadable was moved: %v", f.calls)
	}
}

// m3. rbd's output is stdout and stderr together: a warning line before the
// JSON (a pool with mon_host and no conf) is not "in use", and the delete
// goes ahead.
func TestCephDeleteDisk_WarningBeforeTheJSONIsRead(t *testing.T) {
	resetCephPurges(t)
	f := newFakeCeph()
	f.images["lv/a-root"] = map[string]bool{}
	warn := "did not load config file, using default settings.\n"
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		out, err := f.run(ctx, name, args...)
		if name == "rbd" && (slices.Contains(args, "status") || slices.Contains(args, "info")) && err == nil {
			out = append([]byte(warn), out...)
		}
		return out, err
	}
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: run}
	if err := d.DeleteDisk(context.Background(), "rbd:lv/a-root"); err != nil {
		t.Fatalf("DeleteDisk: %v", err)
	}
	if f.has("lv/a-root") || len(f.trash) != 1 {
		t.Fatalf("not moved: %v", f.calls)
	}
}

// m4. The queue is written durably: the new file is synced before it is
// renamed into place, and so is the directory after.
func TestCephPurgeQueue_IsSyncedBeforeAndAfterTheRename(t *testing.T) {
	resetCephPurges(t)
	var synced []string
	prev := syncFile
	syncFile = func(f *os.File) error { synced = append(synced, f.Name()); return f.Sync() }
	t.Cleanup(func() { syncFile = prev })
	dir := t.TempDir()
	if err := ResumeCephPurges(dir); err != nil {
		t.Fatal(err)
	}
	synced = nil
	f := newFakeCeph()
	f.images["lv/a-root"] = map[string]bool{}
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
	if err := d.DeleteDisk(context.Background(), "rbd:lv/a-root"); err != nil {
		t.Fatal(err)
	}
	var file, parent bool
	for _, n := range synced {
		file = file || strings.Contains(filepath.Base(n), cephPurgeStateFile+".tmp-")
		parent = parent || n == dir
	}
	if !file || !parent {
		t.Fatalf("synced %q, want the temp file and %s", synced, dir)
	}
}

// m4. A queue file that does not parse (a torn write) is set aside under a
// name of its own, named for an operator, and the queue is still kept in the
// directory from then on: later purges are not memory-only.
func TestResumeCephPurges_UnreadableQueueIsSetAsideAndNamed(t *testing.T) {
	resetCephPurges(t)
	dir := t.TempDir()
	path := filepath.Join(dir, cephPurgeStateFile)
	if err := os.WriteFile(path, []byte(`[{"pool":"lv","id":"1000`), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = ResumeCephPurges(dir)
	aside := CephPurgeQueueSetAside()
	if len(aside) != 1 || !strings.HasPrefix(filepath.Base(aside[0]), cephPurgeStateFile+".unreadable-") {
		t.Fatalf("set aside %q, want the unreadable file kept under a name of its own", aside)
	}
	if raw, err := os.ReadFile(aside[0]); err != nil || !strings.Contains(string(raw), `"id":"1000`) {
		t.Fatalf("set-aside file %q: %v", raw, err)
	}
	f := newFakeCeph()
	f.images["lv/a-root"] = map[string]bool{}
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
	if err := d.DeleteDisk(context.Background(), "rbd:lv/a-root"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	var saved []CephPurge
	if err != nil || json.Unmarshal(raw, &saved) != nil || len(saved) != 1 {
		t.Fatalf("queue file after the set-aside: %q (%v); want the new purge kept", raw, err)
	}
	// Still named after a restart, until an operator removes it.
	resetCephPurgeQueue()
	_ = ResumeCephPurges(dir)
	if got := CephPurgeQueueSetAside(); len(got) != 1 || got[0] != aside[0] {
		t.Fatalf("after a restart: %q, want %q still named", got, aside)
	}
}

// m4. The pool's trash entries this host tracks no purge for are listed for
// an operator: litevirt-named ones (a VM disk, a staging copy), whatever
// their source. One this host's queue tracks, or an operator's own image, is
// not.
func TestCephUntrackedTrash_ListsLitevirtEntriesNoPurgeTracks(t *testing.T) {
	resetCephPurges(t)
	f := newFakeCeph()
	f.images["lv/a-root"] = map[string]bool{}
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
	if err := d.DeleteDisk(context.Background(), "rbd:lv/a-root"); err != nil {
		t.Fatal(err)
	}
	f.trash["lv/0dd1"] = fakeTrashed{name: "web-data", source: "USER"}
	f.trash["lv/0dd2"] = fakeTrashed{name: "db-root+litevirt-incoming-1791668868-5fa9c58c3a1a", source: "REMOVING"}
	f.trash["lv/0dd3"] = fakeTrashed{name: "operatorscratch", source: "USER"}
	got, err := d.UntrackedTrash(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range got {
		names = append(names, e.Pool+"/"+e.ID+" "+e.Name+" "+e.Source)
	}
	slices.Sort(names)
	want := []string{"lv/0dd1 web-data USER", "lv/0dd2 db-root+litevirt-incoming-1791668868-5fa9c58c3a1a REMOVING"}
	if !slices.Equal(names, want) {
		t.Fatalf("untracked %q, want %q", names, want)
	}
}

// m6. A `rbd trash mv` that fails (killed by its timeout, say) may have
// moved the image anyway. The move is recorded before it runs; a failed one
// is reconciled by the image's id: moved (in the trash, gone from the pool)
// → the delete is done and the purge queued; half-moved (in the trash AND
// still named in the pool) → held and named, never purged; not moved →
// forgotten, and the delete fails.
func TestCephTrashMove_AFailedMoveIsReconciledByID(t *testing.T) {
	for _, tc := range []struct {
		name    string
		effect  func(f *fakeCeph, id string)
		wantErr bool
		state   string // "-" nothing pending, else the pending entry's state
	}{
		{"moved", func(f *fakeCeph, id string) {
			f.trash["lv/"+id] = fakeTrashed{name: "a-root", source: "USER"}
			delete(f.images, "lv/a-root")
		}, false, CephPurgeQueued},
		{"half-moved", func(f *fakeCeph, id string) {
			f.trash["lv/"+id] = fakeTrashed{name: "a-root", source: "USER"}
		}, true, CephPurgeHalfMoved},
		{"not moved", func(f *fakeCeph, id string) {}, true, "-"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetCephPurges(t)
			f := newFakeCeph()
			f.images["lv/a-root"] = map[string]bool{}
			f.trash = map[string]fakeTrashed{}
			f.before["trash mv"] = func() {
				tc.effect(f, f.ids["lv/a-root"])
				f.fail["trash mv"] = errors.New("signal: killed")
			}
			d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
			err := d.DeleteDisk(context.Background(), "rbd:lv/a-root")
			if (err != nil) != tc.wantErr {
				t.Fatalf("DeleteDisk: %v, want error %v", err, tc.wantErr)
			}
			p := CephPendingPurges()
			if tc.state == "-" {
				if len(p) != 0 {
					t.Fatalf("pending %+v, want nothing", p)
				}
				return
			}
			if len(p) != 1 || p[0].State != tc.state {
				t.Fatalf("pending %+v, want one %q", p, tc.state)
			}
			attemptCephPurges()
			if tc.state == CephPurgeHalfMoved && f.called("trash rm") != 0 {
				t.Fatalf("a half-moved image was purged: %v", f.calls)
			}
			if tc.state == CephPurgeQueued && len(f.trash) != 0 {
				t.Fatalf("a moved image was not purged: %v", f.calls)
			}
		})
	}
}

// m6. A move a crash interrupted — recorded, never resolved — is reconciled
// when the daemon starts, the same way.
func TestResumeCephPurges_ReconcilesAnInterruptedMove(t *testing.T) {
	resetCephPurges(t)
	dir := t.TempDir()
	f := newFakeCeph()
	t.Cleanup(OverrideCephRunnerForTest(f.run))
	f.images["lv/live"] = map[string]bool{}
	f.ids = map[string]string{"lv/live": "11"}
	f.trash = map[string]fakeTrashed{
		"lv/22": {name: "gone", source: "USER"},
		"lv/11": {name: "live", source: "USER"},
	}
	saved := []CephPurge{
		{Pool: "lv", ID: "11", Image: "live", State: cephPurgeMoving},  // half-moved
		{Pool: "lv", ID: "22", Image: "gone", State: cephPurgeMoving},  // moved
		{Pool: "lv", ID: "33", Image: "never", State: cephPurgeMoving}, // crashed before the move
	}
	raw, _ := json.Marshal(saved)
	if err := os.WriteFile(filepath.Join(dir, cephPurgeStateFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ResumeCephPurges(dir); err != nil {
		t.Fatal(err)
	}
	attemptCephPurges()
	got := map[string]string{}
	for _, p := range CephPendingPurges() {
		got[p.ID] = p.State
	}
	if len(got) != 1 || got["11"] != CephPurgeHalfMoved {
		t.Fatalf("pending %v, want only lv/11 held as half-moved", got)
	}
	if _, ok := f.trash["lv/22"]; ok || !f.has("lv/live") {
		t.Fatalf("trash %v: the moved image not purged, or the live one touched", f.trash)
	}
}

// m5. A user delete's wait for an image's watchers fits the caller's own
// deadline: it refuses as in use before the deadline, rather than failing on
// a cancelled context.
func TestCephDeleteDisk_InUseWaitFitsTheCallersDeadline(t *testing.T) {
	resetCephPurges(t)
	f := newFakeCeph()
	f.installSleep(t)
	f.images["lv/a-root"] = map[string]bool{}
	f.watched = map[string]time.Duration{"lv/a-root": time.Hour}
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err := d.DeleteDisk(ctx, "rbd:lv/a-root")
	var inUse *cephInUseError
	if !errors.As(err, &inUse) {
		t.Fatalf("got %v, want an in-use refusal", err)
	}
	if f.now > 16*time.Second {
		t.Fatalf("waited %v for watchers with 20 s left", f.now)
	}
}
