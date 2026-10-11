package storage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The storage tests drive purges by hand (attemptCephPurges): a background
// loop would run against a fake that is not safe for concurrent use.
func init() { cephPurgeGo = func(func()) {} }

// resetCephPurges empties the purge queue (and forgets any state file) for
// one test, and again after it.
func resetCephPurges(t *testing.T) {
	t.Helper()
	resetCephPurgeQueue()
	t.Cleanup(resetCephPurgeQueue)
}

// m1. rbd's error text comes from strerror, which glibc translates under the
// host's locale; the permission check reads that text. Every rbd runs under
// the C locale, whatever the daemon inherited.
func TestCephRunner_RunsRBDUnderTheCLocale(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\necho \"LC_ALL=$LC_ALL\"\n"
	if err := os.WriteFile(filepath.Join(dir, "rbd"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("LC_ALL", "de_DE.UTF-8")
	out, err := cephRunner(context.Background(), "rbd", "info")
	if err != nil {
		t.Fatalf("run the stand-in rbd: %v: %s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "LC_ALL=C" {
		t.Fatalf("rbd ran with %q, want LC_ALL=C", got)
	}
}

// m2. ENOENT for an image the pool still lists is not "the image is not
// there": a rename into place racing the start, or a clone whose parent is
// missing. Transient, never a refusal for good.
func TestCephProbeDisk_ENOENTButListedIsTransient(t *testing.T) {
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		for _, a := range args {
			switch a {
			case "info":
				return []byte("rbd: error opening image x: (2) No such file or directory"), rbdExit(2)
			case "ls":
				return []byte("other-image\nx\n"), nil
			}
		}
		return nil, nil
	}}
	err := d.ProbeDisk(context.Background(), "rbd:lv/x")
	if err == nil || IsPermanentCephError(err) {
		t.Fatalf("got %v, want a transient error for an image the pool lists", err)
	}
}

// I-R3-2. The probe's budget is its caller's to judge, once per VM: a probe
// asked for with less than ProbeBound left runs, bounded by what is left.
func TestCephProbeDisk_LeavesTheBudgetToItsCaller(t *testing.T) {
	var seen []string
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: probeRun("", 0, true, &seen)}
	ctx, cancel := context.WithTimeout(context.Background(), ProbeBound-time.Second)
	defer cancel()
	_ = d.ProbeDisk(ctx, "rbd:lv/x")
	if len(seen) != 1 {
		t.Fatalf("probe with %v left: rbd calls %v; want it run", ProbeBound-time.Second, seen)
	}
}

// I-R3-3. A delete moves the image to the pool's trash — quick, and the same
// whatever the image's size — and reports success then; the objects are
// purged in the background (`rbd trash rm` of the image's id), tracked until
// done. No `rbd rm` with a short cap that a large image outlives.
func TestCephDeleteDisk_MovesToTrashAndPurgesInTheBackground(t *testing.T) {
	resetCephPurges(t)
	f := newFakeCeph()
	f.images["lv/a-root"] = map[string]bool{}
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
	if err := d.DeleteDisk(context.Background(), "rbd:lv/a-root"); err != nil {
		t.Fatalf("DeleteDisk: %v", err)
	}
	if f.has("lv/a-root") || f.called("rm ") != 0 || f.called("trash mv lv/a-root") != 1 {
		t.Fatalf("not moved to the trash: %v", f.calls)
	}
	pending := CephPendingPurges()
	if len(pending) != 1 || pending[0].Pool != "lv" || pending[0].Image != "a-root" || pending[0].ID == "" {
		t.Fatalf("pending purges %+v, want lv/a-root tracked", pending)
	}
	attemptCephPurges()
	if len(f.trash) != 0 || f.called("trash rm lv/"+pending[0].ID) != 1 {
		t.Fatalf("trash %v after the purge ran (calls %v)", f.trash, f.calls)
	}
	if got := CephPendingPurges(); len(got) != 0 {
		t.Fatalf("a finished purge is still tracked: %+v", got)
	}
}

// I-R3-3. The purge deletes every object of the image, minutes for a large
// one: it runs with no short cap.
func TestCephPurge_HasNoShortCap(t *testing.T) {
	resetCephPurges(t)
	f := newFakeCeph()
	f.images["lv/big-data"] = map[string]bool{}
	var left time.Duration = -1
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "trash rm") {
			left = 0
			if dl, ok := ctx.Deadline(); ok {
				left = time.Until(dl)
			} else {
				left = 1 << 62
			}
		}
		return f.run(ctx, name, args...)
	}
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: run}
	if err := d.DeleteDisk(context.Background(), "rbd:lv/big-data"); err != nil {
		t.Fatal(err)
	}
	attemptCephPurges()
	if left < time.Hour {
		t.Fatalf("rbd trash rm ran with %v left, want no short cap", left)
	}
}

// I-R3-3. A purge that fails is kept, with its error, and retried; it is gone
// from the queue only once rbd has removed it.
func TestCephPurge_FailureIsTrackedAndRetried(t *testing.T) {
	resetCephPurges(t)
	f := newFakeCeph()
	f.images["lv/a-root"] = map[string]bool{}
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
	if err := d.DeleteDisk(context.Background(), "rbd:lv/a-root"); err != nil {
		t.Fatal(err)
	}
	f.fail["trash rm"] = rbdExit(110)
	attemptCephPurges()
	p := CephPendingPurges()
	if len(p) != 1 || p[0].Attempts != 1 || !strings.Contains(p[0].LastError, "110") {
		t.Fatalf("after a failed purge: %+v, want it kept with its error", p)
	}
	delete(f.fail, "trash rm")
	attemptCephPurges()
	if len(CephPendingPurges()) != 0 || len(f.trash) != 0 {
		t.Fatalf("purge not retried: pending %+v trash %v", CephPendingPurges(), f.trash)
	}
}

// Lab 2: a killed client's watch lasts about 30 s. A user's delete waits it
// out and succeeds, as the blocking rm it replaces did.
func TestCephDeleteDisk_DeadWatchClearsThenDeletes(t *testing.T) {
	resetCephPurges(t)
	f := newFakeCeph()
	f.installSleep(t)
	f.images["lv/a-root"] = map[string]bool{}
	f.watched = map[string]time.Duration{"lv/a-root": 30 * time.Second}
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
	if err := d.DeleteDisk(context.Background(), "rbd:lv/a-root"); err != nil {
		t.Fatalf("delete after a dead client's watch: %v", err)
	}
	if f.has("lv/a-root") || len(f.trash) != 1 {
		t.Fatalf("image %v trash %v", f.has("lv/a-root"), f.trash)
	}
}

// I-R3-3. A delete that finds its image gone from the pool but left in the
// trash by an interrupted `rbd rm` (source REMOVING) purges it, tracked. An
// image someone moved to the trash by hand (source USER, not litevirt's) is
// left for them: `rbd trash restore` must still work.
func TestCephDeleteDisk_GoneButLeftInTheTrashIsPurged(t *testing.T) {
	resetCephPurges(t)
	f := newFakeCeph()
	f.trash = map[string]fakeTrashed{
		"lv/dead01": {name: "a-root", source: "REMOVING"},
		"lv/user01": {name: "a-root", source: "USER"},
	}
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
	if err := d.DeleteDisk(context.Background(), "rbd:lv/a-root"); err != nil {
		t.Fatalf("DeleteDisk: %v", err)
	}
	p := CephPendingPurges()
	if len(p) != 1 || p[0].ID != "dead01" {
		t.Fatalf("pending %+v, want the interrupted rm's leftover lv/dead01", p)
	}
	attemptCephPurges()
	if _, ok := f.trash["lv/dead01"]; ok {
		t.Fatalf("the interrupted rm's leftover was not purged: %v", f.calls)
	}
	if _, ok := f.trash["lv/user01"]; !ok {
		t.Fatalf("an image someone else moved to the trash was purged: %v", f.calls)
	}
}

// I-R3-3. The queue survives a daemon restart: it is kept in a file under
// the data directory, and resumed at start.
func TestCephPurges_SurviveARestart(t *testing.T) {
	resetCephPurges(t)
	dir := t.TempDir()
	f := newFakeCeph()
	t.Cleanup(OverrideCephRunnerForTest(f.run))
	if err := ResumeCephPurges(dir); err != nil {
		t.Fatal(err)
	}
	f.images["lv/a-root"] = map[string]bool{}
	d := &cephDriver{pool: "lv", opts: map[string]string{"id": "litevirt", "keyring": "/k"}}
	if err := d.DeleteDisk(context.Background(), "rbd:lv/a-root"); err != nil {
		t.Fatal(err)
	}
	p0 := CephPendingPurges()
	if len(p0) != 1 {
		t.Fatalf("pending purges %+v, want one", p0)
	}
	id := p0[0].ID
	raw, err := os.ReadFile(filepath.Join(dir, cephPurgeStateFile))
	if err != nil || !strings.Contains(string(raw), id) {
		t.Fatalf("state file %q, %v; want it to name %s", raw, err, id)
	}

	resetCephPurgeQueue() // the daemon restarts
	if err := ResumeCephPurges(dir); err != nil {
		t.Fatal(err)
	}
	p := CephPendingPurges()
	if len(p) != 1 || p[0].ID != id || p[0].Opts["keyring"] != "/k" {
		t.Fatalf("after a restart: %+v, want lv/%s with the pool's identity", p, id)
	}
	attemptCephPurges()
	if len(f.trash) != 0 || f.called("trash rm lv/"+id) != 1 {
		t.Fatalf("the resumed purge did not run: %v", f.calls)
	}
	raw, _ = os.ReadFile(filepath.Join(dir, cephPurgeStateFile))
	var left []CephPurge
	if err := json.Unmarshal(raw, &left); err != nil || len(left) != 0 {
		t.Fatalf("state file after the purge: %s (%v)", raw, err)
	}
}

// I-R3-3. A rollback's staging image goes the same way: nothing is left in
// the pool, and nothing in the trash once the purge has run.
func TestCephCloneDisk_RollbackLeavesNothingInTheTrash(t *testing.T) {
	resetCephPurges(t)
	f := newFakeCeph()
	f.partialCopy = true
	f.images["lv/src-root"] = map[string]bool{}
	d := &cephDriver{pool: "lv", name: "ceph", opts: map[string]string{}, run: f.run}
	if _, err := d.CloneDisk(context.Background(), "rbd:lv/src-root", DiskOptions{VMName: "dst", DiskName: "root"}); err == nil {
		t.Fatal("a failed copy reported success")
	}
	attemptCephPurges()
	if len(f.trash) != 0 || f.called("rm ") != 0 {
		t.Fatalf("trash %v calls %v", f.trash, f.calls)
	}
}

// I-R3-3. rbd exits ENOENT for a missing keyring or conf as well as for an
// id gone from the trash: a purge is forgotten only once the trash itself
// answers without it.
func TestCephPurge_ENOENTWithoutTheTrashAnsweringIsKept(t *testing.T) {
	resetCephPurges(t)
	f := newFakeCeph()
	f.images["lv/a-root"] = map[string]bool{}
	d := &cephDriver{pool: "lv", opts: map[string]string{}, run: f.run}
	if err := d.DeleteDisk(context.Background(), "rbd:lv/a-root"); err != nil {
		t.Fatal(err)
	}
	keyringMissing := struct {
		out []byte
		err error
	}{[]byte("auth: unable to find a keyring: (2) No such file or directory"), rbdExit(2)}
	f.failOut["trash rm"] = keyringMissing
	f.failOut["trash ls"] = keyringMissing
	attemptCephPurges()
	if p := CephPendingPurges(); len(p) != 1 || len(f.trash) != 1 {
		t.Fatalf("pending %+v trash %v: a purge that never reached the cluster was forgotten", p, f.trash)
	}
}
