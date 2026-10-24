package health

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// deadSetAsideStore stands in for a hard NFS mount whose server has stopped
// answering, under the set-aside copies' calls (superseded_bound.go): a glob
// of one of its directories, or an lstat, remove or rename of one of its
// paths, blocks until the test ends. Released, the call fails as an I/O error
// would, so it changes nothing on disk after the test. Every other path
// answers at once.
type deadSetAsideStore struct {
	paths   map[string]bool
	ops     map[string]bool // "" = every op
	release chan struct{}
	once    sync.Once
}

func deadSetAsideStorage(t *testing.T, paths ...string) *deadSetAsideStore {
	t.Helper()
	return deadSetAsideOps(t, "", paths...)
}

// deadSetAsideOps is deadSetAsideStorage for one op only ("glob", "lstat",
// "remove", "rename" or "link", a link keyed by its new name; "" for all):
// the others answer.
func deadSetAsideOps(t *testing.T, op string, paths ...string) *deadSetAsideStore {
	t.Helper()
	s := &deadSetAsideStore{paths: map[string]bool{}, ops: map[string]bool{op: true}, release: make(chan struct{})}
	for _, p := range paths {
		s.paths[p] = true
	}
	glob, lstat, remove, rename, link := supersededGlob, supersededLstat, supersededRemove, supersededRename, linkFile
	t.Cleanup(func() {
		supersededGlob, supersededLstat, supersededRemove, supersededRename, linkFile = glob, lstat, remove, rename, link
	})
	t.Cleanup(storage.OverrideFSCallBoundForTest(200 * time.Millisecond))
	t.Cleanup(func() { s.once.Do(func() { close(s.release) }) })
	supersededGlob = func(pattern string) ([]string, error) {
		if err := s.hold("glob", filepath.Dir(pattern)); err != nil {
			return nil, err
		}
		return filepath.Glob(pattern)
	}
	supersededLstat = func(p string) (os.FileInfo, error) {
		if err := s.hold("lstat", p); err != nil {
			return nil, err
		}
		return os.Lstat(p)
	}
	supersededRemove = func(p string) error {
		if err := s.hold("remove", p); err != nil {
			return err
		}
		return os.Remove(p)
	}
	supersededRename = func(from, to string) error {
		if err := s.hold("rename", from); err != nil {
			return err
		}
		return os.Rename(from, to)
	}
	linkFile = func(from, to string) error {
		if err := s.hold("link", to); err != nil {
			return err
		}
		return os.Link(from, to)
	}
	return s
}

func (s *deadSetAsideStore) hold(op, p string) error {
	if !s.paths[p] || !(s.ops[""] || s.ops[op]) {
		return nil
	}
	<-s.release
	return errors.New("input/output error (released at the end of the test)")
}

// setAsideReturnsWithin runs fn and fails the test if it has not returned
// within d: a sweep, RPC or pass held by storage that does not answer.
func setAsideReturnsWithin(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v: it waits on storage that does not answer", what, d)
	}
}

// The hourly sweep and `lv host superseded-disks` glob and lstat every
// host-local disk directory. A `dir` pool on a hard NFS mount whose server is
// gone blocked them for the whole outage. Each look is now bounded, and a look
// that does not answer is never "no copy there":
//
//   - the listing fails with the no-answer, never a list silently missing the
//     copies there (replica pruning keeps every copy's backing file by it);
//   - the sweep removes what it may in the directories that answered, nothing
//     under the one that did not, and reports it.
//
// Mutations: the glob and the lstat unbounded — red on the time limit; a glob
// or lstat no-answer read as nothing there — the listing succeeds and the
// sweep reports nothing: red.
func TestSupersededSweep_StorageThatDoesNotAnswerHoldsNothingAndIsNeverEmpty(t *testing.T) {
	for _, tc := range []struct {
		name string
		dead func(pooledDir, pooledCopy string) string
	}{
		{"its directory does not answer", func(dir, _ string) string { return dir }},
		{"its copy does not answer", func(_, copyPath string) string { return copyPath }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db, dataDir, paths := retentionFixture(t)
			now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
			old := now.Add(-8 * 24 * time.Hour)
			pooledDir := filepath.Dir(paths["pooled"])
			goneLocal := supersededAt(t, filepath.Join(dataDir, "disks", "deleted-root.qcow2"), old)
			gonePooled := supersededAt(t, filepath.Join(pooledDir, "deleted-root.qcow2"), old)
			deadSetAsideStorage(t, tc.dead(pooledDir, gonePooled))

			var listErr error
			setAsideReturnsWithin(t, 3*time.Second, "ListSupersededDisks", func() {
				_, listErr = ListSupersededDisks(ctx, db, dataDir)
			})
			if !storage.IsFSNoAnswer(listErr) {
				t.Fatalf("ListSupersededDisks error = %v, want the no-answer (a list missing the copies there reads as complete)", listErr)
			}

			var removed []SupersededCopy
			var purgeErr error
			setAsideReturnsWithin(t, 3*time.Second, "PurgeSupersededDisks", func() {
				removed, purgeErr = PurgeSupersededDisks(ctx, db, dataDir, 7*24*time.Hour, now, nil)
			})
			if !storage.IsFSNoAnswer(purgeErr) {
				t.Errorf("PurgeSupersededDisks error = %v, want the no-answer reported", purgeErr)
			}
			if len(removed) != 1 || removed[0].Path != goneLocal || exists(goneLocal) {
				t.Errorf("removed %+v, want only %s, from the directory that answered", removed, goneLocal)
			}
			if !exists(gonePooled) {
				t.Errorf("%s, under storage that does not answer, was removed", gonePooled)
			}
		})
	}
}

// A copy whose removal does not answer is not counted removed, and the sweep
// or the operator's --remove reports it rather than waiting on it. The sweep
// goes on past it: an eligible copy after it, in a directory that answers, is
// removed in the same pass (review M2).
//
// Mutations: the remove unbounded — red on the time limit; a remove error
// read as already gone — no error and the copy counted: red; the sweep stops
// at the no-answer — the later copy stays: red.
func TestSupersededSweep_ARemoveThatDoesNotAnswerIsNotCounted(t *testing.T) {
	ctx := context.Background()
	db, dataDir, _ := retentionFixture(t)
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	gone := supersededAt(t, filepath.Join(dataDir, "disks", "deleted-root.qcow2"), now.Add(-8*24*time.Hour))
	// Eligible too, listed after gone (set aside later), in a directory that
	// answers: the sweep removes it this pass all the same.
	later := supersededAt(t, filepath.Join(t.TempDir(), "pool", "deleted-root.qcow2"), now.Add(-15*24*time.Hour/2))
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "other", HostName: "node-a", State: "running", Spec: "{}"},
		nil, []corrosion.DiskRecord{{VMName: "other", DiskName: "root", HostName: "node-a", Path: filepath.Join(filepath.Dir(later), "other-root.qcow2"), StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	deadSetAsideOps(t, "remove", gone)

	var removed []SupersededCopy
	var err error
	setAsideReturnsWithin(t, 3*time.Second, "PurgeSupersededDisks", func() {
		removed, err = PurgeSupersededDisks(ctx, db, dataDir, 7*24*time.Hour, now, nil)
	})
	if !storage.IsFSNoAnswer(err) || len(removed) != 1 || removed[0].Path != later || exists(later) {
		t.Errorf("PurgeSupersededDisks = %+v, %v; want only %s removed (after the one that did not answer) and the no-answer", removed, err, later)
	}
	setAsideReturnsWithin(t, 3*time.Second, "RemoveSupersededDisks", func() {
		removed, err = RemoveSupersededDisks(ctx, db, dataDir, []string{gone})
	})
	if !storage.IsFSNoAnswer(err) || len(removed) != 0 {
		t.Errorf("RemoveSupersededDisks = %+v, %v; want nothing removed and the no-answer", removed, err)
	}
	if !exists(gone) {
		t.Fatalf("%s is gone", gone)
	}
}

// A failover start's set-aside renames an old copy right after looking at
// it. A server that stops answering between the two used to hold the
// reconcile pass on the rename. It is bounded now: the start gets the
// no-answer (and waits for a later pass), and no set-aside is recorded for a
// rename that is not known to have happened.
//
// Mutations: the rename unbounded — red on the time limit; the set-aside
// recorded although the rename did not answer — red.
func TestSetAsideSupersededDisk_ARenameThatDoesNotAnswerHoldsNoPass(t *testing.T) {
	db, _, r, path := supersededFixture(t, "pending")
	ctx := context.Background()
	disks, err := corrosion.GetVMDisks(ctx, db, "vm1")
	if err != nil || len(disks) != 1 {
		t.Fatalf("disks %+v, %v", disks, err)
	}
	deadSetAsideOps(t, "rename", path)
	var aside string
	setAsideReturnsWithin(t, 3*time.Second, "setAsideSupersededDisk", func() {
		aside, err = r.setAsideSupersededDisk(ctx, "vm1", "p1", disks[0])
	})
	if !storage.IsFSNoAnswer(err) || aside != "" {
		t.Fatalf("setAsideSupersededDisk = %q, %v; want the no-answer", aside, err)
	}
	if _, _, ok := strandedRow(t, db, "vm1", "node-a"); ok {
		t.Fatal("a set-aside was recorded for a rename that did not answer")
	}
	if !exists(path) {
		t.Fatalf("the disk at %s is gone", path)
	}
}

// The returning host's stranded-disk tend renames the real disk aside right
// after looking at it: bounded the same way, and the entry keeps no copy the
// rename is not known to have made.
//
// Mutation: the rename unbounded — red on the time limit.
func TestTendStrandedDisks_ARenameThatDoesNotAnswerHoldsNoPass(t *testing.T) {
	db, _, r, _, path := strandedFixture(t)
	ctx := context.Background()
	recordWeb(t, db, time.Date(2026, 10, 9, 13, 0, 0, 0, time.UTC))
	deadSetAsideOps(t, "rename", path)
	setAsideReturnsWithin(t, 3*time.Second, "tendStrandedDisks", func() { r.tendStrandedDisks(ctx) })
	_, ev, ok := strandedRow(t, db, "web", "node-a")
	if !ok || len(ev.Disks) != 1 || ev.Disks[0].Copy != "" {
		t.Fatalf("stranded disks %+v, want the entry kept with no copy", ev)
	}
	if !exists(path) {
		t.Fatalf("the real disk at %s is gone", path)
	}
}

// The operator's --restore looks at the disk's path, then renames the file
// there aside and links the copy into place: a path that does not answer is
// never "nothing there" (the copy linked over it), and a rename or link that
// does not answer holds no RPC.
//
// Mutations: the lstat, the rename or the link unbounded — red on the time
// limit; the look's no-answer read as "nothing there" — the link is tried
// and fails EEXIST, not the no-answer: red; the link's no-answer reported as
// "nothing was changed" — red.
func TestRestoreSupersededDisk_StorageThatDoesNotAnswerHoldsNoRPC(t *testing.T) {
	for _, tc := range []struct {
		name string
		op   string // the call that does not answer; "" = every call
		msg  string // the error says so
	}{
		{"the disk's path does not answer", "", "cannot be told"},
		// Only the look: read as "nothing there", the link would be tried
		// (and fail on the file that is there) — review M1.
		{"only the look at the disk's path does not answer", "lstat", "cannot be told"},
		{"the rename after the look does not answer", "rename", "lands later"},
		// The disk is renamed back over the link that did not answer.
		{"the link of the copy into place does not answer", "link", "may still land"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testReconcilerDB(t)
			ctx := context.Background()
			dataDir := t.TempDir()
			path := filepath.Join(dataDir, "disks", "web-root.qcow2")
			copyPath := supersededAt(t, path, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
			if err := os.WriteFile(path, []byte("rebuilt blank"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "web", HostName: "node-a", State: "stopped", StateDetail: "operator-stop", Spec: "{}"},
				nil, []corrosion.DiskRecord{{VMName: "web", DiskName: "root", HostName: "node-a", Path: path, StorageType: "local"}}); err != nil {
				t.Fatal(err)
			}
			deadSetAsideOps(t, tc.op, path)
			var err error
			setAsideReturnsWithin(t, 3*time.Second, "RestoreSupersededDisk", func() {
				_, err = RestoreSupersededDisk(ctx, db, dataDir, "node-a", copyPath, func(string) bool { return false }, time.Now())
			})
			if !storage.IsFSNoAnswer(err) || !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("RestoreSupersededDisk error = %v, want the no-answer, saying %q", err, tc.msg)
			}
			if b, _ := os.ReadFile(path); string(b) != "rebuilt blank" || !exists(copyPath) {
				t.Fatalf("a restore that could not look changed the disk (%q) or the copy", b)
			}
		})
	}
}
