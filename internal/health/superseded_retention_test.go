package health

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// supersededAt writes a set-aside copy of disk path, named as
// setAsideSupersededDisk names it, set aside at t.
func supersededAt(t *testing.T, path string, at time.Time) string {
	t.Helper()
	p := supersededName(path, at)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("old copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

// retentionFixture records, on host node-a, VM "ran" (running) and VM "broke"
// (error, its failover start failed), each with one host-local disk under
// <dataDir>/disks, and VM "pooled" with its disk in a pool directory outside
// it. It returns the data dir and the disk paths.
func retentionFixture(t *testing.T) (*corrosion.Client, string, map[string]string) {
	t.Helper()
	db := testReconcilerDB(t)
	ctx := context.Background()
	dataDir := t.TempDir()
	paths := map[string]string{
		"ran":    filepath.Join(dataDir, "disks", "ran-root.qcow2"),
		"broke":  filepath.Join(dataDir, "disks", "broke-root.qcow2"),
		"pooled": filepath.Join(t.TempDir(), "pool", "pooled-root.qcow2"),
	}
	for vm, state := range map[string]string{"ran": "running", "broke": "error", "pooled": "running"} {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: vm, HostName: "node-a", State: state, Spec: "{}"},
			nil, []corrosion.DiskRecord{{VMName: vm, DiskName: "root", HostName: "node-a", Path: paths[vm], StorageType: "local"}}); err != nil {
			t.Fatal(err)
		}
	}
	return db, dataDir, paths
}

// The retention rule: a copy is removed once it is older than the retention
// and the VM whose disk it was set aside from no longer exists. While the VM
// exists, in any state, the copy may be the only one of that VM's data from
// before a failover, so the sweep never removes it: only an operator does
// (RemoveSupersededDisks). Nothing else is touched: not a young copy, not the
// live disk, not a file that merely looks similar.
//
// Mutations: drop the retention of a copy whose VM exists — the running VM's
// old copies (ran, pooled) go and the test is red; drop the age check — the
// young copy of the deleted VM goes and the test is red; scan only
// <dataDir>/disks — the pool directory's deleted-VM copy stays and the test
// is red.
func TestPurgeSupersededDisks_KeepsEveryCopyWhileItsVMExists(t *testing.T) {
	ctx := context.Background()
	db, dataDir, paths := retentionFixture(t)
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	old, young := now.Add(-8*24*time.Hour), now.Add(-time.Hour)

	oldRan := supersededAt(t, paths["ran"], old)
	youngRan := supersededAt(t, paths["ran"], young)
	oldBroke := supersededAt(t, paths["broke"], old)
	oldPooled := supersededAt(t, paths["pooled"], old)
	gone := supersededAt(t, filepath.Join(dataDir, "disks", "deleted-root.qcow2"), old) // its VM was deleted
	youngGone := supersededAt(t, filepath.Join(dataDir, "disks", "deleted-root.qcow2"), young)
	gonePooled := supersededAt(t, filepath.Join(filepath.Dir(paths["pooled"]), "deleted-root.qcow2"), old)
	if err := os.WriteFile(paths["ran"], []byte("live disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	lookalike := filepath.Join(dataDir, "disks", "ran-root.qcow2.superseded-notatime")
	if err := os.WriteFile(lookalike, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	removed, err := PurgeSupersededDisks(ctx, db, dataDir, 7*24*time.Hour, now)
	if err != nil {
		t.Fatalf("PurgeSupersededDisks: %v", err)
	}
	for _, p := range []string{gone, gonePooled} {
		if exists(p) {
			t.Errorf("%s is past the retention and its VM is gone; it was kept", p)
		}
	}
	for _, p := range []string{oldRan, youngRan, oldBroke, oldPooled, youngGone, paths["ran"], lookalike} {
		if !exists(p) {
			t.Errorf("%s was removed", p)
		}
	}
	if len(removed) != 2 {
		t.Fatalf("removed %d copies (%+v), want 2", len(removed), removed)
	}
}

// An operator removes a copy its VM still holds by naming it: the sweep and a
// bare purge never do. A copy held by a failed or unfinished start is not
// removed even by name, and a path that is not a set-aside copy is refused.
//
// Mutations: let RemoveSupersededDisks skip a retained copy — the named copy
// of the running VM stays and the test is red; let it remove a held copy —
// the failed VM's copy goes and the test is red.
func TestRemoveSupersededDisks_RemovesOnlyWhatIsNamed(t *testing.T) {
	ctx := context.Background()
	db, dataDir, paths := retentionFixture(t)
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	ran1 := supersededAt(t, paths["ran"], now.Add(-time.Hour))
	ran2 := supersededAt(t, paths["ran"], now.Add(-2*time.Hour))
	broke := supersededAt(t, paths["broke"], now.Add(-time.Hour))
	if err := os.WriteFile(paths["ran"], []byte("live disk"), 0o600); err != nil {
		t.Fatal(err)
	}

	if gone, err := PurgeSupersededDisks(ctx, db, dataDir, 0, now); err != nil || len(gone) != 0 {
		t.Fatalf("a bare purge removed %+v (err %v); a copy whose VM exists is removed only by name", gone, err)
	}
	removed, err := RemoveSupersededDisks(ctx, db, dataDir, []string{ran1})
	if err != nil {
		t.Fatalf("RemoveSupersededDisks: %v", err)
	}
	if len(removed) != 1 || removed[0].Path != ran1 || exists(ran1) {
		t.Fatalf("removed %+v; want exactly %s gone", removed, ran1)
	}
	if !exists(ran2) {
		t.Fatalf("%s was not named and was removed", ran2)
	}
	if _, err := RemoveSupersededDisks(ctx, db, dataDir, []string{broke}); err == nil || !exists(broke) {
		t.Fatalf("a copy held by a failed start was removed by name (err %v)", err)
	}
	if _, err := RemoveSupersededDisks(ctx, db, dataDir, []string{paths["ran"]}); err == nil || !exists(paths["ran"]) {
		t.Fatalf("the live disk, which is not a set-aside copy, was accepted for removal (err %v)", err)
	}
}

// The listing names, for each copy, the disk and VM it came from, when it was
// set aside, and why it is held, so an operator can decide what to keep.
func TestListSupersededDisks_SaysWhatAndWhy(t *testing.T) {
	ctx := context.Background()
	db, dataDir, paths := retentionFixture(t)
	at := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	p := supersededAt(t, paths["broke"], at)

	got, err := ListSupersededDisks(ctx, db, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("listed %+v, want the one copy", got)
	}
	c := got[0]
	if c.Path != p || c.DiskPath != paths["broke"] || !c.SetAsideAt.Equal(at) || c.VM != "broke" ||
		c.VMState != "error" || c.Held == "" || c.SizeBytes != int64(len("old copy")) {
		t.Fatalf("listed %+v", c)
	}
}

// A copy whose VM exists and is not in a failed start is listed as retained,
// with why, so the listing says the sweep will not remove it.
//
// Mutation: leave Retained empty — the test is red.
func TestListSupersededDisks_SaysACopyIsRetainedWhileItsVMExists(t *testing.T) {
	ctx := context.Background()
	db, dataDir, paths := retentionFixture(t)
	p := supersededAt(t, paths["ran"], time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC))

	got, err := ListSupersededDisks(ctx, db, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Path != p || got[0].Held != "" || !strings.Contains(got[0].Retained, "ran") {
		t.Fatalf("listed %+v, want the copy retained for VM ran", got)
	}
}
