package health

import (
	"context"
	"os"
	"path/filepath"
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

// The retention rule: a copy is removed once it is older than the retention,
// unless the VM whose disk it was set aside from is in error, pending or
// starting — a failover start that failed, or one still running, may need
// it put back. Nothing else is touched: not a young copy, not the live disk,
// not a file that merely looks similar.
//
// Mutations: drop the age check — the young copy goes and the test is red;
// drop the hold — the failed VM's copy goes and the test is red; scan only
// <dataDir>/disks — the pool directory's copy stays and the test is red.
func TestPurgeSupersededDisks_RemovesOnlyOldUnheldCopies(t *testing.T) {
	ctx := context.Background()
	db, dataDir, paths := retentionFixture(t)
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	old, young := now.Add(-8*24*time.Hour), now.Add(-time.Hour)

	oldRan := supersededAt(t, paths["ran"], old)
	youngRan := supersededAt(t, paths["ran"], young)
	oldBroke := supersededAt(t, paths["broke"], old)
	oldPooled := supersededAt(t, paths["pooled"], old)
	gone := supersededAt(t, filepath.Join(dataDir, "disks", "deleted-root.qcow2"), old) // its VM was deleted
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
	if len(removed) != 3 {
		t.Fatalf("removed %d copies (%+v), want 3", len(removed), removed)
	}
	for _, p := range []string{oldRan, oldPooled, gone} {
		if exists(p) {
			t.Errorf("%s is past the retention and its VM is not in a failed start; it was kept", p)
		}
	}
	for _, p := range []string{youngRan, oldBroke, paths["ran"], lookalike} {
		if !exists(p) {
			t.Errorf("%s was removed", p)
		}
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
