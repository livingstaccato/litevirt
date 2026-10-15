package health

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

func fileExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// deleteWeb deletes web as `lv rm web` on this release does: its delete
// marks the open records of web (MarkStrandedForDelete) before the
// tombstone.
func deleteWeb(t *testing.T, db *corrosion.Client) {
	t.Helper()
	ctx := context.Background()
	if err := MarkStrandedForDelete(ctx, db, "node-b", "web", false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteVM(ctx, db, "web"); err != nil {
		t.Fatal(err)
	}
}

func strandedOpen(t *testing.T, db *corrosion.Client) bool {
	t.Helper()
	row, _, ok := strandedRow(t, db, "web", "node-a")
	return ok && row.Lifecycle != corrosion.ConditionResolved
}

// webSeed writes web's seed on node-a, stamped for the VM whose spec uuid is
// owner ("" leaves it unstamped).
func webSeed(t *testing.T, dataDir, owner string) string {
	t.Helper()
	iso := lv.CloudInitISOPath(dataDir, "web")
	if err := os.MkdirAll(filepath.Dir(iso), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(iso, []byte("seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cloudinit.StampSeed(iso, owner); err != nil {
		t.Fatal(err)
	}
	return iso
}

// web was recorded on node-a while node-a was down, deleted, created again
// and deleted again: the record's entry is the first web's, the tombstone the
// second's. The file at the path is left where it is (it was not recorded for
// the VM the tombstone names), and the record is resolved.
//
// Mutation: drop the incarnation match in tendDeletedVMStranded — the file
// is set aside.
func TestTendDeletedVMStranded_LeavesAFileNotRecordedForTheDeletedVM(t *testing.T) {
	db, _, r, _, path := strandedFixture(t)
	ctx := context.Background()
	recordWeb(t, db, time.Now())
	disks, err := corrosion.GetVMDisks(ctx, db, "web")
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteVM(ctx, db, "web"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "web", HostName: "node-b", State: "running"}, nil, disks); err != nil {
		t.Fatal(err)
	}
	if err := db.Execute(ctx, `UPDATE vms SET created_at = ? WHERE name = 'web'`,
		time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	deleteWeb(t, db)
	r.tendStrandedDisks(ctx)
	if !fileExists(path) {
		t.Fatalf("the file at %s, recorded for another web, was moved", path)
	}
	if strandedOpen(t, db) {
		t.Fatal("the record is still open")
	}
}

// The deleted VM's own seed goes; a seed stamped for another VM of the name
// (one being created here again), or an unstamped one, stays.
//
// Mutation: drop the stamp match in removeDeletedVMSeed — the other VM's
// seed is removed.
func TestTendDeletedVMStranded_RemovesOnlyTheDeletedVMsSeed(t *testing.T) {
	for _, tc := range []struct {
		name, owner string
		gone        bool
	}{
		{"the deleted VM's", "web-1", true},
		{"another VM's", "web-2", false},
		{"unstamped", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, _, r, dataDir, _ := strandedFixture(t)
			ctx := context.Background()
			if err := db.Execute(ctx, `UPDATE vms SET spec = ? WHERE name = 'web'`, `{"uuid":"web-1"}`); err != nil {
				t.Fatal(err)
			}
			recordWeb(t, db, time.Now())
			r.tendStrandedDisks(ctx) // sets the disk aside
			iso := webSeed(t, dataDir, tc.owner)
			if err := corrosion.DeleteVM(ctx, db, "web"); err != nil {
				t.Fatal(err)
			}
			r.tendStrandedDisks(ctx)
			if fileExists(iso) == tc.gone {
				t.Fatalf("seed present %v, want %v", fileExists(iso), !tc.gone)
			}
			if tc.gone && fileExists(cloudinit.SeedOwnerPath(iso)) {
				t.Fatal("the seed's stamp was left behind")
			}
			if strandedOpen(t, db) {
				t.Fatal("the record is still open")
			}
		})
	}
}

// With no libvirt connection a host cannot tell whether a domain of the name
// is live: it acts on nothing, and resolves the record rather than holding it
// open for good.
//
// Mutation: wait instead — the record stays open.
func TestTendDeletedVMStranded_WithoutLibvirtResolvesAndActsOnNothing(t *testing.T) {
	db, _, _, dataDir, path := strandedFixture(t)
	ctx := context.Background()
	r := NewReconciler("node-a", dataDir, db, nil)
	recordWeb(t, db, time.Now())
	if err := corrosion.DeleteVM(ctx, db, "web"); err != nil {
		t.Fatal(err)
	}
	r.tendStrandedDisks(ctx)
	if !fileExists(path) {
		t.Fatal("the disk was moved with no way to tell whether a domain uses it")
	}
	if strandedOpen(t, db) {
		t.Fatal("the record is still open")
	}
}

// A VM of the name created again on this host writes its disk before its row
// reaches the replica. Once that row is there — here, landing while the pass
// looks at the file — the deleted VM's disk path is not touched.
//
// Mutation: drop the live-row check before the rename (stillMay) — the new
// VM's disk is renamed.
func TestTendDeletedVMStranded_NeverMovesADiskOnceALiveRowOfTheNameExists(t *testing.T) {
	db, _, r, _, path := strandedFixture(t)
	ctx := context.Background()
	recordWeb(t, db, time.Now())
	deleteWeb(t, db)
	inserted := false
	r.diskLstat = func(p string) (os.FileInfo, error) {
		if !inserted && p == path {
			inserted = true
			// The row first, its disk records after it: only the row
			// can tell the pass, not a reference to the path.
			if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "web", HostName: "node-a", State: "creating"}, nil, nil); err != nil {
				t.Errorf("insert the new web: %v", err)
			}
		}
		return os.Lstat(p)
	}
	r.tendStrandedDisks(ctx)
	if !inserted {
		t.Fatal("the pass never looked at the disk")
	}
	if !fileExists(path) {
		t.Fatalf("the disk at %s was moved with a live row of web in the replica", path)
	}
}

// A disk path that reads as missing once the VM is deleted keeps its entry
// while its directory is empty, as an unmounted volume's mount point is: the
// disk comes back with the volume. The record stays open; once the path is
// back, the next pass sets the disk aside and resolves it. (Missing from a
// directory that lists other files, it is gone: see
// TestTendStrandedDisks_ClearsWhenNothingIsLeftToKeep.)
//
// Mutation: drop the entry of a missing path on the deleted-VM pass — the
// record is resolved while the path is missing.
func TestTendDeletedVMStranded_KeepsTheEntryOfAPathThatReadsAsMissing(t *testing.T) {
	db, _, r, _, path := strandedFixture(t)
	ctx := context.Background()
	recordWeb(t, db, time.Now())
	deleteWeb(t, db)
	hidden := filepath.Join(t.TempDir(), "volume")
	if err := os.Rename(path, hidden); err != nil { // the volume is unmounted
		t.Fatal(err)
	}
	r.tendStrandedDisks(ctx)
	if !strandedOpen(t, db) {
		t.Fatal("the record was resolved while the disk's path reads as missing")
	}
	if err := os.Rename(hidden, path); err != nil { // the volume is mounted
		t.Fatal(err)
	}
	r.tendStrandedDisks(ctx)
	if fileExists(path) {
		t.Fatalf("the disk back at %s was not set aside", path)
	}
	if strandedOpen(t, db) {
		t.Fatal("the record is still open once the disk is set aside")
	}
}

// A domain of the name that starts after the pass first looked at it, and
// before the rename, keeps the disk at its path: the state is read again
// immediately before the rename.
//
// Mutation: drop the domain re-read in stillMay — the disk is renamed under
// the running domain.
func TestTendDeletedVMStranded_ReReadsTheDomainBeforeTheRename(t *testing.T) {
	db, fake, r, _, path := strandedFixture(t)
	ctx := context.Background()
	recordWeb(t, db, time.Now())
	deleteWeb(t, db)
	fake.DefineStoppedDomain("web", "52:54:00:00:00:02")
	reads := 0
	fake.FailDomainStateReason = func(name string) error {
		if name == "web" {
			reads++
			if reads == 2 { // after the first look: the domain starts
				fake.SetState("web", "running")
			}
		}
		return nil
	}
	r.tendStrandedDisks(ctx)
	if reads < 2 {
		t.Fatalf("the domain's state was read %d time(s) before the rename, want it read again", reads)
	}
	if !fileExists(path) {
		t.Fatal("the disk was renamed under a domain that started before the rename")
	}
}
