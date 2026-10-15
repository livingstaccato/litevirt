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
	if err := corrosion.DeleteVM(ctx, db, "web"); err != nil {
		t.Fatal(err)
	}
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
