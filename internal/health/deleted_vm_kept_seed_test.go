package health

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A seed `lv rm --keep-disks` kept is never removed: the reconciler's pass
// on a host with an open record of the deleted VM keeps the VM's own seed
// with its disks (review m8). The deleted VM's seed after a delete that kept
// nothing still goes (TestTendDeletedVMStranded_RemovesOnlyTheDeletedVMsSeed).
//
// Mutation: drop the deleteKept check before removeDeletedVMSeed — the seed
// is removed, red.
func TestTendDeletedVMStranded_KeepsTheSeedOfADeleteThatKeptTheDisks(t *testing.T) {
	db, _, r, dataDir, _ := strandedFixture(t)
	ctx := context.Background()
	if err := db.Execute(ctx, `UPDATE vms SET spec = ? WHERE name = 'web'`, `{"uuid":"web-1"}`); err != nil {
		t.Fatal(err)
	}
	recordWeb(t, db, time.Now())
	r.tendStrandedDisks(ctx) // sets the disk aside
	iso := webSeed(t, dataDir, "web-1")
	// lv rm --keep-disks web, on its owner.
	if err := MarkStrandedForDelete(ctx, db, "node-b", "web", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteVM(ctx, db, "web"); err != nil {
		t.Fatal(err)
	}
	r.tendStrandedDisks(ctx)
	if !fileExists(iso) {
		t.Fatal("the reconciler removed the seed a --keep-disks delete kept")
	}
}

// The listing of kept files includes the cloud-init seeds a create moved to
// .kept- names, marked as seeds, and not the stamp beside one (review m4):
// they can hold user-data, and an operator has to find them to remove them.
//
// Mutation: leave the seed directory out of ListKeptDisks — the seed is not
// listed, red.
func TestListKeptDisks_ListsAKeptSeed(t *testing.T) {
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	iso := webSeed(t, dataDir, "web-1")
	kept := KeptName(iso, time.Now())
	if err := os.Rename(iso, kept); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(cloudinit.SeedOwnerPath(iso), cloudinit.SeedOwnerPath(kept)); err != nil {
		t.Fatal(err)
	}
	got, err := ListKeptDisks(context.Background(), db, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Path != kept || got[0].DiskPath != iso || !got[0].Seed {
		t.Fatalf("kept files = %+v; want the seed %s, from %s, marked a seed", got, kept, iso)
	}
}
