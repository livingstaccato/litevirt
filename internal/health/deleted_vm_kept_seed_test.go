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

// The seed of a deleted VM kept where it was — after `lv rm --keep-disks`,
// on a failover's old host where no create of the name follows — is listed
// too, marked a seed, so an operator can find it (re-review N2). The seed of
// a VM that exists, or one stamped for another VM of the name, is not.
//
// Mutation: drop keptSeedsInPlace from ListKeptDisks — the deleted VM's seed
// is not listed, red; drop the stamp match — the other VM's is, red.
func TestListKeptDisks_ListsADeletedVMsSeedKeptInPlace(t *testing.T) {
	db := corrosion.NewTestClientT(t)
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	vm := func(name, u string, deleted bool) {
		t.Helper()
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: name, HostName: "node-a", State: "stopped",
			Spec: `{"uuid":"` + u + `"}`}, nil, nil); err != nil {
			t.Fatal(err)
		}
		if deleted {
			if err := corrosion.DeleteVM(ctx, db, name); err != nil {
				t.Fatal(err)
			}
		}
	}
	dataDir := t.TempDir()
	seed := func(name, owner string) string {
		t.Helper()
		iso := lv.CloudInitISOPath(dataDir, name)
		if err := os.MkdirAll(filepath.Dir(iso), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(iso, []byte("user-data"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := cloudinit.StampSeed(iso, owner); err != nil {
			t.Fatal(err)
		}
		return iso
	}
	vm("gone", "gone-1", true)
	kept := seed("gone", "gone-1")
	vm("old", "old-1", true)
	legacy := seed("old", "")
	vm("live", "live-1", false)
	seed("live", "live-1")
	vm("other", "other-1", true)
	seed("other", "other-2")

	got, err := ListKeptDisks(ctx, db, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]KeptCopy{}
	for _, k := range got {
		listed[k.Path] = k
	}
	for _, want := range []string{kept, legacy} {
		if k, ok := listed[want]; !ok || !k.Seed || k.DiskPath != want {
			t.Errorf("%s: listed %+v, %v; want it listed as a seed kept in place", want, k, ok)
		}
	}
	if len(got) != 2 {
		t.Errorf("kept files = %+v; want only the deleted VMs' own seeds", got)
	}
}
