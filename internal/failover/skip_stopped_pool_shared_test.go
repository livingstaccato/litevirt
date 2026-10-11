package failover

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// colonelpanik/litevirt#258 fix round 4: a stopped VM is re-keyed off its
// failed host only when no disk can still be written there. Its shared-disk
// fence check counts a disk shared by its POOL as shared, by the one
// definition (corrosion.DiskOnSharedStorage), so such a disk cannot slip
// past it: with the shared-storage fence enforced and no proof-grade fence,
// the VM stays where it is. (Today the host-local check before it already
// keeps such a disk — typed local — on its host; the fence check no longer
// depends on that.)
//
// Mutation "storage type only" (the fence check uses
// VMHasWritableSharedDisk) together with the host-local check by pool — red;
// the host-local check by pool alone — green (the fence check holds by
// itself).
func TestStoppedVMRekeyable_PoolSharedDiskNeedsAProofGradeFence(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	seedVMWithDisk(t, ctx, db, "pd", "bad", "local")
	if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{
		HostName: "bad", Name: "pool", Driver: "nfs", Source: "nas:/vm", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	vm, _ := corrosion.GetVM(ctx, db, "pd")
	disks, _ := corrosion.GetVMDisks(ctx, db, "pd")
	c := newTestCoordinator("coordinator", db)
	c.SharedStorageFenceEnforce = true
	c.Gate = gateEnforcing(capabilities.SharedStorageFenceV1)
	if c.stoppedVMRekeyable(ctx, "bad", *vm, disks, "") {
		t.Error("a stopped VM on a pool-shared disk was re-keyable without a proof-grade fence")
	}
}

// The same VM with its disk typed nfs is re-keyable with the fence off, as on
// main: the fence check narrows nothing a genuinely shared disk was allowed.
func TestStoppedVMRekeyable_SharedDiskFenceOffUnchanged(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	seedVMWithDisk(t, ctx, db, "sd", "bad", "nfs")
	vm, _ := corrosion.GetVM(ctx, db, "sd")
	disks, _ := corrosion.GetVMDisks(ctx, db, "sd")
	c := newTestCoordinator("coordinator", db)
	if !c.stoppedVMRekeyable(ctx, "bad", *vm, disks, "") {
		t.Error("an nfs stopped VM was not re-keyable with the fence off")
	}
}
