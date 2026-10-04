package fleet

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A disk placement update that FAILED on one node must not move the disk's
// recorded placement anywhere.
//
// UpdateDiskPlacement is the commit point of a volume move, and it is strict:
// a zero-row result is ErrNoRowsAffected and the move is abandoned. The
// statement used to be relayed anyway, so every peer holding the disk row
// applied a path and pool the mover had given up on — and, since parked
// updates, b itself adopted it once the row reached it. The cluster then
// converged, unanimously, on a placement no volume was ever copied to.
//
// IndependentReplicas runs no anti-entropy, so what the push loop leaves is
// what the cluster keeps; the blocks only order b's failed write ahead of the
// row reaching it, and are lifted before convergence is judged.
func TestFleet_IndependentReplicas_FailedDiskPlacementMovesNothing(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	a, b, cn := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)

	c.SetLinkFault(a, b, LinkFault{Block: true})
	c.SetLinkFault(cn, b, LinkFault{Block: true})
	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
		Name: "vm-disk", HostName: a.Name, Spec: `{}`, State: "stopped",
	}, nil, []corrosion.DiskRecord{{
		VMName: "vm-disk", DiskName: "vda", HostName: a.Name,
		Path: "/pool-a/vm-disk.qcow2", StorageType: "dir", StorageVolume: "pool-a",
	}}); err != nil {
		t.Fatalf("InsertVM on a: %v", err)
	}
	waitVM(t, cn, "vm-disk")
	if vm := vmOn(t, b, "vm-disk"); vm != nil {
		t.Fatalf("premise: b already has vm-disk: %+v", vm)
	}

	err := corrosion.UpdateDiskPlacement(ctx, b.DB, "vm-disk", "vda", a.Name,
		"/pool-b/vm-disk.qcow2", "dir", "pool-b")
	if !errors.Is(err, corrosion.ErrNoRowsAffected) {
		t.Fatalf("premise: b's placement update err=%v, want ErrNoRowsAffected", err)
	}
	// Give b's push loop time to deliver whatever it is going to deliver.
	time.Sleep(300 * time.Millisecond)

	c.ClearLinkFaults()
	waitVM(t, b, "vm-disk")
	c.WaitConverged(t, convergeTimeout)

	for _, n := range c.Nodes {
		disks, err := corrosion.GetVMDisks(ctx, n.DB, "vm-disk")
		if err != nil {
			t.Fatalf("%s: GetVMDisks: %v", n.Name, err)
		}
		if len(disks) != 1 {
			t.Fatalf("%s: disks = %+v, want exactly vda", n.Name, disks)
		}
		if d := disks[0]; d.Path != "/pool-a/vm-disk.qcow2" || d.StorageVolume != "pool-a" {
			t.Errorf("%s: vda is at %q in %q; the placement update b reported as FAILED moved it",
				n.Name, d.Path, d.StorageVolume)
		}
	}
}
