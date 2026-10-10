package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// An rbd disk is in the cluster, not on a host: there is no file to stat, and
// it is never "missing" here. Read as a missing file it was either refused as
// a lost disk or — on a failover — "rebuilt" as a local overlay of its image,
// booting the VM on a blank copy while its real disk sat in the pool.
//
// Mutation: stat rbd paths like files again (drop isNetworkDiskPath from the
// check) — the VM is refused and the test goes red.
func TestStartLocalVM_RBDDiskIsNotAMissingFile(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	r, fake, _, pulls := missingDiskVM(t, db, t.TempDir(), "vm-rbd", "running")
	if err := corrosion.UpdateDiskPlacement(ctx, db, "vm-rbd", "root", "host-a",
		"rbd:lv/vm-rbd-root", "ceph", "ceph"); err != nil {
		t.Fatal(err)
	}

	r.reconcile(ctx)

	if !startedOrDefined(fake, "vm-rbd") {
		vm, _ := corrosion.GetVM(ctx, db, "vm-rbd")
		t.Fatalf("a VM on an rbd disk was not started: row %+v", vm)
	}
	if *pulls != 0 {
		t.Fatalf("the image was pulled %d time(s) to rebuild an rbd disk", *pulls)
	}
	disks, _ := corrosion.GetVMDisks(ctx, db, "vm-rbd")
	if len(disks) != 1 || disks[0].Path != "rbd:lv/vm-rbd-root" {
		t.Fatalf("disk row changed: %+v", disks)
	}
}
