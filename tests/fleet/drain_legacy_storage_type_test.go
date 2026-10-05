// Fleet scenario for a disk row with no storage type.
//
// A disk row written before storage_type existed has it empty, and the storage
// copy has always taken such a disk as host-local (copiedByStorageMigration).
// Drain classified with a stricter predicate (local/dir only), so a running VM
// whose only host-local disk had an empty type went down drain's raw live
// migration, which copies no storage: it moved onto whatever file sat at that
// path on the target, or nothing.

package fleet

import (
	"context"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Mutation: classify drain's VMs with isHostLocalDiskDriver again — os1 is
// live-migrated without its disk, which never reaches the target; red.
func TestFleet_DrainMovesALegacyUntypedDiskWithItsVM(t *testing.T) {
	sc := newColdStoppedScenario(t)
	if err := sc.src.DB.Execute(context.Background(),
		`UPDATE vm_disks SET storage_type = '' WHERE vm_name = 'os1' AND disk_name = 'root'`); err != nil {
		t.Fatalf("clear the root disk's storage type: %v", err)
	}
	sc.makeRunning(t)

	progress, err := sc.drain(t)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if p := progress["os1"]; p == nil || p.Status != "done" || p.Error != "" {
		t.Fatalf("drain progress for os1 = %+v, want done with no error", p)
	}
	got, err := os.ReadFile(sc.file(sc.dst, sc.disk))
	if err != nil || string(got) != string(sc.payload) {
		t.Fatalf("os1's untyped disk did not arrive intact on %s (err %v, %d bytes)", sc.dst.Name, err, len(got))
	}
	for _, e := range sc.src.Virt.EventLog() {
		if e.Op == "migrate" && e.Domain == "os1" {
			t.Errorf("os1 was live-migrated by libvirt without a storage copy: %s", e.Note)
		}
	}
}

// A snapshotted VM is refused before its disks are copied when one of them is
// host-local; an untyped disk is host-local for that refusal too.
//
// Mutation: classify the snapshot refusal with isHostLocalDiskDriver again —
// the move goes ahead with the snapshot's backing chain left behind; red.
func TestFleet_ColdMigrationRefusesASnapshottedLegacyUntypedDisk(t *testing.T) {
	sc := newColdStoppedScenario(t)
	ctx := context.Background()
	if err := sc.src.DB.Execute(ctx,
		`UPDATE vm_disks SET storage_type = '' WHERE vm_name = 'os1' AND disk_name = 'root'`); err != nil {
		t.Fatalf("clear the root disk's storage type: %v", err)
	}
	if err := corrosion.InsertSnapshot(ctx, sc.src.DB, corrosion.SnapshotRecord{
		ID: "snap-1", VMName: "os1", HostName: sc.src.Name, Name: "before", State: "ready",
	}); err != nil {
		t.Fatalf("InsertSnapshot: %v", err)
	}
	err := sc.migrateCold(t)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "snapshot") {
		t.Fatalf("migrate --cold of a snapshotted VM with an untyped disk = %v, want the snapshot refusal", err)
	}
	if vm := sc.vm(t); vm.HostName != sc.src.Name {
		t.Fatalf("os1 row names %s, want it left on %s", vm.HostName, sc.src.Name)
	}
}
