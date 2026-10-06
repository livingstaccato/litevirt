// A deleted VM's leftovers on a host that was not active when it was deleted.
//
// Observed on the lab: node-4 was drained, which moved dra, drb and drc off
// it; the three were deleted while node-4 was still draining, and node-4 kept
// vms/{dra,drb,drc}/owner_epoch for good. The delete asked only the hosts that
// were active, once.
//
// Now a draining host is asked too (it is in service, running its drain), and
// a host the delete could not reach or did not ask — one in maintenance, say —
// removes a deleted VM's marker by its own records when it becomes active.
package fleet

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// leftoverOnFormerHost: os1 ran on src, with a host-local disk detached there,
// and now runs on dst, which owns it. src keeps the detached disk file and
// os1's owner-epoch marker, as a migration (a drain's included) leaves them.
type leftoverOnFormerHost struct {
	c        *Cluster
	src, dst *Node
	post1    string
	marker   string
}

func newLeftoverOnFormerHost(t *testing.T) *leftoverOnFormerHost {
	t.Helper()
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	src, dst := c.Nodes[0], c.Nodes[1]
	srcData := filepath.Join(c.tmpRoot, src.Name, "data")
	l := &leftoverOnFormerHost{c: c, src: src, dst: dst,
		post1:  filepath.Join(srcData, "disks", "os1-post1.qcow2"),
		marker: filepath.Join(srcData, "vms", "os1", "owner_epoch"),
	}
	if err := corrosion.InsertVM(ctx, src.DB, corrosion.VMRecord{
		Name: "os1", HostName: src.Name, State: "running", CPUActual: 1, MemActual: 512,
	}, nil, []corrosion.DiskRecord{
		{VMName: "os1", DiskName: "root", HostName: src.Name, Path: "/var/lib/litevirt/disks/os1-root.qcow2",
			SizeBytes: 1 << 30, StorageType: "nfs", StorageVolume: "shared", TargetDev: "vda"},
		{VMName: "os1", DiskName: "post1", HostName: src.Name, Path: l.post1,
			SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vdb"},
	}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(l.post1), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(l.post1, 1<<30, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := src.DB.ExecuteRows(ctx, `UPDATE vms SET created_at = ? WHERE name = 'os1'`,
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.SoftDeleteDisk(ctx, src.DB, "os1", "post1"); err != nil {
		t.Fatal(err)
	}
	if err := health.WriteVMOwnerEpochMarker(srcData, "os1", 1); err != nil {
		t.Fatal(err)
	}
	src.Virt.SetState("os1", "running")
	if err := migrateAt(t, c, src, "os1", dst.Name); err != nil {
		t.Fatalf("migrate os1 %s → %s: %v", src.Name, dst.Name, err)
	}
	if err := src.Virt.UndefineDomain("os1", false); err != nil {
		t.Fatal(err)
	}
	dst.Virt.SetState("os1", "running")
	if !present(l.post1) || !present(l.marker) {
		t.Fatal("the migration did not leave the detached disk and the marker on the source")
	}
	return l
}

func (l *leftoverOnFormerHost) setSrcState(t *testing.T, state string) {
	t.Helper()
	if err := corrosion.UpdateHostState(context.Background(), l.src.DB, l.src.Name, state); err != nil {
		t.Fatalf("mark %s %s: %v", l.src.Name, state, err)
	}
}

func (l *leftoverOnFormerHost) deleteOnDst(t *testing.T) {
	t.Helper()
	if _, err := l.c.SelfClient(l.dst).DeleteVM(context.Background(), &pb.DeleteVMRequest{Name: "os1"}); err != nil {
		t.Fatalf("DeleteVM on %s: %v", l.dst.Name, err)
	}
}

func waitGone(paths ...string) bool {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		left := false
		for _, p := range paths {
			left = left || present(p)
		}
		if !left {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// A host that is draining when the VM is deleted is asked like an active one,
// and removes both leftovers while it is still draining.
//
// Mutation: plan the cleanup for active hosts only — both stay on src.
func TestFleet_DeleteReachesAHostThatIsDraining(t *testing.T) {
	l := newLeftoverOnFormerHost(t)
	l.setSrcState(t, "draining")
	l.deleteOnDst(t)
	if !waitGone(l.marker, l.post1) {
		t.Fatalf("%s, draining, still holds os1's leftovers after its delete (marker %v, detached disk %v)",
			l.src.Name, present(l.marker), present(l.post1))
	}
}

// A host in maintenance when the VM is deleted is not asked. Once undrained it
// removes the deleted VM's marker itself, by its own records. (The detached
// disk stays: only the deleting owner can tell which detached files were that
// incarnation's.)
//
// Mutations: never sweep on activation — the marker stays after the undrain;
// ask maintenance hosts at delete time — the marker is gone before the
// undrain.
func TestFleet_HostRemovesADeletedVMsMarkerOnceItIsActiveAgain(t *testing.T) {
	l := newLeftoverOnFormerHost(t)
	l.setSrcState(t, "maintenance")
	ctx := context.Background()
	l.src.Server.DeletedVMMarkerSweepTick(ctx) // the host's loop sees it in maintenance
	l.deleteOnDst(t)
	// The delete's fan-out runs in the background; give it time to have
	// (wrongly) reached src before checking that it did not.
	time.Sleep(500 * time.Millisecond)
	if !present(l.marker) {
		t.Fatal("the delete reached a host in maintenance")
	}
	l.src.Server.DeletedVMMarkerSweepTick(ctx)
	if !present(l.marker) {
		t.Fatal("the marker was swept while the host is in maintenance")
	}

	if _, err := l.c.SelfClient(l.dst).UndrainHost(ctx, &pb.UndrainHostRequest{Name: l.src.Name}); err != nil {
		t.Fatalf("lv host undrain %s: %v", l.src.Name, err)
	}
	l.src.Server.DeletedVMMarkerSweepTick(ctx)
	if present(l.marker) {
		t.Fatalf("%s is active again and still holds vms/os1/owner_epoch of the deleted os1", l.src.Name)
	}
	if present(filepath.Dir(l.marker)) {
		t.Fatalf("%s still holds the vms/os1 directory", l.src.Name)
	}
	if !present(l.post1) {
		t.Fatal("the sweep removed a detached disk; only the deleting owner may name those")
	}
}
