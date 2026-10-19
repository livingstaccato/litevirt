// A delete whose row names this host while the VM's domain is on a peer: the
// peer deletes it, and this host tombstones the row. An unresolved volume
// move recorded here went with the VM, so this host drops its record and the
// condition clears.
//
// Multi-node by construction: the domain the delete finds is on another node,
// reached by the peer-search probe over gRPC.
package fleet

import (
	"context"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// peerDeleteFixture is VM pf recorded on a (node-0) with its domain on b
// (node-1), and a move of its disk recorded on a with its condition open.
func peerDeleteFixture(t *testing.T) (c *Cluster, a, b *Node, aData string) {
	t.Helper()
	ctx := context.Background()
	c = New(t, Options{Nodes: 2})
	a, b = c.Nodes[0], c.Nodes[1]
	aData = filepath.Join(c.tmpRoot, a.Name, "data")
	src := sharedDiskVM(t, c, a, "pf", a.Name, "stopped", "")
	pumpMutations(t, c, a, b)
	if err := b.Virt.DefineDomain(`<domain><name>pf</name><devices><disk type='file' device='disk'><source file='` + src +
		`'/><target dev='vda' bus='virtio'/></disk></devices></domain>`); err != nil {
		t.Fatal(err)
	}
	if err := health.RecordUnresolvedMove(aData, health.UnresolvedMove{VM: "pf", Disk: "root", TargetDev: "vda",
		Src: src, Dst: src + ".copy", Live: true}); err != nil {
		t.Fatal(err)
	}
	if err := health.PublishUnresolvedMoves(ctx, a.DB, aData, a.Name, "pf"); err != nil {
		t.Fatal(err)
	}
	if !health.MoveConditionCovers(ctx, a.DB, "pf", "root") {
		t.Fatal("control: no open condition before the delete")
	}
	return c, a, b, aData
}

// assertPeerDeleteForgot checks that pf's domain is gone from b, its row from
// a, and a's record and condition with them.
func assertPeerDeleteForgot(t *testing.T, a, b *Node, aData string) {
	t.Helper()
	ctx := context.Background()
	if b.Virt.DomainExists("pf") {
		t.Fatalf("pf's domain is still on %s: the delete did not take the peer path", b.Name)
	}
	if vm, _ := corrosion.GetVM(ctx, a.DB, "pf"); vm != nil {
		t.Fatalf("pf's row survived on %s: %+v", a.Name, vm)
	}
	if ms, err := health.UnresolvedMovesOf(aData, "pf"); err != nil || len(ms) != 0 {
		t.Fatalf("%s kept pf's move records: %+v %v", a.Name, ms, err)
	}
	if health.MoveConditionCovers(ctx, a.DB, "pf", "root") {
		t.Fatalf("pf's condition is still open on %s", a.Name)
	}
}

// TestFleet_MoveUnresolved_DeleteFoundOnAPeerForgetsTheRecord: the one
// delete that finds the domain on b, deletes it there and tombstones the row
// on a, forgets a's record and condition.
//
// Mutation: drop the forgetMoveRecords on DeleteVM's found-on-a-peer path —
// a's record and the condition stay, red.
func TestFleet_MoveUnresolved_DeleteFoundOnAPeerForgetsTheRecord(t *testing.T) {
	c, a, b, aData := peerDeleteFixture(t)
	if _, err := c.SelfClient(a).DeleteVM(context.Background(), &pb.DeleteVMRequest{Name: "pf", KeepDisks: true}); err != nil {
		t.Fatalf("delete pf from %s: %v", a.Name, err)
	}
	assertPeerDeleteForgot(t, a, b, aData)
}

// TestFleet_MoveUnresolved_DeleteFoundOnAPeerKeepsTheRecordUntilItsTombstone:
// a first delete, whose tombstone of the row on a fails after the peer
// deleted the domain, keeps a's record and the condition: the row is still
// live there. The retry finds no domain anywhere and completes the delete
// through the stale-record path.
//
// Mutation: move the found-on-a-peer forget above the row's tombstone — the
// failed delete drops them, red.
func TestFleet_MoveUnresolved_DeleteFoundOnAPeerKeepsTheRecordUntilItsTombstone(t *testing.T) {
	ctx := context.Background()
	c, a, b, aData := peerDeleteFixture(t)
	if err := localExec(ctx, a.DB, `CREATE TRIGGER fail_pf_tombstone BEFORE UPDATE OF deleted_at ON vms
		WHEN OLD.name = 'pf' AND NEW.deleted_at IS NOT NULL BEGIN SELECT RAISE(ABORT, 'injected tombstone failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelfClient(a).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "pf", KeepDisks: true}); err == nil {
		t.Fatal("the delete succeeded although its tombstone on a was made to fail")
	}
	if b.Virt.DomainExists("pf") {
		t.Fatalf("pf's domain is still on %s: the delete did not take the peer path", b.Name)
	}
	if vm, _ := corrosion.GetVM(ctx, a.DB, "pf"); vm == nil {
		t.Fatal("control: the failed delete tombstoned pf's row on a")
	}
	if ms, err := health.UnresolvedMovesOf(aData, "pf"); err != nil || len(ms) == 0 {
		t.Fatalf("the failed delete dropped %s's move record: %+v %v", a.Name, ms, err)
	}
	if !health.MoveConditionCovers(ctx, a.DB, "pf", "root") {
		t.Fatal("the failed delete resolved pf's condition")
	}
	if err := localExec(ctx, a.DB, `DROP TRIGGER fail_pf_tombstone`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelfClient(a).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "pf", KeepDisks: true}); err != nil {
		t.Fatalf("retried delete of pf from %s: %v", a.Name, err)
	}
	assertPeerDeleteForgot(t, a, b, aData)
}
