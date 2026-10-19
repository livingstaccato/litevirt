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

// TestFleet_MoveUnresolved_DeleteFoundOnAPeerForgetsTheRecord.
//
// Mutation: drop the forgetMoveRecords on DeleteVM's found-on-a-peer path —
// a's record and the condition stay, red.
func TestFleet_MoveUnresolved_DeleteFoundOnAPeerForgetsTheRecord(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	aData := filepath.Join(c.tmpRoot, a.Name, "data")
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

	if _, err := c.SelfClient(a).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "pf", KeepDisks: true}); err != nil {
		t.Fatalf("delete pf from %s: %v", a.Name, err)
	}
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
