package fleet

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// `lv rm --keep-disks` of a VM recorded on a host removed for good, which has
// a snapshot record, deletes it as a plain `lv rm` does there: nothing on
// that host can be stopped or freed, and `lv snapshot rm`, which the
// snapshot refusal would name, forwards to the removed host and cannot
// succeed (re-review 1, N4).
//
// Red on f4b919f9c: the delete is refused, naming `lv snapshot rm`.
// Mutation: ask the snapshot refusal before the removed-host branch: red.
func TestFleet_RmKeepDisks_OnARemovedHostIsNotRefusedForSnapshots(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 2608})
	a, b, e, d := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
	insertVM(t, a, "vm-old", d.Name)
	if err := corrosion.InsertSnapshot(ctx, a.DB, corrosion.SnapshotRecord{
		ID: "snap-vm-old-s1", VMName: "vm-old", HostName: d.Name, Name: "s1", State: "ok"}); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	genesisByTick(t, c, a)
	enableRecoveryClaims(t, c)
	survivors := []*Node{a, b, e}
	removeForGood(t, c, a, d, survivors...)

	if _, err := c.SelfClient(a).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "vm-old", KeepDisks: true}); err != nil {
		t.Fatalf("lv rm --keep-disks vm-old, recorded on removed %s: %v", d.Name, err)
	}
	if vm, _ := corrosion.GetVM(ctx, a.DB, "vm-old"); vm != nil {
		t.Errorf("vm-old is still live: %+v", vm)
	}
}
