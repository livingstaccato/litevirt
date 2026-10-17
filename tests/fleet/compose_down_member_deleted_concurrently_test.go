// lv compose down racing another deleter of the same member (lab 2
// 2026-10-17, anomaly 2): the stack reconciler on another host took the
// teardown up as it began and deleted members first. The coordinator's delete
// of such a member reached the owner, which held the tombstone and answered
// NotFound; the coordinator's own replica had not received the tombstone, so
// it reported a member that was deleted as a failed deletion, and compose down
// exited non-zero for a teardown that removed every VM. Only a fleet reaches
// this: the coordinator, the owner and the replication between them are
// different daemons.
package fleet

import (
	"context"
	"encoding/json"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Mutation: drop the tombstone answer in the owner's DeleteVM
// (deleteOfNoLiveRow) — the member is an error and the stack stays
// "deleting", red.
func TestFleet_ComposeDown_AMemberDeletedConcurrentlyIsReportedDeleted(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	ctx := context.Background()
	coord, owner, other := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	// The owner's tombstone must not reach the coordinator; every other RPC
	// still flows.
	c.Partition(coord, owner)
	c.Partition(coord, other)

	const createdAt = "2026-10-17T14:20:00.000000001Z"
	spec, _ := json.Marshal(&pb.VMSpec{Name: "fbm1", Cpu: 1, MemoryMib: 128, StackName: "fbm"})
	for _, n := range []*Node{coord, owner} {
		if err := corrosion.InsertVM(ctx, n.DB, corrosion.VMRecord{
			Name: "fbm1", StackName: "fbm", HostName: owner.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 128,
		}, nil, nil); err != nil {
			t.Fatal(err)
		}
		if err := localExec(ctx, n.DB, `UPDATE vms SET created_at = ? WHERE name = 'fbm1'`, createdAt); err != nil {
			t.Fatal(err)
		}
	}
	owner.Virt.SetState("fbm1", "running")
	if err := corrosion.UpsertStack(ctx, coord.DB, corrosion.StackRecord{
		Name: "fbm", State: "active",
		ComposeYAML: "name: fbm\nvms:\n  fbm1:\n    image: tiny\n    cpu: 1\n    memory: 128\n",
	}); err != nil {
		t.Fatal(err)
	}

	// Another deleter wins the member, the way the stack reconciler deletes
	// it: bound to the stack and the incarnation.
	if _, err := owner.Server.DeleteVMForStackCleanup(ctx, &pb.DeleteVMRequest{
		Name: "fbm1", ExpectedStack: "fbm", ExpectedCreatedAt: createdAt,
	}); err != nil {
		t.Fatalf("the first deleter: %v", err)
	}
	if owner.Virt.DomainExists("fbm1") {
		t.Fatal("setup: the first deleter left the domain")
	}
	if vm, _ := corrosion.GetVM(ctx, coord.DB, "fbm1"); vm == nil {
		t.Fatal("setup: the coordinator already has the tombstone; the lag is not exercised")
	}

	progress := composeDown(t, c.SelfClient(coord))
	deleted := false
	for _, p := range progress {
		if p.GetStatus() == "error" {
			t.Errorf("compose down reported an error for a teardown that removed every VM: %+v", p)
		}
		if p.GetVmName() == "fbm1" && p.GetStatus() == "deleted" {
			deleted = true
		}
	}
	if !deleted {
		t.Errorf("no progress reports fbm1 deleted: %v", progress)
	}
	if got := goneStackState(t, coord); got != "(gone)" {
		t.Errorf("stack fbm is %q after compose down, want it gone", got)
	}
}
