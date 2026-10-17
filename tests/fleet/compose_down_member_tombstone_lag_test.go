// Lab 2 2026-10-17, F2: a teardown the stack reconciler finished raised
// stack.vm_outlived_stack for a member it had just deleted. The member's
// owner wrote its tombstone; the reconciler tombstoned the stack and read its
// own replica, where the member's tombstone had not arrived, so a deleted VM
// was reported as one the teardown left, with `lv rm` as the remedy. It
// resolved seconds later. Only a fleet reaches this: the owner's tombstone and
// the stack's tombstone come from different daemons.
package fleet

import (
	"context"
	"encoding/json"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// Mutation: judge every live VM of a torn-down stack on every host, not only
// on the VM's own host — red.
func TestFleet_ComposeDown_AMemberWhoseTombstoneLagsIsNotReportedOutlived(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	ctx := context.Background()
	coord, owner, other := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	// Replication only: every RPC still flows.
	c.Partition(coord, owner)
	c.Partition(coord, other)
	c.Partition(owner, other)

	const createdAt = "2026-10-17T14:20:00.000000001Z"
	spec, _ := json.Marshal(&pb.VMSpec{Name: "fbm1", Cpu: 1, MemoryMib: 128, StackName: "fbm"})
	for _, n := range []*Node{coord, owner, other} {
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

	// The member is deleted on its owner, bound as the reconciler binds it,
	// and the teardown ends with the stack tombstoned on the coordinator.
	if _, err := owner.Server.DeleteVMForStackCleanup(ctx, &pb.DeleteVMRequest{
		Name: "fbm1", ExpectedStack: "fbm", ExpectedCreatedAt: createdAt,
	}); err != nil {
		t.Fatalf("delete the member on its owner: %v", err)
	}
	for _, p := range composeDown(t, c.SelfClient(coord)) {
		if p.GetStatus() == "error" {
			t.Fatalf("setup: compose down reported an error: %+v", p)
		}
	}
	if got := goneStackState(t, coord); got != "(gone)" {
		t.Fatalf("setup: stack fbm is %q, want torn down", got)
	}

	// The stack's tombstone reaches the third node; the owner's tombstone of
	// the member reaches neither.
	c.Heal(coord, other)
	pumpMutations(t, c, coord, other)
	for _, n := range []*Node{coord, other} {
		if rows, _ := n.DB.Query(ctx, `SELECT 1 FROM stacks WHERE name = 'fbm' AND deleted_at IS NOT NULL`); len(rows) != 1 {
			t.Fatalf("setup: %s has no tombstone of stack fbm", n.Name)
		}
		if vm, _ := corrosion.GetVM(ctx, n.DB, "fbm1"); vm == nil {
			t.Fatalf("setup: %s already has the member's tombstone; the lag is not exercised", n.Name)
		}
	}

	for _, n := range []*Node{coord, other} {
		r := health.NewStackReconciler(n.Name, n.DB)
		r.SetCleaner(n.Server)
		r.ReconcileOnce(ctx)
		row, found, err := corrosion.GetHealthCondition(ctx, n.DB, "stack_reconciler", "stack.vm_outlived_stack", "vm", "fbm1")
		if err != nil {
			t.Fatal(err)
		}
		if found && row.Lifecycle != corrosion.ConditionResolved {
			t.Errorf("%s reported fbm1, which its owner deleted, as a VM that outlived its stack: %s", n.Name, row.Evidence)
		}
	}
}
