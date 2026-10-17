// Review I-1: compose down deletes the member incarnation it listed; a new
// incarnation of the member, created on a third node during the down, is not
// deleted, and the teardown ends "deleted" for the member and "torn down" for
// the stack. Nothing deleted the new VM, and nothing said so. The stack
// reconciler now raises stack.vm_outlived_stack for it.
package fleet

import (
	"context"
	"encoding/json"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// Mutation: drop the outlived-stack report from the reconciler pass — red.
func TestFleet_ComposeDown_ANewIncarnationLeftBehindIsReported(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	ctx := context.Background()
	coord, owner, other := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.Partition(coord, owner)
	c.Partition(coord, other)
	c.Partition(owner, other) // B's row never reaches A's old owner

	const createdA = "2026-10-17T14:20:00.000000001Z"
	spec, _ := json.Marshal(&pb.VMSpec{Name: "fbm1", Cpu: 1, MemoryMib: 128, StackName: "fbm"})
	for _, n := range []*Node{coord, owner} {
		if err := corrosion.InsertVM(ctx, n.DB, corrosion.VMRecord{
			Name: "fbm1", StackName: "fbm", HostName: owner.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 128,
		}, nil, nil); err != nil {
			t.Fatal(err)
		}
		if err := localExec(ctx, n.DB, `UPDATE vms SET created_at = ? WHERE name = 'fbm1'`, createdA); err != nil {
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

	// During the down: incarnation A is deleted, and B, recording the same
	// stack, is created on the third node.
	if _, err := owner.Server.DeleteVMForStackCleanup(ctx, &pb.DeleteVMRequest{
		Name: "fbm1", ExpectedStack: "fbm", ExpectedCreatedAt: createdA,
	}); err != nil {
		t.Fatalf("delete incarnation A: %v", err)
	}
	if err := corrosion.InsertVM(ctx, other.DB, corrosion.VMRecord{
		Name: "fbm1", StackName: "fbm", HostName: other.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 128,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	other.Virt.SetState("fbm1", "running")
	b, _ := corrosion.GetVM(ctx, other.DB, "fbm1")
	if b == nil || b.CreatedAt == createdA {
		t.Fatalf("setup: incarnation B = %+v", b)
	}

	progress := composeDown(t, c.SelfClient(coord))
	for _, p := range progress {
		if p.GetStatus() == "error" {
			t.Fatalf("setup: compose down reported an error: %+v", p)
		}
	}
	if got := goneStackState(t, coord); got != "(gone)" {
		t.Fatalf("setup: stack fbm is %q, want torn down", got)
	}
	if !other.Virt.DomainExists("fbm1") {
		t.Fatal("setup: B's domain went too; nothing was left behind")
	}

	// The stack's tombstone reaches the third node over the WAL; its
	// reconciler reports B.
	c.Heal(coord, other)
	pumpMutations(t, c, coord, other)
	if rows, _ := other.DB.Query(ctx, `SELECT 1 FROM stacks WHERE name = 'fbm' AND deleted_at IS NOT NULL`); len(rows) != 1 {
		t.Fatal("the stack's tombstone did not reach the third node")
	}
	if vm, _ := corrosion.GetVM(ctx, other.DB, "fbm1"); vm == nil || vm.CreatedAt != b.CreatedAt {
		t.Fatalf("B's row on the third node = %+v, want B live", vm)
	}
	r := health.NewStackReconciler(other.Name, other.DB)
	r.SetCleaner(other.Server)
	r.ReconcileOnce(ctx)

	row, found, err := corrosion.GetHealthCondition(ctx, other.DB, "stack_reconciler", "stack.vm_outlived_stack", "vm", "fbm1")
	if err != nil {
		t.Fatal(err)
	}
	if !found || row.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("no open stack.vm_outlived_stack condition for B (fbm1 on %s): %+v", other.Name, row)
	}
	var ev struct {
		Stack, Host string
	}
	_ = json.Unmarshal([]byte(row.Evidence), &ev)
	if ev.Stack != "fbm" || ev.Host != other.Name {
		t.Errorf("evidence = %s, want stack fbm on %s", row.Evidence, other.Name)
	}
}
