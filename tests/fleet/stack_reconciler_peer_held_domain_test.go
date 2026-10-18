// Re-review 4 I-1: a member whose row names host O while its domain runs on
// host P. O's delete finds no domain, probes P, and P deletes the domain and
// tombstones the row in its own replica. O answered OK with its own row
// still live, so the stack reconciler on O, which finishes the teardown and
// reports in the same pass, raised stack.vm_outlived_stack for the member it
// had just deleted. Only a fleet reaches this: the probe is a peer RPC, and
// the two replicas are different daemons'.
package fleet

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// Mutation: answer OK on the peer's delete without tombstoning the row here
// — red.
func TestFleet_StackReconciler_APeerHeldDomainIsTombstonedOnTheRowsHost(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	o, p := c.Nodes[0], c.Nodes[1]
	// Replication only: every RPC still flows, so no tombstone written on
	// one reaches the other.
	c.Partition(o, p)

	const createdAt = "2026-10-17T15:10:00.000000001Z"
	spec, _ := json.Marshal(&pb.VMSpec{Name: "pd1", Cpu: 1, MemoryMib: 128, StackName: "pd"})
	for _, n := range []*Node{o, p} {
		if err := corrosion.InsertVM(ctx, n.DB, corrosion.VMRecord{
			Name: "pd1", StackName: "pd", HostName: o.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 128,
		}, nil, nil); err != nil {
			t.Fatal(err)
		}
		if err := localExec(ctx, n.DB, `UPDATE vms SET created_at = ? WHERE name = 'pd1'`, createdAt); err != nil {
			t.Fatal(err)
		}
	}
	p.Virt.SetState("pd1", "running")
	if o.Virt.DomainExists("pd1") {
		t.Fatal("setup: o has a domain pd1")
	}
	if err := corrosion.UpsertStack(ctx, o.DB, corrosion.StackRecord{
		Name: "pd", State: "deleting",
		ComposeYAML: "name: pd\nvms:\n  pd1:\n    image: tiny\n    cpu: 1\n    memory: 128\n",
	}); err != nil {
		t.Fatal(err)
	}

	r := health.NewStackReconciler(o.Name, o.DB)
	r.SetCleaner(o.Server)
	r.SetClock(func() time.Time { return time.Now().Add(2 * time.Minute) }) // past the in-flight grace
	r.ReconcileOnce(ctx)

	if p.Virt.DomainExists("pd1") {
		t.Fatal("setup: the reconciler's delete did not reach the domain on p")
	}
	if vm, _ := corrosion.GetVM(ctx, p.DB, "pd1"); vm != nil {
		t.Fatalf("setup: p did not tombstone pd1: %+v", vm)
	}
	if st, _ := corrosion.GetStack(ctx, o.DB, "pd"); st != nil {
		t.Fatalf("setup: the reconciler did not finish the teardown: %+v", st)
	}
	if vm, _ := corrosion.GetVM(ctx, o.DB, "pd1"); vm != nil {
		t.Errorf("o answered the delete of pd1 with its own row still live: %+v", vm)
	}
	row, found, err := corrosion.GetHealthCondition(ctx, o.DB, "stack_reconciler", "stack.vm_outlived_stack", "vm", "pd1")
	if err != nil {
		t.Fatal(err)
	}
	if found && row.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("o reported pd1, which its delete had just removed from p, as a VM that outlived its stack: %s", row.Evidence)
	}
}
