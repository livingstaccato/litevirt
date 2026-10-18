package fleet

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// TestFleet_ConditionsOfADeletedVMResolveOnEveryNode: a VM is created on one
// node, a second node raises conditions about it, and the VM is deleted
// through the first node's API. The next reconciler pass on a third node
// resolves them, and the resolution replicates to every node. A condition
// about a live VM stays open everywhere.
//
// On lab 1 about 80 conditions naming deleted VMs stayed open: no evaluator
// looks at a VM that no longer exists, so nothing resolved them.
//
// Mutation: drop resolveGoneSubjects from the reconciler pass — every node
// still holds the deleted VM's conditions open.
func TestFleet_ConditionsOfADeletedVMResolveOnEveryNode(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	owner, raiser, sweeper := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)

	for _, name := range []string{"gone1", "kept1"} {
		if err := corrosion.InsertVM(ctx, owner.DB, corrosion.VMRecord{
			Name: name, HostName: owner.Name, State: "stopped", CPUActual: 1, MemActual: 256,
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", name, err)
		}
	}
	c.WaitConverged(t, convergeTimeout)

	type cond struct{ evaluator, code, subject string }
	gone := []cond{
		{health.VMProbeEvaluator, health.CondVMProbeFailing, "gone1"},
		{corrosion.PartitionPauseEvaluator, corrosion.CondVMSettled, "gone1@" + raiser.Name},
	}
	kept := cond{health.VMProbeEvaluator, health.CondVMProbeFailing, "kept1"}
	ts := time.Now().UTC().Format(time.RFC3339)
	for _, k := range append(append([]cond{}, gone...), kept) {
		if err := corrosion.UpsertHealthCondition(ctx, raiser.DB, corrosion.HealthCondition{
			Evaluator: k.evaluator, Code: k.code, SubjectKind: "vm", SubjectID: k.subject,
			Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityWarning,
			Hosts: []string{raiser.Name}, ObserveCount: 1, FirstSeen: ts, LastSeen: ts, ConfirmedAt: ts,
			Reporter: raiser.Name,
		}); err != nil {
			t.Fatalf("raise %v: %v", k, err)
		}
	}
	c.WaitConverged(t, convergeTimeout)

	if _, err := c.SelfClient(owner).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "gone1"}); err != nil {
		t.Fatalf("DeleteVM on %s: %v", owner.Name, err)
	}
	c.WaitConverged(t, convergeTimeout)

	health.NewReconciler(sweeper.Name, t.TempDir(), sweeper.DB, sweeper.Virt).ReconcileOnce(ctx)
	c.WaitConverged(t, convergeTimeout)

	for _, n := range c.Nodes {
		for _, k := range gone {
			row, ok, err := corrosion.GetHealthCondition(ctx, n.DB, k.evaluator, k.code, "vm", k.subject)
			if err != nil || !ok || row.Lifecycle != corrosion.ConditionResolved {
				t.Errorf("%s: %s on vm/%s = (%s, %v, %v) after gone1 was deleted, want resolved",
					n.Name, k.code, k.subject, row.Lifecycle, ok, err)
			}
		}
		row, ok, err := corrosion.GetHealthCondition(ctx, n.DB, kept.evaluator, kept.code, "vm", kept.subject)
		if err != nil || !ok || row.Lifecycle != corrosion.ConditionConfirmed {
			t.Errorf("%s: %s on vm/%s = (%s, %v, %v), want it left open: kept1 still exists",
				n.Name, kept.code, kept.subject, row.Lifecycle, ok, err)
		}
	}
}
