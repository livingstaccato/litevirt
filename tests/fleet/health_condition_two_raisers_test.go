package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_HealthCondition_TwoRaisersConverge: two nodes that both believe
// they hold the detector lease raise the same condition while replication
// between them is cut, and after the heal the WAL push alone must leave them
// with one row.
//
// It did not. UpsertHealthCondition's conflict path copies every column but
// created_at, and each node's INSERT stamped its own wall-clock created_at.
// The later raiser's statement wins on the earlier one by LWW and overwrites
// all of its content and its updated_at — but not its created_at — so the two
// replicas ended as one updated_at over two created_at values. That is an
// exact tie no WAL apply can settle (the upsert is not a full row image, so a
// tied receiver keeps local), and every later write from the lease holder
// leaves created_at alone, so only an anti-entropy pull could repair it. The
// recovery-claim fault scenarios hit this with ha.voter.unavailable and had to
// leave health_conditions out of their convergence wait.
//
// Nothing here runs anti-entropy: WaitConverged waits on the push loops only.
//
// Mutation: bind nowRFC3339Nano() as created_at in UpsertHealthCondition again
// (the f2e3d70b writer) — the replicas stay apart on health_conditions.
func TestFleet_HealthCondition_TwoRaisersConverge(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 1})
	a, b := c.Nodes[0], c.Nodes[1]
	c.WaitConverged(t, convergeTimeout)

	c.SetLinkFaultBoth(a, b, LinkFault{Block: true})
	raise := func(n *Node) {
		t.Helper()
		now := time.Now().UTC().Format(time.RFC3339)
		if err := corrosion.UpsertHealthCondition(ctx, n.DB, corrosion.HealthCondition{
			Evaluator: "recovery_claims", Code: "ha.voter.unavailable", SubjectKind: "cluster", SubjectID: "voters",
			Lifecycle: corrosion.ConditionObserved, Severity: corrosion.SeverityWarning,
			Hosts: []string{"node-2"}, Evidence: `{"detail":"node-2 is offline"}`,
			ObserveCount: 1, FirstSeen: now, LastSeen: now, Reporter: n.Name,
		}); err != nil {
			t.Fatalf("%s: raise: %v", n.Name, err)
		}
	}
	raise(a)
	// Wall-clock apart, so b's write is the strictly newer one and LWW, not a
	// tie, carries it onto a.
	time.Sleep(5 * time.Millisecond)
	raise(b)
	for _, n := range []*Node{a, b} {
		if got := reporter(t, n); got != n.Name {
			t.Fatalf("%s holds a row reported by %q before the heal; the raises were not independent", n.Name, got)
		}
	}

	c.ClearLinkFaults()
	c.WaitConverged(t, convergeTimeout, a, b)
	for _, n := range []*Node{a, b} {
		if got := reporter(t, n); got != b.Name {
			t.Errorf("%s: converged on the row reported by %q, want the later raiser %s", n.Name, got, b.Name)
		}
	}
}

func reporter(t *testing.T, n *Node) string {
	t.Helper()
	h, ok, err := corrosion.GetHealthCondition(context.Background(), n.DB,
		"recovery_claims", "ha.voter.unavailable", "cluster", "voters")
	if err != nil || !ok {
		t.Fatalf("%s: read condition: ok=%v err=%v", n.Name, ok, err)
	}
	return h.Reporter
}
