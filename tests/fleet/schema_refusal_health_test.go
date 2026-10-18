// Fleet scenario (lab eqts-26, A2): while a peer refuses this node's pushes
// because its database schema is behind, `lv health` must say so instead of
// reading HEALTHY, and clear once the peer is pre-staged.
package fleet

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// healthOf returns node n's `lv health` answer.
func healthOf(t *testing.T, c *Cluster, n *Node) *pb.ClusterHealth {
	t.Helper()
	resp, err := c.SelfClient(n).GetClusterHealth(context.Background(), &pb.GetClusterHealthRequest{})
	if err != nil {
		t.Fatalf("GetClusterHealth on %s: %v", n.Name, err)
	}
	return resp
}

// TestFleet_SchemaRefusalDegradesHealth: while node-2, on the old schema,
// refuses node-0's pushes, node-0's `lv health` is DEGRADED by a warning
// condition on host/node-2 whose evidence names the fix; once node-2 is
// pre-staged and takes the push, the condition resolves and health is HEALTHY.
func TestFleet_SchemaRefusalDegradesHealth(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	a, behind := c.Nodes[0], c.Nodes[2]

	// One complete, fresh evaluator so the roll-up can read HEALTHY at all.
	scan := func() {
		if err := corrosion.UpsertHealthEvaluatorStatus(ctx, a.DB, corrosion.HealthEvaluatorStatus{
			Evaluator: "fleet", LastScan: time.Now().UTC().Format(time.RFC3339),
			Coverage: corrosion.CoverageComplete, Reporter: a.Name,
		}); err != nil {
			t.Fatal(err)
		}
	}
	scan()
	if got := healthOf(t, c, a); got.GetOverall() != "HEALTHY" {
		t.Fatalf("baseline health %s %v, want HEALTHY", got.GetOverall(), got.GetReasons())
	}

	behind.DB.SetEffectiveDBSchemaForTest(corrosion.CurrentSchemaVersion - 1)
	insertVM(t, a, "vm-refused", a.Name)

	const code = "replication_peer_schema_behind"
	reason := "condition " + code + " on host/" + behind.Name
	eventually(t, convergeTimeout, a.Name+"'s health to report "+behind.Name+" refusing replication", func() bool {
		a.Server.EvaluateReplicationSchemaHealth(ctx)
		h := healthOf(t, c, a)
		return h.GetOverall() == "DEGRADED" && slices.ContainsFunc(h.GetReasons(), func(r string) bool {
			return strings.Contains(r, reason)
		})
	})
	var cond *pb.HealthCondition
	for _, hc := range healthOf(t, c, a).GetConditions() {
		if hc.GetCode() == code && hc.GetSubjectId() == behind.Name {
			cond = hc
		}
	}
	if cond == nil {
		t.Fatalf("no %s condition on %s", code, behind.Name)
	}
	if cond.GetSeverity() != corrosion.SeverityWarning || !slices.Equal(cond.GetHosts(), []string{behind.Name}) ||
		!strings.Contains(cond.GetEvidence(), "lv host upgrade "+behind.Name) {
		t.Fatalf("condition %+v: want a warning on %s whose evidence names `lv host upgrade %s`",
			cond, behind.Name, behind.Name)
	}
	if vmOn(t, behind, "vm-refused") != nil {
		t.Fatalf("%s took a push from a sender ahead of its schema", behind.Name)
	}

	// Pre-stage the lagging node (what PreStageUpgrade does after its migrate).
	behind.DB.RefreshDBSchemaVersion(ctx)
	eventually(t, 2*convergeTimeout, behind.Name+" to take the refused write once pre-staged", func() bool {
		return vmOn(t, behind, "vm-refused") != nil
	})
	eventually(t, convergeTimeout, a.Name+"'s health to clear the refusal", func() bool {
		a.Server.EvaluateReplicationSchemaHealth(ctx)
		scan()
		return healthOf(t, c, a).GetOverall() == "HEALTHY"
	})
}

// TestFleet_RefusingNodeReportsItselfFromTheMonitor: the node refusing the
// pushes raises the condition on itself, so its own `lv health` is not
// HEALTHY either (m6), and it does so from the HA health monitor the daemon
// runs, with no direct evaluator call (m5). Pre-staged, it resolves it.
func TestFleet_RefusingNodeReportsItselfFromTheMonitor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	a, behind := c.Nodes[0], c.Nodes[2]
	go behind.Server.RunHAHealthMonitor(ctx, 100*time.Millisecond)

	behind.DB.SetEffectiveDBSchemaForTest(corrosion.CurrentSchemaVersion - 1)
	insertVM(t, a, "vm-refused-self", a.Name)

	const evaluator, code = "replication_schema", "replication_peer_schema_behind"
	row := func() (corrosion.HealthCondition, bool) {
		h, ok, err := corrosion.GetHealthCondition(ctx, behind.DB, evaluator, code, "host", behind.Name)
		if err != nil {
			t.Fatal(err)
		}
		return h, ok
	}
	eventually(t, convergeTimeout, behind.Name+" to report its own schema behind", func() bool {
		h, ok := row()
		return ok && h.Lifecycle != corrosion.ConditionResolved && h.Reporter == behind.Name
	})
	if h, _ := row(); h.Severity != corrosion.SeverityWarning || !strings.Contains(h.Evidence, "lv host upgrade "+behind.Name) {
		t.Fatalf("condition %+v: want a warning whose evidence names `lv host upgrade %s`", h, behind.Name)
	}

	behind.DB.RefreshDBSchemaVersion(ctx)
	eventually(t, 2*convergeTimeout, behind.Name+" to take the refused write once pre-staged", func() bool {
		return vmOn(t, behind, "vm-refused-self") != nil
	})
	eventually(t, convergeTimeout, behind.Name+" to resolve its own condition", func() bool {
		h, ok := row()
		return ok && h.Lifecycle == corrosion.ConditionResolved
	})
}
