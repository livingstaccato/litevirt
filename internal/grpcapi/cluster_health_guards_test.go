package grpcapi

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// completeEvaluator is a single evaluator with fresh, complete coverage — the
// baseline against which the leg under test is the only variable.
func completeEvaluator(now time.Time) []corrosion.HealthEvaluatorStatus {
	return []corrosion.HealthEvaluatorStatus{{
		Evaluator: "dual_run", LastScan: now.Format(time.RFC3339),
		Coverage: corrosion.CoverageComplete, Reporter: "h1",
	}}
}

// TestOverallHealth_InfoSeverityDoesNotDegrade pins that an info condition is a
// note, not a fault. The roll-up skips it deliberately: degrading on info
// leaves the cluster permanently yellow for observations nobody is expected to
// act on, which teaches operators to ignore the one signal this endpoint exists
// to give. The behaviour shipped without a guard — this is that guard.
func TestOverallHealth_InfoSeverityDoesNotDegrade(t *testing.T) {
	now := time.Now().UTC()
	info := []corrosion.HealthCondition{{
		Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "vm1",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityInfo,
	}}
	if got := overallHealth(info, completeEvaluator(now), nil, now); got != HealthHealthy {
		t.Errorf("active info condition overall = %q, want HEALTHY", got)
	}

	// The tier above it must still register, or this would be a hole rather
	// than a distinction.
	warn := []corrosion.HealthCondition{{
		Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "vm1",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityWarning,
	}}
	if got := overallHealth(warn, completeEvaluator(now), nil, now); got != HealthDegraded {
		t.Errorf("active warning condition overall = %q, want DEGRADED", got)
	}
}

// TestGetClusterHealth_TombstonedEdgeIsNotReported guards the mesh query's
// tombstone filter now that the same rows feed the overall state: a resurrected
// edge would not merely appear in the body, it would degrade the cluster.
func TestGetClusterHealth_TombstonedEdgeIsNotReported(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.UpsertHealthEvaluatorStatus(context.Background(), s.db, corrosion.HealthEvaluatorStatus{
		Evaluator: "dual_run", LastScan: freshScan(), Coverage: corrosion.CoverageComplete, Reporter: "h1",
	}); err != nil {
		t.Fatalf("status: %v", err)
	}
	if err := s.db.Execute(ctx,
		`INSERT INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at, deleted_at)
		 VALUES ('host-a', 'gone', 'failing', 9, '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z', '2026-09-02T00:00:00Z')`); err != nil {
		t.Fatalf("insert tombstoned edge: %v", err)
	}

	h, err := s.GetClusterHealth(ctx, &pb.GetClusterHealthRequest{})
	if err != nil {
		t.Fatalf("GetClusterHealth: %v", err)
	}
	if n := len(h.GetConnectivity()); n != 0 {
		t.Errorf("connectivity edges = %d, want 0 — a removed host's edge is not a live link", n)
	}
	if got := h.GetOverall(); got != HealthHealthy {
		t.Errorf("overall = %q, want HEALTHY — a tombstoned edge must not degrade the cluster", got)
	}
}
