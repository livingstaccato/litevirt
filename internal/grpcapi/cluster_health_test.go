package grpcapi

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// freshScan is a LastScan inside evaluatorScanTTL — the staleness bound means
// a fixed literal date would read as a stopped detector.
func freshScan() string { return time.Now().UTC().Format(time.RFC3339) }

// TestGetClusterHealth_OverallStates pins the roll-up contract:
//
//	UNKNOWN  — nothing has ever scanned (not the same as nothing wrong);
//	HEALTHY  — complete coverage, no active conditions;
//	DEGRADED — warnings or incomplete coverage;
//	CRITICAL — any ACTIVE critical condition, resolved ones excluded.
func TestGetClusterHealth_OverallStates(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	get := func() *pb.ClusterHealth {
		t.Helper()
		h, err := s.GetClusterHealth(ctx, &pb.GetClusterHealthRequest{})
		if err != nil {
			t.Fatalf("GetClusterHealth: %v", err)
		}
		return h
	}

	if got := get().GetOverall(); got != HealthUnknown {
		t.Fatalf("virgin cluster overall = %q, want UNKNOWN — nothing watching is not nothing wrong", got)
	}

	if err := corrosion.UpsertHealthEvaluatorStatus(context.Background(), s.db, corrosion.HealthEvaluatorStatus{
		Evaluator: "dual_run", LastScan: freshScan(), Coverage: corrosion.CoverageComplete, Reporter: "h1",
	}); err != nil {
		t.Fatalf("status: %v", err)
	}
	if got := get().GetOverall(); got != HealthHealthy {
		t.Fatalf("clean cluster overall = %q, want HEALTHY", got)
	}

	if err := corrosion.UpsertHealthEvaluatorStatus(context.Background(), s.db, corrosion.HealthEvaluatorStatus{
		Evaluator: "dual_run", LastScan: freshScan(), Coverage: corrosion.CoveragePartial, Reporter: "h1",
	}); err != nil {
		t.Fatalf("status: %v", err)
	}
	if got := get().GetOverall(); got != HealthDegraded {
		t.Fatalf("partial-coverage overall = %q, want DEGRADED — blind is not clean", got)
	}

	if err := corrosion.UpsertHealthEvaluatorStatus(context.Background(), s.db, corrosion.HealthEvaluatorStatus{
		Evaluator: "dual_run", LastScan: freshScan(), Coverage: corrosion.CoverageComplete, Reporter: "h1",
	}); err != nil {
		t.Fatalf("status: %v", err)
	}
	if err := corrosion.UpsertHealthCondition(context.Background(), s.db, corrosion.HealthCondition{
		Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "vm1",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityCritical,
		FirstSeen: freshScan(), LastSeen: freshScan(), ConfirmedAt: freshScan(), Reporter: "h1",
	}); err != nil {
		t.Fatalf("condition: %v", err)
	}
	if got := get().GetOverall(); got != HealthCritical {
		t.Fatalf("active critical condition overall = %q, want CRITICAL", got)
	}

	if err := corrosion.UpsertHealthCondition(context.Background(), s.db, corrosion.HealthCondition{
		Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "vm1",
		Lifecycle: corrosion.ConditionResolved, Severity: corrosion.SeverityCritical,
		FirstSeen: freshScan(), LastSeen: freshScan(), ConfirmedAt: freshScan(), ResolvedAt: freshScan(), Reporter: "h1",
	}); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := get().GetOverall(); got != HealthHealthy {
		t.Fatalf("after resolution overall = %q, want HEALTHY — a resolved condition must not count", got)
	}

	if err := corrosion.UpsertHealthCondition(context.Background(), s.db, corrosion.HealthCondition{
		Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "vm2",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityWarning,
		FirstSeen: freshScan(), LastSeen: freshScan(), ConfirmedAt: freshScan(), Reporter: "h1",
	}); err != nil {
		t.Fatalf("condition: %v", err)
	}
	if got := get().GetOverall(); got != HealthDegraded {
		t.Fatalf("active warning condition overall = %q, want DEGRADED", got)
	}

	if err := corrosion.UpsertHealthCondition(context.Background(), s.db, corrosion.HealthCondition{
		Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "vm2",
		Lifecycle: corrosion.ConditionResolved, Severity: corrosion.SeverityWarning,
		FirstSeen: freshScan(), LastSeen: freshScan(), ConfirmedAt: freshScan(), ResolvedAt: freshScan(), Reporter: "h1",
	}); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := get().GetOverall(); got != HealthHealthy {
		t.Fatalf("after resolving warning overall = %q, want HEALTHY", got)
	}

	if err := corrosion.UpsertHealthCondition(context.Background(), s.db, corrosion.HealthCondition{
		Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "vm3",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityInfo,
		FirstSeen: freshScan(), LastSeen: freshScan(), ConfirmedAt: freshScan(), Reporter: "h1",
	}); err != nil {
		t.Fatalf("condition: %v", err)
	}
	if got := get().GetOverall(); got != HealthHealthy {
		t.Fatalf("active info-severity condition overall = %q, want HEALTHY — info must not degrade", got)
	}
}

// TestOverallHealth_FutureLastScanIsNotFresh pins the clock-skew lower bound:
// a future-dated LastScan produces a negative delta, which must not read as
// "fresh" (that would mask a wedged detector behind an apparently-recent scan).
func TestOverallHealth_FutureLastScanIsNotFresh(t *testing.T) {
	now := time.Now().UTC()
	future := now.Add(1 * time.Hour).Format(time.RFC3339)
	evaluators := []corrosion.HealthEvaluatorStatus{
		{Evaluator: "dual_run", LastScan: future, Coverage: corrosion.CoverageComplete, Reporter: "h1"},
	}
	if got := overallHealth(nil, evaluators, nil, now); got != HealthUnknown {
		t.Fatalf("future-dated LastScan overall = %q, want UNKNOWN — clock skew must not read as fresh", got)
	}
}

// TestGetClusterHealth_ConnectivityAffectsOverall pins the connectivity leg of
// the roll-up. The handler already RETURNED the mesh while the overall state
// ignored it entirely, so a fully partitioned cluster could read HEALTHY —
// this goes through GetClusterHealth (not overallHealth directly) precisely
// because the bug was the wiring, not the rule.
func TestGetClusterHealth_ConnectivityAffectsOverall(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.UpsertHealthEvaluatorStatus(context.Background(), s.db, corrosion.HealthEvaluatorStatus{
		Evaluator: "dual_run", LastScan: freshScan(), Coverage: corrosion.CoverageComplete, Reporter: "h1",
	}); err != nil {
		t.Fatalf("status: %v", err)
	}

	get := func() *pb.ClusterHealth {
		t.Helper()
		h, err := s.GetClusterHealth(ctx, &pb.GetClusterHealthRequest{})
		if err != nil {
			t.Fatalf("GetClusterHealth: %v", err)
		}
		return h
	}

	// Healthy edges only: unchanged, still HEALTHY.
	if err := s.db.Execute(ctx,
		`INSERT INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES ('host-a', 'host-b', 'healthy', 0, '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert healthy edge: %v", err)
	}
	resp := get()
	if len(resp.GetConnectivity()) != 1 {
		t.Fatalf("connectivity edges = %d, want 1", len(resp.GetConnectivity()))
	}
	if got := resp.GetOverall(); got != HealthHealthy {
		t.Fatalf("healthy mesh overall = %q, want HEALTHY — a good edge must not degrade", got)
	}

	// One failing edge, conditions and evaluator coverage otherwise clean.
	if err := s.db.Execute(ctx,
		`INSERT INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES ('host-b', 'host-c', 'failing', 5, '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert failing edge: %v", err)
	}
	if got := get().GetOverall(); got != HealthDegraded {
		t.Fatalf("failing-edge overall = %q, want DEGRADED — a dead peer link is a coverage gap, "+
			"and a partitioned mesh must not read HEALTHY", got)
	}
}

// TestOverallHealth_ConnectivityTiers pins that a bad edge lands in the
// DEGRADED bucket and no higher: a broken probe is an observability gap, not
// evidence of corruption, so it must not escalate to CRITICAL (nor invent a
// tier of its own). Unrecognized statuses stay silent rather than degrading —
// a future column value must not blanket-degrade the cluster.
func TestOverallHealth_ConnectivityTiers(t *testing.T) {
	now := time.Now().UTC()
	evaluators := []corrosion.HealthEvaluatorStatus{
		{Evaluator: "dual_run", LastScan: now.Format(time.RFC3339), Coverage: corrosion.CoverageComplete, Reporter: "h1"},
	}
	for _, tc := range []struct {
		status string
		want   string
	}{
		{"healthy", HealthHealthy},
		{"suspect", HealthDegraded},
		{"failing", HealthDegraded},
		{"some-future-state", HealthHealthy},
	} {
		mesh := []connectivityEdge{{Observer: "a", Target: "b", Status: tc.status}}
		if got := overallHealth(nil, evaluators, mesh, now); got != tc.want {
			t.Errorf("edge status %q overall = %q, want %q", tc.status, got, tc.want)
		}
	}

	// A critical condition still wins over a merely-degrading mesh.
	conditions := []corrosion.HealthCondition{{
		Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "vm1",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityCritical,
	}}
	mesh := []connectivityEdge{{Observer: "a", Target: "b", Status: "failing"}}
	if got := overallHealth(conditions, evaluators, mesh, now); got != HealthCritical {
		t.Fatalf("critical condition + failing edge overall = %q, want CRITICAL", got)
	}
}

// TestGetClusterHealth_IncludeResolved checks the request flag actually gates
// whether resolved conditions appear in the response body (the overall state
// already excludes them regardless — this is about the returned list).
func TestGetClusterHealth_IncludeResolved(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.UpsertHealthCondition(context.Background(), s.db, corrosion.HealthCondition{
		Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "vm1",
		Lifecycle: corrosion.ConditionResolved, Severity: corrosion.SeverityWarning,
		FirstSeen: freshScan(), LastSeen: freshScan(), ResolvedAt: freshScan(), Reporter: "h1",
	}); err != nil {
		t.Fatalf("condition: %v", err)
	}

	without, err := s.GetClusterHealth(ctx, &pb.GetClusterHealthRequest{})
	if err != nil {
		t.Fatalf("GetClusterHealth: %v", err)
	}
	if len(without.GetConditions()) != 0 {
		t.Fatalf("include_resolved=false returned %d conditions, want 0", len(without.GetConditions()))
	}

	with, err := s.GetClusterHealth(ctx, &pb.GetClusterHealthRequest{IncludeResolved: true})
	if err != nil {
		t.Fatalf("GetClusterHealth: %v", err)
	}
	if len(with.GetConditions()) != 1 {
		t.Fatalf("include_resolved=true returned %d conditions, want 1", len(with.GetConditions()))
	}
}
