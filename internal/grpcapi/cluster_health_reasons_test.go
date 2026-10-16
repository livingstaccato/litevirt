package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestGetClusterHealth_StaleEvaluatorNamesItself is lab 3's report: the
// shared_lun scan stopped, its evaluator row went stale, and `lv health` said
// DEGRADED with no condition and nothing else to say why. The response must
// name the evaluator.
//
// Mutation: drop the stale-evaluator reason from rollUpHealth and this fails —
// and the cluster no longer reads DEGRADED either, because DEGRADED is derived
// from the reasons.
func TestGetClusterHealth_StaleEvaluatorNamesItself(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	stale := time.Now().UTC().Add(-2 * evaluatorScanTTL).Format(time.RFC3339)
	for _, e := range []corrosion.HealthEvaluatorStatus{
		{Evaluator: "dual_run", LastScan: freshScan(), Coverage: corrosion.CoverageComplete, Reporter: "h1"},
		{Evaluator: "shared_lun", LastScan: stale, Coverage: corrosion.CoverageComplete, Reporter: "h2"},
	} {
		if err := corrosion.UpsertHealthEvaluatorStatus(ctx, s.db, e); err != nil {
			t.Fatalf("status: %v", err)
		}
	}
	h, err := s.GetClusterHealth(adminCtx(), &pb.GetClusterHealthRequest{})
	if err != nil {
		t.Fatalf("GetClusterHealth: %v", err)
	}
	if h.GetOverall() != HealthDegraded || len(h.GetConditions()) != 0 {
		t.Fatalf("overall=%q conditions=%d; want DEGRADED with no condition (the lab's shape)",
			h.GetOverall(), len(h.GetConditions()))
	}
	// tests/e2e (staleEvaluatorScan) reads the last scan back out of this
	// exact shape.
	want := `evaluator shared_lun is stale: last scan "` + stale + `" by h2`
	if len(h.GetReasons()) != 1 || !strings.HasPrefix(h.GetReasons()[0], want) {
		t.Fatalf("reasons = %q; want exactly one, starting %q", h.GetReasons(), want)
	}
}

// TestRollUpHealth_EveryNonHealthyStateHasAReason walks each input that moves
// the roll-up off HEALTHY and requires a reason naming it; and a HEALTHY state
// carries none.
func TestRollUpHealth_EveryNonHealthyStateHasAReason(t *testing.T) {
	now := time.Now().UTC()
	fresh := now.Format(time.RFC3339)
	okEval := corrosion.HealthEvaluatorStatus{Evaluator: "dual_run", LastScan: fresh, Coverage: corrosion.CoverageComplete}
	type rollUpCase struct {
		name       string
		conds      []corrosion.HealthCondition
		evals      []corrosion.HealthEvaluatorStatus
		capacity   []corrosion.HostCapacityObservation
		mesh       []connectivityEdge
		want, says string
	}
	cases := []rollUpCase{
		{name: "healthy", evals: []corrosion.HealthEvaluatorStatus{okEval}, want: HealthHealthy},
		{name: "no evaluator", want: HealthUnknown, says: "no health evaluator"},
		{name: "all stale", evals: []corrosion.HealthEvaluatorStatus{{Evaluator: "dual_run",
			LastScan: now.Add(-time.Hour).Format(time.RFC3339), Coverage: corrosion.CoverageComplete}},
			want: HealthUnknown, says: "dual_run is stale"},
		{name: "future scan", evals: []corrosion.HealthEvaluatorStatus{okEval, {Evaluator: "shared_lun",
			LastScan: now.Add(time.Hour).Format(time.RFC3339), Coverage: corrosion.CoverageComplete}},
			want: HealthDegraded, says: "shared_lun is stale"},
		{name: "partial coverage", evals: []corrosion.HealthEvaluatorStatus{{Evaluator: "dual_run",
			LastScan: fresh, Coverage: corrosion.CoveragePartial, Detail: "host h3 unreachable"}},
			want: HealthDegraded, says: "host h3 unreachable"},
		{name: "warning condition", evals: []corrosion.HealthEvaluatorStatus{okEval},
			conds: []corrosion.HealthCondition{{Code: "coverage_gap", SubjectKind: "host", SubjectID: "h3",
				Severity: corrosion.SeverityWarning, Lifecycle: corrosion.ConditionObserved}},
			want: HealthDegraded, says: "coverage_gap on host/h3"},
		{name: "critical condition", evals: []corrosion.HealthEvaluatorStatus{okEval},
			conds: []corrosion.HealthCondition{{Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "web",
				Severity: corrosion.SeverityCritical, Lifecycle: corrosion.ConditionConfirmed}},
			want: HealthCritical, says: "vm_dual_run on vm/web"},
		{name: "info condition", evals: []corrosion.HealthEvaluatorStatus{okEval},
			conds: []corrosion.HealthCondition{{Code: "advisory", SubjectKind: "host", SubjectID: "h1",
				Severity: corrosion.SeverityInfo, Lifecycle: corrosion.ConditionObserved}},
			want: HealthHealthy},
		{name: "capacity", evals: []corrosion.HealthEvaluatorStatus{okEval},
			capacity: []corrosion.HostCapacityObservation{{HostName: "h2", Complete: false, Detail: "libvirt down"}},
			want:     HealthDegraded, says: "capacity observation for h2"},
		{name: "edge", evals: []corrosion.HealthEvaluatorStatus{okEval},
			mesh: []connectivityEdge{{Observer: "h1", Target: "h2", Status: "suspect"}},
			want: HealthDegraded, says: "h1 -> h2 is suspect"},
		{name: "maintenance edge", evals: []corrosion.HealthEvaluatorStatus{okEval},
			mesh: []connectivityEdge{{Observer: "h1", Target: "h2", Status: "suspect", TargetInMaintenance: true}},
			want: HealthHealthy},
	}
	// A state decided by one cause still lists the others.
	stale := corrosion.HealthEvaluatorStatus{Evaluator: "shared_lun",
		LastScan: now.Add(-time.Hour).Format(time.RFC3339), Coverage: corrosion.CoverageComplete}
	cases = append(cases,
		rollUpCase{name: "critical lists a stale scan too", evals: []corrosion.HealthEvaluatorStatus{okEval, stale},
			conds: []corrosion.HealthCondition{{Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "web",
				Severity: corrosion.SeverityCritical, Lifecycle: corrosion.ConditionConfirmed}},
			want: HealthCritical, says: "shared_lun is stale"},
		rollUpCase{name: "unknown lists a bad link too", evals: []corrosion.HealthEvaluatorStatus{stale},
			mesh: []connectivityEdge{{Observer: "h1", Target: "h2", Status: "suspect"}},
			want: HealthUnknown, says: "h1 -> h2 is suspect"},
	)
	for _, tc := range cases {
		state, reasons := rollUpHealth(tc.conds, tc.evals, tc.capacity, tc.mesh, now)
		if state != tc.want {
			t.Errorf("%s: state %q, want %q (reasons %q)", tc.name, state, tc.want, reasons)
			continue
		}
		if state != overallHealth(tc.conds, tc.evals, tc.capacity, tc.mesh, now) {
			t.Errorf("%s: overallHealth disagrees with rollUpHealth", tc.name)
		}
		if state == HealthHealthy {
			if len(reasons) != 0 {
				t.Errorf("%s: HEALTHY with reasons %q", tc.name, reasons)
			}
			continue
		}
		if !strings.Contains(strings.Join(reasons, "\n"), tc.says) {
			t.Errorf("%s: %s with reasons %q; want one naming %q", tc.name, state, reasons, tc.says)
		}
	}
}

// TestRollUpHealth_ReasonsStayOnOneLine: a free-text detail with a newline must
// not split the `- ` list lv health prints (and tests/e2e parses).
//
// Mutation: make oneLine return s unchanged and this fails.
func TestRollUpHealth_ReasonsStayOnOneLine(t *testing.T) {
	now := time.Now().UTC()
	_, reasons := rollUpHealth(nil, []corrosion.HealthEvaluatorStatus{{Evaluator: "dual_run",
		LastScan: now.Format(time.RFC3339), Coverage: corrosion.CoveragePartial, Detail: "host h3\nunreachable\r\nagain"}},
		[]corrosion.HostCapacityObservation{{HostName: "h2", Detail: "a\nb"}}, nil, now)
	if len(reasons) != 2 {
		t.Fatalf("reasons = %q, want two", reasons)
	}
	for _, r := range reasons {
		if strings.ContainsAny(r, "\r\n") {
			t.Errorf("reason %q spans lines", r)
		}
	}
}
