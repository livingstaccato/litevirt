package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestDualRunObserve_ResolvesNothing: a pass without the lease, on a node
// that has lost every voter majority, records evidence but never proves
// absence — even when its gate reads valid by the time it writes, as after a
// majority that returned mid-pass. The lease holder's passes still resolve.
//
// Mutation: let the observe-only pass run the absent-condition loop
// (gateOK without !rc.observeOnly) — the condition resolves and this goes
// red.
func TestDualRunObserve_ResolvesNothing(t *testing.T) {
	s := dualRunTestServer(t, 2)
	seedVM(t, s, "vmA", "h1", "running")
	_, clears, stop := captureDualRun(t, s)
	defer stop()
	ctx := context.Background()

	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
		"h2": {diskHolderVMs: []string{"vmA"}},
	})
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	if !confirmedCond(s, kindDualRunVM, "vmA") {
		t.Fatal("precondition: should be confirmed")
	}

	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
		"h2": {},
	})
	for i := 0; i < 3; i++ {
		s.observeDualRunWithoutLease(ctx)
	}
	if !confirmedCond(s, kindDualRunVM, "vmA") {
		t.Fatalf("observe-only clean passes changed the condition to %q; only the lease holder may resolve",
			condLifecycle(s, kindDualRunVM, "vmA"))
	}
	if got := clears("ha.dualrun.vm:vmA"); got != 0 {
		t.Fatalf("observe-only passes fired %d cleared event(s)", got)
	}

	// Control: the lease holder resolves on the same evidence.
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	if got := condLifecycle(s, kindDualRunVM, "vmA"); got != corrosion.ConditionResolved {
		t.Fatalf("control: the lease holder's two clean passes left %q, want resolved", got)
	}
}

// TestDualRunObserve_ConfirmsOnlyItsOwnConsecutiveSightings: several nodes
// without the majority each run observe-only passes and share the rows. An
// observation another node made is not this node's previous scan, so it does
// not count toward this node's confirmation; two of its own in a row do.
//
// Mutation: confirm on the row's count alone in observe-only mode (drop
// rc.ownPrev[f]) — the first own pass confirms on h2's observation and this
// goes red.
func TestDualRunObserve_ConfirmsOnlyItsOwnConsecutiveSightings(t *testing.T) {
	s := dualRunTestServerNoLease(t, 2)
	seedVM(t, s, "vmA", "h1", "running")
	ctx := context.Background()
	now := s.db.NowTS()
	if err := corrosion.UpsertHealthCondition(ctx, s.db, corrosion.HealthCondition{
		Evaluator: dualRunEvaluator, Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "vmA",
		Lifecycle: corrosion.ConditionObserved, Severity: corrosion.SeverityWarning,
		Hosts: []string{"h1", "h2"}, Evidence: encodeEvidence("seen by h2", nil),
		ObserveCount: 1, FirstSeen: now, LastSeen: now, Reporter: "h2",
	}); err != nil {
		t.Fatalf("UpsertHealthCondition: %v", err)
	}
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
		"h2": {diskHolderVMs: []string{"vmA"}},
	})

	s.observeDualRunWithoutLease(ctx)
	if got := condLifecycle(s, kindDualRunVM, "vmA"); got != corrosion.ConditionObserved {
		t.Fatalf("after this node's first own sighting the condition is %q, want observed: "+
			"h2's observation is not this node's previous scan", got)
	}
	s.observeDualRunWithoutLease(ctx)
	if !confirmedCond(s, kindDualRunVM, "vmA") {
		t.Fatalf("two consecutive own sightings left %q, want confirmed", condLifecycle(s, kindDualRunVM, "vmA"))
	}
}

// TestDualRunObserve_LeavesTheScanStatusToTheLeader: the evaluator's scan
// status is what consumers read to tell a clean scan from a blind one, and
// is the lease holder's. A pass without the lease writes none.
//
// Mutation: write the scan status from an observe-only pass too — a row
// appears and this goes red.
func TestDualRunObserve_LeavesTheScanStatusToTheLeader(t *testing.T) {
	s := dualRunTestServerNoLease(t, 2)
	ctx := context.Background()
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{"h1": {}, "h2": {}})
	s.observeDualRunWithoutLease(ctx)
	sts, err := corrosion.ListHealthEvaluatorStatus(ctx, s.db)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range sts {
		if st.Evaluator == dualRunEvaluator {
			t.Fatalf("an observe-only pass wrote the scan status %+v", st)
		}
	}
}
