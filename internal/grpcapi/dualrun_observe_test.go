package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// TestDualRunObserve_ResolvesNothing: a pass without the lease, on a node
// that has lost every voter majority, records evidence but never proves
// absence — even when its gate reads valid by the time it writes, as after a
// majority that returned mid-pass. The lease holder's passes still resolve.
//
// Mutation: let the observe-only pass run the absent-condition loop
// (gateOK without !rc.observeOnly) — the condition resolves and this goes
// red.
// quorumLostGate is a gate on a node that has lost the voter majority but
// whose execution gate reads valid, so resolveGateValid alone would let it
// resolve: observe-only passes run only there.
var quorumLostGate = fakeServerGate{execOK: true, quorum: health.QuorumNo, live: 1, needed: 2}

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
	s.SetGate(quorumLostGate)
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
	s.SetGate(quorumLostGate)
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
	s.SetGate(quorumLostGate)
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

// TestDualRunObserve_RaisesNoCoverageGap: a node without the majority knows
// it is cut off; a host it cannot reach is the leader's coverage to report.
// An observe-only pass that raised coverage_gap would page once per node per
// unreachable host (N·(N-1) in a fleet blip) and, re-observing every
// interval, keep the leader from resolving healthy hosts across the cut.
//
// Mutation: keep coverage findings in observe-only passes — a coverage_gap
// row for h2 is written and an observed event fires.
func TestDualRunObserve_RaisesNoCoverageGap(t *testing.T) {
	s := dualRunTestServerNoLease(t, 2)
	s.SetGate(quorumLostGate)
	ctx := context.Background()
	ch, unsub := s.events.Subscribe()
	defer unsub()
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{"h1": {}}, "h2")
	s.observeDualRunWithoutLease(ctx)
	s.observeDualRunWithoutLease(ctx)
	if got := condLifecycle(s, kindDualRunCoverage, "h2"); got != "" {
		t.Fatalf("an observe-only pass raised coverage_gap for the unreachable h2 (%s)", got)
	}
	for {
		select {
		case e := <-ch:
			if e.Action == "ha.condition.observed" || e.Action == "ha.dualrun" {
				t.Fatalf("an observe-only pass published %s %s", e.Action, e.Target)
			}
		default:
			return
		}
	}
}

// TestDualRunObserve_DiscardsAPassThatOutlivedTheQuorumLoss: a pass that
// began without the majority and finishes after it returned (a self probe
// stalled on libvirt) is from before the leader's view and is discarded; and
// a discarded pass breaks the run of own sightings, so confirmation needs
// two passes that each completed.
//
// Mutations: drop the re-check of LeaseQuorumLost before writing — the
// stale pass confirms the row; keep ownSeen across an early return — the
// first sighting after the discarded pass confirms.
func TestDualRunObserve_DiscardsAPassThatOutlivedTheQuorumLoss(t *testing.T) {
	s := dualRunTestServerNoLease(t, 2)
	seedVM(t, s, "vmA", "h1", "running")
	ctx := context.Background()
	lost := fakeServerGate{execOK: true, quorum: health.QuorumNo, live: 1, needed: 2}
	back := fakeServerGate{execOK: true, quorum: health.QuorumYes, live: 2, needed: 2}
	s.SetGate(lost)
	both := map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
		"h2": {diskHolderVMs: []string{"vmA"}},
	}
	s.gatherRuntimeOverride = fixedGather(both)
	s.observeDualRunWithoutLease(ctx)
	if got := condLifecycle(s, kindDualRunVM, "vmA"); got != corrosion.ConditionObserved {
		t.Fatalf("setup: first sighting left %q, want observed", got)
	}

	inner := fixedGather(both)
	s.gatherRuntimeOverride = func(ctx context.Context, hs []string) (map[string]runtimeSnapshot, []string, []string) {
		s.SetGate(back) // the majority returns while the pass is stalled
		return inner(ctx, hs)
	}
	s.observeDualRunWithoutLease(ctx)
	if got := condLifecycle(s, kindDualRunVM, "vmA"); got != corrosion.ConditionObserved {
		t.Fatalf("a pass that finished with the majority back wrote %q, want it discarded", got)
	}

	s.SetGate(lost)
	s.gatherRuntimeOverride = fixedGather(both)
	s.observeDualRunWithoutLease(ctx)
	if got := condLifecycle(s, kindDualRunVM, "vmA"); got != corrosion.ConditionObserved {
		t.Fatalf("the first sighting after a discarded pass left %q, want observed", got)
	}
	s.observeDualRunWithoutLease(ctx)
	if !confirmedCond(s, kindDualRunVM, "vmA") {
		t.Fatalf("two consecutive completed sightings left %q, want confirmed", condLifecycle(s, kindDualRunVM, "vmA"))
	}
}

// TestDualRun_RefreshNeverNarrowsHosts: admission refuses growth on every
// host a condition names, so a refresh — the leader's, or a minority node's
// that saw only its own half — adds hosts and never drops them while the
// condition stands.
//
// Mutation: replace row.Hosts with this pass's evidence (either branch) —
// h2 drops out and this goes red.
func TestDualRun_RefreshNeverNarrowsHosts(t *testing.T) {
	s := dualRunTestServer(t, 3)
	seedVM(t, s, "vmA", "h1", "running")
	ctx := context.Background()
	hostsOf := func() []string {
		h, ok, err := corrosion.GetHealthCondition(ctx, s.db, dualRunEvaluator, "vm_dual_run", "vm", "vmA")
		if err != nil || !ok {
			t.Fatalf("GetHealthCondition: %v %v", ok, err)
		}
		return h.Hosts
	}
	want := func(step string, hs []string, names ...string) {
		t.Helper()
		have := map[string]bool{}
		for _, h := range hs {
			have[h] = true
		}
		for _, n := range names {
			if !have[n] {
				t.Fatalf("%s: hosts %v dropped %s", step, hs, n)
			}
		}
	}
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}}, "h2": {diskHolderVMs: []string{"vmA"}}, "h3": {},
	})
	s.detectDualRunPass(ctx)
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}}, "h2": {}, "h3": {diskHolderVMs: []string{"vmA"}},
	})
	s.detectDualRunPass(ctx) // observed → confirmed
	want("leader confirm", hostsOf(), "h1", "h2", "h3")
	s.detectDualRunPass(ctx) // confirmed refresh
	want("leader refresh", hostsOf(), "h1", "h2", "h3")

	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}}, "h3": {diskHolderVMs: []string{"vmA"}},
	}, "h2")
	s.SetGate(quorumLostGate)
	s.observeDualRunWithoutLease(ctx)
	want("observe-only refresh", hostsOf(), "h1", "h2", "h3")
	if !confirmedCond(s, kindDualRunVM, "vmA") {
		t.Fatalf("an observe-only refresh of a confirmed row left %q", condLifecycle(s, kindDualRunVM, "vmA"))
	}
}
