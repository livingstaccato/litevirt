package grpcapi

import (
	"context"
	"sort"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The detector's gather is not atomic: each host is probed at its own moment.
// A live migration's cutover pauses the source before it resumes the target,
// so no instant has two running copies — but a pass that probed the source
// just BEFORE the cutover and the target just AFTER it reads both as active
// disk-holders. That straddling sighting used to be written as an observed
// vm_dual_run, which admission honours immediately, so the next migration of
// the VM (and growth on both hosts) was refused until two clean passes later.
//
// The fix re-probes the hosts of every multi-holder sighting once, after the
// gather. A cutover cannot straddle a probe that begins after the target was
// already seen running; a real dual run is still there.

// sequencedGather answers the first gather with first and every later one
// with again, recording the hosts each call was asked for.
func sequencedGather(first, again map[string]runtimeSnapshot, againUnreachable ...string) (
	func(context.Context, []string) (map[string]runtimeSnapshot, []string, []string), *[][]string,
) {
	var calls [][]string
	return func(_ context.Context, hosts []string) (map[string]runtimeSnapshot, []string, []string) {
		calls = append(calls, append([]string(nil), hosts...))
		if len(calls) == 1 {
			return first, nil, nil
		}
		return again, append([]string(nil), againUnreachable...), nil
	}, &calls
}

// TestDualRun_CutoverStraddle_IsNotRecorded is the migration case: the first
// gather saw vmA on both hosts, the re-probe sees it only on the target.
// Nothing may be recorded, and admission for the VM and both hosts stays open.
func TestDualRun_CutoverStraddle_IsNotRecorded(t *testing.T) {
	s := dualRunTestServer(t, 3)
	seedVM(t, s, "vmA", "h2", "running") // ownership already committed to the target
	gather, calls := sequencedGather(
		map[string]runtimeSnapshot{
			"h1": {}, "h2": {diskHolderVMs: []string{"vmA"}}, "h3": {diskHolderVMs: []string{"vmA"}},
		},
		map[string]runtimeSnapshot{
			"h2": {diskHolderVMs: []string{"vmA"}}, "h3": {},
		})
	s.gatherRuntimeOverride = gather
	ctx := context.Background()

	s.detectDualRunPass(ctx)

	if got := condLifecycle(s, kindDualRunVM, "vmA"); got != "" {
		t.Fatalf("a cutover-straddling sighting was recorded as vm_dual_run %q — the re-probe saw one holder", got)
	}
	if got := condLifecycle(s, kindOwnerMismatch, "vmA"); got != "" {
		t.Fatalf("the re-probed sole holder is the DB owner, yet runtime_owner_mismatch is %q", got)
	}
	for _, h := range []string{"h2", "h3"} {
		if err := s.checkHostSafety(ctx, h, corrosion.WorkloadVM, "vmA", true, true); err != nil {
			t.Fatalf("admission of vmA onto %s refused after a straddling scan: %v", h, err)
		}
	}
	// The re-probe covers exactly the hosts of the sighting, not the fleet.
	if len(*calls) != 2 {
		t.Fatalf("gather called %d times, want 2 (gather + one re-probe)", len(*calls))
	}
	got := append([]string(nil), (*calls)[1]...)
	sort.Strings(got)
	if len(got) != 2 || got[0] != "h2" || got[1] != "h3" {
		t.Fatalf("re-probe asked for %v, want [h2 h3]", got)
	}
}

// TestDualRun_RealDualRun_BlocksOnTheFirstPass is the split-brain case the
// re-probe must not soften: two holders that are still two holders on the
// re-probe are recorded in the SAME pass, and admission refuses at once.
func TestDualRun_RealDualRun_BlocksOnTheFirstPass(t *testing.T) {
	s := dualRunTestServer(t, 2)
	seedVM(t, s, "vmA", "h1", "running")
	both := map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}}, "h2": {diskHolderVMs: []string{"vmA"}},
	}
	gather, calls := sequencedGather(both, both)
	s.gatherRuntimeOverride = gather
	ctx := context.Background()

	s.detectDualRunPass(ctx)

	if got := condLifecycle(s, kindDualRunVM, "vmA"); got != corrosion.ConditionObserved {
		t.Fatalf("a dual run seen by gather and re-probe: lifecycle %q, want observed on the first pass", got)
	}
	if len(*calls) != 2 {
		t.Fatalf("gather called %d times, want 2 — the finding must have survived a re-probe", len(*calls))
	}
	if err := s.checkHostSafety(ctx, "h2", corrosion.WorkloadVM, "vmA", false, false); err == nil {
		t.Fatal("admission for vmA was not refused on the first pass of a real dual run")
	}
	if err := s.checkHostSafety(ctx, "h2", corrosion.WorkloadVM, "other", true, true); err == nil {
		t.Fatal("growth onto a dual-run host was not refused on the first pass")
	}
}

// TestDualRun_ReprobeBlind_KeepsTheFinding: a re-probe that cannot see an
// involved host completely proves nothing, so the first sighting stands.
func TestDualRun_ReprobeBlind_KeepsTheFinding(t *testing.T) {
	first := map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}}, "h2": {diskHolderVMs: []string{"vmA"}},
	}
	cases := []struct {
		name        string
		again       map[string]runtimeSnapshot
		unreachable []string
	}{
		{"partial", map[string]runtimeSnapshot{"h1": {diskHolderVMs: []string{"vmA"}}, "h2": {partial: true}}, nil},
		{"unreachable", map[string]runtimeSnapshot{"h1": {diskHolderVMs: []string{"vmA"}}}, []string{"h2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := dualRunTestServer(t, 2)
			seedVM(t, s, "vmA", "h1", "running")
			gather, _ := sequencedGather(first, tc.again, tc.unreachable...)
			s.gatherRuntimeOverride = gather
			s.detectDualRunPass(context.Background())
			if got := condLifecycle(s, kindDualRunVM, "vmA"); got != corrosion.ConditionObserved {
				t.Fatalf("re-probe blind to h2: lifecycle %q, want observed — absence was not proven", got)
			}
		})
	}
}

// TestDualRun_ContainerCutoverStraddle_IsNotRecorded: a cold container move
// stops the source before starting the target, so it straddles a gather the
// same way, and is settled the same way.
func TestDualRun_ContainerCutoverStraddle_IsNotRecorded(t *testing.T) {
	s := dualRunTestServer(t, 2)
	seedContainer(t, s, "ctA", "h1", "migrating")
	gather, _ := sequencedGather(
		map[string]runtimeSnapshot{"h1": {runningCTs: []string{"ctA"}}, "h2": {runningCTs: []string{"ctA"}}},
		map[string]runtimeSnapshot{"h1": {}, "h2": {runningCTs: []string{"ctA"}}})
	s.gatherRuntimeOverride = gather
	s.detectDualRunPass(context.Background())
	if got := condLifecycle(s, kindDualRunCT, "ctA"); got != "" {
		t.Fatalf("a container cutover-straddling sighting was recorded as ct_dual_run %q", got)
	}

	// Control: still on both hosts at the re-probe.
	s2 := dualRunTestServer(t, 2)
	seedContainer(t, s2, "ctA", "h1", "migrating")
	both := map[string]runtimeSnapshot{"h1": {runningCTs: []string{"ctA"}}, "h2": {runningCTs: []string{"ctA"}}}
	gather2, _ := sequencedGather(both, both)
	s2.gatherRuntimeOverride = gather2
	s2.detectDualRunPass(context.Background())
	if got := condLifecycle(s2, kindDualRunCT, "ctA"); got != corrosion.ConditionObserved {
		t.Fatalf("a container on two hosts at gather and re-probe: lifecycle %q, want observed", got)
	}
}

// TestDualRun_RecordedDualRunIsNotNarrowedByAFlappingCopy: once a dual run is
// recorded, a re-probe that misses one copy — a host flapping, or a copy that
// stops and starts — is not a cutover straddle. Narrowing it would record the
// pass as clean and resolve a real split brain between sightings, reopening
// admission while both copies still write. The sighting stands, so the
// condition is confirmed and stays.
//
// Mutation: drop the active-condition check from reprobeMultiHolders — the
// second pass is clean, the condition is never confirmed and goes red.
func TestDualRun_RecordedDualRunIsNotNarrowedByAFlappingCopy(t *testing.T) {
	both := map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}}, "h2": {diskHolderVMs: []string{"vmA"}},
	}
	flapped := map[string]runtimeSnapshot{"h1": {diskHolderVMs: []string{"vmA"}}, "h2": {}}
	s := dualRunTestServer(t, 2)
	seedVM(t, s, "vmA", "h1", "running")
	ctx := context.Background()

	gather, _ := sequencedGather(both, both)
	s.gatherRuntimeOverride = gather
	s.detectDualRunPass(ctx)
	if got := condLifecycle(s, kindDualRunVM, "vmA"); got != corrosion.ConditionObserved {
		t.Fatalf("first pass: lifecycle %q, want observed", got)
	}

	for pass := 2; pass <= 4; pass++ {
		gather, _ := sequencedGather(both, flapped)
		s.gatherRuntimeOverride = gather
		s.detectDualRunPass(ctx)
		if got := condLifecycle(s, kindDualRunVM, "vmA"); got != corrosion.ConditionConfirmed {
			t.Fatalf("pass %d with a copy missing only at the re-probe: lifecycle %q, want confirmed", pass, got)
		}
	}
	if err := s.checkHostSafety(ctx, "h2", corrosion.WorkloadVM, "vmA", false, false); err == nil {
		t.Fatal("admission for vmA reopened during a recorded dual run")
	}
}

// TestDualRun_RecordedContainerDualRunIsNotNarrowed is the container case.
func TestDualRun_RecordedContainerDualRunIsNotNarrowed(t *testing.T) {
	both := map[string]runtimeSnapshot{"h1": {runningCTs: []string{"ctA"}}, "h2": {runningCTs: []string{"ctA"}}}
	flapped := map[string]runtimeSnapshot{"h1": {runningCTs: []string{"ctA"}}, "h2": {}}
	s := dualRunTestServer(t, 2)
	seedContainer(t, s, "ctA", "h1", "running")
	ctx := context.Background()
	gather, _ := sequencedGather(both, both)
	s.gatherRuntimeOverride = gather
	s.detectDualRunPass(ctx)
	if got := condLifecycle(s, kindDualRunCT, "ctA"); got != corrosion.ConditionObserved {
		t.Fatalf("first pass: lifecycle %q, want observed", got)
	}
	gather, _ = sequencedGather(both, flapped)
	s.gatherRuntimeOverride = gather
	s.detectDualRunPass(ctx)
	if got := condLifecycle(s, kindDualRunCT, "ctA"); got != corrosion.ConditionConfirmed {
		t.Fatalf("second pass with a copy missing only at the re-probe: lifecycle %q, want confirmed", got)
	}
}
