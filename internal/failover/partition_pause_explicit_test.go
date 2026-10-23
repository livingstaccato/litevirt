package failover

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// The self-pause deadline under an explicit voter generation
// (selfPauseStillStands, docs/design/partition-pause.md §4.2 step 3).
//
// explicitPause is pauseCoordinator with generation 1 = {coordinator, alive,
// down, v4, v5} adopted. coordinator, alive and v4 fail down (the fence
// quorum, 3 of 5); v5's latest verdict about down is an old healthy one, as a
// minority voter's is. down holds the VM; alive is the one placement target.
func explicitPause(t *testing.T) (*Coordinator, *corrosion.Client, context.Context, *monoClock) {
	t.Helper()
	c, db, ctx, mono := pauseCoordinator(t, true)
	for _, v := range []string{"v4", "v5"} {
		ensureVoter(t, db, v)
	}
	healthRow(t, db, "v4", "suspect", offlineThreshold, time.Now())
	healthRow(t, db, "v5", "healthy", 0, time.Now().Add(-time.Hour))
	db.SetVoterConfigGate(func() bool { return true })
	writeGen(t, db, 1, "coordinator", "alive", "down", "v4", "v5")
	if err := corrosion.RecordVoterAdoption(ctx, db, 1); err != nil {
		t.Fatal(err)
	}
	reportedGeneration(c, 1, time.Time{})
	return c, db, ctx, mono
}

// reportedGeneration has down report, in a Ping this node received at at,
// that it had adopted generation gen.
func reportedGeneration(c *Coordinator, gen int64, at time.Time) {
	c.PeerVoterGeneration = func(peer string, before time.Time) (int64, bool) {
		return gen, peer == "down" && at.Before(before)
	}
}

func healthRow(t *testing.T, db *corrosion.Client, observer, status string, failures int, at time.Time) {
	t.Helper()
	if err := db.Execute(context.Background(),
		`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES (?, 'down', ?, ?, NULL, ?)`, observer, status, failures, at.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

func writeGen(t *testing.T, db *corrosion.Client, gen int64, members ...string) {
	t.Helper()
	var ms []corrosion.VoterMember
	for _, m := range members {
		ms = append(ms, corrosion.VoterMember{Name: m})
	}
	change := "rm"
	if len(ms) == 0 {
		change = "reset"
	}
	if err := corrosion.WriteVoterConfig(context.Background(), db, corrosion.VoterConfigValue{
		Generation: gen, Members: ms, Change: change, CreatedBy: "coordinator",
		CreatedAt: time.Now().UTC().Format(time.RFC3339)}, corrosion.ClaimCertificate{}); err != nil {
		t.Fatal(err)
	}
}

// pausedCondition is down's own partition_paused condition, raised at at,
// listing vm/vm as paused.
func pausedCondition(t *testing.T, db *corrosion.Client, at time.Time) {
	t.Helper()
	pausedConditionListing(t, db, at, "vm/vm")
}

// pausedConditionListing is down's partition_paused condition, raised at at,
// listing keys as paused.
func pausedConditionListing(t *testing.T, db *corrosion.Client, at time.Time, keys ...string) {
	t.Helper()
	b, _ := json.Marshal(struct {
		Paused []string `json:"paused"`
	}{keys})
	ts := at.UTC().Format(time.RFC3339)
	if err := corrosion.UpsertHealthCondition(context.Background(), db, corrosion.HealthCondition{
		Evaluator: corrosion.PartitionPauseEvaluator, Code: corrosion.CondPartitionPaused,
		SubjectKind: "host", SubjectID: "down", Lifecycle: corrosion.ConditionConfirmed,
		Severity: corrosion.SeverityWarning, FirstSeen: ts, LastSeen: ts, Evidence: string(b),
	}); err != nil {
		t.Fatal(err)
	}
}

// bridgeAnswer is a non-voter that still reaches down seeing it answer.
func bridgeAnswer(t *testing.T, db *corrosion.Client) {
	t.Helper()
	healthRow(t, db, "bridge", "healthy", 0, time.Now().Add(time.Second))
}

// atDeadline fences down, then runs the coordinator once its wait has passed.
func atDeadline(t *testing.T, c *Coordinator, ctx context.Context, mono *monoClock, db *corrosion.Client, between func()) string {
	t.Helper()
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("setup: VM moved to %q at the fence decision", got)
	}
	if m, a := newestAssurance(t, db, ctx, "down"); a != corrosion.FenceSelfPaused {
		t.Fatalf("setup: fence recorded %s (%s), want self_paused", m, a)
	}
	if between != nil {
		between()
	}
	mono.Advance(health.PartitionPauseWaitFor(10) + time.Second)
	c.run(ctx)
	return vmHost(t, db, ctx)
}

// A plain partition: nobody has seen down answer since the fence, and the
// voters answering it are no majority. Recovered, as before.
func TestSelfPauseExplicit_APlainPartitionIsRecovered(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	if got := atDeadline(t, c, ctx, mono, db, nil); got != "alive" {
		t.Fatalf("VM on %q after the deadline of a plain partition; want it recovered", got)
	}
}

// The lab: a non-voter bridging the halves sees down answer, and down
// reports that it paused during this outage. Recovered.
func TestSelfPauseExplicit_ABridgeWithTheHostsPauseIsRecovered(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	got := atDeadline(t, c, ctx, mono, db, func() {
		bridgeAnswer(t, db)
		pausedCondition(t, db, time.Now())
	})
	if got != "alive" {
		t.Fatalf("VM on %q; a bridged host that reported its pause must be recovered", got)
	}
}

// A bridge sees down answer, and down has reported no pause: it may never
// have paused (a voter set this node does not know, or a one-way cut).
//
// Mutation: skip hostReportsItsPauseIn in selfPauseStillStands — the VM moves.
func TestSelfPauseExplicit_ABridgeWithoutTheHostsPauseIsRefused(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	if got := atDeadline(t, c, ctx, mono, db, func() { bridgeAnswer(t, db) }); got != "down" {
		t.Fatalf("VM recovered to %q although down answered a bridge and reported no pause", got)
	}
}

// A partition_paused condition raised before this outage does not speak for
// it.
//
// Mutation: drop the outage-start check in hostReportsItsPauseIn — the VM moves.
func TestSelfPauseExplicit_AStalePauseConditionIsRefused(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	got := atDeadline(t, c, ctx, mono, db, func() {
		bridgeAnswer(t, db)
		pausedCondition(t, db, time.Now().Add(-time.Hour))
	})
	if got != "down" {
		t.Fatalf("VM recovered to %q on a partition_paused condition from before the outage", got)
	}
}

// Voters answering down, counting down itself, make a majority: it may hold
// its majority (it has come back). Refused, even with its pause reported.
//
// Through run() this cannot be reached for the adopted generation: a voter
// majority answering down leaves no fence quorum failing it, and a host that
// is no fence candidate is not revisited at all. The deadline check is
// therefore called directly, as a coordinator that still listed the host
// would.
//
// Mutation: never refuse in answeredByAVoterMajorityIn — the VM moves.
func TestSelfPauseExplicit_AVoterMajorityAnsweringIsRefused(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	c.run(ctx)
	if m, a := newestAssurance(t, db, ctx, "down"); a != corrosion.FenceSelfPaused {
		t.Fatalf("setup: fence recorded %s (%s), want self_paused", m, a)
	}
	healthRow(t, db, "v4", "healthy", 0, time.Now().Add(time.Second))
	pausedCondition(t, db, time.Now())
	mono.Advance(health.PartitionPauseWaitFor(10) + time.Second)
	if _, ok := c.pauseWaits["down"]; !ok {
		t.Fatal("setup: down had no pending pause wait")
	}
	c.retryPauseWait(ctx, "down")
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM recovered to %q although down, v4 and v5 (3 of 5 voters) last saw it answer", got)
	}
}

// A newer generation this node has not adopted, in which the same answers
// are a majority: down may be counting over it. Refused.
//
// Mutation: drop the newer-generation sets in pauseVoterSets — the VM moves.
func TestSelfPauseExplicit_ANewerGenerationIsCountedToo(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	writeGen(t, db, 2, "alive", "down", "v5")
	got := atDeadline(t, c, ctx, mono, db, func() { pausedCondition(t, db, time.Now()) })
	if got != "down" {
		t.Fatalf("VM recovered to %q although down and v5 are 2 of generation 2's 3", got)
	}
}

// A newer generation that is a reset: a host that adopted it counts over its
// derived set, which this node cannot know, so any observer that has seen it
// answer refuses (fenceStillStands).
//
// Mutation: skip a non-explicit newer generation in pauseVoterSets — the VM
// moves on the bridge's answer and the host's condition.
func TestSelfPauseExplicit_ANewerResetFallsBackToAnyObserver(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	writeGen(t, db, 2)
	got := atDeadline(t, c, ctx, mono, db, func() {
		bridgeAnswer(t, db)
		pausedCondition(t, db, time.Now())
	})
	if got != "down" {
		t.Fatalf("VM recovered to %q past a newer reset generation with a bridge answering", got)
	}
}

// down reports its pause failed after the fence: the pause is no longer
// relied on, and any observer that has seen it answer refuses.
//
// Mutation: drop the relyOnPartitionPause re-check in selfPauseStillStands —
// the VM moves.
func TestSelfPauseExplicit_APauseFailedAfterTheFenceFallsBackToAnyObserver(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	got := atDeadline(t, c, ctx, mono, db, func() {
		bridgeAnswer(t, db)
		pausedCondition(t, db, time.Now())
		ts := time.Now().UTC().Format(time.RFC3339)
		if err := corrosion.UpsertHealthCondition(ctx, db, corrosion.HealthCondition{
			Evaluator: corrosion.PartitionPauseEvaluator, Code: corrosion.CondPartitionPauseFailed,
			SubjectKind: "host", SubjectID: "down", Lifecycle: corrosion.ConditionConfirmed,
			Severity: corrosion.SeverityCritical, FirstSeen: ts, LastSeen: ts,
		}); err != nil {
			t.Fatal(err)
		}
	})
	if got != "down" {
		t.Fatalf("VM recovered to %q although down reported its pause failed and answered a bridge", got)
	}
}

// A successor (or a restarted coordinator) resumes a self-pause fence record
// although a bridge sees the host answer: it waits afresh and applies the
// self-pause rule at its own deadline.
//
// Mutation: drop the self-pause branch in resumeActionFor — the successor
// declines the record (fenceStillStands) and the VM never moves.
func TestSelfPauseExplicit_ASuccessorResumesPastABridge(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("setup: VM moved to %q", got)
	}
	bridgeAnswer(t, db)
	pausedCondition(t, db, time.Now())
	if err := db.Execute(ctx, `DELETE FROM leader_election`); err != nil {
		t.Fatal(err)
	}
	succ := newTestCoordinator("alive", db)
	succ.SetFencer(fencerReturning("best-effort-ssh", true))
	succ.Mono = mono.Now
	succ.PartitionPauseEnforced = func(context.Context) bool { return true }
	succ.PeerPausesOnLoss = func(string) bool { return true }
	succ.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("the successor recovered at once (%q) on a self-pause record", got)
	}
	mono.Advance(health.PartitionPauseWaitFor(10) + time.Second)
	succ.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM on %q after the successor's own wait; a bridged self-pause record must be resumed", got)
	}
}

// failingSince is observer failing down since since (its run's last_seen),
// its row written at written.
func failingSince(t *testing.T, db *corrosion.Client, observer string, since, written time.Time) {
	t.Helper()
	if err := db.Execute(context.Background(),
		`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES (?, 'down', 'suspect', ?, ?, ?)`, observer, 1800,
		since.UTC().Format(time.RFC3339Nano), written.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

// The outage is dated by the voters: with n = 5 and q = 3, the host cannot
// have lost its majority before n−q+1 = 3 of the other voters stopped
// answering. Here v4 has failed down for an hour, v5 for twenty minutes, a
// non-voter for two hours, and coordinator and alive since the cut, so the
// outage begins at the cut and a condition raised ten minutes ago predates it.
//
// Mutations: anchor on the earliest run (an hour ago), or on the (n−q)-th
// (twenty minutes ago, one short), or count non-voters' runs (the third
// earliest becomes twenty minutes ago) — each admits the condition and the VM
// moves.
func TestSelfPauseExplicit_TheOutageBeginsAtTheVotersNMinusQPlus1thRun(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	now := time.Now()
	failingSince(t, db, "v4", now.Add(-time.Hour), now)
	failingSince(t, db, "v5", now.Add(-20*time.Minute), now)
	failingSince(t, db, "far-non-voter", now.Add(-2*time.Hour), now)
	got := atDeadline(t, c, ctx, mono, db, func() {
		bridgeAnswer(t, db)
		pausedCondition(t, db, time.Now().Add(-10*time.Minute))
	})
	if got != "down" {
		t.Fatalf("VM recovered to %q on a condition raised before the third voter lost the host", got)
	}
}

// The same voters with the condition raised after the cut: recovered, so the
// test above refuses on the anchor and nothing else.
func TestSelfPauseExplicit_AConditionAfterTheVotersAnchorIsRecovered(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	now := time.Now()
	failingSince(t, db, "v4", now.Add(-time.Hour), now)
	failingSince(t, db, "v5", now.Add(-20*time.Minute), now)
	failingSince(t, db, "far-non-voter", now.Add(-2*time.Hour), now)
	got := atDeadline(t, c, ctx, mono, db, func() {
		bridgeAnswer(t, db)
		pausedCondition(t, db, time.Now())
	})
	if got != "alive" {
		t.Fatalf("VM on %q; a condition raised after the cut must be accepted", got)
	}
}

// Fewer than n−q+1 voters still fail down with a run spanning the fence (v4's
// row has gone stale): the outage cannot be dated, and nothing is recovered.
// Through run() down would no longer be a fence candidate at all, so the
// deadline check is called directly, as a coordinator that still listed it
// would.
//
// Mutation: drop the too-few-runs refusal in outageStartIn — it indexes past
// the runs it has and the test goes red.
func TestSelfPauseExplicit_TooFewVoterRunsToDateTheOutageAreRefused(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	c.run(ctx)
	if m, a := newestAssurance(t, db, ctx, "down"); a != corrosion.FenceSelfPaused {
		t.Fatalf("setup: fence recorded %s (%s), want self_paused", m, a)
	}
	failingSince(t, db, "v4", time.Now().Add(-time.Hour), time.Now().Add(-time.Hour))
	bridgeAnswer(t, db)
	pausedCondition(t, db, time.Now())
	mono.Advance(health.PartitionPauseWaitFor(10) + time.Second)
	if _, ok := c.pauseWaits["down"]; !ok {
		t.Fatal("setup: down had no pending pause wait")
	}
	c.retryPauseWait(ctx, "down")
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM recovered to %q with only two voters' runs to date the outage by", got)
	}
}

// unlistedWorkloads adds to explicitPause's down a second VM, vm2, and two
// relocatable containers, ct1 and ct2, with alive able to take them all.
func unlistedWorkloads(t *testing.T, db *corrosion.Client) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm2", HostName: "down", Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Execute(ctx, `UPDATE hosts SET cpu_total = 64, mem_total = 65536 WHERE name = 'alive'`); err != nil {
		t.Fatal(err)
	}
	runsContainers(t, db, "alive")
	for _, ct := range []string{"ct1", "ct2"} {
		if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{
			HostName: "down", Name: ct, State: "running", Image: "alpine:3.19",
			CPULimit: 1, MemMiB: 128, Project: "p1", OnHostFailure: "image-recreate",
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// assertLimited checks the listed workloads (vm, ct1) left down and the
// unlisted ones (vm2, ct2) did not.
func assertLimited(t *testing.T, db *corrosion.Client) {
	t.Helper()
	ctx := context.Background()
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("the reported VM is on %q, want it recovered", got)
	}
	if g, _ := corrosion.GetContainer(ctx, db, "down", "ct1"); g != nil {
		t.Fatalf("the reported container ct1 is still on down: %+v", g)
	}
	vm2, err := corrosion.GetVM(ctx, db, "vm2")
	if err != nil || vm2 == nil {
		t.Fatalf("GetVM vm2: %v", err)
	}
	if vm2.HostName != "down" {
		t.Fatalf("vm2 recovered to %q although down did not report pausing it", vm2.HostName)
	}
	if g, _ := corrosion.GetContainer(ctx, db, "down", "ct2"); g == nil {
		t.Fatal("ct2 relocated although down did not report pausing it")
	}
}

// Under a bridge the host's word covers what it reported pausing and nothing
// more: a VM and a container it did not list stay where they are.
//
// Mutations: ignore recoverOnly in recoverWorkloads — vm2 moves; ignore it in
// relocateContainers — ct2 moves.
func TestSelfPauseExplicit_OnlyReportedPausedWorkloadsAreRecovered(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	unlistedWorkloads(t, db)
	atDeadline(t, c, ctx, mono, db, func() {
		bridgeAnswer(t, db)
		pausedConditionListing(t, db, time.Now(), "vm/vm", "ct/ct1")
	})
	assertLimited(t, db)
}

// The limit holds for the whole down-episode, not one recovery pass: a
// refused recovery claim makes the next tick re-run the host's recovery
// (retryClaims), which must not move what the host did not report pausing.
//
// Mutation: lift the limit after the deadline's own pass (as the first cut
// did) — the claim retry moves vm2 and ct2 while down may still run them.
func TestSelfPauseExplicit_AClaimRetryKeepsTheLimit(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	unlistedWorkloads(t, db)
	db.SetRecoveryClaimGate(func() bool { return true })
	refused := false
	cl := &fakeClaimer{decide: func(key corrosion.ClaimKey, v corrosion.ClaimValue) (claims.Outcome, error) {
		if !refused {
			refused = true
			return claims.Outcome{}, errors.New("a voter did not answer in time")
		}
		return decideOurs(key, v)
	}}
	c.Claimer = cl
	c.RecoveryClaimEnforced = func(context.Context) bool { return true }
	c.Gate = fakeFailoverGate{
		supports: map[string]bool{"alive": true},
		enforced: map[string]bool{capabilities.SplitBrainGateV1: true},
	}
	atDeadline(t, c, ctx, mono, db, func() {
		bridgeAnswer(t, db)
		pausedConditionListing(t, db, time.Now(), "vm/vm", "ct/ct1")
	})
	if !refused {
		t.Fatal("setup: no recovery claim was refused at the deadline")
	}
	if !c.claimRetry["down"] {
		t.Fatal("setup: the refused claim scheduled no retry of down's recovery")
	}
	// The bridge saw down answer after the deadline the retry is owed to,
	// so the retry waits out a fresh deadline first (claimRetryOutageOver).
	c.run(ctx)
	mono.Advance(health.PartitionPauseWaitFor(10) + time.Second)
	c.run(ctx)
	c.run(ctx)
	assertLimited(t, db)
	// The stall alert keeps naming what was held back, whatever newer hold
	// reason the retries recorded.
	if held := c.unpausedHeldReason("down"); !strings.Contains(held, "vm/vm2") || !strings.Contains(held, "ct/ct2") {
		t.Fatalf("the held workloads are no longer named for the stall alert: %q", held)
	}
}

// A limited recovery names, as possibly still running on the host, only what
// it would otherwise have recovered: a VM stopped by intent, one with
// on_host_failure=none, one with firmware state, and a stopped container are
// never paused by the host and never moved, and are not named.
//
// Mutation: name every workload the limit drops — the stall alert names
// them.
func TestSelfPauseExplicit_ALimitNamesOnlyWhatWouldBeRecovered(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	unlistedWorkloads(t, db)
	for _, vm := range []corrosion.VMRecord{
		{Name: "stoppedvm", HostName: "down", Spec: `{"on_host_failure":"restart-any"}`, State: "stopped", StateDetail: "operator-stop"},
		{Name: "nonevm", HostName: "down", Spec: `{"on_host_failure":"none"}`, State: "running"},
		{Name: "tpmvm", HostName: "down", Spec: `{"on_host_failure":"restart-any","tpm":true}`, State: "running"},
	} {
		if err := corrosion.InsertVM(ctx, db, vm, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{
		HostName: "down", Name: "stoppedct", State: "stopped", Image: "alpine:3.19",
		CPULimit: 1, MemMiB: 128, Project: "p1", OnHostFailure: "image-recreate",
	}); err != nil {
		t.Fatal(err)
	}
	atDeadline(t, c, ctx, mono, db, func() {
		bridgeAnswer(t, db)
		pausedConditionListing(t, db, time.Now(), "vm/vm", "ct/ct1")
	})
	assertLimited(t, db)
	held := c.unpausedHeldReason("down")
	if !strings.Contains(held, "vm/vm2") || !strings.Contains(held, "ct/ct2") {
		t.Fatalf("the held recoverable workloads are not named: %q", held)
	}
	for _, never := range []string{"stoppedvm", "nonevm", "tpmvm", "stoppedct"} {
		if strings.Contains(held, never) {
			t.Errorf("the stall alert names %s, which would never be recovered, as possibly still running: %q", never, held)
		}
	}
}
