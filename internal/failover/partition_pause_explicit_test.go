package failover

import (
	"context"
	"testing"
	"time"

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
	return c, db, ctx, mono
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

// pausedCondition is down's own partition_paused condition, raised at at.
func pausedCondition(t *testing.T, db *corrosion.Client, at time.Time) {
	t.Helper()
	ts := at.UTC().Format(time.RFC3339)
	if err := corrosion.UpsertHealthCondition(context.Background(), db, corrosion.HealthCondition{
		Evaluator: corrosion.PartitionPauseEvaluator, Code: corrosion.CondPartitionPaused,
		SubjectKind: "host", SubjectID: "down", Lifecycle: corrosion.ConditionConfirmed,
		Severity: corrosion.SeverityWarning, FirstSeen: ts, LastSeen: ts, Evidence: `{"paused":["vm/vm"]}`,
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
// Mutation: skip hostReportsItsPause in selfPauseStillStands — the VM moves.
func TestSelfPauseExplicit_ABridgeWithoutTheHostsPauseIsRefused(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	if got := atDeadline(t, c, ctx, mono, db, func() { bridgeAnswer(t, db) }); got != "down" {
		t.Fatalf("VM recovered to %q although down answered a bridge and reported no pause", got)
	}
}

// A partition_paused condition raised before this outage does not speak for
// it.
//
// Mutation: drop the outage-start check in hostReportsItsPause — the VM moves.
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
// Mutation: never refuse in answeredByAVoterMajority — the VM moves.
func TestSelfPauseExplicit_AVoterMajorityAnsweringIsRefused(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	c.run(ctx)
	if m, a := newestAssurance(t, db, ctx, "down"); a != corrosion.FenceSelfPaused {
		t.Fatalf("setup: fence recorded %s (%s), want self_paused", m, a)
	}
	healthRow(t, db, "v4", "healthy", 0, time.Now().Add(time.Second))
	pausedCondition(t, db, time.Now())
	mono.Advance(health.PartitionPauseWaitFor(10) + time.Second)
	if !c.retryPauseWait(ctx, "down") {
		t.Fatal("setup: down had no pending pause wait")
	}
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

// One voter that has been failing down for an hour (a broken route of its
// own) does not date the outage: the host cannot have lost its majority
// before n−q+1 = 3 voters stopped answering, so the anchor is the third
// earliest run, at the cut. A condition raised half an hour ago predates it.
//
// Mutation: anchor on the earliest run in outageStart — the hour-old run
// admits the half-hour-old condition and the VM moves.
func TestSelfPauseExplicit_ALongFailingObserverCannotPullTheAnchorBack(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	if err := db.Execute(ctx,
		`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES ('v4', 'down', 'suspect', ?, ?, ?)`, 1800,
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	got := atDeadline(t, c, ctx, mono, db, func() {
		bridgeAnswer(t, db)
		pausedCondition(t, db, time.Now().Add(-30*time.Minute))
	})
	if got != "down" {
		t.Fatalf("VM recovered to %q on a condition older than the outage, dated by one long-failing voter", got)
	}
}

// Under a bridge the host's word covers what it reported pausing and nothing
// more: a second VM it did not list stays where it is.
//
// Mutation: ignore recoverOnly in recoverWorkloads — vm2 moves too.
func TestSelfPauseExplicit_OnlyReportedPausedWorkloadsAreRecovered(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm2", HostName: "down", Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	got := atDeadline(t, c, ctx, mono, db, func() {
		bridgeAnswer(t, db)
		pausedCondition(t, db, time.Now()) // lists vm/vm only
	})
	if got != "alive" {
		t.Fatalf("setup: the reported VM is on %q, want it recovered", got)
	}
	vm2, err := corrosion.GetVM(ctx, db, "vm2")
	if err != nil || vm2 == nil {
		t.Fatalf("GetVM vm2: %v", err)
	}
	if vm2.HostName != "down" {
		t.Fatalf("vm2 recovered to %q although down did not report pausing it", vm2.HostName)
	}
}
