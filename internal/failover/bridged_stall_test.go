package failover

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// ha.recovery.bridged: a self-pause deadline that recovered nothing because
// observers outside the majority saw the host answer is made visible, and
// only that refusal is.

// bridgedCond reads down's ha.recovery.bridged; ok is false when there is
// none.
func bridgedCond(t *testing.T, db *corrosion.Client, ctx context.Context) (corrosion.HealthCondition, bridgedEvidence, bool) {
	t.Helper()
	row, ok, err := corrosion.GetHealthCondition(ctx, db, RefenceEvaluator, CondRecoveryBridged, "host", "down")
	if err != nil {
		t.Fatal(err)
	}
	var ev bridgedEvidence
	if ok && row.Evidence != "" {
		if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
			t.Fatalf("evidence %q: %v", row.Evidence, err)
		}
	}
	return row, ev, ok
}

func bridgedOpen(t *testing.T, db *corrosion.Client, ctx context.Context) bool {
	t.Helper()
	row, _, ok := bridgedCond(t, db, ctx)
	return ok && row.Lifecycle != corrosion.ConditionResolved
}

// derivedBridged runs the derived-set stall: a bystander sees down answer
// after the fence, and the deadline recovers nothing. It checks the
// condition is not raised while the wait is still running.
func derivedBridged(t *testing.T) (*Coordinator, *corrosion.Client, context.Context) {
	t.Helper()
	c, db, ctx, mono := pauseCoordinator(t, true)
	c.run(ctx)
	if err := db.Execute(ctx,
		`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES ('bystander', 'down', 'healthy', 0, NULL, ?)`, c.now().Add(time.Second).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	wait := health.PartitionPauseWaitFor(2)
	mono.Advance(wait - time.Second)
	c.run(ctx)
	if bridgedOpen(t, db, ctx) {
		t.Fatalf("%s raised while the host's partition-pause wait was still running", CondRecoveryBridged)
	}
	mono.Advance(2 * time.Second)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("setup: VM recovered to %q although a bystander saw down answer on a derived voter set", got)
	}
	return c, db, ctx
}

// On a derived voter set, a bystander's answer holds the recovery at the
// deadline, and the condition names the host, its workload, the observer,
// the derived set and the way out. Not before the deadline.
//
// Mutations: drop the noteBridgedStall call in retryPauseWait — nothing is
// raised; raise it from the still-waiting branch of retryPauseWait — the
// before-the-deadline check goes red.
func TestBridgedStall_DerivedSetRaisedAtTheDeadline(t *testing.T) {
	_, db, ctx := derivedBridged(t)
	row, ev, ok := bridgedCond(t, db, ctx)
	if !ok || row.Lifecycle != corrosion.ConditionConfirmed {
		t.Fatalf("%s not raised for a recovery a bystander holds: %+v (found %v)", CondRecoveryBridged, row, ok)
	}
	if row.Severity != corrosion.SeverityCritical || !slices.Equal(row.Hosts, []string{"down"}) {
		t.Errorf("severity %s hosts %v, want critical [down]", row.Severity, row.Hosts)
	}
	if !slices.Equal(ev.Workloads, []string{"vm/vm"}) {
		t.Errorf("workloads %v, want [vm/vm]", ev.Workloads)
	}
	if !slices.Contains(ev.Observers, "bystander") {
		t.Errorf("observers %v do not name the bystander", ev.Observers)
	}
	if !ev.DerivedVoterSet {
		t.Error("derived_voter_set is false on a cluster with no voter generation")
	}
	for _, want := range []string{"lv host fence-confirm down", "lv cluster voter init", "heal the partition"} {
		if !strings.Contains(ev.Remedy, want) {
			t.Errorf("remedy %q does not say %q", ev.Remedy, want)
		}
	}
}

// An operator confirms the host off: the recovery resumes and the condition
// resolves.
//
// Mutation: drop resolveBridgedSettled from the cycle — it stays open.
func TestBridgedStall_ClearsWhenTheRecoveryProceeds(t *testing.T) {
	c, db, ctx := derivedBridged(t)
	if !bridgedOpen(t, db, ctx) {
		t.Fatal("setup: not raised")
	}
	poweredOff(t, db, "bystander")
	operatorConfirms(t, db, ctx, "down")
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("setup: VM on %q after the operator confirmed the host off", got)
	}
	if bridgedOpen(t, db, ctx) {
		t.Fatalf("%s still open after the recovery proceeded", CondRecoveryBridged)
	}
}

// The partition heals: the voters see down again, it is returned to service,
// and the condition resolves with the workload where it was.
//
// Mutation: drop resolveBridgedSettled from the cycle — it stays open.
func TestBridgedStall_ClearsWhenThePartitionHeals(t *testing.T) {
	c, db, ctx := derivedBridged(t)
	for _, o := range []string{"coordinator", "alive"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'down', 'healthy', 0, NULL, ?)`, o, c.now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	c.run(ctx)
	if st := hostState(t, db, ctx); st != "active" {
		t.Fatalf("setup: down is %s after the heal, want active", st)
	}
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("setup: VM moved to %q at the heal", got)
	}
	if bridgedOpen(t, db, ctx) {
		t.Fatalf("%s still open after the partition healed", CondRecoveryBridged)
	}
}

// Under an explicit generation a bridge sees down answer and down has not
// reported its pause: held, and raised, saying the set is not derived.
func TestBridgedStall_ExplicitSetWithoutTheHostsPauseIsRaised(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	if got := atDeadline(t, c, ctx, mono, db, func() { bridgeAnswer(t, db) }); got != "down" {
		t.Fatalf("setup: VM recovered to %q", got)
	}
	row, ev, ok := bridgedCond(t, db, ctx)
	if !ok || row.Lifecycle != corrosion.ConditionConfirmed {
		t.Fatalf("%s not raised for a bridged hold under an explicit generation: %+v", CondRecoveryBridged, row)
	}
	if ev.DerivedVoterSet || strings.Contains(ev.Remedy, "voter init") {
		t.Errorf("evidence says derived (%v) or asks for genesis (%q) under an adopted generation", ev.DerivedVoterSet, ev.Remedy)
	}
	if !slices.Contains(ev.Observers, "bridge") {
		t.Errorf("observers %v do not name the bridge", ev.Observers)
	}
}

// A voter majority answering down means it may have come back, not that a
// bridge holds it: refused, and not raised.
//
// Mutation: report every refusal as bridged in selfPauseStillStands — raised.
func TestBridgedStall_AVoterMajorityAnsweringIsNotRaised(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	c.run(ctx)
	healthRow(t, db, "v4", "healthy", 0, time.Now().Add(time.Second))
	pausedCondition(t, db, time.Now())
	mono.Advance(health.PartitionPauseWaitFor(10) + time.Second)
	c.retryPauseWait(ctx, "down") // a refusal keeps the wait and reports false
	if _, ok := c.pauseWaits["down"]; !ok {
		t.Fatal("setup: down had no pending pause wait, or its deadline went ahead")
	}
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("setup: VM recovered to %q", got)
	}
	if bridgedOpen(t, db, ctx) {
		t.Fatalf("%s raised for a host a voter majority answers", CondRecoveryBridged)
	}
}

// down reported its pause failed: the hold is the power-off question, not a
// bridge, and is not raised.
//
// Mutation: report the not-relied-on refusal as bridged — raised.
func TestBridgedStall_APauseThatFailedIsNotRaised(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	got := atDeadline(t, c, ctx, mono, db, func() {
		bridgeAnswer(t, db)
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
		t.Fatalf("setup: VM recovered to %q", got)
	}
	if bridgedOpen(t, db, ctx) {
		t.Fatalf("%s raised for a host whose pause failed", CondRecoveryBridged)
	}
}

// beforeFence is the pre-fence form on a derived voter set {coordinator,
// alive, down} (quorum 2): alive fails down, but the coordinator, a voter
// (a witness bridging the split), sees it answer, so down is no fence
// candidate. Its verdict is an hour old: a checker does not re-stamp a
// steadily healthy edge. down reports its pause, raised pausedFor ago.
func beforeFence(t *testing.T, pausedFor time.Duration) (*Coordinator, *corrosion.Client, context.Context, *monoClock) {
	t.Helper()
	c, db, ctx, mono := pauseCoordinator(t, true)
	healthRow(t, db, "alive", "suspect", offlineThreshold, time.Now())
	healthRow(t, db, "coordinator", "healthy", 0, time.Now().Add(-time.Hour))
	pausedCondition(t, db, time.Now().Add(-pausedFor))
	c.run(ctx)
	if len(fenceResults(t, db, ctx)) != 0 {
		t.Fatalf("setup: down was fenced: %v", fenceResults(t, db, ctx))
	}
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("setup: VM moved to %q", got)
	}
	return c, db, ctx, mono
}

// fenceResults lists down's fencing_log results.
func fenceResults(t *testing.T, db *corrosion.Client, ctx context.Context) []string {
	t.Helper()
	rows, err := db.Query(ctx, `SELECT result FROM fencing_log WHERE host_name = 'down'`)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.String("result"))
	}
	return out
}

// A host paused longer than the wait that is no fence candidate, with a
// voter failing it and observers answering it, is raised before any fence.
//
// Mutations: drop the noteBridgedBeforeFence call from the cycle — nothing is
// raised; count only fresh answering verdicts — nothing is raised; drop the
// paused-longer-than-the-wait check — the fresh-pause test goes red.
func TestBridgedStall_BeforeAnyFenceIsRaised(t *testing.T) {
	_, db, ctx, _ := beforeFence(t, time.Hour)
	row, ev, ok := bridgedCond(t, db, ctx)
	if !ok || row.Lifecycle != corrosion.ConditionConfirmed || row.Severity != corrosion.SeverityCritical {
		t.Fatalf("%s not raised for a host held before any fence: %+v (found %v)", CondRecoveryBridged, row, ok)
	}
	if !slices.Equal(ev.Workloads, []string{"vm/vm"}) || !slices.Equal(ev.Observers, []string{"coordinator"}) || !ev.DerivedVoterSet {
		t.Errorf("evidence %s: want vm/vm, observer coordinator, derived", row.Evidence)
	}
	for _, want := range []string{"lv host fence-confirm down", "heal the partition", "no fence candidate"} {
		if !strings.Contains(ev.Remedy+" "+ev.Detail, want) {
			t.Errorf("evidence %s does not say %q", row.Evidence, want)
		}
	}
}

// A pause younger than the wait is the ordinary wait for a fence quorum.
func TestBridgedStall_BeforeAnyFenceNotWithinTheWait(t *testing.T) {
	_, db, ctx, _ := beforeFence(t, 0)
	if bridgedOpen(t, db, ctx) {
		t.Fatalf("%s raised for a pause younger than the wait", CondRecoveryBridged)
	}
}

// The partition heals: a quorum of voters answers down, and the condition
// resolves — here on a successor coordinator, from the replica.
//
// Mutations: drop the voter-quorum check in bridgedBeforeFence — it stays
// open; drop the not-held case from resolveBridgedSettled — it stays open.
func TestBridgedStall_BeforeAnyFenceClearsOnASuccessor(t *testing.T) {
	_, db, ctx, _ := beforeFence(t, time.Hour)
	if !bridgedOpen(t, db, ctx) {
		t.Fatal("setup: not raised")
	}
	healthRow(t, db, "alive", "healthy", 0, time.Now())
	if err := db.Execute(ctx, `DELETE FROM leader_election`); err != nil {
		t.Fatal(err)
	}
	succ := newTestCoordinator("alive", db)
	succ.PartitionPauseEnforced = func(context.Context) bool { return true }
	succ.PeerPausesOnLoss = func(string) bool { return true }
	succ.run(ctx)
	if bridgedOpen(t, db, ctx) {
		t.Fatalf("%s still open on the successor after a quorum answered down", CondRecoveryBridged)
	}
	row, _, _ := bridgedCond(t, db, ctx)
	if row.Reporter != "alive" {
		t.Errorf("resolved by %q, want the successor", row.Reporter)
	}
}

// The way out the condition names: the operator powers down off (now every
// voter fails it) and runs `lv host fence-confirm`. The recovery follows —
// on the confirmation, or after the coordinator's own fence and wait — and
// the condition resolves with it.
func TestBridgedStall_BeforeAnyFenceTheWayOutRecovers(t *testing.T) {
	c, db, ctx, mono := beforeFence(t, time.Hour)
	if !bridgedOpen(t, db, ctx) {
		t.Fatal("setup: not raised")
	}
	healthRow(t, db, "coordinator", "suspect", offlineThreshold, time.Now())
	operatorConfirms(t, db, ctx, "down")
	c.run(ctx)
	if vmHost(t, db, ctx) != "alive" {
		mono.Advance(health.PartitionPauseWaitFor(2) + time.Second)
		c.run(ctx)
	}
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM on %q after the operator powered down off and confirmed it", got)
	}
	if bridgedOpen(t, db, ctx) {
		t.Fatalf("%s still open after the recovery", CondRecoveryBridged)
	}
}

// A voter quorum answering down is a host coming back, about to resume, not
// one a bridge holds: not raised. Five voters (quorum 3): alive fails down,
// coordinator, v4 and v5 see it answer.
//
// Mutation: drop the voter-quorum check in bridgedBeforeFence — raised.
func TestBridgedStall_BeforeAnyFenceAVoterQuorumAnsweringIsNotRaised(t *testing.T) {
	c, db, ctx, _ := pauseCoordinator(t, true)
	for _, v := range []string{"v4", "v5"} {
		ensureVoter(t, db, v)
		healthRow(t, db, v, "healthy", 0, time.Now().Add(-time.Hour))
	}
	healthRow(t, db, "alive", "suspect", offlineThreshold, time.Now())
	healthRow(t, db, "coordinator", "healthy", 0, time.Now().Add(-time.Hour))
	pausedCondition(t, db, time.Now().Add(-time.Hour))
	c.run(ctx)
	if bridgedOpen(t, db, ctx) {
		t.Fatalf("%s raised for a host a quorum of voters sees answer", CondRecoveryBridged)
	}
}

// A fence candidate whose fence this cycle deferred (here: this node was
// itself stalled moments ago) is not "no fence candidate": not raised.
//
// Mutation: drop the fence-candidate check in bridgedBeforeFence — raised.
func TestBridgedStall_BeforeAnyFenceADeferredCandidateIsNotRaised(t *testing.T) {
	c, db, ctx, _ := pauseCoordinator(t, true)
	c.LocalStall = func() bool { return true }
	healthRow(t, db, "bystander", "healthy", 0, time.Now().Add(-time.Hour))
	pausedCondition(t, db, time.Now().Add(-time.Hour))
	c.run(ctx)
	if len(fenceResults(t, db, ctx)) != 0 || hostState(t, db, ctx) != "active" {
		t.Fatalf("setup: the fence of down was not deferred: %v %s", fenceResults(t, db, ctx), hostState(t, db, ctx))
	}
	if bridgedOpen(t, db, ctx) {
		t.Fatalf("%s raised for a fence candidate whose fence was deferred", CondRecoveryBridged)
	}
}

// A bridged refusal is re-checked every cycle (refusePauseWait): the
// condition is written once per reason, not on every re-check, and it
// resolves when the deadline goes ahead on the host's late report, though
// the limit leaves an unlisted workload behind (named by the stall alert).
//
// Mutations: raise on every re-check — the observe count climbs; drop the
// resolve on the deadline going ahead — still open after the recovery.
func TestBridgedStall_ARecheckedRefusalWritesOnceAndResolvesWhenTheDeadlineGoesAhead(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm2", HostName: "down", Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Execute(ctx, `UPDATE hosts SET cpu_total = 64, mem_total = 65536 WHERE name = 'alive'`); err != nil {
		t.Fatal(err)
	}
	if got := atDeadline(t, c, ctx, mono, db, func() { bridgeAnswer(t, db) }); got != "down" {
		t.Fatalf("setup: VM recovered to %q", got)
	}
	row, _, ok := bridgedCond(t, db, ctx)
	if !ok || row.Lifecycle != corrosion.ConditionConfirmed {
		t.Fatalf("setup: %s not raised at a bridged refusal: %+v", CondRecoveryBridged, row)
	}
	first := row.ObserveCount
	c.run(ctx)
	c.run(ctx)
	if row, _, _ := bridgedCond(t, db, ctx); row.ObserveCount != first {
		t.Fatalf("%s rewritten on each re-check of the same refusal: observe count %d, want %d", CondRecoveryBridged, row.ObserveCount, first)
	}
	pausedCondition(t, db, time.Now()) // lists vm/vm only
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("setup: VM on %q after down's condition arrived", got)
	}
	if bridgedOpen(t, db, ctx) {
		t.Fatalf("%s still open after the deadline went ahead", CondRecoveryBridged)
	}
	if held := c.unpausedHeldReason("down"); !strings.Contains(held, "vm/vm2") {
		t.Fatalf("the stall alert does not name the workload the limit left: %q", held)
	}
}

// partitionPausedUnreadable makes every read of down's partition_paused
// condition fail, as a store error would, while every other condition reads
// as before: health_conditions becomes a view whose evidence column cannot be
// computed for that one code. Writes to it fail.
func partitionPausedUnreadable(t *testing.T, db *corrosion.Client, ctx context.Context) {
	t.Helper()
	for _, q := range []string{
		`ALTER TABLE health_conditions RENAME TO health_conditions_real`,
		`CREATE VIEW health_conditions AS SELECT evaluator, code, subject_kind, subject_id, lifecycle, severity, hosts,
			CASE WHEN code = '` + corrosion.CondPartitionPaused + `' THEN json_extract('{' || evidence, '$') ELSE evidence END AS evidence,
			observe_count, clean_count, first_seen, last_seen, confirmed_at, resolved_at, reporter, created_at, updated_at, deleted_at
			FROM health_conditions_real`,
	} {
		if err := db.Execute(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
}

// A store error reading the host's own partition_paused condition, with a
// bridge seeing the host answer, is not a bridge: the refusal is the read
// error, named on its own in the stall alert, and not reported bridged.
//
// Mutation: report the unreadable refusal bridged — bridged is true here.
func TestBridgedStall_AnUnreadableConditionIsNotABridge(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	c.run(ctx)
	w, ok := c.pauseWaits["down"]
	if !ok {
		t.Fatal("setup: no pause wait")
	}
	bridgeAnswer(t, db)
	pausedCondition(t, db, time.Now())
	partitionPausedUnreadable(t, db, ctx)
	h, err := corrosion.GetHost(ctx, db, "down")
	if err != nil || h == nil {
		t.Fatalf("GetHost: %v", err)
	}
	v := c.selfPauseStillStands(ctx, h, w.fenceAt, time.Time{})
	if v.ok || v.bridged || v.why != whyPausedUnreadable {
		t.Fatalf("verdict on an unreadable partition_paused = %+v; want a refusal %q, not bridged", v, whyPausedUnreadable)
	}
	mono.Advance(health.PartitionPauseWaitFor(10) + time.Second)
	c.retryPauseWait(ctx, "down")
	if got := c.holdReason["down"]; !strings.Contains(got, whyPausedUnreadable) || strings.Contains(got, "saw the host answer") {
		t.Fatalf("the stall reason %q does not name the read error on its own", got)
	}
}

// refuseAgain re-checks down's refused deadline once.
func refuseAgain(t *testing.T, c *Coordinator, ctx context.Context) {
	t.Helper()
	c.retryPauseWait(ctx, "down")
	if _, ok := c.pauseWaits["down"]; !ok {
		t.Fatal("setup: the deadline went ahead, or there is no wait")
	}
}

// The same bridged refusal re-checked while the observers seeing the host
// answer change is one refusal: ha.recovery.bridged is raised once, not
// rewritten each time the first answering observer is another one.
//
// Mutation: de-duplicate on why (which names the observers) instead of the
// refusal's key — the observe count goes to 2.
func TestBridgedStall_ChangingObserversDoNotReRaise(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	if got := atDeadline(t, c, ctx, mono, db, func() { bridgeAnswer(t, db) }); got != "down" {
		t.Fatalf("setup: VM recovered to %q", got)
	}
	row, ev, ok := bridgedCond(t, db, ctx)
	if !ok || row.ObserveCount != 1 {
		t.Fatalf("setup: %s not raised once: %+v", CondRecoveryBridged, row)
	}
	if !strings.Contains(ev.Detail, "its own report") {
		t.Errorf("detail %q does not say that under an adopted generation the host's own report is what decides", ev.Detail)
	}
	// A second observer sees down answer, and the first one's row is
	// rewritten (INSERT OR REPLACE re-creates it): the set and its order change.
	healthRow(t, db, "bridge2", "healthy", 0, time.Now().Add(time.Second))
	refuseAgain(t, c, ctx)
	healthRow(t, db, "bridge", "healthy", 0, time.Now().Add(2*time.Second))
	refuseAgain(t, c, ctx)
	if row, _, _ := bridgedCond(t, db, ctx); row.ObserveCount != 1 || row.Lifecycle != corrosion.ConditionConfirmed {
		t.Fatalf("%s rewritten as the answering observers changed: observe_count %d, lifecycle %s",
			CondRecoveryBridged, row.ObserveCount, row.Lifecycle)
	}
}

// A refusal that stops being bridged — a voter majority now sees the host
// answer, so it is coming back — resolves ha.recovery.bridged rather than
// leaving it saying a bridge holds the host.
//
// Mutation: drop the resolve from refusePauseWait — it stays open.
func TestBridgedStall_ResolvedWhenTheRefusalIsNoLongerBridged(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	if got := atDeadline(t, c, ctx, mono, db, func() { bridgeAnswer(t, db) }); got != "down" {
		t.Fatalf("setup: VM recovered to %q", got)
	}
	if !bridgedOpen(t, db, ctx) {
		t.Fatal("setup: not raised")
	}
	healthRow(t, db, "v4", "healthy", 0, time.Now().Add(time.Second))
	refuseAgain(t, c, ctx)
	if bridgedOpen(t, db, ctx) {
		t.Fatalf("%s still open after the refusal became a voter majority answering the host", CondRecoveryBridged)
	}
}
