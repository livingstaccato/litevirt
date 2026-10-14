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
	if !c.retryPauseWait(ctx, "down") {
		t.Fatal("setup: down had no pending pause wait")
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
