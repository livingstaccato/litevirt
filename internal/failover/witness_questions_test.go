package failover

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
)

// Questions Q1, Q2 and Q4 of the witness drill design (2026-10-15), each
// pinned on the coordinator alone: the fleet cannot make them deterministic,
// and none needs more than one node's replica. Q3 is witness_claim_retry_test.go.

// bridgedRow is down's ha.recovery.bridged, if raised and not resolved.
func bridgedRow(t *testing.T, db *corrosion.Client, ctx context.Context) (bridgedEvidence, bool) {
	t.Helper()
	row, ok, err := corrosion.GetHealthCondition(ctx, db, RefenceEvaluator, CondRecoveryBridged, "host", "down")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || row.Lifecycle == corrosion.ConditionResolved {
		return bridgedEvidence{}, false
	}
	var ev bridgedEvidence
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
		t.Fatalf("ha.recovery.bridged evidence %q: %v", row.Evidence, err)
	}
	return ev, true
}

// Q1. A host whose proof-grade fence FAILED while a non-voter bridge still
// reaches it: the failed fence's retry is refused on every cycle, because
// the bridge saw the host answer after the attempt, and the host has
// reported pausing its workloads. Nothing recovers them and nothing will
// while the bridge lasts: the stall a bridge causes, which
// ha.recovery.bridged names. Neither of its two forms covered it — the
// deadline form needs a self-pause fence, and the before-fence form skips an
// offline host.
//
// Mutation: drop the bridged raise on a refused retry — no condition.
func TestWitnessQ1_AFailedFenceHeldByABridgeRaisesBridged(t *testing.T) {
	db, ctx := seedDownHost(t, "ipmi", nil)
	thirdVoter(t, db, ctx)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "ipmi", Success: false, Detail: "BMC unreachable"}
	})
	c.run(ctx)
	if got := hostState(t, db, ctx); got != "offline" {
		t.Fatalf("setup: down is %q after a failed fence, want offline", got)
	}
	ageFenceRows(t, db, ctx, fenceRetryBase+time.Second)
	c.lastFenceAt = nil
	bridgeAnswer(t, db)
	pausedCondition(t, db, time.Now())
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("setup: VM moved to %q", got)
	}
	if !strings.Contains(c.holdReason["down"], "has answered since") {
		t.Fatalf("setup: the retry was not refused on the bridge's answer (hold %q)", c.holdReason["down"])
	}
	ev, ok := bridgedRow(t, db, ctx)
	if !ok {
		t.Fatal("no ha.recovery.bridged for a host whose failed fence is held only by a bridge's answer")
	}
	if len(ev.Observers) != 1 || ev.Observers[0] != "bridge" {
		t.Errorf("bridged observers = %v, want [bridge]", ev.Observers)
	}
	if !strings.Contains(ev.Detail, "fence") {
		t.Errorf("bridged detail does not say the fence failed: %q", ev.Detail)
	}

	// The bridge goes: the retry runs (and fails again); nothing holds the
	// host on a bridge any more, but it stays offline with its workload, so
	// the condition stays until the workload moves or the host comes back.
	// Here: an operator confirms it off and the VM moves; the condition
	// resolves.
	poweredOff(t, db, "bridge")
	operatorConfirms(t, db, ctx, "down")
	c.run(ctx)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM on %q after an operator confirmed down off", got)
	}
	if _, ok := bridgedRow(t, db, ctx); ok {
		t.Error("ha.recovery.bridged outlived the recovery")
	}
}

// Q2. At an exact fence quorum (3 of 5), one failing voter's probe succeeds
// once after the deadline, so for a few cycles only 2 voters fail down and
// it is no fence candidate. The deadline is re-checked only from the fence
// loop, so it is not re-checked meanwhile — safe, recovery waits — but the
// stall reason must not keep saying the coordinator is waiting out the pause
// when the deadline has passed. When the voter fails down again, the
// deadline is re-checked and the VM recovered.
//
// Mutation: drop the not-a-candidate stall reason — it still reads
// "waiting out the host's partition pause".
func TestWitnessQ2_AVoterHiccupAtExactQuorumNamesWhyTheDeadlineWaits(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	c.run(ctx)
	if m, a := newestAssurance(t, db, ctx, "down"); a != corrosion.FenceSelfPaused {
		t.Fatalf("setup: fence recorded %s (%s), want self_paused", m, a)
	}
	pausedCondition(t, db, time.Now())
	// v4's run restarted: it failed twice since its one success.
	healthRow(t, db, "v4", "suspect", 2, time.Now())
	mono.Advance(health.PartitionPauseWaitFor(10) + time.Second)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("setup: VM moved to %q while down was no fence candidate", got)
	}
	reason := c.holdReason["down"]
	if strings.Contains(reason, "waiting out") {
		t.Fatalf("the stall reason after the deadline, with down no fence candidate, still says it is waiting: %q", reason)
	}
	for _, want := range []string{"deadline has passed", "2 of 3"} {
		if !strings.Contains(reason, want) {
			t.Fatalf("the stall reason %q does not say %q", reason, want)
		}
	}
	healthRow(t, db, "v4", "suspect", offlineThreshold, time.Now())
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM on %q once down was a fence candidate again past its deadline; want it recovered", got)
	}
}

// Q4. down's clock runs 60 s behind: its partition_paused condition, raised
// during this outage, carries a first_seen a minute before the voters began
// failing it, more than fenceSkewMargin. While a bridge sees down answer the
// deadline refuses on that ("predates this outage") and raises
// ha.recovery.bridged — erring safe, as intended. The hold is bounded by the
// bridge: once no observer sees down answer, the deadline recovers.
//
// Mutation: refuse a predating condition when no observer sees the host
// answer too (pausedThisOutageIn) — the VM never moves.
func TestWitnessQ4_AVictimClockBehindHoldsOnlyWhileBridged(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	got := atDeadline(t, c, ctx, mono, db, func() {
		bridgeAnswer(t, db)
		pausedCondition(t, db, time.Now().Add(-60*time.Second))
	})
	if got != "down" {
		t.Fatalf("VM recovered to %q while bridged, on a condition dated before the outage", got)
	}
	if !strings.Contains(c.holdReason["down"], "predates this outage") {
		t.Fatalf("the refusal is not the skewed condition's: %q", c.holdReason["down"])
	}
	if _, ok := bridgedRow(t, db, ctx); !ok {
		t.Fatal("no ha.recovery.bridged for a skew-held, bridged deadline")
	}
	for i := 0; i < 2; i++ {
		c.run(ctx)
		if got := vmHost(t, db, ctx); got != "down" {
			t.Fatalf("VM recovered to %q on re-check %d while still bridged", got, i+1)
		}
	}
	// The bridge loses down too.
	healthRow(t, db, "bridge", "suspect", offlineThreshold, time.Now())
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM on %q once no observer sees down answer; the skew hold must end with the bridge", got)
	}
}

// Q1's bridged form is not raised when a voter majority sees the host answer:
// that is a host coming back, not a bridge. Through run() a voter majority
// answering leaves no fence candidate to retry, so it is called directly.
//
// Mutation: skip the voter-majority check in noteBridgedRetry — raised.
func TestWitnessQ1_AVoterMajorityAnsweringIsNotABridge(t *testing.T) {
	db, ctx := seedDownHost(t, "ipmi", nil)
	thirdVoter(t, db, ctx)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "ipmi", Success: false, Detail: "BMC unreachable"}
	})
	c.run(ctx) // the failed fence, and this cycle's voter set
	pausedCondition(t, db, time.Now())
	for _, o := range []string{"alive", "third"} {
		healthRow(t, db, o, "healthy", 0, time.Now())
	}
	h, err := corrosion.GetHost(ctx, db, "down")
	if err != nil || h == nil {
		t.Fatal(err)
	}
	c.noteBridgedRetry(ctx, h, time.Now().Add(-time.Minute))
	if _, ok := bridgedRow(t, db, ctx); ok {
		t.Fatal("ha.recovery.bridged raised although voters alive and third, with down, are a majority answering it")
	}
	// The control: one voter answering, with the rest failing, is a bridge.
	healthRow(t, db, "third", "suspect", offlineThreshold, time.Now())
	c.noteBridgedRetry(ctx, h, time.Now().Add(-time.Minute))
	if _, ok := bridgedRow(t, db, ctx); !ok {
		t.Fatal("control: no ha.recovery.bridged with one voter answering and no majority")
	}
}
