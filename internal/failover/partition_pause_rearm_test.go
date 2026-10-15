package failover

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A self-pause deadline that refuses is re-checked on every later cycle
// (retryPauseWait), under the full rule each time, until it recovers or the
// episode ends. Before this, the wait was dropped on a refusal and the host
// stayed handled (c.fenced), so a transient read error or a condition that
// replicated a moment late left the paused workloads running nowhere until
// the lease moved or the leader restarted.

// renameTable moves table aside (to) or back, as a transient read error of it.
func renameTable(t *testing.T, db *corrosion.Client, ctx context.Context, from, to string) {
	t.Helper()
	if _, err := db.DB().ExecContext(ctx, `ALTER TABLE `+from+` RENAME TO `+to); err != nil {
		t.Fatal(err)
	}
}

// The deadline's read of down's condition fails on the first cycle and
// succeeds on the next: the next cycle recovers the VM down reported pausing.
//
// Mutation: drop the re-arm in retryPauseWait — the VM stays on down.
func TestPartitionPauseRearm_AReadErrorAtTheDeadlineIsRetriedNextCycle(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	got := atDeadline(t, c, ctx, mono, db, func() {
		bridgeAnswer(t, db)
		pausedCondition(t, db, time.Now())
		renameTable(t, db, ctx, "health_conditions", "health_conditions_aside")
	})
	if got != "down" {
		t.Fatalf("VM recovered to %q although down's condition could not be read", got)
	}
	if _, ok := c.pauseWaits["down"]; !ok {
		t.Fatal("the refused deadline was dropped: nothing will re-check it")
	}
	renameTable(t, db, ctx, "health_conditions_aside", "health_conditions")
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM on %q after the condition became readable; want it recovered on the next cycle", got)
	}
	if _, ok := c.pauseWaits["down"]; ok {
		t.Fatal("the wait outlived the recovery")
	}
}

// A bridge sees down answer and down's condition has not replicated yet at
// the deadline: refused. It arrives a moment later: the next cycle recovers.
//
// Mutation: drop the re-arm in retryPauseWait — the VM stays on down.
func TestPartitionPauseRearm_AConditionThatArrivesAfterTheDeadlineIsRecovered(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	if got := atDeadline(t, c, ctx, mono, db, func() { bridgeAnswer(t, db) }); got != "down" {
		t.Fatalf("setup: VM recovered to %q although down answered a bridge and reported no pause", got)
	}
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM recovered to %q on a re-check that still has no word from down", got)
	}
	pausedCondition(t, db, time.Now())
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM on %q after down's condition arrived; want it recovered on the next cycle", got)
	}
}

// The stall alert's reason after a refused deadline says it was refused, and
// why, not that the coordinator is still waiting out the pause.
//
// Mutation: drop the noteHold on a refusal — the reason still reads
// "waiting out the host's partition pause".
func TestPartitionPauseRearm_TheStallReasonNamesTheRefusal(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	atDeadline(t, c, ctx, mono, db, func() { bridgeAnswer(t, db) })
	reason := c.holdReason["down"]
	if strings.Contains(reason, "waiting out") {
		t.Fatalf("the stall reason after a refused deadline still says it is waiting: %q", reason)
	}
	for _, want := range []string{"refused at the partition-pause deadline", "has not reported pausing anything", "fence-confirm down"} {
		if !strings.Contains(reason, want) {
			t.Fatalf("the stall reason %q does not say %q", reason, want)
		}
	}
	var got string
	c.OnRecoveryStalled = func(host, _ string, reason string, _ int, _ time.Time) {
		if host == "down" {
			got = reason
		}
	}
	c.stallSince = map[string]time.Time{"down": time.Now().Add(-2 * recoveryStallAfter)}
	c.alertStalledRecoveries(ctx, map[string]int{"down": 1}, nil)
	if !strings.Contains(got, "refused at the partition-pause deadline") {
		t.Fatalf("the stall alert reads %q; want the refusal named", got)
	}
}

// A refused deadline that keeps refusing does not keep the operator out: a
// fence-confirm is still acted on, and it ends the wait.
//
// Mutation: report a refused wait as handled (return true) — the
// confirmation is never reached and the VM stays.
func TestPartitionPauseRearm_AnOperatorConfirmationStillLands(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	if got := atDeadline(t, c, ctx, mono, db, func() { bridgeAnswer(t, db) }); got != "down" {
		t.Fatalf("setup: VM recovered to %q", got)
	}
	poweredOff(t, db, "bridge")
	operatorConfirms(t, db, ctx, "down")
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM on %q after an operator confirmed down off", got)
	}
	if _, ok := c.pauseWaits["down"]; ok {
		t.Fatal("the wait outlived the operator's confirmation")
	}
}

// The episode ending clears a re-armed wait.
//
// Mutation: drop the pauseWaits delete from forgetHost — the wait stays.
func TestPartitionPauseRearm_ForgetHostClearsTheWait(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	atDeadline(t, c, ctx, mono, db, func() { bridgeAnswer(t, db) })
	if _, ok := c.pauseWaits["down"]; !ok {
		t.Fatal("setup: no re-armed wait")
	}
	c.forgetHost("down")
	if _, ok := c.pauseWaits["down"]; ok {
		t.Fatal("forgetHost left the wait behind")
	}
}

// A fence recorded since the refused deadline (another coordinator's) takes
// down back through the fence path, which decides afresh: a fence that
// relies on the pause starts its own wait. The refused wait, whose deadline
// has passed, must not stand in for it.
//
// Mutation: keep the wait when the fence path is taken — recoverFenced finds
// the passed deadline and recovers without the deadline's rule.
func TestPartitionPauseRearm_ANewFenceStartsAFreshWait(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	if got := atDeadline(t, c, ctx, mono, db, func() { bridgeAnswer(t, db) }); got != "down" {
		t.Fatalf("setup: VM recovered to %q", got)
	}
	if err := db.Execute(ctx, `INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
		VALUES ('other-coordinator-fence', 'down', 'best-effort-ssh', 'fenced', ?, ?)`,
		time.Now().Add(2*time.Second).UTC().Format(time.RFC3339),
		corrosion.FencePauseReliance+"ssh unreachable, assumed"); err != nil {
		t.Fatal(err)
	}
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM recovered to %q on a new self-pause fence whose own wait has not passed", got)
	}
	w, ok := c.pauseWaits["down"]
	if !ok || !mono.Now().Before(w.deadline) || w.refused != "" {
		t.Fatalf("the new fence did not start a fresh wait: %+v (present %v)", w, ok)
	}
}

// A claim retry owed to down (armed before its deadline, or left from an
// earlier recovery) does not run while down's recovery waits on a deadline
// that refused: it would recover everything with no deadline rule and no
// limit, while down, which never reported pausing, may run it all.
//
// Mutation: drop the pause-wait gate in retryClaims — the VM moves at the
// refused deadline.
func TestPartitionPauseRearm_AClaimRetryDoesNotBypassARefusedDeadline(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	c.retryClaimsFor("down")
	if got := atDeadline(t, c, ctx, mono, db, func() { bridgeAnswer(t, db) }); got != "down" {
		t.Fatalf("VM recovered to %q at a refused deadline on a claim retry", got)
	}
	for i := 0; i < 2; i++ {
		c.run(ctx)
		if got := vmHost(t, db, ctx); got != "down" {
			t.Fatalf("VM recovered to %q on cycle %d after a refused deadline, on a claim retry", got, i+2)
		}
	}
}

// A claim retry left from an earlier outage, which healed before the retry
// ran, does not run in the next: there down's manual fence waits for an
// operator, and a stale retry would recover it without one.
//
// Mutation: drop the claim-retry clear from forgetHost — the VM moves with
// no confirmation.
func TestPartitionPauseRearm_AStaleClaimRetryDoesNotRunInTheNextOutage(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(manualFencer())
	// The earlier outage: down was handled and a claim refused; it came back
	// (state active) before the retry ran.
	c.fenced["down"] = true
	c.retryClaimsFor("down")
	c.claimRetryProposals = map[corrosion.ClaimKey]claimRetryProposal{
		{TargetKind: "vm", TargetName: "vm"}:    {source: "down"},
		{TargetKind: "vm", TargetName: "other"}: {source: "elsewhere"},
	}
	for i := 0; i < 3; i++ {
		c.run(ctx)
		if got := vmHost(t, db, ctx); got != "down" {
			t.Fatalf("VM recovered to %q on cycle %d of an outage whose manual fence nobody confirmed", got, i+1)
		}
	}
	if len(c.claimRetryProposals) != 1 {
		t.Fatalf("claim retry proposals after the outage ended: %v; want only the other host's", c.claimRetryProposals)
	}
}

// A fence recorded since this coordinator's recovery takes down back through
// the fence path ahead of any claim retry owed to the older one, and the
// retry does not outlive it.
//
// Mutations: run retryClaims for a host whose recorded fence is newer than
// the one it acted on — the claim retry recovers on the new self-pause fence
// before its wait; drop the claim-retry clear on the fence path — the retry
// is still owed.
func TestPartitionPauseRearm_ANewerFenceGoesAheadOfAClaimRetry(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	pausedCondition(t, db, time.Now())
	if got := atDeadline(t, c, ctx, mono, db, nil); got != "alive" {
		t.Fatalf("setup: VM on %q after a plain deadline", got)
	}
	// Put the VM back on down, as though its recovery's claim were refused
	// and a retry is owed.
	if err := db.Execute(ctx, `UPDATE vms SET host_name = 'down' WHERE name = 'vm'`); err != nil {
		t.Fatal(err)
	}
	c.retryClaimsFor("down")
	if err := db.Execute(ctx, `INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
		VALUES ('other-coordinator-fence', 'down', 'best-effort-ssh', 'fenced', ?, ?)`,
		time.Now().Add(2*time.Second).UTC().Format(time.RFC3339),
		corrosion.FencePauseReliance+"ssh unreachable, assumed"); err != nil {
		t.Fatal(err)
	}
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM recovered to %q on a claim retry ahead of a newer self-pause fence's wait", got)
	}
	if c.claimRetry["down"] {
		t.Fatal("the claim retry owed to the older fence outlived the newer one")
	}
	if _, ok := c.pauseWaits["down"]; !ok {
		t.Fatal("the newer self-pause fence started no wait")
	}
}
