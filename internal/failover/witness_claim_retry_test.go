package failover

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// Q3, on the coordinator alone (the fleet scenario is
// TestFleet_PartitionPause_ClaimRetryOwedToAnEarlierOutageWaitsAgain). down's
// first outage: its deadline goes ahead and the VM's claim is refused, so a
// retry is owed. down then answers (nobody fails it), and 20 s later fails
// again: every voter's failing run began after the deadline the retry
// is owed to. The retry must not move the VM on that deadline: it waits out
// a fresh partition-pause deadline, then recovers.
//
// Mutations: drop claimRetryOutageOver, or the moment it judges by
// (claimRetryAt) — the retry runs at once on the earlier deadline (its
// claim, the second, is refused) and no fresh wait starts; take its drop
// branch even when the pause is relied on — no fresh wait starts either.
func TestWitnessQ3_AClaimRetryFromAnEarlierOutageWaitsAFreshDeadline(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	db.SetRecoveryClaimGate(func() bool { return true })
	// The first claim (first outage) and the second (at the fresh deadline)
	// are refused; the third decides.
	decides := 0
	c.Claimer = &fakeClaimer{decide: func(key corrosion.ClaimKey, v corrosion.ClaimValue) (claims.Outcome, error) {
		decides++
		if decides <= 2 {
			return claims.Outcome{}, errors.New("a voter did not answer in time")
		}
		return decideOurs(key, v)
	}}
	c.RecoveryClaimEnforced = func(context.Context) bool { return true }
	c.Gate = fakeFailoverGate{
		supports: map[string]bool{"alive": true},
		enforced: map[string]bool{capabilities.SplitBrainGateV1: true},
	}
	var offset time.Duration
	c.Now = func() time.Time { return time.Now().Add(offset) }
	if got := atDeadline(t, c, ctx, mono, db, func() { pausedCondition(t, db, time.Now()) }); got != "down" {
		t.Fatalf("setup: VM on %q, want its claim refused at the first deadline", got)
	}
	if decides != 1 || !c.claimRetry["down"] {
		t.Fatal("setup: no claim retry is owed")
	}

	// The second outage: down answered in between, so every voter's failing
	// run began after the first. 20 s on, well inside the lease: a lease
	// re-taken as a new tenure forgets the episode (forgetEpisodes).
	offset = 20 * time.Second
	for _, o := range []string{"coordinator", "alive", "v4"} {
		failingSince(t, db, o, time.Now().Add(offset-10*time.Second), time.Now().Add(offset))
	}
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM recovered to %q on a claim retry owed to the earlier outage, before any wait in this one", got)
	}
	if _, ok := c.pauseWaits["down"]; !ok {
		t.Fatal("the retry owed to the earlier outage started no fresh partition-pause wait")
	}
	mono.Advance(health.PartitionPauseWaitFor(10) + time.Second)
	c.run(ctx)
	if decides != 2 || !c.claimRetry["down"] {
		t.Fatalf("setup: the fresh deadline made %d claims in all, want its claim refused and a retry owed", decides)
	}
	// A retry owed within this outage acts on its fresh deadline and runs on
	// the next cycle, with no second wait.
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM on %q on the cycle after the fresh deadline's refused claim; want its retry to recover it", got)
	}
}

// q3Outage1 is the first outage of the Q3 scenario: down's deadline goes
// ahead and its VM's first claim is refused, so a retry is owed; later
// claims decide. It returns the clock offset the test moves c.Now by.
func q3Outage1(t *testing.T) (*Coordinator, *corrosion.Client, context.Context, *monoClock, *int, *time.Duration) {
	t.Helper()
	c, db, ctx, mono := explicitPause(t)
	db.SetRecoveryClaimGate(func() bool { return true })
	decides := 0
	c.Claimer = &fakeClaimer{decide: func(key corrosion.ClaimKey, v corrosion.ClaimValue) (claims.Outcome, error) {
		decides++
		if decides <= 1 {
			return claims.Outcome{}, errors.New("a voter did not answer in time")
		}
		return decideOurs(key, v)
	}}
	c.RecoveryClaimEnforced = func(context.Context) bool { return true }
	c.Gate = fakeFailoverGate{
		supports: map[string]bool{"alive": true},
		enforced: map[string]bool{capabilities.SplitBrainGateV1: true},
	}
	offset := new(time.Duration)
	c.Now = func() time.Time { return time.Now().Add(*offset) }
	if got := atDeadline(t, c, ctx, mono, db, func() { pausedCondition(t, db, time.Now()) }); got != "down" {
		t.Fatalf("setup: VM on %q, want its claim refused at the first deadline", got)
	}
	if decides != 1 || !c.claimRetry["down"] {
		t.Fatal("setup: no claim retry is owed")
	}
	return c, db, ctx, mono, &decides, offset
}

// Review I-1: one observer whose failing run spans the moment the retry is
// owed to does not make it the same outage when another has seen down
// answer since. v4's path to down never healed, so its run reaches back
// before the first deadline; v5 saw down answer after it; coordinator and
// alive fail down again in a second outage. The retry is judged as
// fenceStillStands judges a fence (the run spans AND nobody answered since):
// the outage is over, and a self-pause host waits out a fresh deadline.
//
// Mutation: judge by observerStreakSpans alone (v4's run) — the retry runs at
// once on the first outage's deadline and the VM moves with no wait.
func TestWitnessQ3_ARetryIsNotRunOnOneObserversSpanningRunWhenAnotherSawTheHostAnswer(t *testing.T) {
	c, db, ctx, _, decides, offset := q3Outage1(t)
	t0 := time.Now()
	*offset = 20 * time.Second
	failingSince(t, db, "v4", t0.Add(-10*time.Second), t0.Add(*offset))
	healthRow(t, db, "v5", "healthy", 0, t0.Add(8*time.Second))
	for _, o := range []string{"coordinator", "alive"} {
		failingSince(t, db, o, t0.Add(*offset-10*time.Second), t0.Add(*offset))
	}
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM recovered to %q on a retry owed to the earlier outage: v4's spanning run hid v5's answer", got)
	}
	if *decides != 1 {
		t.Fatalf("the retry made a claim (%d in all) on the earlier outage's deadline", *decides)
	}
	if _, ok := c.pauseWaits["down"]; !ok {
		t.Fatal("the retry owed to the earlier outage started no fresh partition-pause wait")
	}
}

// Review I-2: a host that leaves fenced/offline while a retry is owed (an
// upgrade's 'upgrading' write, a drain) has its wait dropped by
// retryPauseWait. The retry must not then run on the earlier outage's
// deadline: the moment it is owed to is kept through the fresh wait, a
// missing moment is an outage that is over, and retryClaims refuses a host
// that is not fenced or offline.
//
// Mutations: delete claimRetryAt in the fresh-wait branch AND leave a retry
// with no moment as it is (the head before round 1) — the VM moves on the
// cycle after the wait is dropped.
func TestWitnessQ3_ARetryIsNotRunOnAHostThatLeftOfflineDuringItsFreshWait(t *testing.T) {
	c, db, ctx, _, decides, offset := q3Outage1(t)
	buf := captureSlog(t)
	*offset = 20 * time.Second
	for _, o := range []string{"coordinator", "alive", "v4"} {
		failingSince(t, db, o, time.Now().Add(*offset-10*time.Second), time.Now().Add(*offset))
	}
	c.run(ctx)
	if _, ok := c.pauseWaits["down"]; !ok {
		t.Fatal("setup: the retry owed to the earlier outage started no fresh wait")
	}
	if _, ok := c.claimRetryAt["down"]; !ok {
		t.Fatal("the fresh wait forgot the moment the retry is owed to")
	}
	if err := corrosion.UpdateHostState(ctx, db, "down", "upgrading"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		c.run(ctx)
		if got := vmHost(t, db, ctx); got != "down" {
			t.Fatalf("cycle %d: VM recovered to %q on a retry owed to the earlier outage, off an 'upgrading' host", i+1, got)
		}
	}
	if *decides != 1 {
		t.Fatalf("a retry made a claim (%d in all) for an 'upgrading' host", *decides)
	}
	if strings.Contains(buf.String(), "retrying the recovery claims") {
		t.Fatal("the claim retry ran for an 'upgrading' host")
	}
}

// Review I-2, retryClaims' own guard: it never recovers a host outside
// fenced/offline, whatever is owed, as retryPauseWait does not.
//
// Mutation: drop the state check — the VM moves off the 'upgrading' host.
func TestRetryClaims_RefusesAHostThatIsNotFencedOrOffline(t *testing.T) {
	db, c := claimFixture(t, &fakeClaimer{decide: decideOurs})
	ctx := context.Background()
	if !c.acquireLease(ctx) {
		t.Fatal("setup: no lease")
	}
	if err := corrosion.UpdateHostState(ctx, db, "dead", "upgrading"); err != nil {
		t.Fatal(err)
	}
	c.retryClaimsFor("dead")
	if c.retryClaims(ctx, "dead") {
		t.Fatal("retryClaims reported it handled an 'upgrading' host")
	}
	if vm := mustVM(t, db, "vm1"); vm.HostName != "dead" || vm.PendingActionID != "" {
		t.Fatalf("retryClaims recovered vm1 off an 'upgrading' host: %+v", vm)
	}
	if err := corrosion.UpdateHostState(ctx, db, "dead", "fenced"); err != nil {
		t.Fatal(err)
	}
	if !c.retryClaims(ctx, "dead") {
		t.Fatal("setup: retryClaims did not run for a fenced host")
	}
}

// Review I-2: a retry owed with no moment recorded is an outage that is
// over, never one left as it is.
//
// Mutation: leave a retry with no moment as it is — the retry and the
// episode stay, and retryClaims would run on them.
func TestClaimRetryOutageOver_AMissingMomentIsAnOutageOver(t *testing.T) {
	db, c := claimFixture(t, &fakeClaimer{decide: decideOurs})
	ctx := context.Background()
	if err := corrosion.UpdateHostState(ctx, db, "dead", "fenced"); err != nil {
		t.Fatal(err)
	}
	c.fenced["dead"] = true
	c.retryClaimsFor("dead")
	c.claimRetryOutageOver(ctx, "dead")
	if c.claimRetry["dead"] || c.fenced["dead"] {
		t.Fatalf("a retry with no moment recorded was left as it is (retry %v, fenced %v)",
			c.claimRetry["dead"], c.fenced["dead"])
	}
}

// Review I-2: a recovery resumed on an operator's confirmation records its
// moment (the confirmation is the operator's word that the host is off now),
// so a claim it leaves refused is retried within the outage, not dropped as
// one owed to an outage that is over.
//
// Mutation: drop noteRecoveryAt from resumeFromConfirmation — the retry is
// dropped and the confirmation, already spent, strands the VM.
func TestConfirmationResume_RecordsItsMomentSoARefusedClaimIsRetried(t *testing.T) {
	refuse := true
	cl := &fakeClaimer{decide: func(k corrosion.ClaimKey, v corrosion.ClaimValue) (claims.Outcome, error) {
		if refuse {
			return claims.Outcome{}, errors.New("a voter did not answer in time")
		}
		return decideOurs(k, v)
	}}
	db, c := claimFixture(t, cl)
	ctx := context.Background()
	if !c.acquireLease(ctx) {
		t.Fatal("setup: no lease")
	}
	for _, o := range []string{"coord", "live", "other"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'dead', 'suspect', 1800, ?, ?)`, o,
			time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.InsertFenceLog(ctx, db, corrosion.FenceLogRecord{
		ID: "earlier-fence", HostName: "dead", Method: "ssh", Result: "fenced", Detail: "poweroff accepted",
	}); err != nil {
		t.Fatal(err)
	}
	operatorConfirms(t, db, ctx, "dead")
	if !c.resumeFromConfirmation(ctx, "dead") {
		t.Fatal("setup: the confirmation was not resumed")
	}
	if !c.claimRetry["dead"] {
		t.Fatal("setup: the refused claim is not owed a retry")
	}
	refuse = false
	c.claimRetryOutageOver(ctx, "dead")
	if !c.claimRetry["dead"] {
		t.Fatal("the retry a confirmation resume left owed was judged an outage that is over")
	}
	c.retryClaims(ctx, "dead")
	if vm := mustVM(t, db, "vm1"); vm.HostName == "dead" && vm.PendingActionID == "" {
		t.Fatal("the claim refused in a confirmation resume was not retried")
	}
}

// Review m5: a host that cannot be read is skipped this cycle, neither run
// nor re-judged.
//
// Mutation: report the host handled on a read error — the caller goes on to
// retryClaims.
func TestClaimRetryOutageOver_AReadFailureSkipsTheHost(t *testing.T) {
	db, c := claimFixture(t, &fakeClaimer{decide: decideOurs})
	ctx := context.Background()
	c.fenced["dead"] = true
	c.retryClaimsFor("dead")
	c.noteRecoveryAt("dead", time.Now())
	if err := db.Execute(ctx, `ALTER TABLE hosts RENAME TO hosts_away`); err != nil {
		t.Fatal(err)
	}
	skipped := !c.claimRetryOutageOver(ctx, "dead")
	if err := db.Execute(ctx, `ALTER TABLE hosts_away RENAME TO hosts`); err != nil {
		t.Fatal(err)
	}
	if !skipped {
		t.Fatal("a host whose row could not be read was not skipped")
	}
	if !c.claimRetry["dead"] || !c.fenced["dead"] {
		t.Fatal("a read failure re-judged the retry")
	}
}
