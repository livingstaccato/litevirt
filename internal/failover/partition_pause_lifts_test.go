package failover

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// What lifts, keeps or replaces a bridged host's recovery limit
// (limitRecovery, docs/design/partition-pause.md §4.2 step 3). Each test
// starts from limitedEpisode: down answered a bridge and reported pausing vm
// and ct1, so those moved and vm2 and ct2 are held.

// limitedEpisode is explicitPause with unlistedWorkloads, past a bridged
// deadline that recovered only vm and ct1.
func limitedEpisode(t *testing.T) (*Coordinator, *corrosion.Client, context.Context, *monoClock) {
	t.Helper()
	c, db, ctx, mono := explicitPause(t)
	unlistedWorkloads(t, db)
	atDeadline(t, c, ctx, mono, db, func() {
		bridgeAnswer(t, db)
		pausedConditionListing(t, db, time.Now(), "vm/vm", "ct/ct1")
	})
	assertLimited(t, db)
	if c.recoverOnly["down"] == nil || c.unpausedHeldReason("down") == "" {
		t.Fatal("setup: the bridged deadline left no recovery limit")
	}
	return c, db, ctx, mono
}

func vm2Host(t *testing.T, db *corrosion.Client) string {
	t.Helper()
	vm2, err := corrosion.GetVM(context.Background(), db, "vm2")
	if err != nil || vm2 == nil {
		t.Fatalf("GetVM vm2: %v", err)
	}
	return vm2.HostName
}

func assertLifted(t *testing.T, c *Coordinator) {
	t.Helper()
	if c.recoverOnly["down"] != nil {
		t.Fatalf("the recovery limit was not lifted: %v", c.recoverOnly["down"])
	}
	if held := c.unpausedHeldReason("down"); held != "" {
		t.Fatalf("the held names outlived the limit: %q", held)
	}
}

// Back in service: the episode is over, and nothing of it is kept.
//
// Mutation: drop unlimitRecovery from forgetHost — the limit outlives the
// episode.
func TestRecoveryLimit_LiftsWhenTheHostIsBackInService(t *testing.T) {
	c, db, ctx, _ := limitedEpisode(t)
	if err := corrosion.UpdateHostState(ctx, db, "down", "active"); err != nil {
		t.Fatal(err)
	}
	c.clearRecoveredFromFenced(ctx)
	assertLifted(t, c)
}

// An operator confirms down off: that vouches for every workload on it, so
// vm2 and ct2 move too.
//
// Mutation: drop unlimitRecovery from resumeFromConfirmation — vm2 stays.
func TestRecoveryLimit_LiftsOnAnOperatorConfirmation(t *testing.T) {
	c, db, ctx, _ := limitedEpisode(t)
	poweredOff(t, db, "bridge")
	operatorConfirms(t, db, ctx, "down")
	c.run(ctx)
	if got := vm2Host(t, db); got != "alive" {
		t.Fatalf("vm2 on %q after an operator confirmed down off; want it recovered", got)
	}
	if g, _ := corrosion.GetContainer(ctx, db, "down", "ct2"); g != nil {
		t.Fatal("ct2 still on down after an operator confirmed it off")
	}
	assertLifted(t, c)
}

// A fence that proves down off (an IPMI power-off, verified) answers for
// every workload on it.
//
// Mutation: drop the lift in recoverFenced — vm2 stays.
func TestRecoveryLimit_LiftsOnAProofGradeFence(t *testing.T) {
	c, db, ctx, _ := limitedEpisode(t)
	h, err := corrosion.GetHost(ctx, db, "down")
	if err != nil || h == nil {
		t.Fatalf("GetHost: %v", err)
	}
	c.recoverFenced(ctx, h, fence.Result{Method: "ipmi", Success: true, Detail: "chassis power off, verified"}, "ipmi", false)
	if got := vm2Host(t, db); got != "alive" {
		t.Fatalf("vm2 on %q after a verified IPMI power-off of down; want it recovered", got)
	}
	assertLifted(t, c)
}

// A fence that does not prove down off does not vouch for what down did not
// report pausing: a lenient best-effort success, a best-effort that failed and
// went ahead anyway, and a strict SSH power-off nobody saw land.
//
// Mutation: lift on any fence that does not rest on the pause (as round 3
// did) — vm2 moves while down may still run it.
func TestRecoveryLimit_AFenceThatDoesNotProveItOffKeepsTheLimit(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fr       fence.Result
		ranUnder string
	}{
		{"lenient best-effort", fence.Result{Method: "best-effort-ssh", Success: true, Detail: "ssh unreachable, assumed"}, "best-effort"},
		{"failed best-effort", fence.Result{Method: "best-effort-ssh", Success: false, Detail: "ssh unreachable"}, "best-effort"},
		{"strict ssh", fence.Result{Method: "ssh", Success: true, Detail: "poweroff accepted [path=managed]"}, "ssh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, db, ctx, _ := limitedEpisode(t)
			h, err := corrosion.GetHost(ctx, db, "down")
			if err != nil || h == nil {
				t.Fatalf("GetHost: %v", err)
			}
			if tc.fr.Method == "best-effort-ssh" {
				h.FenceStrategy = "best-effort"
			}
			c.recoverFenced(ctx, h, tc.fr, tc.ranUnder, false)
			assertLimited(t, db)
			if held := c.unpausedHeldReason("down"); !strings.Contains(held, "vm/vm2") {
				t.Fatalf("vm2 is no longer named as held: %q", held)
			}
		})
	}
}

// down is removed for good with a proof-grade fence: proved off, every
// workload recorded on it is recovered.
//
// Mutation: drop unlimitRecovery from recoverRemovedHosts — vm2 is never
// claimed.
func TestRecoveryLimit_LiftsWhenTheHostIsRemovedWithAProofGradeFence(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	unlistedWorkloads(t, db)
	db.SetRecoveryClaimGate(func() bool { return true })
	cl := &fakeClaimer{decide: decideOurs}
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
	assertLimited(t, db)
	if c.recoverOnly["down"] == nil {
		t.Fatal("setup: no recovery limit")
	}
	if err := db.Execute(ctx, `INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
		VALUES ('ipmi-down', 'down', 'ipmi', 'fenced', ?, '')`, time.Now().Add(time.Second).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteHost(ctx, db, "down"); err != nil {
		t.Fatal(err)
	}
	c.recoverRemovedHosts(ctx)
	claimed := false
	for _, k := range cl.calls {
		if strings.Contains(k.String(), "vm2") {
			claimed = true
		}
	}
	if !claimed {
		t.Fatalf("vm2 was not claimed for recovery from a host removed with a proof-grade fence: %v", cl.calls)
	}
	assertLifted(t, c)
}

// laterDeadline puts down's recovery behind a second pause wait that has
// already passed, as a re-fence in the same episode would, and runs it. A
// deadline that refuses reports false and keeps the wait, so the result is
// not checked here.
func laterDeadline(t *testing.T, c *Coordinator, ctx context.Context, mono *monoClock) {
	t.Helper()
	c.pauseWaits["down"] = pauseWait{deadline: mono.Now().Add(-time.Second), fenceAt: time.Now(), wait: time.Minute}
	c.retryPauseWait(ctx, "down")
}

// bridgeGone is the bridge losing down too: its latest verdict is a failure.
func bridgeGone(t *testing.T, db *corrosion.Client) {
	t.Helper()
	healthRow(t, db, "bridge", "suspect", offlineThreshold, time.Now().Add(2*time.Second))
}

// A later deadline at which nobody has seen down answer, while down's own
// condition from this outage still lists what it paused: its word still
// covers only that, so vm2 and ct2 stay.
//
// Mutation: drop the paused list on the quiet path (as round 3 did) — vm2
// moves while down may still run it.
func TestRecoveryLimit_AQuietLaterDeadlineKeepsTheHostsList(t *testing.T) {
	c, db, ctx, mono := limitedEpisode(t)
	bridgeGone(t, db)
	laterDeadline(t, c, ctx, mono)
	assertLimited(t, db)
	if held := c.unpausedHeldReason("down"); !strings.Contains(held, "vm/vm2") {
		t.Fatalf("vm2 is no longer named as held: %q", held)
	}
}

// The same, through the any-observer fallback: the pause is no longer relied
// on (down's latest probe answer no longer says it pauses), so the deadline
// is fenceStillStands' and quiet. The condition still lists what down paused,
// and a limit is held, so it still covers only that.
//
// Mutation: skip the paused list on the fallback path — vm2 moves.
func TestRecoveryLimit_AQuietFallbackDeadlineKeepsTheHostsList(t *testing.T) {
	c, db, ctx, mono := limitedEpisode(t)
	bridgeGone(t, db)
	c.PeerPausesOnLoss = func(string) bool { return false }
	laterDeadline(t, c, ctx, mono)
	assertLimited(t, db)
}

// assertStillLimited checks the limit from limitedEpisode outlived a later
// deadline: vm2 and ct2 stay on down, and the stall alert still names vm2.
func assertStillLimited(t *testing.T, c *Coordinator, db *corrosion.Client) {
	t.Helper()
	assertLimited(t, db)
	if c.recoverOnly["down"] == nil {
		t.Fatal("the recovery limit was lifted")
	}
	if held := c.unpausedHeldReason("down"); !strings.Contains(held, "vm/vm2") {
		t.Fatalf("vm2 is no longer named as held: %q", held)
	}
}

// A later quiet deadline at which down's condition has meanwhile resolved:
// that is no word that down now runs nothing it did not list, so the list
// this coordinator holds from this down-episode still bounds what moves.
//
// Mutation: lift the limit when the later deadline finds no condition (as
// round 4 did) — vm2 moves while down may still run it.
func TestRecoveryLimit_AQuietLaterDeadlineWithAResolvedConditionKeepsTheLimit(t *testing.T) {
	c, db, ctx, mono := limitedEpisode(t)
	bridgeGone(t, db)
	ts := time.Now().UTC().Format(time.RFC3339)
	if err := corrosion.UpsertHealthCondition(ctx, db, corrosion.HealthCondition{
		Evaluator: corrosion.PartitionPauseEvaluator, Code: corrosion.CondPartitionPaused,
		SubjectKind: "host", SubjectID: "down", Lifecycle: corrosion.ConditionResolved,
		Severity: corrosion.SeverityWarning, FirstSeen: ts, LastSeen: ts,
	}); err != nil {
		t.Fatal(err)
	}
	laterDeadline(t, c, ctx, mono)
	assertStillLimited(t, c, db)
}

// A later quiet deadline at which one voter's row about down has gone stale,
// so too few voter runs remain to date the outage: the condition cannot be
// re-established, and the held list still bounds what moves.
//
// Mutation: lift the limit when the outage cannot be dated — vm2 moves.
func TestRecoveryLimit_AQuietLaterDeadlineWithAStaleVoterRowKeepsTheLimit(t *testing.T) {
	c, db, ctx, mono := limitedEpisode(t)
	bridgeGone(t, db)
	failingSince(t, db, "v4", time.Now().Add(-time.Hour), time.Now().Add(-time.Hour))
	laterDeadline(t, c, ctx, mono)
	assertStillLimited(t, c, db)
}

// The outage cannot be dated because host_health cannot be read: that is a
// read error, not "too few voters", and it refuses the deadline, as every
// other read error at a self-pause deadline does. Through a whole deadline
// the earlier reads of host_health would refuse first, so the outage dating
// is reached directly.
//
// Mutations: report the read error as too few voter runs — the held list
// comes back and the deadline goes ahead; or, with that, lift the limit (as
// round 4 did) — nil comes back.
func TestRecoveryLimit_AnUnreadableOutageRefusesTheDeadline(t *testing.T) {
	c, db, ctx, _ := limitedEpisode(t)
	sets, _, err := c.pauseVoterSets(ctx, "down")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(ctx, `DROP TABLE host_health`); err != nil {
		t.Fatal(err)
	}
	why, only, ok := c.pausedThisOutage(ctx, "down", time.Now(), sets)
	if ok {
		t.Fatalf("a deadline whose outage could not be read went ahead (limit %v)", only)
	}
	if why != whyPausedUnreadable {
		t.Fatalf("refused with %q, want %q", why, whyPausedUnreadable)
	}
	if c.recoverOnly["down"] == nil {
		t.Fatal("the recovery limit was lifted")
	}
}

// down's condition cannot be read at a later quiet deadline: the deadline is
// refused, so nothing moves and the limit stands. (The pause-failed read
// fails too, so this deadline is quietFallback's; the explicit path shares
// pausedThisOutage.)
//
// Mutation: recover on an unreadable condition instead of refusing — the
// limit is lifted and vm2 moves.
func TestRecoveryLimit_AnUnreadableConditionRefusesTheDeadline(t *testing.T) {
	c, db, ctx, mono := limitedEpisode(t)
	bridgeGone(t, db)
	if _, err := db.DB().ExecContext(ctx, `DROP TABLE health_conditions`); err != nil {
		t.Fatal(err)
	}
	laterDeadline(t, c, ctx, mono)
	if got := vm2Host(t, db); got != "down" {
		t.Fatalf("vm2 recovered to %q although down's condition could not be read", got)
	}
	if c.recoverOnly["down"] == nil {
		t.Fatal("the recovery limit was lifted on an unreadable condition")
	}
	sets, _, err := c.pauseVoterSets(ctx, "down")
	if err != nil {
		t.Fatal(err)
	}
	if why, only, ok := c.pausedThisOutage(ctx, "down", time.Now(), sets); ok || why != whyPausedUnreadable {
		t.Fatalf("pausedThisOutage on an unreadable condition = %q, %v, %v; want a refusal", why, only, ok)
	}
}

// A later bridged deadline whose list now includes vm2 (down has since
// paused it): vm2 moves, and the stall alert stops naming it.
//
// Mutation: keep unpausedHeld when the list is replaced — the alert still
// says vm2 may be running on down after it moved.
func TestRecoveryLimit_ANewListForgetsHeldNamesItNowCovers(t *testing.T) {
	c, db, ctx, mono := limitedEpisode(t)
	pausedConditionListing(t, db, time.Now(), "vm/vm", "vm/vm2", "ct/ct1")
	bridgeAnswer(t, db)
	c.pauseWaits["down"] = pauseWait{deadline: mono.Now().Add(-time.Second), fenceAt: time.Now().Add(-time.Second), wait: time.Minute}
	if !c.retryPauseWait(ctx, "down") {
		t.Fatal("setup: down had no pending pause wait")
	}
	if got := vm2Host(t, db); got != "alive" {
		t.Fatalf("vm2 on %q although down now reports pausing it", got)
	}
	held := c.unpausedHeldReason("down")
	if strings.Contains(held, "vm/vm2") {
		t.Fatalf("the stall alert still names vm2 as possibly running on down after it moved: %q", held)
	}
	if !strings.Contains(held, "ct/ct2") {
		t.Fatalf("ct2, still unlisted, is no longer named as held: %q", held)
	}
}
