package failover

import (
	"context"
	"errors"
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
