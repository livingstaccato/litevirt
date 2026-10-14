package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// A coordinator that takes the failover lease back after another node held
// it behaves as a fresh successor: what it remembered of each host's outage
// from its earlier tenure is gone, and it re-derives from the replicated
// fence records (forgetEpisodes). In the gap the host may have come back,
// failed again and been fenced afresh, and nothing it remembered speaks for
// that outage.

// A claim retry owed when the lease moved does not run on regain: down's
// fence is manual and nobody has confirmed it, so nothing has fenced it and
// it may run everything.
//
// Mutations: drop the gap on losing the lease, or the claimRetry reset —
// the VM moves with no confirmation.
func TestLeaseRegain_AStaleClaimRetryDoesNotRecoverAnUnconfirmedHost(t *testing.T) {
	db, ctx := seedDownHost(t, "manual", nil)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(manualFencer())
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("setup: the unconfirmed manual fence moved the VM to %q", got)
	}
	c.retryClaimsFor("down")
	seedLease(t, db, "other", time.Now().Add(time.Minute))
	c.run(ctx)
	seedLease(t, db, "other", time.Now().Add(-time.Second))
	for i := 0; i < 2; i++ {
		c.run(ctx)
		if got := vmHost(t, db, ctx); got != "down" {
			t.Fatalf("VM recovered to %q on cycle %d after regaining the lease, with no confirmation", got, i+1)
		}
	}
}

// A pause wait from before the gap does not decide the new outage: another
// node led while this one stalled, and fenced down afresh on a self-pause.
// On regain the old wait, long past its deadline, would recover at once,
// before down has necessarily paused for this outage; the new fence starts
// its own wait, and its rule recovers once that has passed.
//
// Mutations: drop the gap on a new lease term, or the pauseWaits reset — the
// VM moves on regain.
func TestLeaseRegain_AStalePauseWaitDoesNotDecideTheNewOutage(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	c.run(ctx)
	if _, ok := c.pauseWaits["down"]; !ok {
		t.Fatal("setup: no pause wait")
	}
	// While this node stalled, "other" took the lease, saw down come back and
	// fail again, fenced it on a self-pause, and its lease ran out.
	seedLease(t, db, "other", time.Now().Add(-time.Second))
	if err := db.Execute(ctx, `INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
		VALUES ('other-coordinator-fence', 'down', 'best-effort-ssh', 'fenced', ?, ?)`,
		time.Now().Add(2*time.Second).UTC().Format(time.RFC3339),
		corrosion.FencePauseReliance+"ssh unreachable, assumed"); err != nil {
		t.Fatal(err)
	}
	mono.Advance(health.PartitionPauseWaitFor(10) + time.Second)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("VM recovered to %q on regaining the lease, on a wait from before the gap", got)
	}
	w, ok := c.pauseWaits["down"]
	if !ok || !mono.Now().Before(w.deadline) {
		t.Fatalf("the new self-pause fence started no wait of its own: %+v (present %v)", w, ok)
	}
	mono.Advance(health.PartitionPauseWaitFor(10) + time.Second)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("VM on %q after the new fence's own deadline; want it recovered under its rule", got)
	}
}

// m1: a recovery resumed on an operator's confirmation records the fence it
// recovered on, so a claim it had refused is retried on the next tick rather
// than refused as a retry owed to an older fence.
//
// Mutation: drop noteFencedOn from resumeFromConfirmation — the retry does
// not run and the VM stays.
func TestConfirmationResume_RecordsTheFenceSoARefusedClaimIsRetried(t *testing.T) {
	refuse := true
	cl := &fakeClaimer{decide: func(k corrosion.ClaimKey, v corrosion.ClaimValue) (claims.Outcome, error) {
		if refuse {
			return claims.Outcome{}, &claims.NoMajorityError{Phase: "accept", Got: 1, Need: 2,
				Refusals: []claims.Refusal{{Voter: "live", Reason: corrosion.RefusalOwnerReachable, Detail: "live still reaches dead"}}}
		}
		return decideOurs(k, v)
	}}
	db, c := claimFixture(t, cl)
	ctx := context.Background()
	if !c.acquireLease(ctx) {
		t.Fatal("setup: no lease")
	}
	// A previous leader fenced dead (an unproven fence); an operator has
	// since confirmed it off. This coordinator never acted on that fence.
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
	c.retryClaims(ctx, "dead")
	if vm := mustVM(t, db, "vm1"); vm.HostName == "dead" && vm.PendingActionID == "" {
		t.Fatal("the claim refused in a confirmation resume was not retried")
	}
}
