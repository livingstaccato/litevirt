package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
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

// breakLeaseReadOnce makes one holdLease fail on a lease read error, as a
// transient store fault would, and restores the table.
func breakLeaseReadOnce(t *testing.T, c *Coordinator, db *corrosion.Client, ctx context.Context) {
	t.Helper()
	if err := db.Execute(ctx, `ALTER TABLE leader_election RENAME TO leader_election_away`); err != nil {
		t.Fatal(err)
	}
	if c.holdLease(ctx) {
		t.Fatal("setup: holdLease held the lease with its table gone")
	}
	if err := db.Execute(ctx, `ALTER TABLE leader_election_away RENAME TO leader_election`); err != nil {
		t.Fatal(err)
	}
}

// A single lease read error on a leader that never lost the lease is no gap:
// the row still names it unexpired, at its own term, so no other node can
// have led. The pause wait keeps its deadline and the fence its record of
// what moved; a reset would re-anchor the wait and leave the host fenced for
// a manual undrain.
//
// Mutation: mark a gap in dropLeaseTerm — the wait is re-anchored.
func TestLeaseRegain_ATransientLeaseReadErrorKeepsTheEpisode(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	c.run(ctx)
	w, ok := c.pauseWaits["down"]
	if !ok {
		t.Fatal("setup: no pause wait")
	}
	_, relocKnown := c.fenceRelocated["down"]
	breakLeaseReadOnce(t, c, db, ctx)
	mono.Advance(time.Second)
	c.run(ctx)
	got, ok := c.pauseWaits["down"]
	if !ok || !got.deadline.Equal(w.deadline) {
		t.Fatalf("pause wait after a transient lease read error: %+v (present %v), want the deadline %v kept",
			got, ok, w.deadline)
	}
	if _, known := c.fenceRelocated["down"]; known != relocKnown {
		t.Errorf("fenceRelocated[down] known=%v after a transient lease read error, was %v", known, relocKnown)
	}
	if !c.fenced["down"] {
		t.Error("down forgotten as fenced after a transient lease read error")
	}
}

// expireLeaseRow makes the failover lease row's expiry a second past, its
// holder and term unchanged: a lease that lapsed while its holder did not
// renew it.
func expireLeaseRow(t *testing.T, db *corrosion.Client, ctx context.Context) {
	t.Helper()
	if err := db.Execute(ctx, `UPDATE leader_election SET expires_at = ? WHERE key = 'failover'`,
		time.Now().Add(-time.Second).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
}

// quorumToggleGate reads the cluster quorum as lost while *lost holds, and
// enforces nothing.
type quorumToggleGate struct {
	fakeFailoverGate
	lost *bool
}

func (g quorumToggleGate) QuorumProof(context.Context) (health.QuorumState, int, int) {
	if *g.lost {
		return health.QuorumNo, 1, 3
	}
	return health.QuorumYes, 2, 3
}

// A stand-down for want of the voter majority (or inside its regain grace)
// that ends while the lease row still names this node unexpired is no gap
// either. One that outlasts the lease is: the row has lapsed, another node
// may have led, and the episode is forgotten.
//
// Mutations: mark a gap on the quorum stand-down — the short blip re-anchors
// the wait; treat a lapsed own row as continuing (ownTenureLive ignores the
// expiry) — the long one keeps it.
func TestLeaseRegain_AQuorumStandDownKeepsTheEpisodeUntilTheLeaseLapses(t *testing.T) {
	c, db, ctx, mono := explicitPause(t)
	// Before lease_term_ledger_v1 latches no term is minted, so the lease row's
	// expiry is all that tells a lapse from a lease never let go.
	db.SetLeaseTermLedgerGate(func() bool { return false })
	lost := false
	c.Gate = quorumToggleGate{fakeFailoverGate: fakeFailoverGate{enforced: map[string]bool{}}, lost: &lost}
	c.run(ctx)
	w, ok := c.pauseWaits["down"]
	if !ok {
		t.Fatal("setup: no pause wait")
	}
	lost = true
	c.run(ctx)
	lost = false
	mono.Advance(time.Second)
	c.run(ctx)
	if got, ok := c.pauseWaits["down"]; !ok || !got.deadline.Equal(w.deadline) {
		t.Fatalf("pause wait after a short quorum stand-down: %+v (present %v), want the deadline %v kept",
			got, ok, w.deadline)
	}

	lost = true
	c.run(ctx)
	// The stand-down outlasts the lease: the row, still naming this node,
	// has expired.
	expireLeaseRow(t, db, ctx)
	lost = false
	mono.Advance(time.Second)
	c.run(ctx)
	if got, ok := c.pauseWaits["down"]; ok && got.deadline.Equal(w.deadline) {
		t.Fatalf("pause wait kept its deadline %v across a lapsed lease; another node may have led", w.deadline)
	}
}

// A renewal mid-cycle that comes back as a new tenure aborts the cycle, as
// the next starts afresh, but is not a step-down: this node still leads, so
// stranded_workloads keeps its value rather than reading 0.
//
// Mutations: step the gauges down on a new tenure — the gauge reads 0;
// carry on after it (treat it as held) — down2 is fenced in the same cycle.
func TestRun_ANewTenureMidCycleAbortsWithoutSteppingDown(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	for _, h := range []struct{ name, state string }{
		{"stale", "fenced"}, {"down1", "active"}, {"down2", "active"}, {"coord", "active"},
	} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h.name, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: h.state, FenceStrategy: "best-effort",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h.name, err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "stale", State: "running",
		Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	c := newTestCoordinator("coord", db)
	fm := newFakeMetrics()
	c.Metrics = fm
	c.run(ctx)
	if fm.stranded != 1 {
		t.Fatalf("premise: gauge = %d while leader, want 1", fm.stranded)
	}

	fenceQuorum(t, ctx, db, []string{"coord", "down1", "down2"}, "down1")
	fenceQuorum(t, ctx, db, []string{"coord", "down1", "down2"}, "down2")
	// Workloads that need the fences this test makes run.
	needsFence(t, db, "down1")
	needsFence(t, db, "down2")
	var fenced []string
	c.SetFencer(func(ctx context.Context, h fence.HostConfig) fence.Result {
		if len(fenced) == 0 {
			// This node's own lease lapses during the fence: the next
			// renewal takes it back as a new tenure.
			expireLeaseRow(t, db, ctx)
		}
		fenced = append(fenced, h.Name)
		return fence.Result{Method: "test", Detail: "stub", Success: true}
	})
	c.run(ctx)

	if len(fenced) != 1 {
		t.Fatalf("fenced %v in the cycle whose lease renewed as a new tenure; want the cycle aborted after the first", fenced)
	}
	if fm.stranded != 1 {
		t.Errorf("gauge = %d after a renewal as a new tenure, want 1: this node still leads", fm.stranded)
	}
}

// setLeaseExpiry rewrites the failover lease row's expiry, holder and term
// unchanged.
func setLeaseExpiry(t *testing.T, db *corrosion.Client, ctx context.Context, at time.Time) {
	t.Helper()
	if err := db.Execute(ctx, `UPDATE leader_election SET expires_at = ? WHERE key = 'failover'`,
		at.UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
}

// briefStandDown runs one cycle with the voter majority lost, then sets the
// lease row's expiry to expiry before the majority returns and the next cycle
// re-takes the lease. It reports whether the re-take kept down's pause wait.
func briefStandDown(t *testing.T, expiryIn time.Duration, ledger bool, after func(*Coordinator, *monoClock)) bool {
	t.Helper()
	c, db, ctx, mono := explicitPause(t)
	if !ledger {
		db.SetLeaseTermLedgerGate(func() bool { return false })
	}
	lost := false
	c.Gate = quorumToggleGate{fakeFailoverGate: fakeFailoverGate{enforced: map[string]bool{}}, lost: &lost}
	c.run(ctx)
	w, ok := c.pauseWaits["down"]
	if !ok {
		t.Fatal("setup: no pause wait")
	}
	lost = true
	c.run(ctx)
	setLeaseExpiry(t, db, ctx, c.now().Add(expiryIn))
	if after != nil {
		after(c, mono)
	}
	lost = false
	mono.Advance(time.Second)
	c.run(ctx)
	got, ok := c.pauseWaits["down"]
	return ok && got.deadline.Equal(w.deadline)
}

// The lease row still names this node, with less than fenceSkewMargin left:
// a peer whose clock runs that far ahead has seen it expire and may have
// taken the lease, its take not yet replicated here. The re-take is a gap.
//
// Mutation: compare the expiry with this node's clock alone (no margin) —
// the wait is kept.
func TestLeaseRegain_ARowAPeerAheadSeesExpiredIsAGap(t *testing.T) {
	if briefStandDown(t, fenceSkewMargin-2*time.Second, true, nil) {
		t.Fatal("pause wait kept across a re-take of a lease a peer whose clock runs ahead could have taken")
	}
}

// A brief stand-down whose row keeps more than the margin left is no gap.
//
// Mutation: a margin larger than the head-room left (2×fenceSkewMargin) — the
// wait is re-anchored.
func TestLeaseRegain_ARowLiveBeyondTheMarginIsNoGap(t *testing.T) {
	if !briefStandDown(t, fenceSkewMargin+3*time.Second, true, nil) {
		t.Fatal("pause wait re-anchored after a brief stand-down whose lease row stayed live beyond the skew margin")
	}
}

// Before lease terms are minted no term comparison backs the row, so a
// stand-down longer than tenureStandDownBound is a gap even while the row
// still looks live here.
//
// Mutation: drop the stand-down bound — the wait is kept.
func TestLeaseRegain_AnUnlatchedLongStandDownIsAGap(t *testing.T) {
	if !briefStandDown(t, leaseDuration, false, nil) {
		t.Fatal("setup: a brief unlatched stand-down re-anchored the wait")
	}
	long := func(_ *Coordinator, mono *monoClock) { mono.Advance(tenureStandDownBound) }
	if briefStandDown(t, leaseDuration, false, long) {
		t.Fatal("pause wait kept across an unlatched stand-down longer than the bound")
	}
}

// The stand-down is measured on the monotonic clock: a wall clock stepped
// back during it (an NTP correction) does not make a long stand-down look
// short.
//
// Mutation: measure it on c.now() — the step back hides the stand-down and
// the wait is kept.
func TestLeaseRegain_AWallClockStepBackDoesNotShortenAStandDown(t *testing.T) {
	stepBack := func(c *Coordinator, mono *monoClock) {
		mono.Advance(tenureStandDownBound)
		c.Now = func() time.Time { return time.Now().Add(-time.Minute) }
	}
	if briefStandDown(t, leaseDuration, false, stepBack) {
		t.Fatal("pause wait kept across a long unlatched stand-down during which the wall clock stepped back")
	}
}
