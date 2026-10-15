package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// staleTermFixture is claimFixture with lease terms enforced on this
// coordinator, which holds the lease at its own term 5.
func staleTermFixture(t *testing.T, cl *fakeClaimer) (*corrosion.Client, *Coordinator) {
	t.Helper()
	db, c := claimFixture(t, cl)
	c.LeaseTermEnforce = true
	c.Gate = fakeFailoverGate{
		supports: map[string]bool{"live": true, "other": true},
		enforced: map[string]bool{capabilities.SplitBrainGateV1: true, capabilities.LeaseTermV1: true},
	}
	// This coordinator holds the lease; its own term is 5.
	if _, _, err := corrosion.AcquireLeaseWithTerm(context.Background(), db, corrosion.LeaseKeyFailover, "coord",
		10*time.Minute, time.Now()); err != nil {
		t.Fatal(err)
	}
	c.leaseTerm.Store(5)
	return db, c
}

// vm1Key is the attempt-0 key of vm1 at owner epoch 4, scoped to its
// incarnation.
func vm1Key(t *testing.T, db *corrosion.Client) corrosion.ClaimKey {
	t.Helper()
	inc, ok, err := corrosion.WorkloadIncarnation(context.Background(), db, "vm", "vm1")
	if err != nil || !ok {
		t.Fatalf("vm1's incarnation: %v %v", ok, err)
	}
	return corrosion.ClaimKey{TargetKind: "vm", TargetName: "vm1", OwnerEpoch: 4, Incarnation: inc}
}

// pendingAtTerm writes, as a coordinator at lease term `term` did, a certified
// reschedule of vm1 off dead to live, decided at key, and returns it.
func pendingAtTerm(t *testing.T, db *corrosion.Client, key corrosion.ClaimKey, id string, term int64) corrosion.ActionProof {
	t.Helper()
	p := corrosion.ActionProof{ID: id, Action: corrosion.ActionReschedule, TargetKind: "vm", TargetName: "vm1",
		DestHost: "live", Coordinator: "earlier-holder", OwnerEpoch: "4",
		LeaseTerm: term, LeaseKey: corrosion.LeaseKeyFailover}
	out, err := decideOurs(key, corrosion.ClaimValue{Proof: &p, SourceHost: "dead"})
	if err != nil {
		t.Fatal(err)
	}
	if p.ClaimCertificate, err = out.Certificate.Encode(); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.WriteVMRescheduleProof(context.Background(), db, p, "vm1", "live"); err != nil {
		t.Fatal(err)
	}
	return p
}

// abandonsAll signs every abandonment it is asked for.
func abandonsAll(host string, _ corrosion.ClaimKey, proofID string) (string, error) {
	return "ab:" + host + "/" + proofID, nil
}

// A certified pending reschedule written at a lease term the lease has since
// outrun is abandoned by its destination, claimed again at the next attempt
// on that abandonment, and the row is re-pointed at the decided proof, which
// carries this holder's term.
//
// Mutation: staleTermProblem never reports — nothing is asked and vm1 stays
// pending on the stale proof.
func TestStaleTermSweep_APendingProofTheLeaseOutranIsDecidedAgain(t *testing.T) {
	ctx := context.Background()
	cl := &fakeClaimer{decide: decideOurs, abandon: abandonsAll}
	db, c := staleTermFixture(t, cl)
	key := vm1Key(t, db)
	old := pendingAtTerm(t, db, key, "at-term-3", 3)

	c.sweepStaleTermProofs(ctx)

	if len(cl.abandonAsked) != 1 || cl.abandonAsked[0] != "live/at-term-3" {
		t.Fatalf("abandonments asked %v, want live's of at-term-3", cl.abandonAsked)
	}
	next := key
	next.Attempt = 1
	if len(cl.calls) != 1 || cl.calls[0] != next {
		t.Fatalf("claims %v, want one at %s", cl.calls, next)
	}
	ev := cl.evidence[0]
	if ev == nil || ev.Abandonment != "ab:live/at-term-3" || ev.PriorCertificate != old.ClaimCertificate ||
		ev.PriorValue == nil || ev.PriorValue.Proof == nil || ev.PriorValue.Proof.ID != old.ID || ev.PriorValue.SourceHost != "dead" {
		t.Fatalf("supersede evidence %+v does not carry the abandoned value, its certificate and the abandonment", ev)
	}
	vm := mustVM(t, db, "vm1")
	if vm.PendingActionID == old.ID || vm.PendingActionID == "" || vm.HostName != "live" || vm.State != "pending" {
		t.Fatalf("vm1 was not re-pointed at a new proof: %+v", vm)
	}
	pr, ok, err := corrosion.GetActionProof(ctx, db, vm.PendingActionID)
	if err != nil || !ok {
		t.Fatalf("the new pending proof: %v %v", ok, err)
	}
	if pr.LeaseTerm != 5 || pr.LeaseKey != corrosion.LeaseKeyFailover || pr.Coordinator != "coord" ||
		pr.DestHost != "live" || pr.OwnerEpoch != "4" || pr.ClaimCertificate == "" {
		t.Fatalf("the new pending proof is not this holder's certified move at term 5: %+v", pr.ActionProof)
	}
	cert, err := corrosion.DecodeClaimCertificate(pr.ClaimCertificate)
	if err != nil || cert.Key != next {
		t.Fatalf("the new proof's certificate decides %v (%v), want %s", cert.Key, err, next)
	}
}

// Nothing is decided or written until the destination has abandoned the
// stale proof: one it refuses to abandon (it has claimed it) stays the
// pending proof, and no claim is made.
//
// Mutation: claim without the abandonment — a claim is made.
func TestStaleTermSweep_NoAbandonmentNoClaim(t *testing.T) {
	ctx := context.Background()
	cl := &fakeClaimer{decide: decideOurs}
	db, c := staleTermFixture(t, cl)
	old := pendingAtTerm(t, db, vm1Key(t, db), "at-term-3", 3)
	c.sweepStaleTermProofs(ctx)
	if len(cl.abandonAsked) != 1 {
		t.Fatalf("abandonments asked %v, want one", cl.abandonAsked)
	}
	if len(cl.calls) != 0 {
		t.Fatalf("a claim was made without the destination's abandonment: %v", cl.calls)
	}
	if vm := mustVM(t, db, "vm1"); vm.PendingActionID != old.ID {
		t.Fatalf("vm1 was re-pointed without an abandonment: %+v", vm)
	}
}

// A pending proof at this holder's own term, or with enforcement off here, is
// left alone.
//
// Mutation: judge by the latch alone (drop the flag) — the flag-off arm asks
// for an abandonment.
func TestStaleTermSweep_ACurrentProofOrEnforcementOffIsLeft(t *testing.T) {
	ctx := context.Background()
	cl := &fakeClaimer{decide: decideOurs, abandon: abandonsAll}
	db, c := staleTermFixture(t, cl)
	key := vm1Key(t, db)
	cur := pendingAtTerm(t, db, key, "at-term-5", 5)
	c.sweepStaleTermProofs(ctx)
	if len(cl.abandonAsked) != 0 || len(cl.calls) != 0 {
		t.Fatalf("a proof at this holder's own term was swept: abandon %v claims %v", cl.abandonAsked, cl.calls)
	}
	if err := db.Execute(ctx, `UPDATE runtime_action_proofs SET lease_term = 3 WHERE id = ?`, cur.ID); err != nil {
		t.Fatal(err)
	}
	c.LeaseTermEnforce = false
	c.sweepStaleTermProofs(ctx)
	if len(cl.abandonAsked) != 0 || len(cl.calls) != 0 {
		t.Fatalf("a coordinator with enforcement.lease_term off swept a proof: abandon %v claims %v", cl.abandonAsked, cl.calls)
	}
}

// A row that has moved off the stale proof (its destination failed it, or a
// newer recovery re-pointed it) is not written over.
//
// Mutation: drop ReplaceVMRescheduleProof's pending_action_id guard — vm1 is
// pointed at the new proof although the row had moved on.
func TestStaleTermSweep_ARowThatMovedOnIsNotWrittenOver(t *testing.T) {
	ctx := context.Background()
	cl := &fakeClaimer{abandon: abandonsAll}
	db, c := staleTermFixture(t, cl)
	pendingAtTerm(t, db, vm1Key(t, db), "at-term-3", 3)
	cl.decide = func(key corrosion.ClaimKey, v corrosion.ClaimValue) (claims.Outcome, error) {
		// The row moves on while the claim is decided.
		if err := db.Execute(ctx, `UPDATE vms SET pending_action_id = 'newer' WHERE name = 'vm1'`); err != nil {
			t.Fatal(err)
		}
		return decideOurs(key, v)
	}
	c.sweepStaleTermProofs(ctx)
	if len(cl.calls) != 1 {
		t.Fatalf("setup: claims %v, want one", cl.calls)
	}
	if vm := mustVM(t, db, "vm1"); vm.PendingActionID != "newer" {
		t.Fatalf("a row that moved on was written over: %+v", vm)
	}
}

// certifyUncertified certifies a pre-claims proof for its own value; when
// that value's stamp is below this holder's term, it goes straight on past
// it, as the sweep would.
//
// Mutation: drop the supersedeStaleTerm call in certifyUncertified — vm1
// stays pending on the stale proof.
func TestCertifyUncertified_AStaleStampMovesOn(t *testing.T) {
	ctx := context.Background()
	cl := &fakeClaimer{decide: decideOurs, abandon: abandonsAll}
	db, c := staleTermFixture(t, cl)
	p := corrosion.ActionProof{ID: "pre-latch", Action: corrosion.ActionReschedule, TargetKind: "vm", TargetName: "vm1",
		DestHost: "live", Coordinator: "earlier-holder", OwnerEpoch: "4",
		FenceEpoch: "host=dead;fence_id=f1;ts=2026-01-01T00:00:00Z",
		LeaseTerm:  3, LeaseKey: corrosion.LeaseKeyFailover}
	if err := corrosion.WriteVMRescheduleProof(ctx, db, p, "vm1", "live"); err != nil {
		t.Fatal(err)
	}
	c.certifyUncertified(ctx)
	if len(cl.calls) != 2 || cl.calls[0].Attempt != 0 || cl.calls[1].Attempt != 1 {
		t.Fatalf("claims %v, want attempt 0 (certify) then attempt 1 (past the stale stamp)", cl.calls)
	}
	vm := mustVM(t, db, "vm1")
	pr, ok, err := corrosion.GetActionProof(ctx, db, vm.PendingActionID)
	if err != nil || !ok || pr.ID == p.ID || pr.LeaseTerm != 5 {
		t.Fatalf("vm1 is pending on %+v, want a proof at term 5 in place of the stale one", pr.ActionProof)
	}
}

// recertifyReplaced re-certifies a proof whose certificate a forced voter
// generation replaced; when its stamp is below this holder's term, it goes
// on past it.
//
// Mutation: drop the supersedeStaleTerm call in recertifyReplaced — vm1
// stays pending on the stale, re-certified proof.
func TestRecertifyReplaced_AStaleStampMovesOn(t *testing.T) {
	ctx := context.Background()
	cl := &fakeClaimer{decide: decideOurs, abandon: abandonsAll}
	db, c := staleTermFixture(t, cl)
	old := pendingAtTerm(t, db, vm1Key(t, db), "at-term-3", 3)
	// Generation 2 forced, and adopted here: generation 1 certifies nothing.
	if _, err := db.DB().ExecContext(ctx, `INSERT INTO voter_configs
		(generation, members_json, members_hash, change, certificate, created_by, created_at, updated_at)
		VALUES (2, '[]', '', 'force:test', '', 'test', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(ctx, `INSERT INTO local_voter_adoption (generation, adopted_at) VALUES (2, '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	c.recertifyReplaced(ctx)
	if len(cl.calls) != 2 || cl.calls[0].Attempt != 0 || cl.calls[1].Attempt != 1 {
		t.Fatalf("claims %v, want attempt 0 (re-certify) then attempt 1 (past the stale stamp)", cl.calls)
	}
	vm := mustVM(t, db, "vm1")
	pr, ok, err := corrosion.GetActionProof(ctx, db, vm.PendingActionID)
	if err != nil || !ok || pr.ID == old.ID || pr.LeaseTerm != 5 {
		t.Fatalf("vm1 is pending on %+v, want a proof at term 5 in place of the stale one", pr.ActionProof)
	}
}

// A decided value for ANOTHER action at a superseded stamp — another
// coordinator's promote from an earlier tenure — is not deferred to: the
// executors refuse it, so deferring would retry it on every tick for good.
// Its destination abandons it and the claim moves on to this coordinator's
// own value.
//
// Mutation: judge the stamp after the action check (the code before) — the
// promote is returned and the site defers to it.
func TestClaimRecovery_AStaleValueOfAnotherActionMovesOn(t *testing.T) {
	ctx := context.Background()
	cl := &fakeClaimer{abandon: abandonsAll}
	cl.decide = func(key corrosion.ClaimKey, v corrosion.ClaimValue) (claims.Outcome, error) {
		if key.Attempt > 0 {
			return decideOurs(key, v)
		}
		p := *v.Proof
		p.ID, p.Action, p.DestHost, p.Coordinator, p.LeaseTerm = "their-promote", corrosion.ActionPromote, "other", "other-coord", 3
		out, err := decideOurs(key, corrosion.ClaimValue{Proof: &p, SourceHost: v.SourceHost})
		out.Ours = false
		return out, err
	}
	db, c := staleTermFixture(t, cl)
	vm := mustVM(t, db, "vm1")
	proposal := corrosion.ActionProof{ID: "mine", Action: corrosion.ActionReschedule, TargetKind: "vm", TargetName: "vm1",
		DestHost: "live", Coordinator: "coord", OwnerEpoch: "4", LeaseTerm: 5, LeaseKey: corrosion.LeaseKeyFailover}
	got, err := c.claimRecovery(ctx, proposal, "dead", vm.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Ours || got.Proof.ID != "mine" {
		t.Fatalf("decided %+v, want this coordinator's own value past the stale promote", got.Proof)
	}
	if len(cl.abandonAsked) != 1 || cl.abandonAsked[0] != "other/their-promote" {
		t.Fatalf("abandonments asked %v, want other's of their-promote", cl.abandonAsked)
	}
}
