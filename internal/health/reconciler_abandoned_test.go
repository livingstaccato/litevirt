package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// abandonHere records, as a destination does, that this node will never run
// proofID (node-local, docs/design/recovery-claims.md §3.12).
func abandonHere(t *testing.T, db *corrosion.Client, proofID string) {
	t.Helper()
	if err := db.ExecuteLocal(context.Background(), func(tx *corrosion.LocalTx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO local_abandoned_proofs
			(proof_id, target_kind, target_name, owner_epoch, attempt, reason, abandoned_at)
			VALUES (?, 'vm', 'vm1', 0, 0, 'test', ?)`, proofID, time.Now().UTC().Format(time.RFC3339Nano))
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func assertAbandonedStartIsTerminal(t *testing.T, db *corrosion.Client, reason string) {
	t.Helper()
	ctx := context.Background()
	if reason != ReasonClaimLost {
		t.Errorf("refusal reason = %q, want %q", reason, ReasonClaimLost)
	}
	pr, _, _ := corrosion.GetActionProof(ctx, db, "p1")
	if pr.Status != corrosion.ProofFailed {
		t.Errorf("proof status = %q, want failed: an abandoned proof never runs here, so retrying it is a loop", pr.Status)
	}
	if fresh, _ := corrosion.GetVM(ctx, db, "vm1"); fresh == nil || fresh.PendingActionID != "" {
		t.Errorf("the VM is still pending on the abandoned proof: %+v", fresh)
	}
}

// TestStartPendingVM_AnAbandonedProofIsTerminal: a pending start whose proof
// this host has abandoned is refused at the claim, and the refusal is
// terminal — the proof fails and the row leaves pending — not a transient
// retried every tick.
//
// Mutation: drop the ErrProofAbandoned arm at the claim — the refusal is
// logged as transient and the row stays pending on the proof.
func TestStartPendingVM_AnAbandonedProofIsTerminal(t *testing.T) {
	ctx := context.Background()
	db, fake, r, vm := pendingProofFixture(t, 0, "", "node-z")
	var reason string
	r.SetGateRefusedObserver(func(_, rs string) { reason = rs })
	abandonHere(t, db, "p1")
	r.startPendingVM(ctx, vm)
	if startedOrDefined(fake, "vm1") {
		t.Fatal("a VM was started from a proof this host abandoned")
	}
	assertAbandonedStartIsTerminal(t, db, reason)
}

// TestStartPendingVM_AReleaseAfterTheClaimNeverStarts: a release recorded
// between the claim and the start (an operator's `lv cluster claim-release`,
// which nothing else holds off once the start lease has expired) is caught
// by the start checkpoint, which the database appends only for a proof this
// host has not abandoned. Nothing is defined or started.
//
// Mutation: drop the start checkpoint before DefineDomain — the VM starts
// from a proof this host has promised never to run.
func TestStartPendingVM_AReleaseAfterTheClaimNeverStarts(t *testing.T) {
	ctx := context.Background()
	db, fake, r, vm := pendingProofFixture(t, 0, "", "node-z")
	var reason string
	r.SetGateRefusedObserver(func(_, rs string) { reason = rs })
	r.proofClaimedHook = func(context.Context) { abandonHere(t, db, "p1") }
	r.startPendingVM(ctx, vm)
	if startedOrDefined(fake, "vm1") {
		t.Fatal("a VM was started from a proof released after its claim")
	}
	assertAbandonedStartIsTerminal(t, db, reason)

	// And the checkpoint is what an unabandoned start records.
	db2, fake2, r2, vm2 := pendingProofFixture(t, 0, "", "node-z")
	r2.startPendingVM(ctx, vm2)
	if !startedOrDefined(fake2, "vm1") {
		t.Fatal("control: the unabandoned start did not run")
	}
	if pr, _, _ := corrosion.GetActionProof(ctx, db2, "p1"); !corrosion.ProofStepDone(pr.StepState, "start_attempted") {
		t.Fatalf("the start recorded no start checkpoint: step_state %q", pr.StepState)
	}
}
