package failover

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A decided value whose proof is already SPENT — completed or failed — can
// never run again (docs/design/recovery-claims.md §10 item 37). When the
// legacy-key bridge adopted one (its destination could not answer the
// exclusion in time), the scoped key decides it, and without a way past it
// the workload would wait behind a proof that will never execute.

// spentDecision decides, at attempt 0, another coordinator's reschedule whose
// proof this replica holds completed; at later attempts, the proposal.
func spentDecision() func(corrosion.ClaimKey, corrosion.ClaimValue) (claims.Outcome, error) {
	return func(key corrosion.ClaimKey, v corrosion.ClaimValue) (claims.Outcome, error) {
		if key.Attempt > 0 {
			return decideOurs(key, v)
		}
		return decideTheirs(corrosion.ActionReschedule, "other")(key, v)
	}
}

func completeTheirProof(t *testing.T, db *corrosion.Client) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.WriteActionProof(ctx, db, corrosion.ActionProof{ID: "their-proof", Action: corrosion.ActionReschedule,
		TargetKind: "vm", TargetName: "vm1", DestHost: "other", Coordinator: "other-coord", OwnerEpoch: "4"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Execute(ctx, `UPDATE runtime_action_proofs SET status = 'completed', executor_host = 'other' WHERE id = 'their-proof'`); err != nil {
		t.Fatal(err)
	}
}

// TestReschedule_ASpentDecisionMovesOnOnAForeignAbandonment: the destination
// that ran the spent proof signs that it was not this incarnation's, and the
// claim moves to attempt 1 on that evidence.
//
// Mutation: drop the spent-proof arm of supersedeEvidence — the claim stops at
// attempt 0 and nothing is recovered.
func TestReschedule_ASpentDecisionMovesOnOnAForeignAbandonment(t *testing.T) {
	cl := &fakeClaimer{decide: spentDecision()}
	cl.foreign = func(host string, key corrosion.ClaimKey, proofID string) (string, error) {
		return "foreign-abandonment-of-" + proofID, nil
	}
	db, c := claimFixture(t, cl)
	completeTheirProof(t, db)
	c.run(context.Background())

	if len(cl.calls) < 2 || cl.calls[1].Attempt != 1 {
		t.Fatalf("the claim did not move past the spent decision: %v", cl.calls)
	}
	if ev := cl.evidence[1]; ev == nil || ev.Abandonment != "foreign-abandonment-of-their-proof" {
		t.Fatalf("attempt 1 did not carry the destination's foreign abandonment: %+v", ev)
	}
	if vm := mustVM(t, db, "vm1"); vm.PendingActionID == "" || vm.PendingActionID == "their-proof" {
		t.Fatalf("the VM was not recovered past the spent decision: %+v", vm)
	}
}

// TestReschedule_ASpentDecisionIsNotWritten: when the destination cannot show
// the spent proof is another incarnation's, the claim refuses — it does not
// point the VM at a proof that can never run, which would hide it from every
// later recovery — and the next tick retries.
//
// Mutation: write the decided value even when its proof is spent — the VM is
// pending on a proof that never runs, and off the failed host for good.
func TestReschedule_ASpentDecisionIsNotWritten(t *testing.T) {
	cl := &fakeClaimer{decide: spentDecision()}
	cl.foreign = func(string, corrosion.ClaimKey, string) (string, error) {
		return "", errors.New("the destination cannot show it")
	}
	db, c := claimFixture(t, cl)
	completeTheirProof(t, db)
	c.run(context.Background())

	if vm := mustVM(t, db, "vm1"); vm.HostName != "dead" || vm.PendingActionID != "" {
		t.Fatalf("the VM was pointed at a decision that can never run: host=%s pending=%q", vm.HostName, vm.PendingActionID)
	}
	if !c.claimRetry["dead"] {
		t.Fatal("the refused claim is not retried next tick")
	}
}
