package health

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

var errUnprovenForTest = errors.New("no certificate verifies")

// TestStartPendingVM_RecoveryClaimGateRefusesAnUnprovenProof: a reschedule
// proof is claimed off the replicated row, never over an RPC, so the
// certificate check has to run HERE, after the exact-match and owner-epoch
// checks and before the claim (docs/design/recovery-claims.md §3.10). A
// refused proof stays pending and unclaimed, for the certificate to verify on
// a later tick.
//
// Mutation: drop the recoveryClaimGate call in startPendingVM — the VM starts
// from a proof no majority certified, which is the second writable owner of
// colonelpanik/litevirt#250.
func TestStartPendingVM_RecoveryClaimGateRefusesAnUnprovenProof(t *testing.T) {
	ctx := context.Background()
	db, fake, r, vm := pendingProofFixture(t, 0, "", "node-z")
	var gotReason string
	r.SetGateRefusedObserver(func(_, reason string) { gotReason = reason })
	r.SetRecoveryClaimGate(func(context.Context, corrosion.ProofRecord) (string, error) {
		return ReasonClaimUnproven, errUnprovenForTest
	})

	r.startPendingVM(ctx, vm)

	if startedOrDefined(fake, "vm1") {
		t.Fatal("a VM was started from a proof whose recovery-claim certificate did not verify")
	}
	if gotReason != ReasonClaimUnproven {
		t.Errorf("refusal reason = %q, want %q", gotReason, ReasonClaimUnproven)
	}
	pr, ok, _ := corrosion.GetActionProof(ctx, db, "p1")
	if !ok || pr.Status != corrosion.ProofPrepared {
		t.Errorf("proof status = %q (ok=%v), want prepared — a refused proof must not be consumed", pr.Status, ok)
	}
	if fresh, _ := corrosion.GetVM(ctx, db, "vm1"); fresh == nil || fresh.PendingActionID != "p1" {
		t.Errorf("the refused start did not leave the row pending: %+v", fresh)
	}
}

// TestStartPendingVM_RecoveryClaimGateAccepts: a verified certificate (the gate
// answers proceed) starts the VM exactly as before.
func TestStartPendingVM_RecoveryClaimGateAccepts(t *testing.T) {
	ctx := context.Background()
	_, fake, r, vm := pendingProofFixture(t, 0, "", "node-z")
	var seen corrosion.ProofRecord
	r.SetRecoveryClaimGate(func(_ context.Context, pr corrosion.ProofRecord) (string, error) {
		seen = pr
		return "", nil
	})
	r.startPendingVM(ctx, vm)
	if !startedOrDefined(fake, "vm1") {
		t.Fatal("a proof the gate accepted did not start the VM")
	}
	if seen.ID != "p1" {
		t.Fatalf("the gate judged proof %q, want the pending proof p1", seen.ID)
	}
}
