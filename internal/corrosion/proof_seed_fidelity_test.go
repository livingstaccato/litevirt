package corrosion

import (
	"context"
	"errors"
	"testing"
)

// TestWriteActionProofValidated_RefusesToSeedADifferentProof.
//
// The function validates a presented proof's lease_term/lease_key via
// ProofBindingEqual and then persists through proofInsertStmt — which swaps in
// insertProofPreTermSQL when this node's emit gate is closed, omitting BOTH
// columns so the row lands at the NOT NULL defaults (0, ”). It reported
// success having stored something other than what it checked.
//
// The gate is per-node (MayEmitTermCarryingProof == MayMintLeaseTerm, wired to
// DurablyLatched), so a staggered roll makes this ordinary: a latched
// coordinator forwards a term-carrying proof to a peer that has not latched.
// A retry then re-presents (5,"failover") against the persisted (0,""),
// ProofBindingEqual is false, and the caller gets ErrProofDiverges — breaking
// the idempotent-retry contract this function's own doc promises, and blaming
// a divergence that never happened.
//
// Refusing at the first delivery is strictly better than succeeding and
// failing confusingly on the retry: the coordinator learns immediately that
// this executor cannot record the binding it was asked to honour.
func TestWriteActionProofValidated_RefusesToSeedADifferentProof(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)

	// This node cannot emit term-carrying proofs — mid rolling upgrade.
	c.SetLeaseTermLedgerGate(func() bool { return false })

	p := ActionProof{
		ID: "p1", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm1",
		DestHost: "node-b", Coordinator: "coord-a",
		LeaseTerm: 5, LeaseKey: LeaseKeyFailover,
	}

	err := WriteActionProofValidated(ctx, c, p)
	if err == nil {
		t.Fatal("accepted a term-carrying proof it cannot persist faithfully; the row lands " +
			"at (0, \"\") and the coordinator's identical retry then fails ErrProofDiverges")
	}
	if errors.Is(err, ErrProofDiverges) {
		t.Fatalf("the refusal must not blame a divergence that has not happened: %v", err)
	}

	// And nothing was written, so a later retry on a node that HAS latched is
	// not fighting a seeded sentinel row.
	rows, qerr := c.Query(ctx, `SELECT lease_term FROM runtime_action_proofs WHERE id = ?`, "p1")
	if qerr != nil {
		t.Fatalf("query: %v", qerr)
	}
	if len(rows) != 0 {
		t.Fatalf("a refused proof was still seeded (%d row(s)); the sentinel it leaves "+
			"behind is what breaks the retry", len(rows))
	}
}

// A proof carrying NO term is the ordinary pre-ledger shape and must still be
// accepted with the gate closed, or a mixed-version fleet stops working.
func TestWriteActionProofValidated_TermlessProofStillSeeds(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	c.SetLeaseTermLedgerGate(func() bool { return false })

	p := ActionProof{
		ID: "p2", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm2",
		DestHost: "node-b", Coordinator: "coord-a",
	}
	if err := WriteActionProofValidated(ctx, c, p); err != nil {
		t.Fatalf("a termless proof was refused with the gate closed: %v", err)
	}
	rows, err := c.Query(ctx, `SELECT id FROM runtime_action_proofs WHERE id = ?`, "p2")
	if err != nil || len(rows) != 1 {
		t.Fatalf("termless proof not seeded: rows=%d err=%v", len(rows), err)
	}
}

// And with the gate OPEN a term-carrying proof seeds faithfully.
func TestWriteActionProofValidated_SeedsTheTermWhenItCan(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)

	p := ActionProof{
		ID: "p3", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm3",
		DestHost: "node-b", Coordinator: "coord-a",
		LeaseTerm: 5, LeaseKey: LeaseKeyFailover,
	}
	if err := WriteActionProofValidated(ctx, c, p); err != nil {
		t.Fatalf("WriteActionProofValidated: %v", err)
	}
	rows, err := c.Query(ctx, `SELECT lease_term, lease_key FROM runtime_action_proofs WHERE id = ?`, "p3")
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	if got := rows[0].Int64("lease_term"); got != 5 {
		t.Errorf("lease_term = %d, want 5 — the validated binding must be what is stored", got)
	}

	// The idempotent retry the doc promises.
	if err := WriteActionProofValidated(ctx, c, p); err != nil {
		t.Fatalf("an identical retry failed: %v", err)
	}
}
