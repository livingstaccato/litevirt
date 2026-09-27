package corrosion

import (
	"context"
	"errors"
	"testing"
)

// TestTermFence_IgnoresPeerAuthoredProofs is the remote denial of recovery.
//
// The fenced-claim guard used to count rows in runtime_action_proofs matching
// (lease_term, lease_key, executor_host) with a different coordinator. That
// table is REPLICATED and anti-entropy repaired, so any cluster member could
// insert rows naming a victim host as executor_host across a span of terms —
// they are small monotone integers, so a few hundred rows cover months — and
// every legitimate fenced claim on that host at those terms would then see a
// "conflicting claimant" and refuse.
//
// The victim's reconciler stops being able to claim a reschedule, and the rows
// are durable replicated data, so it stays that way. The fence has to reason
// over something a peer cannot author.
func TestTermFence_IgnoresPeerAuthoredProofs(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	const victim = "kvm001"
	fence := &TermFence{Key: LeaseKeyFailover, Term: 7, Coordinator: "real-coordinator"}

	// A hostile peer plants a conflicting claim for the victim at this term.
	if err := c.Execute(ctx,
		`INSERT INTO runtime_action_proofs
		   (id, action, target_kind, target_name, dest_host, coordinator, executor_host,
		    status, lease_key, lease_term, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"planted", ActionReschedule, "vm", "vm1", victim, "evil", victim,
		"completed", LeaseKeyFailover, int64(7), nowRFC3339(), c.NowTS()); err != nil {
		t.Fatalf("plant proof: %v", err)
	}

	// The victim's own legitimate claim.
	if err := WriteActionProof(ctx, c, ActionProof{
		ID: "legit", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm2",
		DestHost: victim, Coordinator: "real-coordinator",
		LeaseKey: LeaseKeyFailover, LeaseTerm: 7,
	}); err != nil {
		t.Fatalf("write legit proof: %v", err)
	}

	err := ClaimActionProofFenced(ctx, c, "legit", victim, fence)
	if errors.Is(err, ErrTermClaimantConflict) {
		t.Fatal("a peer-authored row in the replicated proof table fenced this host's own " +
			"claim; anyone in the cluster could plant those and durably deny a victim's " +
			"recovery at every term")
	}
	if err != nil {
		t.Fatalf("the legitimate claim did not land: %v", err)
	}
}

// The fence must still fire on a genuine second claimant — otherwise moving the
// binding local would simply delete the protection.
func TestTermFence_StillFencesASecondClaimant(t *testing.T) {
	ctx := context.Background()
	c := apTestClient(t)
	const executor = "kvm001"

	for _, p := range []struct{ id, coord string }{{"p1", "coord-a"}, {"p2", "coord-b"}} {
		if err := WriteActionProof(ctx, c, ActionProof{
			ID: p.id, Action: ActionReschedule, TargetKind: "vm", TargetName: "vm-" + p.id,
			DestHost: executor, Coordinator: p.coord,
			LeaseKey: LeaseKeyFailover, LeaseTerm: 9,
		}); err != nil {
			t.Fatalf("write %s: %v", p.id, err)
		}
	}

	// coord-a claims first and binds this executor for (failover, 9).
	if err := ClaimActionProofFenced(ctx, c, "p1", executor,
		&TermFence{Key: LeaseKeyFailover, Term: 9, Coordinator: "coord-a"}); err != nil {
		t.Fatalf("first claim should have bound cleanly: %v", err)
	}

	// coord-b now tries to act for the same term on the same executor.
	err := ClaimActionProofFenced(ctx, c, "p2", executor,
		&TermFence{Key: LeaseKeyFailover, Term: 9, Coordinator: "coord-b"})
	if !errors.Is(err, ErrTermClaimantConflict) {
		t.Fatalf("a SECOND coordinator claimed the same lease term on the same executor "+
			"(err=%v); that is the split-brain the fence exists to catch", err)
	}
}
