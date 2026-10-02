package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestLegacyValueIsThisIncarnation is the bridge's attribution test
// (docs/design/recovery-claims.md §10 item 37): a legacy value is this
// incarnation's decision unless its proof was minted before this incarnation
// existed — by more than the clock skew the cluster tolerates, because a
// misattribution that way decides a second value for one recovery, while one
// the other way only re-decides what the legacy key would have. Whether the
// proof ran does not matter: this incarnation's completed decision is
// re-adopted, so a lagging claim of it is a no-op rather than a fresh
// decision; a previous incarnation's pending one is left behind.
//
// Mutations: reject a completed or failed proof (the pre-review rule) — the
// same incarnation's completed decision is decided afresh; adopt whatever the
// proof's mint time — the previous incarnation's pending decision is adopted.
func TestLegacyValueIsThisIncarnation(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	const inc = "2026-10-01T12:00:00.123456789Z"
	write := func(id, status, createdAt string) {
		t.Helper()
		if err := corrosion.WriteActionProof(ctx, s.db, corrosion.ActionProof{ID: id, Action: corrosion.ActionReschedule,
			TargetKind: "vm", TargetName: "vm1", DestHost: "b", Coordinator: "a", OwnerEpoch: "1"}); err != nil {
			t.Fatal(err)
		}
		if err := s.db.Execute(ctx, `UPDATE runtime_action_proofs SET status = ?, created_at = ? WHERE id = ?`,
			status, createdAt, id); err != nil {
			t.Fatal(err)
		}
	}
	write("same-pending", "prepared", "2026-10-01T12:01:00Z")
	write("same-completed", corrosion.ProofCompleted, "2026-10-01T12:05:00Z")
	write("same-failed", corrosion.ProofFailed, "2026-10-01T12:05:00Z")
	write("within-skew", corrosion.ProofCompleted, "2026-10-01T11:57:00Z")
	write("previous-pending", "prepared", "2026-10-01T11:00:00Z")
	write("previous-completed", corrosion.ProofCompleted, "2026-09-30T06:29:19Z")
	value := func(id string) corrosion.ClaimValue {
		return corrosion.ClaimValue{Proof: &corrosion.ActionProof{ID: id}, SourceHost: "a"}
	}
	for id, want := range map[string]bool{
		"same-pending": true, "same-completed": true, "same-failed": true, "within-skew": true,
		"not-here-yet": true, "previous-pending": false, "previous-completed": false,
	} {
		if got := s.legacyValueIsThisIncarnation(ctx, value(id), inc); got != want {
			t.Errorf("legacyValueIsThisIncarnation(%s) = %v, want %v", id, got, want)
		}
	}
	if s.legacyValueIsThisIncarnation(ctx, corrosion.ClaimValue{SourceHost: "a"}, inc) {
		t.Error("a value with no proof was attributed to the incarnation")
	}
}

// TestClaimKeyFor_ScopedOnlyOnceLatched: before claim_incarnation_v1 latches
// every coordinator claims the legacy key, so no recovery is claimed under two
// keys by coordinators that disagree about the format.
//
// Mutation: scope the key whatever the latch says — the pre-latch key carries
// the incarnation.
func TestClaimKeyFor_ScopedOnlyOnceLatched(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	g := &fakeServerGate{enforcedTok: map[string]bool{}}
	s.gate = g
	if k := s.ClaimKeyFor(ctx, "vm", "vm1", 2, "inc"); k.Incarnation != "" {
		t.Fatalf("before the latch the key is %s, want the legacy key", k)
	}
	g.enforcedTok[capabilities.ClaimIncarnationV1] = true
	if k := s.ClaimKeyFor(ctx, "vm", "vm1", 2, "inc"); k.Incarnation != "inc" || k.OwnerEpoch != 2 {
		t.Fatalf("after the latch the key is %s, want it scoped to inc", k)
	}
	// A row with no created_at is not left on the legacy key: it is given
	// the fixed incarnation, so the format never depends on a row.
	if k := s.ClaimKeyFor(ctx, "vm", "vm1", 2, ""); k.Incarnation != corrosion.UnstampedIncarnation {
		t.Fatalf("a row with no created_at was keyed %s, want incarnation %q", k, corrosion.UnstampedIncarnation)
	}
}
