package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestLegacyValueMayRun is the bridge's proof test (docs/design/recovery-claims.md
// §10 item 37): a legacy value whose proof this replica holds spent never runs
// again and is left behind; one whose proof is pending, or not here yet, may be
// the current incarnation's decision and is adopted.
//
// Mutation: make legacyValueMayRun return true for every proof — the spent and
// tombstoned cases are adopted.
func TestLegacyValueMayRun(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	write := func(id, status string, deleted bool) {
		t.Helper()
		if err := corrosion.WriteActionProof(ctx, s.db, corrosion.ActionProof{ID: id, Action: corrosion.ActionReschedule,
			TargetKind: "vm", TargetName: "vm1", DestHost: "b", Coordinator: "a", OwnerEpoch: "1"}); err != nil {
			t.Fatal(err)
		}
		if err := s.db.Execute(ctx, `UPDATE runtime_action_proofs SET status = ? WHERE id = ?`, status, id); err != nil {
			t.Fatal(err)
		}
		if deleted {
			if err := s.db.Execute(ctx, `UPDATE runtime_action_proofs SET deleted_at = '2026-10-01T00:00:00Z' WHERE id = ?`, id); err != nil {
				t.Fatal(err)
			}
		}
	}
	write("pending", "prepared", false)
	write("done", corrosion.ProofCompleted, false)
	write("gave-up", corrosion.ProofFailed, false)
	write("reaped", corrosion.ProofCompleted, true)
	value := func(id string) corrosion.ClaimValue {
		return corrosion.ClaimValue{Proof: &corrosion.ActionProof{ID: id}, SourceHost: "a"}
	}
	for id, want := range map[string]bool{"pending": true, "not-here-yet": true, "done": false, "gave-up": false, "reaped": false} {
		if got := s.legacyValueMayRun(ctx, value(id)); got != want {
			t.Errorf("legacyValueMayRun(%s) = %v, want %v", id, got, want)
		}
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
	if k := s.ClaimKeyFor(ctx, "vm", "vm1", 2, ""); k.Incarnation != "" {
		t.Fatalf("a row with no created_at was scoped: %s", k)
	}
}
