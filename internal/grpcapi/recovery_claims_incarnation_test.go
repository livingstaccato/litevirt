package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

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
