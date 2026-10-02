package grpcapi

import (
	"context"
	"strings"
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

// legacyHeldFixture is a VM recorded on a failed host, the key its recovery
// is claimed under after claim_incarnation_v1 latched, and two legacy values:
// "own", the decision the row is pending on, and "theirs", a previous
// incarnation's decision the row is not.
func legacyHeldFixture(t *testing.T) (*Server, corrosion.ClaimKey, corrosion.ClaimValue, corrosion.ClaimValue) {
	t.Helper()
	ctx := context.Background()
	s := testServer(t)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm-l", HostName: "dead", Spec: `{}`, State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	own := corrosion.ActionProof{ID: "own", Action: corrosion.ActionReschedule, TargetKind: "vm", TargetName: "vm-l",
		DestHost: "slow", Coordinator: "coord", OwnerEpoch: "0"}
	if err := corrosion.WriteVMRescheduleProof(ctx, s.db, own, "vm-l", "slow"); err != nil {
		t.Fatal(err)
	}
	theirs := own
	theirs.ID = "theirs"
	if err := corrosion.WriteActionProof(ctx, s.db, theirs); err != nil {
		t.Fatal(err)
	}
	vm, err := corrosion.GetVM(ctx, s.db, "vm-l")
	if err != nil || vm == nil || vm.PendingActionID != "own" {
		t.Fatalf("fixture: %+v %v", vm, err)
	}
	key := corrosion.ClaimKey{TargetKind: "vm", TargetName: "vm-l", OwnerEpoch: 0, Incarnation: corrosion.IncarnationOf(vm.CreatedAt)}
	return s, key, corrosion.ClaimValue{Proof: &own, SourceHost: "dead"}, corrosion.ClaimValue{Proof: &theirs, SourceHost: "dead"}
}

func legacyHeldRow(t *testing.T, s *Server) (corrosion.HealthCondition, bool) {
	t.Helper()
	row, found, err := corrosion.GetHealthCondition(context.Background(), s.db, claimEvaluator, condClaimLegacyHeld, "vm", "vm-l")
	if err != nil {
		t.Fatal(err)
	}
	return row, found && row.Lifecycle != corrosion.ConditionResolved
}

// TestNoteLegacyHeld_NotForThisIncarnationsOwnPendingDecision: a legacy value
// the bridge could not exclude in time is this incarnation's own decision
// when this replica shows the row pending on it — its destination is merely
// slow — and ha.claim.legacy_held is not raised for it. A value the row is
// not pending on is ambiguous, and is.
//
// Mutation: drop the own-decision check from noteLegacyHeld — the condition
// is raised for the VM's own pending decision.
func TestNoteLegacyHeld_NotForThisIncarnationsOwnPendingDecision(t *testing.T) {
	ctx := context.Background()
	s, key, own, theirs := legacyHeldFixture(t)
	s.noteLegacyHeld(ctx, key, own, "slow did not answer within the exclusion timeout")
	if row, open := legacyHeldRow(t, s); open {
		t.Fatalf("ha.claim.legacy_held raised for the VM's own pending decision: %+v", row)
	}
	s.noteLegacyHeld(ctx, key, theirs, "slow did not answer within the exclusion timeout")
	row, open := legacyHeldRow(t, s)
	if !open || !strings.Contains(row.Evidence, "theirs") {
		t.Fatalf("ha.claim.legacy_held not raised for a value the VM is not pending on: %+v", row)
	}
}

// TestNoteLegacyHeld_ReassertIsIdempotentAndReraises: the failover
// coordinator re-asserts the condition every tick it refuses an adopted spent
// decision (NoteLegacyHeld), so a raise whose write failed is retried. An open
// row for the same decision is left alone — the re-assert writes nothing, so
// it does not replicate a row per tick — and a row that is missing or
// resolved is raised again.
//
// Mutations: compare the whole evidence (detail included) for the
// already-raised check — every re-assert rewrites the row; return early
// whenever a row is found — a resolved row is never raised again.
func TestNoteLegacyHeld_ReassertIsIdempotentAndReraises(t *testing.T) {
	ctx := context.Background()
	s, key, _, theirs := legacyHeldFixture(t)
	s.NoteLegacyHeld(ctx, key, theirs, "slow did not answer")
	first, open := legacyHeldRow(t, s)
	if !open {
		t.Fatal("NoteLegacyHeld raised nothing")
	}
	s.NoteLegacyHeld(ctx, key, theirs, "a different reason, the next tick")
	again, _ := legacyHeldRow(t, s)
	if again.ObserveCount != first.ObserveCount || again.Evidence != first.Evidence {
		t.Fatalf("a re-assert of an open row rewrote it: %+v -> %+v", first, again)
	}

	// Resolved (or never written): raised again.
	s.resolveLegacyHeld(ctx, true)
	if _, open := legacyHeldRow(t, s); open {
		t.Fatal("fixture: the row did not resolve")
	}
	s.NoteLegacyHeld(ctx, key, theirs, "slow did not answer")
	if row, open := legacyHeldRow(t, s); !open || !strings.Contains(row.Evidence, "theirs") {
		t.Fatalf("a resolved row was not raised again: %+v", row)
	}
}
