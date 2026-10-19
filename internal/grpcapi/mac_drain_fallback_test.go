package grpcapi

import (
	"context"
	"strconv"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// The journal fallback exempts a start only for the VM exactly as that open
// move handed it over: on this host at the journaled owner epoch + 1,
// stopped, with no stop intent (or the drain's own) — the boundary
// resumeDrainColdMove recovers within. An open move whose terminal step is
// late does not exempt a later operator stop, nor a later placement; and a
// marker that was rejected never falls back to the journal.
func TestStartVM_ADrainJournalExemptsOnlyTheMovesOwnHandoff(t *testing.T) {
	const dup = "52:54:00:00:2f:01"
	const journaled = int64(4) // the epoch the move was journaled at
	setup := func(t *testing.T, epoch int64, detail string) *Server {
		t.Helper()
		s := testServer(t)
		ctx := context.Background()
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "moved", HostName: s.hostName, State: "stopped", StateDetail: detail},
			[]corrosion.InterfaceRecord{{VMName: "moved", NetworkName: "lan", MAC: dup}}, nil); err != nil {
			t.Fatal(err)
		}
		if err := s.db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = ? WHERE name = 'moved'`, epoch); err != nil {
			t.Fatal(err)
		}
		seedNICOf(t, s, "theirs", dup)
		// The old move, still open here (its terminal step not arrived).
		if _, err := corrosion.BeginDrainColdMove(ctx, s.db,
			corrosion.VMRecord{Name: "moved", HostName: "src-host", OwnerEpoch: journaled}, "src-host", s.hostName, "attempt-1"); err != nil {
			t.Fatal(err)
		}
		return s
	}
	refused := func(t *testing.T, ctx context.Context, s *Server) {
		t.Helper()
		if err := s.refuseStartOnSharedMAC(ctx, "moved"); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("got %v, want the shared-MAC refusal", err)
		}
	}
	t.Run("the move's own handoff resumes", func(t *testing.T) {
		s := setup(t, journaled+1, "")
		if err := s.refuseStartOnSharedMAC(context.Background(), "moved"); err != nil {
			t.Fatalf("the genuine handoff, unmarked: %v", err)
		}
	})
	t.Run("an operator stop after the handoff", func(t *testing.T) {
		refused(t, context.Background(), setup(t, journaled+1, "operator-stop"))
	})
	t.Run("another drain's stop at the handoff's epoch", func(t *testing.T) {
		// A later drain m1 of this host stopped the VM and failed: the row
		// names m1's stop, at the epoch the open m0 handed over.
		refused(t, context.Background(), setup(t, journaled+1, health.DrainStopDetail("m1-other")))
	})
	t.Run("the open move's own stop intent", func(t *testing.T) {
		s := setup(t, journaled+1, "")
		moves, err := corrosion.ListDrainColdMoves(context.Background(), s.db, "src-host")
		if err != nil || len(moves) != 1 {
			t.Fatalf("the open move: %v %v", moves, err)
		}
		if err := s.db.Execute(context.Background(), `UPDATE vms SET state_detail = ? WHERE name = 'moved'`, health.DrainStopDetail(moves[0].OperationID)); err != nil {
			t.Fatal(err)
		}
		if err := s.refuseStartOnSharedMAC(context.Background(), "moved"); err != nil {
			t.Fatalf("the open move's own stop intent: %v", err)
		}
	})
	t.Run("a later placement", func(t *testing.T) {
		refused(t, context.Background(), setup(t, journaled+3, ""))
	})
	t.Run("not yet handed over", func(t *testing.T) {
		refused(t, context.Background(), setup(t, journaled, ""))
	})
	t.Run("a rejected marker does not fall back", func(t *testing.T) {
		s := setup(t, journaled+3, "")
		peer := peerCtxFor(t, s, "src-host")
		stale := metadata.NewIncomingContext(peer, metadata.Pairs(DrainResumeFromMDKey, "src-host",
			DrainResumeEpochMDKey, strconv.FormatInt(journaled+1, 10)))
		refused(t, stale, s)
	})
	t.Run("a rejected marker on the move's own handoff does not fall back", func(t *testing.T) {
		// The marker names another epoch than the row's: it is rejected,
		// and a rejected marker is not rescued by the journal.
		s := setup(t, journaled+1, "")
		peer := peerCtxFor(t, s, "src-host")
		wrong := metadata.NewIncomingContext(peer, metadata.Pairs(DrainResumeFromMDKey, "src-host",
			DrainResumeEpochMDKey, strconv.FormatInt(journaled+7, 10)))
		refused(t, wrong, s)
	})
}
