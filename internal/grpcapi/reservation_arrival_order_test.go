package grpcapi

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Arrival order is not id order. Ids are random, so the claimant with the
// LARGER id can arrive and win first; every claimant arriving after it must
// still count it, whatever its own id. These pin that through the real
// admission path, with ids chosen so the winner sorts after the newcomer.

// TestAdmit_AWinnerWithALargerIDHoldsAgainstASmallerOne: room for one. The
// first admission (a large id) wins and holds its lease; the second (a small
// id) arrives afterwards and must be refused. Under the earlier-only rule the
// second ignored the first as a "later racer" and was admitted too.
//
// Mutation: drop the admitted marker in decideReservation, or count only
// earlier ids in corrosion.reservationCounts — this goes red.
func TestAdmit_AWinnerWithALargerIDHoldsAgainstASmallerOne(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	admissionHost(t, s) // room for ONE 1024 MiB admission

	first, err := s.admitWithReservationID(ctx, "zzzzzzzz-arrives-first", "CreateVM", "test-host", "_default",
		"vm:first", 1, 1024, intentResourceGrow)
	if err != nil {
		t.Fatalf("first admission onto an empty host: %v", err)
	}
	defer first.release(ctx)

	second, err := s.admitWithReservationID(ctx, "00000000-arrives-second", "CreateVM", "test-host", "_default",
		"vm:second", 1, 1024, intentResourceGrow)
	if status.Code(err) != codes.ResourceExhausted {
		if second != nil {
			second.release(ctx)
		}
		t.Fatalf("second admission onto a host the first already filled: got %v, want ResourceExhausted — "+
			"an admitted claim must hold against a smaller id that arrives after it", err)
	}
}

// TestAdmit_NoAdmissionVerifiesBetweenAnotherVerifyAndItsMarker: room for
// one. The large-id claimant passes verify and, before it writes its admitted
// marker, a small-id claimant arrives. Unserialized, the newcomer sees the
// winner as a racer still deciding (no marker), ignores it, and is admitted —
// while the winner, which verified before the newcomer existed, never counted
// it. admissionMu makes the newcomer wait until the marker is written.
//
// Mutation: drop admissionMu from decideReservation — this goes red.
func TestAdmit_NoAdmissionVerifiesBetweenAnotherVerifyAndItsMarker(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	admissionHost(t, s)

	const winnerID = "zzzzzzzz-verifies-first"
	winnerVerified := make(chan struct{})
	newcomerDone := make(chan struct{})
	var once sync.Once
	s.admissionVerifiedHook = func(opID string) {
		if opID != winnerID {
			return
		}
		once.Do(func() {
			close(winnerVerified)
			// Hold the gap open: long enough for an unserialized newcomer to
			// finish, bounded so a serialized one (blocked on the lock) cannot
			// deadlock the test.
			select {
			case <-newcomerDone:
			case <-time.After(500 * time.Millisecond):
			}
		})
	}

	type result struct {
		lease *reservationLease
		err   error
	}
	winnerRes := make(chan result, 1)
	go func() {
		l, err := s.admitWithReservationID(context.WithoutCancel(ctx), winnerID, "CreateVM", "test-host", "_default",
			"vm:winner", 1, 1024, intentResourceGrow)
		winnerRes <- result{l, err}
	}()
	<-winnerVerified
	newcomer, nerr := s.admitWithReservationID(ctx, "00000000-arrives-in-the-gap", "CreateVM", "test-host", "_default",
		"vm:newcomer", 1, 1024, intentResourceGrow)
	close(newcomerDone)
	w := <-winnerRes

	admitted := 0
	for _, r := range []result{w, {newcomer, nerr}} {
		if r.err == nil {
			admitted++
			r.lease.release(ctx)
		} else if status.Code(r.err) != codes.ResourceExhausted {
			t.Fatalf("unexpected admission error: %v", r.err)
		}
	}
	if admitted != 1 {
		t.Fatalf("admitted %d onto a host with room for one (winner err=%v, newcomer err=%v)", admitted, w.err, nerr)
	}
	if w.err != nil {
		t.Fatalf("the claimant that verified first was refused: %v", w.err)
	}
}

// TestAdmit_TheAdmittedMarkerIsWritten pins the durable half directly: a lease
// that passed verify carries OpStepAdmitted, and one that failed does not
// exist as a live claim.
func TestAdmit_TheAdmittedMarkerIsWritten(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	admissionHost(t, s)
	lease, err := s.admitWithReservation(ctx, "CreateVM", "test-host", "_default", "vm:probe", 1, 1024,
		corrosion.QuotaAmount{VCPU: 1, MemMiB: 1024}, intentResourceGrow)
	if err != nil {
		t.Fatalf("admission: %v", err)
	}
	defer lease.release(ctx)
	steps, err := corrosion.ListOperationSteps(ctx, s.db, lease.id, 0)
	if err != nil {
		t.Fatal(err)
	}
	marked := false
	for _, st := range steps {
		if st.StepName == corrosion.OpStepAdmitted {
			marked = true
		}
	}
	if !marked {
		t.Fatalf("admitted lease %s carries no %q step: %+v", lease.id, corrosion.OpStepAdmitted, steps)
	}
	op, err := corrosion.GetOperation(ctx, s.db, lease.id)
	if err != nil || op == nil {
		t.Fatalf("GetOperation: %v", err)
	}
	rv, err := corrosion.DecodeReservation(op.ReservationJSON)
	if err != nil || !rv.Provisional {
		t.Fatalf("lease reservation %q is not provisional (err %v): a claim that never says it is "+
			"still deciding cannot keep the tie-break", op.ReservationJSON, err)
	}
}
