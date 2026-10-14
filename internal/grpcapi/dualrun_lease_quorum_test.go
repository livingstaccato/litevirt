package grpcapi

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// TestDualRunLease_NotTakenOrRenewedWithoutQuorum: a node that has lost every
// voter majority neither takes nor renews the dual-run detector's lease. A
// minority holder renewing it reaches a node bridging the halves, whose word
// that the lease is live refuses the majority's takeover and leaves the
// majority without dual-run coverage for the whole partition (lab 1,
// TestDrill1, 2026-10-14).
//
// Mutation: drop the LeaseQuorumLost check in acquireDualRunLease — the lease
// is taken, then renewed, with the quorum lost, and both checks go red.
func TestDualRunLease_NotTakenOrRenewedWithoutQuorum(t *testing.T) {
	ctx := context.Background()
	s := dualRunTestServerNoLease(t, 2)

	s.SetGate(fakeServerGate{execOK: true, quorum: health.QuorumNo, live: 1, needed: 2})
	if s.acquireDualRunLease(ctx, time.Minute) {
		t.Fatal("took the dual-run lease with the voter majority lost")
	}
	if h, _, err := corrosion.ReadLeaseRow(ctx, s.db, dualRunLeaseKey); err != nil || h != "" {
		t.Fatalf("a lease row names %q (%v) after a refused take", h, err)
	}

	s.SetGate(fakeServerGate{execOK: true, quorum: health.QuorumYes, live: 2, needed: 2})
	if !s.acquireDualRunLease(ctx, time.Minute) {
		t.Fatal("setup: could not take the free lease with the majority held")
	}
	_, first, err := corrosion.ReadLeaseRow(ctx, s.db, dualRunLeaseKey)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // expires_at has whole seconds
	s.SetGate(fakeServerGate{execOK: true, quorum: health.QuorumNo, live: 1, needed: 2})
	if s.acquireDualRunLease(ctx, time.Minute) {
		t.Fatal("renewed the dual-run lease with the voter majority lost")
	}
	if _, again, err := corrosion.ReadLeaseRow(ctx, s.db, dualRunLeaseKey); err != nil || again != first {
		t.Fatalf("the lease's expiry moved from %s to %s (%v) with the voter majority lost", first, again, err)
	}
}
