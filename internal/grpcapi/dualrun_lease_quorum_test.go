package grpcapi

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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
	var stalls []corrosion.LeaseNoMajority
	s.db.SetLeaseNoMajorityObserver(func(_ context.Context, ev corrosion.LeaseNoMajority) {
		if !ev.Live {
			stalls = append(stalls, ev)
		}
	})

	s.SetGate(fakeServerGate{execOK: true, quorum: health.QuorumNo, live: 1, needed: 2})
	if s.acquireDualRunLease(ctx, time.Minute) {
		t.Fatal("took the dual-run lease with the voter majority lost")
	}
	// Nobody holds it and this node cannot take it: a stalled takeover.
	if len(stalls) != 1 || stalls[0].Key != dualRunLeaseKey || stalls[0].TTL != 2*time.Minute {
		t.Fatalf("stand-downs reported %+v, want one for %s with its TTL", stalls, dualRunLeaseKey)
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
	// Its own lease is still live: a holder that cannot renew, not a takeover.
	if len(stalls) != 1 {
		t.Fatalf("a holder standing down over its own live lease was reported as a stalled takeover: %+v", stalls)
	}
}

// TestRunRebalance_RefusedWithoutQuorum: on a node that has lost the voter
// majority the rebalancer takes no lease, so RunRebalance says so instead of
// reporting zero proposals as if the cluster were balanced.
//
// Mutation: drop the LeaseQuorumLost check in RunRebalance — the call
// succeeds with no proposals and this goes red.
func TestRunRebalance_RefusedWithoutQuorum(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())
	seedAutoImbalance(t, ctx, s.db)
	s.SetGate(fakeServerGate{execOK: true, quorum: health.QuorumNo, live: 1, needed: 2})
	_, err := s.RunRebalance(ctx, &pb.RunRebalanceRequest{DryRun: true})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("RunRebalance without the voter majority: %v, want FailedPrecondition", err)
	}
}
