package grpcapi

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/health"
)

// TestStoreLeaseThreshold_RetainingDoesNotRenew is the cache's unbounded
// refusal.
//
// The clamp keeps a higher cached threshold over a lower fresh observation,
// which is right — a slow sweep finishing after a fast one must not walk the
// bound backwards. But it re-stamped the entry's timestamp while doing it, and
// every accept pays for a fresh sweep. So with requests arriving faster than
// the 3s TTL, each lower observation clamps up and resets the clock, and a
// threshold that legitimately dropped from 6 to 4 — the peer holding 6 became
// unreachable — refuses term-5 proofs forever rather than for the documented
// window. The expiry check then bounds nothing, because the entry can never
// reach it.
func TestStoreLeaseThreshold_RetainingDoesNotRenew(t *testing.T) {
	s := testServer(t)
	const key = "failover"

	s.storeLeaseThreshold(key, 6)

	s.leaseBarrierMu.Lock()
	first := s.leaseBarrierCache[key].at
	s.leaseBarrierMu.Unlock()

	// The reporter of 6 is gone; every later sweep sees 4, arriving well inside
	// the TTL — the traffic pattern the barrier's own cache asymmetry creates.
	for range 5 {
		time.Sleep(2 * time.Millisecond)
		s.storeLeaseThreshold(key, 4)
	}

	s.leaseBarrierMu.Lock()
	e := s.leaseBarrierCache[key]
	s.leaseBarrierMu.Unlock()

	if e.threshold != 6 {
		t.Fatalf("threshold = %d, want the retained 6 inside the TTL", e.threshold)
	}
	if !e.at.Equal(first) {
		t.Fatalf("retaining 6 over repeated observations of 4 re-stamped the entry "+
			"(%v -> %v); the TTL can never elapse while traffic continues, so the "+
			"refusal of term-5 proofs becomes permanent", first, e.at)
	}
}

// And once the TTL genuinely elapses the lower observation must win, or the
// retention would be permanent for a different reason.
func TestStoreLeaseThreshold_LowerWinsAfterTheTTL(t *testing.T) {
	s := testServer(t)
	const key = "failover"

	s.storeLeaseThreshold(key, 6)

	// Age the entry past the TTL without sleeping for it.
	s.leaseBarrierMu.Lock()
	e := s.leaseBarrierCache[key]
	e.at = time.Now().Add(-2 * leaseBarrierCacheTTL)
	s.leaseBarrierCache[key] = e
	s.leaseBarrierMu.Unlock()

	s.storeLeaseThreshold(key, 4)

	s.leaseBarrierMu.Lock()
	got := s.leaseBarrierCache[key].threshold
	s.leaseBarrierMu.Unlock()
	if got != 4 {
		t.Fatalf("threshold = %d after the TTL elapsed, want the fresh 4; an expired "+
			"entry that still clamps is a permanent refusal", got)
	}
}

// TestRunLeaseTermSweep_RepairCannotLowerAnObservedTerm is the repair round
// discarding evidence.
//
// The repair exists to undo this node's own short-deadlining of a silent peer,
// so it asks strictly more peers and its answer COUNT and coverage rightly
// replace the first pass's. Its high-water must not: a term this node has
// already seen cannot be un-seen because a later round failed to reach the
// peer holding it.
//
// The first sweep observes term 9 from one peer. During the repair that peer
// becomes unreachable and a quorum answers 4. Returning 4 admits a term-5
// proof this node directly observed to be superseded — the exact admission the
// barrier exists to refuse.
func TestRunLeaseTermSweep_RepairCannotLowerAnObservedTerm(t *testing.T) {
	s := testServer(t)
	s.SetGate(fakeServerGate{
		execOK:  true,
		quorum:  health.QuorumYes,
		needed:  2,
		healthy: []string{"peer-a", "peer-b"},
	})

	// peer-a is memoised as silent, so the sweep short-deadlines it and the
	// repair round fires.
	s.noteSilentPeers([]string{"peer-a"}, map[string]bool{})

	round := 0
	fanOutFn = func(_ context.Context, _ string, local int64, peers []string, _ map[string]bool) (int64, int, map[string]bool) {
		round++
		if round == 1 {
			// peer-b is reachable and holds the superseding term.
			return 9, 2, map[string]bool{"peer-b": true}
		}
		// The holder of 9 is gone; the rest agree on a lower term.
		return 4, 2, map[string]bool{"peer-a": true}
	}
	t.Cleanup(func() { fanOutFn = nil })

	got, ok := s.runLeaseTermSweep(context.Background(), "failover")
	if !ok {
		t.Fatal("fixture inert: the sweep refused rather than returning a threshold")
	}
	if round < 2 {
		t.Fatalf("fixture inert: the repair round never fired (rounds=%d)", round)
	}
	if got != 9 {
		t.Fatalf("sweep returned %d after directly observing term 9; a term once seen "+
			"cannot be un-seen by a later round that could not reach the peer holding it, "+
			"and returning %d admits a term-5 proof known to be superseded", got, got)
	}
}
