package corrosion

import (
	"context"
	"testing"
	"time"
)

// TestAcquireLeaseWithTerm_LapseDuringTheCallIsANewTenure is the stale-clock
// hole in the tenure classification.
//
// nowRFC and expires were computed ONCE at function entry and then compared
// against on every loop iteration. A holder that enters renewal before its
// expiry and then stalls past the TTL -- a GC pause, an IO stall, a slow DB --
// resumes and still compares curExpires against the PRE-PAUSE instant. Its own
// expired lease therefore reads as live, the call is classified as a renewal,
// and it returns the OLD term while writing an expiry that may already be in
// the past.
//
// That is the exact case AcquireLeaseWithTerm's own doc says must mint a new
// tenure: "a lease that fully lapsed and was re-taken -- even by its own prior
// holder -- is a NEW tenure, because the lapse is exactly the window in which
// other nodes were entitled to act." Work from before the lapse was
// indistinguishable from work after it.
func TestAcquireLeaseWithTerm_LapseDuringTheCallIsANewTenure(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	// Seconds, not milliseconds: leader_election expiries are RFC3339, which
	// has one-second resolution, so a sub-second lapse is not representable in
	// the stored value at all.
	const ttl = time.Second

	held, first, err := AcquireLeaseWithTerm(ctx, db, LeaseKeyFailover, "h1", ttl, time.Now())
	if err != nil || !held || first <= 0 {
		t.Fatalf("setup: held=%v term=%d err=%v; want a held lease with a term", held, first, err)
	}

	// The stall: the classification happens, then this caller sleeps past its
	// own TTL before the renewal commits.
	renewClassifiedHook = func() { time.Sleep(ttl + 1200*time.Millisecond) }
	t.Cleanup(func() { renewClassifiedHook = nil })

	held, second, err := AcquireLeaseWithTerm(ctx, db, LeaseKeyFailover, "h1", ttl, time.Now())
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if held && second == first {
		t.Fatalf("a lease that lapsed during the call was renewed at its old term %d; "+
			"the lapse is the window in which other nodes were entitled to act, so work "+
			"from before it must not carry the same term as work after it", first)
	}
}

// The ordinary renewal path must keep its term — a fix that minted on every
// renewal would make a holder invalidate its own in-flight work every interval.
func TestAcquireLeaseWithTerm_PromptRenewalKeepsItsTerm(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)

	held, first, err := AcquireLeaseWithTerm(ctx, db, LeaseKeyFailover, "h1", time.Minute, time.Now())
	if err != nil || !held || first <= 0 {
		t.Fatalf("setup: held=%v term=%d err=%v", held, first, err)
	}
	held, second, err := AcquireLeaseWithTerm(ctx, db, LeaseKeyFailover, "h1", time.Minute, time.Now())
	if err != nil || !held {
		t.Fatalf("prompt renewal: held=%v err=%v", held, err)
	}
	if second != first {
		t.Fatalf("a prompt renewal bumped the term %d -> %d; the holder would invalidate "+
			"its own in-flight work every renewal interval", first, second)
	}
}

// TestReopenedMintGateDoesNotReuseAnEarlierTenuresTerm is the term-reuse hole
// on the gate-closed path.
//
// A node can mint term N, lose its activation marker so MayMintLeaseTerm goes
// false, let the lease LAPSE, and re-take it termlessly. Its leader_election
// row now describes a new incarnation while leader_lease_terms still records
// term N against the same holder. When the gate reopens with that new lease
// live, the classification reads "same tenure, term already recorded: renew,
// mint nothing" — holder identity matches — and hands back term N.
//
// Proofs from before the lapse then carry the same term as work after it, and
// the lapse is exactly the window in which other nodes were entitled to act.
// Holder identity does not prove an uninterrupted tenure; that is the rule the
// expiry check enforces one branch above, and it has to hold here too.
func TestReopenedMintGateDoesNotReuseAnEarlierTenuresTerm(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)

	held, first, err := AcquireLeaseWithTerm(ctx, db, LeaseKeyFailover, "h1", time.Second, time.Now())
	if err != nil || !held || first <= 0 {
		t.Fatalf("setup: held=%v term=%d err=%v", held, first, err)
	}

	// The marker is lost: this node can no longer mint.
	db.SetLeaseTermLedgerGate(func() bool { return false })

	// The lease LAPSES and is re-taken termlessly — a new incarnation.
	lapsed := time.Now().Add(5 * time.Second)
	held, term, err := AcquireLeaseWithTerm(ctx, db, LeaseKeyFailover, "h1", time.Second, lapsed)
	if err != nil || !held {
		t.Fatalf("termless re-take: held=%v err=%v", held, err)
	}
	if term != 0 {
		t.Fatalf("a gate-closed acquisition reported term %d, want 0", term)
	}

	// The marker comes back while that new lease is still live.
	db.SetLeaseTermLedgerGate(func() bool { return true })

	held, reopened, err := AcquireLeaseWithTerm(ctx, db, LeaseKeyFailover, "h1", time.Minute, lapsed)
	if err != nil || !held {
		t.Fatalf("gate reopened: held=%v err=%v", held, err)
	}
	if reopened == first {
		t.Fatalf("the reopened gate handed back term %d from the tenure that ended at the "+
			"lapse; work from before it is now indistinguishable from work after it", first)
	}
}
