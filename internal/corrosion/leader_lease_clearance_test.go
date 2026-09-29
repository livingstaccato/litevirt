package corrosion

import (
	"context"
	"testing"
	"time"
)

// clearanceProbe is a LeaseMintClearanceFunc that records what it was asked
// and answers `allow`.
type clearanceProbe struct {
	allow bool
	asked []int64
}

func (p *clearanceProbe) fn(_ context.Context, _ string, next int64) (bool, string) {
	p.asked = append(p.asked, next)
	if p.allow {
		return true, ""
	}
	return false, "test: a peer already holds this term"
}

// A withheld mint records nothing and reports "not held" — the shape of a lost
// race, which every caller already handles by retrying next poll.
func TestLeaseMintClearance_WithheldMintRecordsNoTerm(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	p := &clearanceProbe{allow: false}
	c.SetLeaseMintClearance(p.fn)

	held, term, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second, leaseTestNow)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if held || term != 0 {
		t.Fatalf("held=%v term=%d with the mint withheld; want not held, no term", held, term)
	}
	if len(p.asked) != 1 || p.asked[0] != 1 {
		t.Fatalf("clearance asked about %v, want exactly [1]: one question per call, about the term "+
			"it would mint", p.asked)
	}
	if n := termRowCount(t, c, "failover"); n != 0 {
		t.Fatalf("%d term rows after a withheld mint, want 0", n)
	}
	if holder, _, _ := leaseRow(ctx, c, "failover"); holder != "" {
		t.Fatalf("lease row names %q after a withheld mint; the lease and its term are taken together or not at all", holder)
	}

	p.allow = true
	if held, term, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second, leaseTestNow); err != nil || !held || term != 1 {
		t.Fatalf("once cleared: held=%v term=%d err=%v, want term 1", held, term, err)
	}
}

// A renewal mints nothing, so it asks nothing: a holder keeps its lease
// through a partition exactly as before.
func TestLeaseMintClearance_RenewalDoesNotAsk(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	p := &clearanceProbe{allow: true}
	c.SetLeaseMintClearance(p.fn)

	if held, _, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second, leaseTestNow); err != nil || !held {
		t.Fatalf("acquire: held=%v err=%v", held, err)
	}
	p.allow = false // a renewal must succeed even when a mint would be withheld
	p.asked = nil
	held, term, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second, leaseTestNow.Add(5*time.Second))
	if err != nil || !held || term != 1 {
		t.Fatalf("renewal: held=%v term=%d err=%v, want term 1", held, term, err)
	}
	if len(p.asked) != 0 {
		t.Fatalf("a renewal asked the mint clearance about %v", p.asked)
	}
}

// A non-holder polling a peer's LIVE lease never reaches the mint, so it must
// not pay for the clearance's peer read on every poll.
func TestLeaseMintClearance_LivePeerLeaseDoesNotAsk(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	seedLease(t, c, "failover", "host-b", leaseTestNow.Add(30*time.Second))
	p := &clearanceProbe{allow: true}
	c.SetLeaseMintClearance(p.fn)

	held, _, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second, leaseTestNow)
	if err != nil || held {
		t.Fatalf("held=%v err=%v against a peer's live lease, want not held", held, err)
	}
	if len(p.asked) != 0 {
		t.Fatalf("polling a peer's live lease asked the mint clearance about %v", p.asked)
	}
}
