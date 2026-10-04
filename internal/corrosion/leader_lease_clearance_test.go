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
	reqs  []LeaseMintRequest
}

func (p *clearanceProbe) fn(_ context.Context, req LeaseMintRequest) (bool, string) {
	p.asked = append(p.asked, req.Term)
	p.reqs = append(p.reqs, req)
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

// The clearance is told whether a mint is a TAKEOVER — this replica shows no
// live tenure of ours — because only a takeover must also confirm that no peer
// sees the lease live. A mint over our own live lease (retiring a contested
// term) must say false: the contest loser's own row names it live, and holding
// the winner's retirement to it would stall the convergence.
func TestLeaseMintClearance_TellsATakeoverFromAMintOverOurOwnLease(t *testing.T) {
	ctx := context.Background()

	t.Run("a free lease is a takeover", func(t *testing.T) {
		c := testClient(t)
		p := &clearanceProbe{allow: true}
		c.SetLeaseMintClearance(p.fn)
		if held, _, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second, leaseTestNow); err != nil || !held {
			t.Fatalf("acquire: held=%v err=%v", held, err)
		}
		want := LeaseMintRequest{Key: "failover", Term: 1, Holder: "host-a", Takeover: true,
			Now: leaseTestNow.Format(time.RFC3339)}
		if len(p.reqs) != 1 || p.reqs[0] != want {
			t.Fatalf("clearance asked %+v, want exactly [%+v]", p.reqs, want)
		}
	})

	t.Run("an expired peer lease is a takeover", func(t *testing.T) {
		c := testClient(t)
		seedLease(t, c, "failover", "host-b", leaseTestNow.Add(-time.Second))
		p := &clearanceProbe{allow: true}
		c.SetLeaseMintClearance(p.fn)
		if held, _, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second, leaseTestNow); err != nil || !held {
			t.Fatalf("acquire: held=%v err=%v", held, err)
		}
		if len(p.reqs) != 1 || !p.reqs[0].Takeover {
			t.Fatalf("clearance asked %+v, want one takeover", p.reqs)
		}
	})

	t.Run("retiring our own contested term is not", func(t *testing.T) {
		c := testClient(t)
		p := &clearanceProbe{allow: true}
		c.SetLeaseMintClearance(p.fn)
		if held, term, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second, leaseTestNow); err != nil || !held || term != 1 {
			t.Fatalf("acquire: held=%v term=%d err=%v", held, term, err)
		}
		c.noteLeaseTermClaims("failover", 1, "host-a", "host-z") // host-a continues
		p.reqs = nil
		held, term, err := AcquireLeaseWithTerm(ctx, c, "failover", "host-a", 30*time.Second, leaseTestNow.Add(5*time.Second))
		if err != nil || !held || term != 2 {
			t.Fatalf("retire: held=%v term=%d err=%v, want term 2", held, term, err)
		}
		if len(p.reqs) != 1 || p.reqs[0].Takeover || p.reqs[0].Term != 2 {
			t.Fatalf("clearance asked %+v, want one non-takeover mint of term 2", p.reqs)
		}
	})
}
