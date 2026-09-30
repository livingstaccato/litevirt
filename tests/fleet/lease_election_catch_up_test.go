// Fleet scenarios for a node whose term ledger is current but whose
// leader_election row is not.
//
// The mint clearance (lease_claim_catch_up_test.go) stops a node minting a term
// the cluster has already minted. It says nothing about whether the lease the
// ledger's newest term names is still LIVE, and that is read from the node's
// own leader_election row alone. The two tables do not travel together:
// renewals touch only leader_election, and leader_election is anti-entropy
// excluded, so a replica can hold every term row and still carry the holder's
// expiry from several renewals ago — or no row at all, on a node that got its
// ledger by anti-entropy or a reseed. Such a node reads a live holder's lease as
// lapsed, mints the next term above it (which the clearance passes: no peer has
// that term) and deposes it. The holder learns of the new term, fails closed on
// its next renewal, and a lease that was never free has changed hands, with both
// nodes believing they lead until the term row arrives.
package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

func expiresAt(t time.Time) string { return t.Add(catchUpTTL).UTC().Format(time.RFC3339) }

// waitLeaseRow waits until n's own leader_election row names holder with the
// given expiry.
func waitLeaseRow(t *testing.T, n *Node, holder, expires string) {
	t.Helper()
	eventually(t, convergeTimeout, n.Name+" lease row "+holder+"@"+expires, func() bool {
		h, e, err := leaseRowFor(t, n)
		return err == nil && h == holder && e == expires
	})
}

// assertOnlyLeader checks, on every node's own replica, that the node reports
// itself leader exactly when it is want.
func assertOnlyLeader(t *testing.T, c *Cluster, want *Node, at time.Time) {
	t.Helper()
	for _, n := range c.Nodes {
		is, err := corrosion.IsLeaseHolder(context.Background(), n.DB, leaseTermKey, n.Name, at)
		if err != nil {
			t.Fatalf("%s IsLeaseHolder: %v", n.Name, err)
		}
		if is != (n == want) {
			t.Errorf("%s believes it leads = %v; want only %s to", n.Name, is, want.Name)
		}
	}
}

// TestFleet_LeaseClaim_AStaleElectionRowDoesNotDeposeALiveHolder:
//
//  1. a holds the lease at term 1; every replica has the term row and a's row;
//  2. pushes into b are held back, and a renews — the renewal reaches the third
//     node but not b, so b's row still carries a's first expiry;
//  3. past that expiry, but well inside a's real one, b polls. Its ledger is
//     current (term 1, a's), so the term clearance has nothing to refuse.
//
// b must not take the lease: a is live, and says so when asked.
func TestFleet_LeaseClaim_AStaleElectionRowDoesNotDeposeALiveHolder(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 11})
	a, b, other := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	gates := runCheckers(t, c)
	wireMintClearance(c)

	// 1.
	t0 := time.Now().UTC()
	if held, term := acquireAt(t, a, t0); !held || term != 1 {
		t.Fatalf("%s: held=%v term=%d, want term 1", a.Name, held, term)
	}
	c.WaitConverged(t, convergeTimeout)
	waitLeaseRow(t, b, a.Name, expiresAt(t0))

	// 2. Nothing more reaches b. a renews.
	c.SetLinkFault(a, b, LinkFault{Block: true})
	c.SetLinkFault(other, b, LinkFault{Block: true})
	renewed := t0.Add(30 * time.Second)
	if held, term := acquireAt(t, a, renewed); !held || term != 1 {
		t.Fatalf("%s renewal: held=%v term=%d, want term 1", a.Name, held, term)
	}
	waitLeaseRow(t, other, a.Name, expiresAt(renewed))

	// Preconditions: b's ledger is current, its election row is not.
	if newest, err := corrosion.CurrentLeaseTerm(ctx, b.DB, leaseTermKey); err != nil || newest != 1 {
		t.Fatalf("precondition: %s's ledger must be at term 1 (got %d, %v)", b.Name, newest, err)
	}
	if h, e, err := leaseRowFor(t, b); err != nil || h != a.Name || e != expiresAt(t0) {
		t.Fatalf("precondition: %s's row must still carry %s's first expiry (got %q %q %v)", b.Name, a.Name, h, e, err)
	}

	// 3. b polls after its stale expiry, before a's real one.
	poll := t0.Add(catchUpTTL + catchUpPoll)
	if held, term := acquireAt(t, b, poll); held {
		t.Fatalf("%s took the lease at term %d from a stale leader_election row while %s's "+
			"lease was live until %s", b.Name, term, a.Name, expiresAt(renewed))
	}
	if st, live, need := gates[b.Name].QuorumProof(ctx); st != health.QuorumYes {
		t.Fatalf("%s lost quorum (%v, %d/%d) — the refusal above proves nothing", b.Name, st, live, need)
	}
	if newest, err := corrosion.CurrentLeaseTerm(ctx, b.DB, leaseTermKey); err != nil || newest != 1 {
		t.Fatalf("%s's ledger is at term %d (%v) after the poll; want no new term minted", b.Name, newest, err)
	}
	assertOnlyLeader(t, c, a, poll)

	// Heal. a keeps its tenure at term 1; b defers.
	c.ClearLinkFaults()
	c.WaitConverged(t, convergeTimeout)
	next := poll.Add(catchUpPoll)
	if held, term := acquireAt(t, a, next); !held || term != 1 {
		t.Fatalf("%s: held=%v term=%d after the heal; a live holder's tenure must not move", a.Name, held, term)
	}
	if held, term := acquireAt(t, b, next); held {
		t.Fatalf("%s took the lease (term %d) from a live holder", b.Name, term)
	}
	waitLeaseRow(t, b, a.Name, expiresAt(next))
	assertOnlyLeader(t, c, a, next)
}

// TestFleet_LeaseClaim_AMissingElectionRowDoesNotDeposeALiveHolder is the same
// hazard with no row at all: a node that has the term ledger (anti-entropy and
// a reseed carry it; neither carries leader_election) but has not yet received
// a single renewal reads the lease as free.
func TestFleet_LeaseClaim_AMissingElectionRowDoesNotDeposeALiveHolder(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 12})
	a, b := c.Nodes[0], c.Nodes[1]
	runCheckers(t, c)
	wireMintClearance(c)

	t0 := time.Now().UTC()
	if held, term := acquireAt(t, a, t0); !held || term != 1 {
		t.Fatalf("%s: held=%v term=%d, want term 1", a.Name, held, term)
	}
	c.WaitConverged(t, convergeTimeout)
	waitLeaseRow(t, b, a.Name, expiresAt(t0))
	// Local-only: b's replica loses the row without anything replicating.
	if _, err := b.DB.DB().ExecContext(ctx, `DELETE FROM leader_election WHERE key = ?`, leaseTermKey); err != nil {
		t.Fatalf("drop %s's row: %v", b.Name, err)
	}

	poll := t0.Add(catchUpPoll)
	if held, term := acquireAt(t, b, poll); held {
		t.Fatalf("%s took the lease at term %d with no leader_election row while %s's lease "+
			"was live until %s", b.Name, term, a.Name, expiresAt(t0))
	}
	if newest, err := corrosion.CurrentLeaseTerm(ctx, b.DB, leaseTermKey); err != nil || newest != 1 {
		t.Fatalf("%s's ledger is at term %d (%v); want no new term minted", b.Name, newest, err)
	}
	if held, term := acquireAt(t, a, poll); !held || term != 1 {
		t.Fatalf("%s: held=%v term=%d; a live holder's tenure must not move", a.Name, held, term)
	}
	c.WaitConverged(t, convergeTimeout)
	assertOnlyLeader(t, c, a, poll)
}

// TestFleet_LeaseClaim_ADeadHolderIsTakenOverOnceEveryReportedExpiryPasses
// bounds the cost: the check withholds a takeover only while some peer reports
// the lease live. When the holder is dead, the node takes over as soon as the
// newest expiry any peer reported has passed — one TTL after the holder's last
// renewal that reached anyone, as an ordinary expiry would.
func TestFleet_LeaseClaim_ADeadHolderIsTakenOverOnceEveryReportedExpiryPasses(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 13})
	a, b, other := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	runCheckers(t, c)
	wireMintClearance(c)

	t0 := time.Now().UTC()
	if held, term := acquireAt(t, a, t0); !held || term != 1 {
		t.Fatalf("%s: held=%v term=%d, want term 1", a.Name, held, term)
	}
	c.WaitConverged(t, convergeTimeout)
	waitLeaseRow(t, b, a.Name, expiresAt(t0))

	c.SetLinkFault(a, b, LinkFault{Block: true})
	c.SetLinkFault(other, b, LinkFault{Block: true})
	renewed := t0.Add(30 * time.Second)
	if held, _ := acquireAt(t, a, renewed); !held {
		t.Fatalf("%s renewal refused", a.Name)
	}
	waitLeaseRow(t, other, a.Name, expiresAt(renewed))
	// a dies. The third node still reports its last renewal.
	c.Kill(a)

	early := t0.Add(catchUpTTL + catchUpPoll)
	if held, term := acquireAt(t, b, early); held {
		t.Fatalf("%s took the lease at term %d while %s reported it live until %s",
			b.Name, term, other.Name, expiresAt(renewed))
	}
	ok, why := b.Server.LeaseMintClearance(context.Background(), termMint(b, 2, early))
	if ok || !strings.Contains(why, a.Name) {
		t.Fatalf("%s's clearance: ok=%v reason=%q; want it withheld on %s's reported live lease", b.Name, ok, why, a.Name)
	}

	late := renewed.Add(catchUpTTL + catchUpPoll)
	if held, term := acquireAt(t, b, late); !held || term != 2 {
		t.Fatalf("%s: held=%v term=%d once every reported expiry has passed; want a takeover at term 2",
			b.Name, held, term)
	}
}
