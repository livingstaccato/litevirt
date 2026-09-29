// Fleet scenarios for a node that claims a lease term from a STALE ledger.
//
// Observed on the 5-node lab (build beda4047), key dual_run_detector: node-5
// held term 4 and was stopped; node-3 took term 5 two minutes later. When
// node-5 came back its replica still said "term 4, mine, expired", so five
// seconds after start — before node-3's term-5 row had reached it — it minted
// its OWN term 5. Two rows for one (key, term) are an immutable-ledger
// conflict that never heals: lww_unresolved on every host, stuck_different in
// `lv doctor divergence`, and an operator has to run
// `lv cluster acknowledge-lease-term`.
//
// A restart is only one way in. A node that is cut off and later reconnected
// holds exactly the same stale view, with no restart at all, which is why the
// scenario here reconnects rather than restarts: the gate has to hold for both.
package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// wireMintClearance gives every node the mint clearance the daemon wires: the
// quorum high-water check a node runs before it records a new term.
func wireMintClearance(c *Cluster) {
	for _, n := range c.Nodes {
		n.DB.SetLeaseMintClearance(n.Server.LeaseMintClearance)
	}
}

// runCheckers starts every node's real health checker, waits for each to hold
// quorum, and — unlike startCheckers — leaves them probing until the test ends.
//
// The clearance reads QuorumProof on every mint, and a checker whose loop has
// stopped reads its own silence as a process stall after one check interval
// (health/stall.go) and stops counting its peers. A scenario that stepped past
// that would see every mint withheld for "no quorum", and its assertion that a
// stale node does not mint would pass for the wrong reason.
func runCheckers(t *testing.T, c *Cluster) map[string]*health.Checker {
	t.Helper()
	gates := gateAll(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	for _, n := range c.Nodes {
		go gates[n.Name].Start(ctx)
	}
	for _, n := range c.Nodes {
		node := n
		eventually(t, 20*time.Second, "quorum on "+node.Name, func() bool {
			state, _, _ := gates[node.Name].QuorumProof(context.Background())
			return state == health.QuorumYes
		})
	}
	return gates
}

// catchUpTTL and catchUpPoll are the failover coordinator's lease duration and
// poll interval; the scenario steps virtual time the way the coordinator does.
const (
	catchUpTTL  = 45 * time.Second
	catchUpPoll = 5 * time.Second
)

func acquireAt(t *testing.T, n *Node, at time.Time) (bool, int64) {
	t.Helper()
	held, term, err := corrosion.AcquireLeaseWithTerm(context.Background(), n.DB, leaseTermKey, n.Name, catchUpTTL, at)
	if err != nil {
		t.Fatalf("%s acquire at %s: %v", n.Name, at.Format(time.RFC3339), err)
	}
	return held, term
}

// TestFleet_LeaseClaim_AReconnectedNodeDoesNotReclaimFromAStaleLedger is the
// lab's sequence on three independent replicas:
//
//  1. a holds the lease at term 1, and every replica has that row;
//  2. a is cut off;
//  3. b takes the lease over at term 2 once a's has expired;
//  4. a reconnects with b's row NOT yet delivered — a can reach its peers, but
//     nothing has been pushed into it;
//  5. a's next poll must NOT record term 2.
//
// Before the fix a classified its own expired row as a lapse-and-retake,
// allocated MAX(term)+1 = 2 from its own replica, and committed it: two
// claimants for term 2, forever.
func TestFleet_LeaseClaim_AReconnectedNodeDoesNotReclaimFromAStaleLedger(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 1})
	a, b, other := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	gates := runCheckers(t, c)
	wireMintClearance(c)

	// 1. a holds term 1, everywhere.
	t0 := time.Now().UTC()
	if held, term := acquireAt(t, a, t0); !held || term != 1 {
		t.Fatalf("%s: held=%v term=%d, want the first tenure at term 1", a.Name, held, term)
	}
	c.WaitConverged(t, convergeTimeout)

	// 2. a is cut off — its daemon stopped, as far as anyone can tell.
	c.Isolate(a)

	// 3. b takes over once a's lease has expired. a is unreachable, so b's
	// quorum read collects b and the third node: a quorum of three.
	takeover := t0.Add(catchUpTTL + catchUpPoll)
	start := time.Now()
	held, term := acquireAt(t, b, takeover)
	takeoverCost := time.Since(start)
	if !held || term != 2 {
		t.Fatalf("%s: held=%v term=%d at the takeover; a survivor must take a dead holder's "+
			"expired lease at the next term", b.Name, held, term)
	}
	c.WaitConverged(t, convergeTimeout, b, other)

	// 4. a comes back. Its outbound links heal — it can dial its peers and ask
	// them — but nothing is pushed INTO it yet, so its replica still says
	// "term 1, mine, expired".
	for _, p := range []*Node{b, other} {
		c.SetLinkFault(a, p, LinkFault{})
	}
	if newest, err := corrosion.CurrentLeaseTerm(ctx, a.DB, leaseTermKey); err != nil || newest != 1 {
		t.Fatalf("precondition: %s's replica must still be at term 1 (got %d, %v)", a.Name, newest, err)
	}

	// 5. a polls from its stale view.
	if held, term := acquireAt(t, a, takeover); held {
		t.Fatalf("%s took the lease at term %d from a replica that had not seen %s's term 2", a.Name, term, b.Name)
	}
	// Withheld for the RIGHT reason: a holds quorum, and its peers told it term
	// 2 is taken. A refusal for want of quorum would make this scenario pass
	// without the high-water check doing anything.
	if st, live, need := gates[a.Name].QuorumProof(ctx); st != health.QuorumYes {
		t.Fatalf("%s lost quorum (%v, %d/%d) — the refusal above proves nothing", a.Name, st, live, need)
	}
	if ok, why := a.Server.LeaseMintClearance(ctx, leaseTermKey, 2); ok || !strings.Contains(why, "term 2") {
		t.Fatalf("%s's clearance for term 2: ok=%v reason=%q; want it withheld because a peer "+
			"has already recorded term 2", a.Name, ok, why)
	}
	if h, found := leaseTermHolderAt(t, a, 2); found && h == a.Name {
		t.Fatalf("%s recorded its OWN term 2 while %s already held term 2. That is the lab's "+
			"permanent immutable-ledger conflict: a term must not be minted until this node "+
			"has confirmed the quorum high-water mark for the key", a.Name, b.Name)
	}

	// Heal. The ledger converges to ONE claimant of term 2 on every replica,
	// and a — whose replica now knows — defers to b's live tenure.
	healed := time.Now()
	c.ClearLinkFaults()
	c.WaitConverged(t, convergeTimeout)
	catchUp := time.Since(healed)
	for _, n := range c.Nodes {
		h, found := leaseTermHolderAt(t, n, 2)
		if !found || h != b.Name {
			t.Errorf("%s: term 2 holder = %q (found=%v), want %s", n.Name, h, found, b.Name)
		}
	}
	if held, term := acquireAt(t, b, takeover.Add(catchUpPoll)); !held || term != 2 {
		t.Errorf("%s: held=%v term=%d after the heal, want its uninterrupted term 2", b.Name, held, term)
	}
	if held, term := acquireAt(t, a, takeover.Add(catchUpPoll)); held {
		t.Errorf("%s took the lease (term %d) from a live holder after catching up", a.Name, term)
	}
	t.Logf("takeover mint incl. quorum high-water read: %s; reconnected node caught up %s after the heal",
		takeoverCost, catchUp)
}

// TestFleet_LeaseClaim_ACatchingUpNodeTakesOverOnceItHasTheRow bounds the
// cost: the gate WITHHOLDS a mint, it does not strand the lease. When the
// holder really is dead, the reconnected node takes over as soon as its replica
// has the row it was missing — at the next term, above it.
func TestFleet_LeaseClaim_ACatchingUpNodeTakesOverOnceItHasTheRow(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2})
	a, b, other := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	runCheckers(t, c)
	wireMintClearance(c)

	t0 := time.Now().UTC()
	if held, term := acquireAt(t, a, t0); !held || term != 1 {
		t.Fatalf("%s: held=%v term=%d, want term 1", a.Name, held, term)
	}
	c.WaitConverged(t, convergeTimeout)
	c.Isolate(a)
	takeover := t0.Add(catchUpTTL + catchUpPoll)
	if held, term := acquireAt(t, b, takeover); !held || term != 2 {
		t.Fatalf("%s: held=%v term=%d, want term 2", b.Name, held, term)
	}
	c.WaitConverged(t, convergeTimeout, b, other)

	// b dies before a comes back; the third node is how a catches up. a can
	// ask it first; its pushes into a resume a moment later.
	c.Isolate(b)
	c.SetLinkFault(a, other, LinkFault{})

	// Not yet delivered: a asks, sees term 2, and waits.
	if held, term := acquireAt(t, a, takeover); held {
		t.Fatalf("%s minted term %d before its replica had the term-2 row", a.Name, term)
	}
	if ok, why := a.Server.LeaseMintClearance(context.Background(), leaseTermKey, 2); ok || !strings.Contains(why, "term 2") {
		t.Fatalf("%s's clearance for term 2: ok=%v reason=%q; want it withheld on the peer's term 2",
			a.Name, ok, why)
	}

	// Once the row has arrived, and b's lease has expired, a takes over at 3.
	c.SetLinkFault(other, a, LinkFault{})
	start := time.Now()
	eventually(t, convergeTimeout, a.Name+" receives term 2", func() bool {
		newest, err := corrosion.CurrentLeaseTerm(context.Background(), a.DB, leaseTermKey)
		return err == nil && newest == 2
	})
	delivered := time.Since(start)
	later := takeover.Add(2*catchUpTTL + catchUpPoll)
	held, term := acquireAt(t, a, later)
	if !held || term != 3 {
		t.Fatalf("%s: held=%v term=%d once caught up and %s's lease expired; want a takeover "+
			"at term 3", a.Name, held, term, b.Name)
	}
	t.Logf("term-2 row reached the reconnected node %s after its links healed", delivered)
}

// TestFleet_LeaseClaim_AClusterOfOneMintsWithoutAsking pins the case the gate
// must NOT block: a node with nobody to ask — a single-node cluster, or the
// first node of a new one — has no peer that could hold a higher term. Its
// checker has JUST started, as it has on a daemon's first poll, so quorum is
// still in the startup warm-up (Unknown until the first probe cycle) and a
// quorum read would refuse. It mints at once.
func TestFleet_LeaseClaim_AClusterOfOneMintsWithoutAsking(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	solo := c.Nodes[0]
	gates := gateAll(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go gates[solo.Name].Start(ctx)
	wireMintClearance(c)

	eventually(t, 5*time.Second, "checker warm-up begins", func() bool {
		st, _, _ := gates[solo.Name].QuorumProof(context.Background())
		return st == health.QuorumUnknown
	})

	if held, term := acquireAt(t, solo, time.Now().UTC()); !held || term != 1 {
		t.Fatalf("a cluster of one: held=%v term=%d, want term 1 at once", held, term)
	}
}

// TestFleet_LeaseClaim_ANodeWithoutQuorumWaitsForIt defines the other side: a
// node that HAS peers but can reach none of them cannot confirm that no peer
// already holds the next term, so it does not mint one — and mints as soon as a
// quorum answers. Nothing a lease authorises (a fence, a reschedule) is
// permitted without quorum anyway, so withholding the term costs no action.
func TestFleet_LeaseClaim_ANodeWithoutQuorumWaitsForIt(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 3})
	a := c.Nodes[0]
	runCheckers(t, c)
	wireMintClearance(c)

	c.Isolate(a)
	at := time.Now().UTC()
	if held, term := acquireAt(t, a, at); held {
		t.Fatalf("%s minted term %d with no peer reachable; it cannot know no peer holds it", a.Name, term)
	}
	if newest, err := corrosion.CurrentLeaseTerm(context.Background(), a.DB, leaseTermKey); err != nil || newest != 0 {
		t.Fatalf("%s's ledger has term %d (err %v) after a refused claim; want nothing recorded", a.Name, newest, err)
	}

	c.ClearLinkFaults()
	if held, term := acquireAt(t, a, at.Add(catchUpPoll)); !held || term != 1 {
		t.Fatalf("%s: held=%v term=%d once its peers answer again, want term 1", a.Name, held, term)
	}
}
