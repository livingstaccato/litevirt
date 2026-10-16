// Fleet scenarios for two nodes taking one lease over at the same moment.
//
// The takeover clearance is a quorum READ of the term ledger's high water, not
// a lock. When two survivors poll on the same tick they both read the same
// high water, both clear, and both record the next term: two holders for one
// term, each acting as the lease's leader, and an immutable-ledger conflict
// that only `lv cluster acknowledge-lease-term` clears. The sibling
// shared_lun_detector fix reproduced it with aligned 60 s tickers.
//
// lease_term_claim_v1 makes the clearance DECIDE the term among the voter
// generation (grpcapi lease_term_claim.go). These scenarios put two claimants
// past the read before either records anything — the worst alignment two
// tickers can have — and require exactly one holder per term.
package fleet

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// leaseClaimFleet is n independent replicas with real health checkers, voter
// generation 1 (every node) adopted, the daemon's mint clearance wired, and —
// when latch — lease_term_claim_v1 latched through the real checkers, which
// needs every node to advertise it.
func leaseClaimFleet(t *testing.T, n int, seed int64, latch bool) (*Cluster, map[string]*health.Checker) {
	t.Helper()
	c := New(t, Options{Nodes: n, IndependentReplicas: true, FaultSeed: seed})
	gates := runCheckers(t, c)
	genesisByTick(t, c, c.Nodes[0])
	if latch {
		latchLeaseTermClaims(t, c, gates)
	}
	wireMintClearance(c)
	return c, gates
}

// latchLeaseTermClaims drives lease_term_claim_v1's latch on every node.
func latchLeaseTermClaims(t *testing.T, c *Cluster, gates map[string]*health.Checker) {
	t.Helper()
	for _, n := range c.Nodes {
		node := n
		eventually(t, 20*time.Second, "lease_term_claim_v1 latches on "+node.Name, func() bool {
			g := gates[node.Name]
			return g.Enforced(context.Background(), capabilities.LeaseTermClaimV1) &&
				g.DurablyLatched(capabilities.LeaseTermClaimV1)
		})
	}
}

// holdFirstTerm has holder take the lease at term 1, everywhere.
func holdFirstTerm(t *testing.T, c *Cluster, holder *Node, at time.Time) {
	t.Helper()
	if held, term := acquireAt(t, holder, at); !held || term != 1 {
		t.Fatalf("%s: held=%v term=%d, want the first tenure at term 1", holder.Name, held, term)
	}
	c.WaitConverged(t, convergeTimeout)
}

// takeResult is one claimant's answer.
type takeResult struct {
	held bool
	term int64
}

// alignClearances makes every claimant's next mint wait, AFTER its clearance
// has answered and BEFORE it records anything, until every claimant has had
// its answer: two pollers on one tick, at the worst possible offset. hook,
// when set, may change a claimant's answer (after the barrier).
func alignClearances(t *testing.T, claimants []*Node, hook func(n *Node, ok bool) bool) {
	t.Helper()
	var mu sync.Mutex
	arrived := 0
	all := make(chan struct{})
	for _, n := range claimants {
		node := n
		var once sync.Once
		node.DB.SetLeaseMintClearance(func(ctx context.Context, req corrosion.LeaseMintRequest) (bool, string) {
			ok, why := node.Server.LeaseMintClearance(ctx, req)
			once.Do(func() {
				mu.Lock()
				arrived++
				if arrived == len(claimants) {
					close(all)
				}
				mu.Unlock()
				select {
				case <-all:
				case <-time.After(20 * time.Second):
				}
			})
			if hook != nil {
				ok = hook(node, ok)
			}
			return ok, why
		})
	}
}

// takeOver runs every claimant's acquire at once, each at its own clock, with
// their clearances aligned, and restores the daemon's clearance afterwards.
func takeOver(t *testing.T, claimants []*Node, at func(*Node) time.Time, hook func(*Node, bool) bool) map[string]takeResult {
	t.Helper()
	alignClearances(t, claimants, hook)
	defer func() {
		for _, n := range claimants {
			n.DB.SetLeaseMintClearance(n.Server.LeaseMintClearance)
		}
	}()
	out := make(map[string]takeResult, len(claimants))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, n := range claimants {
		wg.Add(1)
		go func(n *Node) {
			defer wg.Done()
			held, term, err := corrosion.AcquireLeaseWithTerm(context.Background(), n.DB, leaseTermKey, n.Name, catchUpTTL, at(n))
			if err != nil {
				t.Errorf("%s acquire: %v", n.Name, err)
			}
			mu.Lock()
			out[n.Name] = takeResult{held: held, term: term}
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	return out
}

// takeHolders names the claimants that came back holding the lease.
func takeHolders(res map[string]takeResult) []string {
	var out []string
	for name, r := range res {
		if r.held {
			out = append(out, fmt.Sprintf("%s@%d", name, r.term))
		}
	}
	return out
}

// requireOneHolder fails unless exactly one claimant holds term, and every
// replica in nodes records that one claimant for it.
func requireOneHolder(t *testing.T, c *Cluster, res map[string]takeResult, term int64, nodes ...*Node) *Node {
	t.Helper()
	if hs := takeHolders(res); len(hs) > 1 {
		t.Fatalf("%d claimants came back holding the lease: %v — two holders for one term", len(hs), hs)
	}
	var winner *Node
	for _, n := range nodes {
		if r := res[n.Name]; r.held {
			if r.term != term {
				t.Fatalf("%s holds term %d, want %d", n.Name, r.term, term)
			}
			winner = n
		}
	}
	if winner == nil {
		t.Fatalf("no claimant holds term %d: %+v", term, res)
	}
	c.WaitConverged(t, convergeTimeout, nodes...)
	ctx := context.Background()
	for _, n := range nodes {
		h, ok, err := corrosion.LeaseTermHolder(ctx, n.DB, leaseTermKey, term)
		if err != nil || !ok || h != winner.Name {
			t.Fatalf("%s records term %d for %q (found=%v, err %v); %s holds it", n.Name, term, h, ok, err, winner.Name)
		}
	}
	return winner
}

// TestFleet_LeaseTakeover_AlignedClaimantsYieldOneHolder: the holder dies and
// two survivors take its lease over on the same tick. Each clears the quorum
// high-water read — neither has recorded anything yet — before either
// records the next term.
//
// Without the claim both record term 2. With it the voters decide term 2 for
// one of them; the other learns that and records nothing.
//
// The cases are the alignment itself, the two claimants' clocks 20 s apart
// (the decision uses no clock), and two claimants that cannot reach each
// other at all — neither replication nor RPC — while both reach a majority of
// the voters through the others.
//
// Mutation: skip claimLeaseTerm in grpcapi's LeaseMintClearance — both
// claimants hold term 2 and every case goes red.
func TestFleet_LeaseTakeover_AlignedClaimantsYieldOneHolder(t *testing.T) {
	for _, tc := range []struct {
		name  string
		nodes int
		skew  time.Duration
		apart bool // the two claimants cannot reach each other
	}{
		{name: "aligned", nodes: 3},
		{name: "skewed clocks", nodes: 3, skew: 20 * time.Second},
		{name: "claimants cut off from each other", nodes: 5, apart: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := leaseClaimFleet(t, tc.nodes, 41, true)
			a, b, d := c.Nodes[0], c.Nodes[1], c.Nodes[2]
			t0 := time.Now().UTC()
			holdFirstTerm(t, c, a, t0)

			c.Kill(a)
			if tc.apart {
				c.SetLinkFaultBoth(b, d, LinkFault{Block: true, BlockClaims: true})
			}
			takeover := t0.Add(catchUpTTL + catchUpPoll)
			res := takeOver(t, []*Node{b, d}, func(n *Node) time.Time {
				if n == b {
					return takeover.Add(tc.skew)
				}
				return takeover
			}, nil)
			if tc.apart {
				c.SetLinkFaultBoth(b, d, LinkFault{})
			}
			survivors := c.Nodes[1:]
			requireOneHolder(t, c, res, 2, survivors...)
		})
	}
}

// TestFleet_LeaseTakeover_NoMajorityNoHolder: the two survivors of three are
// cut off from each other, so each reaches one voter of three — itself. Fail
// closed: neither holds the lease, rather than both. Healed, they take it
// over on the same tick and exactly one holds term 2.
//
// Mutation: skip claimLeaseTerm — the healed takeover yields two holders.
func TestFleet_LeaseTakeover_NoMajorityNoHolder(t *testing.T) {
	c, _ := leaseClaimFleet(t, 3, 43, true)
	a, b, d := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	t0 := time.Now().UTC()
	holdFirstTerm(t, c, a, t0)

	c.Kill(a)
	c.SetLinkFaultBoth(b, d, LinkFault{Block: true, BlockClaims: true})
	takeover := t0.Add(catchUpTTL + catchUpPoll)
	same := func(*Node) time.Time { return takeover }
	if res := takeOver(t, []*Node{b, d}, same, nil); len(takeHolders(res)) != 0 {
		t.Fatalf("a claimant without a majority of the voters holds the lease: %v", takeHolders(res))
	}
	for _, n := range []*Node{b, d} {
		if newest, err := corrosion.CurrentLeaseTerm(context.Background(), n.DB, leaseTermKey); err != nil || newest != 1 {
			t.Fatalf("%s recorded term %d (err %v) without a majority", n.Name, newest, err)
		}
	}

	c.SetLinkFaultBoth(b, d, LinkFault{})
	res := takeOver(t, []*Node{b, d}, func(*Node) time.Time { return takeover.Add(catchUpPoll) }, nil)
	requireOneHolder(t, c, res, 2, b, d)
}

// TestFleet_LeaseTakeover_AWinnerThatNeverRecordsItsTermIsWaitedOut: the
// voters decide term 2 for one claimant, and it dies before recording it. The
// other learned the decision and must neither record term 2 — it is another
// node's — nor take the lease over while the winner could still be acting
// under it. One TTL after it learned, it takes the lease at term 3.
//
// Five nodes, so the survivor and the two bystanders are still a majority of
// the voters once the winner is gone too.
//
// Mutations: drop the wait in corrosion's decidedElsewhere — the survivor
// takes the lease inside the TTL; drop the move above the decided term — it
// asks about term 2 forever and never holds the lease.
func TestFleet_LeaseTakeover_AWinnerThatNeverRecordsItsTermIsWaitedOut(t *testing.T) {
	c, _ := leaseClaimFleet(t, 5, 47, true)
	a, b, d := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	t0 := time.Now().UTC()
	holdFirstTerm(t, c, a, t0)

	c.Kill(a)
	takeover := t0.Add(catchUpTTL + catchUpPoll)
	// The winner's process stops between the decision and its mint.
	var winnerName atomic.Value
	res := takeOver(t, []*Node{b, d}, func(*Node) time.Time { return takeover }, func(n *Node, ok bool) bool {
		if ok {
			winnerName.Store(n.Name)
			return false
		}
		return ok
	})
	if hs := takeHolders(res); len(hs) != 0 {
		t.Fatalf("holders %v; the winner was stopped before its mint", hs)
	}
	name, _ := winnerName.Load().(string)
	if name == "" {
		t.Fatal("no claimant won the decision for term 2")
	}
	winner, loser := b, d
	if name == d.Name {
		winner, loser = d, b
	}
	c.Kill(winner)

	// It learned the decision at takeover, or — had its own claim not
	// completed then — on its next poll, catchUpPoll later.
	for _, at := range []time.Time{takeover.Add(catchUpPoll), takeover.Add(catchUpTTL - time.Second)} {
		if held, term := acquireAt(t, loser, at); held {
			t.Fatalf("%s took the lease at term %d %s after learning %s holds term 2; that node could still be acting",
				loser.Name, term, at.Sub(takeover), winner.Name)
		}
	}
	held, term := acquireAt(t, loser, takeover.Add(catchUpPoll+catchUpTTL+time.Second))
	if !held || term != 3 {
		t.Fatalf("%s: held=%v term=%d a TTL after learning; want the lease at term 3", loser.Name, held, term)
	}
	if h, ok, _ := corrosion.LeaseTermHolder(context.Background(), loser.DB, leaseTermKey, 2); ok {
		t.Fatalf("%s records term 2 for %s; nobody recorded it", loser.Name, h)
	}
}

// TestFleet_LeaseTakeover_AlignedTickersRotateWithOneHolderPerTerm runs the
// lease the way the daemons do — every node polling, here on ONE shared tick
// — and keeps handing it over: the holder stops polling until another node
// has taken it. Every term must end with one claimant on every replica.
func TestFleet_LeaseTakeover_AlignedTickersRotateWithOneHolderPerTerm(t *testing.T) {
	const (
		ttl  = 2 * time.Second
		tick = 200 * time.Millisecond
		want = 5 // takeovers
	)
	c, _ := leaseClaimFleet(t, 3, 53, true)
	ctx := context.Background()

	var mu sync.Mutex
	paused := map[string]bool{}
	holder := map[string]int64{} // node -> term it last came back holding
	ticks := make([]chan time.Time, len(c.Nodes))
	var wg sync.WaitGroup
	for i, n := range c.Nodes {
		ticks[i] = make(chan time.Time)
		wg.Add(1)
		go func(n *Node, tc chan time.Time) {
			defer wg.Done()
			for now := range tc {
				mu.Lock()
				p := paused[n.Name]
				mu.Unlock()
				if p {
					continue
				}
				held, term, err := corrosion.AcquireLeaseWithTerm(ctx, n.DB, leaseTermKey, n.Name, ttl, now)
				if err != nil {
					t.Errorf("%s acquire: %v", n.Name, err)
					continue
				}
				mu.Lock()
				if held {
					holder[n.Name] = term
				} else {
					delete(holder, n.Name)
				}
				mu.Unlock()
			}
		}(n, ticks[i])
	}
	stop := func() {
		for _, tc := range ticks {
			close(tc)
		}
		wg.Wait()
	}
	broadcast := func() {
		now := time.Now()
		var bw sync.WaitGroup
		for _, tc := range ticks {
			bw.Add(1)
			go func(tc chan time.Time) { defer bw.Done(); tc <- now }(tc)
		}
		bw.Wait()
	}

	maxTerm := int64(0)
	takeovers := 0
	deadline := time.Now().Add(90 * time.Second)
	var current string
	for takeovers < want && time.Now().Before(deadline) {
		broadcast()
		time.Sleep(tick)
		mu.Lock()
		var names []string
		for name, term := range holder {
			names = append(names, fmt.Sprintf("%s@%d", name, term))
			if term > maxTerm {
				maxTerm = term
			}
		}
		if len(holder) > 1 {
			// Two nodes came back holding: both act as the leader.
			sameTerm := map[int64]int{}
			for _, term := range holder {
				sameTerm[term]++
			}
			for term, n := range sameTerm {
				if n > 1 {
					mu.Unlock()
					stop()
					t.Fatalf("two holders of term %d at once: %v", term, names)
				}
			}
		}
		var next string
		for name := range holder {
			next = name
		}
		if next != "" && next != current {
			if current != "" {
				takeovers++
				paused[current] = false
			}
			current = next
			// Hand it on: the holder stops polling, and its last answer is
			// forgotten so it is not mistaken for a current one.
			paused[current] = true
			delete(holder, current)
		}
		mu.Unlock()
	}
	stop()
	if takeovers < want {
		t.Fatalf("only %d takeovers in the time allowed, want %d", takeovers, want)
	}
	c.WaitConverged(t, convergeTimeout)
	for term := int64(1); term <= maxTerm; term++ {
		var first string
		for _, n := range c.Nodes {
			h, ok, err := corrosion.LeaseTermHolder(ctx, n.DB, leaseTermKey, term)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				continue // a term decided for a node that never recorded it
			}
			if first == "" {
				first = h
			} else if h != first {
				t.Fatalf("term %d has two claimants: %s and %s", term, first, h)
			}
		}
	}
}

// TestFleet_LeaseTakeover_MixedVersionsKeepTheOldClearance: while one node
// runs a build without lease-term claims (here: it does not advertise the
// token), the token cannot latch, and nothing is claimed — that node would
// not answer a lease-term claim, and asking it would stop every takeover for
// the length of a rolling upgrade. Takeovers clear on the high-water read as
// they always did. Once that node advertises the token too, the latch forms
// and the next takeover is claimed.
//
// Mutation: claim before the latch (leaseTermClaimMode ignoring it) — the
// voters hold a decision for term 2 and this goes red.
func TestFleet_LeaseTakeover_MixedVersionsKeepTheOldClearance(t *testing.T) {
	ctx := context.Background()
	c, gates := leaseClaimFleet(t, 3, 59, false)
	a, b, old := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	var upgraded atomic.Bool
	for _, n := range c.Nodes {
		node := n
		gates[node.Name].SetPeerPinger(func(pctx context.Context, host string) ([]string, time.Time, error) {
			caps, wall, err := node.Server.PeerCapabilities(pctx, host)
			if host == old.Name && !upgraded.Load() {
				caps = withoutToken(caps, capabilities.LeaseTermClaimV1)
			}
			return caps, wall, err
		})
	}
	if gates[a.Name].Enforced(ctx, capabilities.LeaseTermClaimV1) {
		t.Fatalf("%s latched across %s, which does not advertise it", capabilities.LeaseTermClaimV1, old.Name)
	}

	t0 := time.Now().UTC()
	holdFirstTerm(t, c, a, t0)
	c.Kill(a)
	takeover := t0.Add(catchUpTTL + catchUpPoll)
	if held, term := acquireAt(t, b, takeover); !held || term != 2 {
		t.Fatalf("%s: held=%v term=%d; a takeover must still work before the latch", b.Name, held, term)
	}
	for _, n := range c.Nodes {
		if _, found, err := n.DB.ClaimState(ctx, corrosion.LeaseTermClaimKey(leaseTermKey, 2)); err != nil || found {
			t.Fatalf("%s holds lease-term claim state (found=%v, err %v) before the latch", n.Name, found, err)
		}
	}

	// a comes back and the last node upgrades: every node advertises the
	// token, and it latches.
	c.ClearLinkFaults()
	c.WaitConverged(t, convergeTimeout)
	upgraded.Store(true)
	latchLeaseTermClaims(t, c, gates)
	// b's lease lapses; old takes it over, now under a claim.
	later := takeover.Add(catchUpTTL + catchUpPoll)
	if held, term := acquireAt(t, old, later); !held || term != 3 {
		t.Fatalf("%s: held=%v term=%d after the latch, want term 3", old.Name, held, term)
	}
	st, found, err := old.DB.ClaimState(ctx, corrosion.LeaseTermClaimKey(leaseTermKey, 3))
	if err != nil || !found || st.Value == nil || st.Value.LeaseTerm == nil || st.Value.LeaseTerm.Holder != old.Name {
		t.Fatalf("term 3 was not claimed after the latch: %+v found=%v err=%v", st, found, err)
	}
}
