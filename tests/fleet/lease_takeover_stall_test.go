// Fleet scenarios for a lease takeover that cannot happen, and for one that
// many survivors race, both found on lab 1 (8fce70da).
//
// With voters really down, every lease fails closed before its claim: the
// failover coordinator, the dual-run detector and the rebalancer stand down
// at the health voter-quorum check, and the mint clearance at the quorum
// high-water read. ha.lease.claim_no_majority and its counter were raised
// only by the claim, so neither ever fired in the one case they exist for.
//
// With a dead voter holding the lease, five survivors claimed its next term
// at once. Each phase waited out the dead voter's call timeout, and every
// claimant outbid the others as soon as it was outranked: the ballot rounds
// reached 39 and the takeover came a TTL late.
package fleet

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/health"
)

// noMajorityRow is n's replica's ha.lease.claim_no_majority row for the lease.
func noMajorityRow(t *testing.T, n *Node) (corrosion.HealthCondition, bool) {
	t.Helper()
	row, found, err := corrosion.GetHealthCondition(context.Background(), n.DB, "lease_term_claim",
		"ha.lease.claim_no_majority", "cluster", leaseTermKey)
	if err != nil {
		t.Fatal(err)
	}
	return row, found && row.Lifecycle != corrosion.ConditionResolved
}

// TestFleet_LeaseTakeover_VotersDownRaiseTheStall: three of five voters stop —
// the holder among them — so the two survivors have no voter majority. Each
// polls the failover lease past its expiry for longer than a TTL, one the way
// the failover coordinator does (it stands down at the voter-quorum check
// before it asks for the lease) and one through the lease path directly (its
// mint clearance stops at the quorum high-water read). Neither reaches a
// claim. Both must still count the polls and raise ha.lease.claim_no_majority
// a TTL into the stall.
//
// Mutations: no report from the coordinator's stand-down — the first half
// goes red; none from the high-water read — the second half goes red.
func TestFleet_LeaseTakeover_VotersDownRaiseTheStall(t *testing.T) {
	ctx := context.Background()
	c, gates := leaseClaimFleet(t, 5, 79, true)
	a, b, d := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	t0 := time.Now().UTC()
	holdFirstTerm(t, c, a, t0)

	var mu sync.Mutex
	counted := map[string]int{}
	for _, n := range []*Node{b, d} {
		name := n.Name
		n.Server.SetLeaseClaimNoMajorityObserver(func(lease string) {
			mu.Lock()
			defer mu.Unlock()
			if lease == leaseTermKey {
				counted[name]++
			}
		})
	}
	count := func(n *Node) int {
		mu.Lock()
		defer mu.Unlock()
		return counted[n.Name]
	}

	// Stopped, not cut off by a seam: their gRPC servers are gone, so the
	// survivors' health checkers see them down.
	for _, n := range []*Node{a, c.Nodes[3], c.Nodes[4]} {
		c.Crash(n)
	}
	for _, n := range []*Node{b, d} {
		node := n
		eventually(t, 60*time.Second, node.Name+" sees the voter majority lost", func() bool {
			st, _, _ := gates[node.Name].QuorumProof(ctx)
			return st != health.QuorumYes
		})
	}

	takeover := t0.Add(catchUpTTL + catchUpPoll)
	stalled := takeover.Add(catchUpTTL + time.Second)

	// d: the failover coordinator's own poll.
	var virt atomic.Value
	coord := failover.NewCoordinator(d.Name, d.DB)
	coord.Gate = gates[d.Name]
	coord.Now = func() time.Time { return virt.Load().(time.Time) }
	for _, at := range []time.Time{takeover, stalled} {
		virt.Store(at)
		coord.RunOnce(ctx)
	}
	if term := coord.LeaseTerm(); term != 0 {
		t.Fatalf("%s's coordinator holds term %d without a voter majority", d.Name, term)
	}
	if count(d) < 2 {
		t.Fatalf("%s's coordinator stood down %d times for want of the voter majority counted, want 2", d.Name, count(d))
	}
	if row, raised := noMajorityRow(t, d); !raised || row.Reporter != d.Name {
		t.Fatalf("%s raised no ha.lease.claim_no_majority a TTL into the stall (row %+v)", d.Name, row)
	}

	// b: the lease path, which stops at the quorum high-water read.
	for _, at := range []time.Time{takeover, stalled} {
		if held, term := acquireAt(t, b, at); held {
			t.Fatalf("%s took term %d without a voter majority", b.Name, term)
		}
	}
	if count(b) < 2 {
		t.Fatalf("%s's mints withheld at the quorum read counted %d, want 2", b.Name, count(b))
	}
	if row, raised := noMajorityRow(t, b); !raised || row.Reporter != b.Name {
		t.Fatalf("%s raised no ha.lease.claim_no_majority a TTL into the stall (row %+v)", b.Name, row)
	}
	for _, n := range []*Node{b, d} {
		if newest, err := corrosion.CurrentLeaseTerm(ctx, n.DB, leaseTermKey); err != nil || newest != 1 {
			t.Fatalf("%s recorded term %d (err %v) without a voter majority", n.Name, newest, err)
		}
	}
}

// TestFleet_LeaseTakeover_FiveClaimantsAgainstADeadVoterDecideAtOnce: six
// voters, and the lease holder — one of them — is powered off: a call to it
// hangs until the caller gives up. The five survivors take the lease over on
// one tick, each claiming term 2.
//
// The claimant every voter ranks first must decide well inside one call
// timeout rather than wait out the dead voter on every phase; every claimant
// must come back from that one poll, with exactly one holder; and the voters
// must not have been driven through many ballot rounds.
//
// On 8fce70da each phase waited out the dead voter, so no claimant came back
// in under two call timeouts, and the outbid claimants outbid each other.
//
// Mutations: wait for every voter in each phase (ReturnAtQuorum off) — no
// claimant decides inside a call timeout. The deadline-bound dead Ping can
// mask Yield-off here; the causal anti-duel control is
// internal/claims/TestProposer_YieldLetsTheLeaderFinish. The production lease
// yield ranges and preference are covered by TestLeaseTermClaimSpec_EndsAtQuorumAndYields.
// This fleet case retains its final-round bound as a preservation assertion.
func TestFleet_LeaseTakeover_FiveClaimantsAgainstADeadVoterDecideAtOnce(t *testing.T) {
	ctx := context.Background()
	c, _ := leaseClaimFleet(t, 6, 83, true)
	a := c.Nodes[0]
	survivors := c.Nodes[1:]
	t0 := time.Now().UTC()
	holdFirstTerm(t, c, a, t0)

	// Powered off: a's own calls fail, and calls into it are held until the
	// caller's deadline, as a dial to a dead host is. The fresh capability
	// Ping must wait too; BlockProbe would refuse it before ClaimDelay is reached.
	for _, o := range survivors {
		c.SetLinkFault(o, a, LinkFault{Block: true, ProbeDelay: time.Minute, ClaimDelay: time.Minute})
		c.SetLinkFault(a, o, LinkFault{Block: true, BlockClaims: true, BlockProbe: true})
	}

	takeover := t0.Add(catchUpTTL + catchUpPoll)
	type answer struct {
		held    bool
		term    int64
		elapsed time.Duration
	}
	res := make(map[string]answer, len(survivors))
	var mu sync.Mutex
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, n := range survivors {
		wg.Add(1)
		go func(n *Node) {
			defer wg.Done()
			<-start
			began := time.Now()
			held, term, err := corrosion.AcquireLeaseWithTerm(ctx, n.DB, leaseTermKey, n.Name, catchUpTTL, takeover)
			if err != nil {
				t.Errorf("%s acquire: %v", n.Name, err)
			}
			mu.Lock()
			res[n.Name] = answer{held: held, term: term, elapsed: time.Since(began)}
			mu.Unlock()
		}(n)
	}
	close(start)
	wg.Wait()

	first := time.Duration(1<<63 - 1)
	var holders []string
	for name, r := range res {
		if r.elapsed < first {
			first = r.elapsed
		}
		if r.held {
			if r.term != 2 {
				t.Fatalf("%s holds term %d, want 2", name, r.term)
			}
			holders = append(holders, name)
		}
	}
	t.Logf("claimants: %+v", res)
	if len(holders) != 1 {
		t.Fatalf("holders after one poll of five claimants: %v, want exactly one", holders)
	}
	if first >= claims.DefaultCallTimeout {
		t.Fatalf("the first claimant came back after %s: a claim with its quorum waited out the dead voter", first)
	}

	key := corrosion.LeaseTermClaimKey(leaseTermKey, 2)
	maxRound := uint64(0)
	for _, n := range survivors {
		st, found, err := n.DB.ClaimState(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		if found && st.Promised.Round > maxRound {
			maxRound = st.Promised.Round
		}
	}
	if maxRound > 4 {
		t.Fatalf("the voters were driven to ballot round %d deciding one term among five claimants", maxRound)
	}
	c.WaitConverged(t, convergeTimeout, survivors...)
	for _, n := range survivors {
		h, ok, err := corrosion.LeaseTermHolder(ctx, n.DB, leaseTermKey, 2)
		if err != nil || !ok || h != holders[0] {
			t.Fatalf("%s records term 2 for %q (found=%v, err %v); %s holds it", n.Name, h, ok, err, holders[0])
		}
	}
}
