// Fleet scenarios for a CONTESTED leader lease: two or more survivors claim the
// same expired lease within one replication latency, so each commits the same
// term with itself as holder before it sees anyone else's claim.
//
// That is not a partition scenario. It is what every ordinary leader death
// looks like when the survivors poll on the same interval, and it was observed
// on the lab: after a fence-confirm, three nodes each logged the leader-only
// resume path within two seconds, and `lv doctor divergence` showed the
// failover term rows stuck_different on every node for ten days.
//
// The ledger's "keep local, flag" merge is deliberate and these scenarios do
// not change it — two claims for one (key, term) stay two claims. What they pin
// is that the LEASE converges anyway: one claimant keeps acting, every other
// claimant stands down, and the survivor moves to a fresh, uncontested term so
// the contested one can never again look current to anyone.
package fleet

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// contestTTL is the failover coordinator's lease duration, and contestPoll its
// poll interval. The scenario steps virtual time the way the coordinator does,
// so "converges within N polls" means the same thing here as in production.
const (
	contestTTL  = 45 * time.Second
	contestPoll = 5 * time.Second
)

// replicateWAL carries every node's WAL to every other node — the ordinary,
// continuous replication path, and the only one that moves leader_election at
// all (the table is anti-entropy excluded).
func replicateWAL(t *testing.T, c *Cluster) {
	t.Helper()
	for _, from := range c.Nodes {
		for _, to := range c.Nodes {
			if from != to {
				pumpMutations(t, c, from, to)
			}
		}
	}
}

// replicateAll is replicateWAL followed by a full anti-entropy exchange in both
// directions — the most generous healthy replication the harness can model. A
// split that survives this is not waiting for the network.
func replicateAll(t *testing.T, c *Cluster) {
	t.Helper()
	replicateWAL(t, c)
	for _, from := range c.Nodes {
		dump := from.DB.DumpStateBytes()
		for _, to := range c.Nodes {
			if from == to {
				continue
			}
			if err := to.DB.MergeStateBytesLWW(dump); err != nil {
				t.Fatalf("anti-entropy %s→%s: %v", from.Name, to.Name, err)
			}
		}
	}
}

type pollResult struct {
	held bool
	term int64
}

// pollAll runs one coordinator tick on every node at virtual time at.
func pollAll(t *testing.T, c *Cluster, at time.Time) map[string]pollResult {
	t.Helper()
	out := make(map[string]pollResult, len(c.Nodes))
	for _, n := range c.Nodes {
		held, term, err := corrosion.AcquireLeaseWithTerm(context.Background(), n.DB, leaseTermKey, n.Name, contestTTL, at)
		if err != nil {
			t.Fatalf("%s acquire at %s: %v", n.Name, at.Format(time.RFC3339), err)
		}
		out[n.Name] = pollResult{held, term}
	}
	return out
}

func holdersOf(res map[string]pollResult) []string {
	var hs []string
	for name, r := range res {
		if r.held {
			hs = append(hs, fmt.Sprintf("%s@%d", name, r.term))
		}
	}
	return hs
}

// contestClaim has every node claim an expired lease before any node has
// heard from another: each sees an unheld lease and an empty ledger, and each
// commits term 1 naming itself.
func contestClaim(t *testing.T, c *Cluster, t0 time.Time) {
	t.Helper()
	first := pollAll(t, c, t0)
	for _, n := range c.Nodes {
		if r := first[n.Name]; !r.held || r.term != 1 {
			t.Fatalf("%s: held=%v term=%d; every node must claim term 1 for this to be "+
				"the contested case", n.Name, r.held, r.term)
		}
	}
}

// runContest drives n nodes through a simultaneous claim of an expired lease,
// then through `polls` healthy coordinator ticks with `replicate` run before
// each, and returns every tick after the claim.
func runContest(t *testing.T, nodes, polls int, replicate func(*testing.T, *Cluster)) (*Cluster, []map[string]pollResult) {
	t.Helper()
	c := New(t, Options{Nodes: nodes})
	t.Cleanup(c.Stop)

	t0 := time.Now().UTC()
	contestClaim(t, c, t0)

	// Now replication is healthy, forever. Nothing is partitioned from here on.
	ticks := make([]map[string]pollResult, 0, polls)
	at := t0
	for i := 0; i < polls; i++ {
		replicate(t, c)
		at = at.Add(contestPoll)
		ticks = append(ticks, pollAll(t, c, at))
	}
	replicate(t, c)
	return c, ticks
}

// assertOneStableHolder: from the first tick after the claims were exchanged,
// exactly ONE node holds the lease on every tick, and it is the same node every
// time. This is stronger than eventual convergence and is what the stand-down
// and takeover-deferral rules buy: a loser stops on the tick it learns of a
// lower claim, and never takes the lease back when its own stale row expires.
func assertOneStableHolder(t *testing.T, ticks []map[string]pollResult) {
	t.Helper()
	var first string
	for i, tick := range ticks {
		hs := holdersOf(tick)
		if len(hs) != 1 {
			t.Fatalf("tick %d (%s after the claims were exchanged): %d holders %v, want exactly "+
				"one. Every claimant but one must stand down as soon as it learns of a "+
				"lower-sorting claim", i, time.Duration(i+1)*contestPoll, len(hs), hs)
		}
		name := strings.SplitN(hs[0], "@", 2)[0]
		if first == "" {
			first = name
		} else if name != first {
			t.Fatalf("tick %d (%s): the lease moved %s -> %s with every node alive. A "+
				"stood-down claimant re-took the lease when its own stale row expired, "+
				"minting above the survivor and restarting the contest", i,
				time.Duration(i+1)*contestPoll, first, name)
		}
	}
}

// assertConverged checks the whole property on a cluster that has had ample
// healthy time: exactly one holder, every replica's lease row naming it, and its
// term the newest on every replica with the same holder on every replica.
func assertConverged(t *testing.T, c *Cluster, ticks []map[string]pollResult) {
	t.Helper()
	ctx := context.Background()
	last := ticks[len(ticks)-1]

	hs := holdersOf(last)
	if len(hs) != 1 {
		t.Fatalf("after %s of fully healthy replication, %d nodes still believe they hold "+
			"the %q lease: %v. A contested claim must converge to ONE holder; every other "+
			"claimant has to stand down and stop renewing",
			time.Duration(contestPolls)*contestPoll, len(hs), leaseTermKey, hs)
	}
	var winner string
	var term int64
	for name, r := range last {
		if r.held {
			winner, term = name, r.term
		}
	}

	for _, n := range c.Nodes {
		holder, _, err := leaseRowFor(t, n)
		if err != nil {
			t.Fatalf("read %s lease row: %v", n.Name, err)
		}
		if holder != winner {
			t.Errorf("%s's leader_election row names %q, want the converged holder %q",
				n.Name, holder, winner)
		}
		newest, err := corrosion.CurrentLeaseTerm(ctx, n.DB, leaseTermKey)
		if err != nil {
			t.Fatalf("%s newest term: %v", n.Name, err)
		}
		if newest != term {
			t.Errorf("%s's newest term is %d, want the holder's term %d", n.Name, newest, term)
		}
		h, found, err := corrosion.LeaseTermHolder(ctx, n.DB, leaseTermKey, term)
		if err != nil {
			t.Fatalf("%s holder of term %d: %v", n.Name, term, err)
		}
		if !found || h != winner {
			t.Errorf("%s records term %d as held by %q (found=%v), want %q. The term the "+
				"survivor acts under must be one EVERY replica attributes to it — a term "+
				"two replicas attribute to different holders is still contested",
				n.Name, term, h, found, winner)
		}
	}
	if term <= 1 {
		t.Errorf("the survivor is still acting under the contested term %d; it must move to "+
			"a fresh term above it so the contested one can never look current again", term)
	}
}

// contestPolls is ten TTLs of polling — far past any convergence bound the fix
// claims, so a failure here is a split that never heals, not a slow one.
const contestPolls = int(10 * contestTTL / contestPoll)

// TestFleet_LeaseContest_TwoClaimantsConvergeToOneHolder is the headline: two
// survivors claim one expired lease at once, and with replication fully healthy
// afterwards the lease must end up with exactly one of them.
//
// Before the fix neither ever stood down. Each replica's leader_election row
// names its own node (the peer's upsert is a no-op against a live row whose
// holder differs), each replica's term-1 row names its own node (the ledger
// keeps local), so each node classifies every tick as a renewal of its own
// tenure and renews forever.
func TestFleet_LeaseContest_TwoClaimantsConvergeToOneHolder(t *testing.T) {
	c, ticks := runContest(t, 2, contestPolls, replicateAll)
	assertOneStableHolder(t, ticks)
	assertConverged(t, c, ticks)
}

// TestFleet_LeaseContest_ThreeClaimantsConvergeToOneHolder is the lab's shape:
// three survivors of a four-node cluster. Each node learns the other claims by
// separate pairwise exchanges, so a rule that only works for a pair — or that
// lets two nodes each believe they won — shows up here.
func TestFleet_LeaseContest_ThreeClaimantsConvergeToOneHolder(t *testing.T) {
	c, ticks := runContest(t, 3, contestPolls, replicateAll)
	assertOneStableHolder(t, ticks)
	assertConverged(t, c, ticks)
}

// TestFleet_LeaseContest_ConvergesOnTheWALAlone: no anti-entropy at all, only
// the continuous WAL stream. Anti-entropy runs about once a minute, and a
// contest noticed only there would leave every claimant acting for that long;
// the WAL apply is where each claimant first receives the other's mint, so it
// is where the contest has to be noticed.
func TestFleet_LeaseContest_ConvergesOnTheWALAlone(t *testing.T) {
	c, ticks := runContest(t, 3, contestPolls, replicateWAL)
	assertOneStableHolder(t, ticks)
	assertConverged(t, c, ticks)
}

// TestFleet_LeaseContest_ALoserTakesOverWhenTheWinnerDies: the takeover
// deferral must be BOUNDED. A stood-down claimant defers taking over its own
// expired row because the winner may be renewing over it — but if the winner is
// dead, nothing ever renews, and a deferral that never ended would strand the
// lease on every replica whose row still names a loser.
func TestFleet_LeaseContest_ALoserTakesOverWhenTheWinnerDies(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	t.Cleanup(c.Stop)
	winner, loser := c.Nodes[0], c.Nodes[1]
	if winner.Name > loser.Name {
		winner, loser = loser, winner
	}

	t0 := time.Now().UTC()
	contestClaim(t, c, t0)
	replicateAll(t, c)

	// The loser learns of the lower claim and stands down on its next tick. The
	// winner never polls again: it died the moment the claims crossed, so it
	// neither retires the term nor renews anything.
	at := t0.Add(contestPoll)
	if held, term, err := corrosion.AcquireLeaseWithTerm(ctx, loser.DB, leaseTermKey, loser.Name, contestTTL, at); err != nil {
		t.Fatalf("%s tick: %v", loser.Name, err)
	} else if held {
		t.Fatalf("%s still holds (term %d) after learning of %s's lower claim; it must stand down",
			loser.Name, term, winner.Name)
	}

	// Its own claim expired at t0+TTL. Deferral lasts one further TTL; after that
	// the winner is presumed dead exactly as an ordinary expiry presumes it.
	deadline := t0.Add(2*contestTTL + 2*contestPoll)
	for at = at.Add(contestPoll); !at.After(deadline); at = at.Add(contestPoll) {
		held, term, err := corrosion.AcquireLeaseWithTerm(ctx, loser.DB, leaseTermKey, loser.Name, contestTTL, at)
		if err != nil {
			t.Fatalf("%s tick at +%s: %v", loser.Name, at.Sub(t0), err)
		}
		if held {
			// < not <=: expires_at is whole-second RFC3339, so the window closes up
			// to a second before t0+2*TTL and a takeover exactly there is on time.
			if at.Sub(t0) < 2*contestTTL {
				t.Fatalf("%s took over at +%s, inside the deferral window (its claim expired at "+
					"+%s and the winner gets one further TTL to renew over it)",
					loser.Name, at.Sub(t0), contestTTL)
			}
			if term <= 1 {
				t.Fatalf("%s took over at the contested term %d; a takeover is a new tenure "+
					"and must mint above it", loser.Name, term)
			}
			return
		}
	}
	t.Fatalf("%s never took over a lease whose only other claimant is dead (checked until "+
		"+%s). The takeover deferral must end one TTL after expiry, or a dead winner strands "+
		"the lease forever", loser.Name, deadline.Sub(t0))
}
