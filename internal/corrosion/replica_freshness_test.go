package corrosion

import (
	"context"
	"testing"

	"github.com/hashicorp/memberlist"
)

// Every process starts untrusted: the gap a restart opens is exactly what the
// signal is about, so there is nothing to carry over.
func TestReplicaFreshness_StartsNotCaughtUp(t *testing.T) {
	c := newPruneTestClient(t)
	if ok, why := c.ReplicaCaughtUp(); ok || why == "" {
		t.Fatalf("a fresh process must not report its replica caught up (ok=%v why=%q)", ok, why)
	}
	c.markReplicaCaughtUp(c.replicaFreshnessGen(), "peer-1")
	if ok, _ := c.ReplicaCaughtUp(); !ok {
		t.Fatal("a completed exchange must mark the replica caught up")
	}
}

func TestReplicaFreshness_StaleResetsAndReportsWhy(t *testing.T) {
	c := newPruneTestClient(t)
	c.markReplicaCaughtUp(c.replicaFreshnessGen(), "peer-1")
	c.MarkReplicaStale("lost every peer")
	ok, why := c.ReplicaCaughtUp()
	if ok {
		t.Fatal("MarkReplicaStale must withdraw the caught-up state")
	}
	if why != "lost every peer" {
		t.Fatalf("reason = %q, want the reset's reason", why)
	}
}

// A pass that began before a reset proves nothing about the gap the reset
// opened, and must not mark it closed when it finishes.
func TestReplicaFreshness_PassStraddlingAResetMarksNothing(t *testing.T) {
	c := newPruneTestClient(t)
	gen := c.replicaFreshnessGen() // pass begins
	c.MarkReplicaStale("lost every peer")
	c.markReplicaCaughtUp(gen, "peer-1") // pass completes
	if ok, _ := c.ReplicaCaughtUp(); ok {
		t.Fatal("an exchange that straddled a staleness reset must not mark the replica caught up")
	}
	c.markReplicaCaughtUp(c.replicaFreshnessGen(), "peer-1")
	if ok, _ := c.ReplicaCaughtUp(); !ok {
		t.Fatal("an exchange begun after the reset must mark it caught up")
	}
}

// Losing the LAST gossip peer makes the replica stale; losing one of several
// does not (the survivors are still replicating to this node).
func TestReplicaFreshness_LastPeerLeavingResets(t *testing.T) {
	c := newPruneTestClient(t)
	e := &membershipEvents{client: c}
	e.NotifyJoin(&memberlist.Node{Name: c.hostName}) // self: not a peer
	e.NotifyJoin(&memberlist.Node{Name: "peer-1"})
	e.NotifyJoin(&memberlist.Node{Name: "peer-2"})
	c.markReplicaCaughtUp(c.replicaFreshnessGen(), "peer-1")

	e.NotifyLeave(&memberlist.Node{Name: "peer-1"})
	if ok, _ := c.ReplicaCaughtUp(); !ok {
		t.Fatal("losing one of several peers must not reset freshness")
	}
	e.NotifyLeave(&memberlist.Node{Name: "peer-2"})
	if ok, _ := c.ReplicaCaughtUp(); ok {
		t.Fatal("losing the last gossip peer must reset freshness")
	}
}

// Self joining/leaving is not peer churn; memberlist notifies a join for the
// local node too, and it must not count as a peer that can later "leave last".
func TestReplicaFreshness_SelfIsNotAPeer(t *testing.T) {
	c := newPruneTestClient(t)
	e := &membershipEvents{client: c}
	e.NotifyJoin(&memberlist.Node{Name: c.hostName})
	e.NotifyJoin(&memberlist.Node{Name: "peer-1"})
	c.markReplicaCaughtUp(c.replicaFreshnessGen(), "peer-1")
	e.NotifyLeave(&memberlist.Node{Name: c.hostName})
	if ok, _ := c.ReplicaCaughtUp(); !ok {
		t.Fatal("the local node's own leave event must not reset freshness")
	}
}

// Backstops: the re-join loop and an anti-entropy pass that find no peers at
// all both reset freshness, in case the leave event was missed.
func TestReplicaFreshness_RejoinTickWithNoPeersResets(t *testing.T) {
	c := isolationClient(t)
	c.markReplicaCaughtUp(c.replicaFreshnessGen(), "peer-1")
	c.membershipTick(context.Background(), isolatedRejoiner(), reporter(c))
	if ok, _ := c.ReplicaCaughtUp(); ok {
		t.Fatal("a re-join pass that sees no peers must reset freshness")
	}
}

func TestReplicaFreshness_HealthyRejoinTickKeepsIt(t *testing.T) {
	c := isolationClient(t)
	c.markReplicaCaughtUp(c.replicaFreshnessGen(), "peer-1")
	c.membershipTick(context.Background(), healthyRejoiner(), reporter(c))
	if ok, _ := c.ReplicaCaughtUp(); !ok {
		t.Fatal("a re-join pass that sees peers must not reset freshness")
	}
}

func TestReplicaFreshness_AntiEntropyWithNoPeersResets(t *testing.T) {
	c := newPruneTestClient(t)
	c.SetMembersForTests(func() []PeerInfo { return nil })
	c.markReplicaCaughtUp(c.replicaFreshnessGen(), "peer-1")
	NewAntiEntropy(c, t.TempDir(), 0).RunOnce(context.Background())
	if ok, _ := c.ReplicaCaughtUp(); ok {
		t.Fatal("an anti-entropy pass that finds no peers must reset freshness")
	}
}

// An exchange that did not complete — here the peer cannot even be dialled —
// proves nothing and must not mark the replica caught up.
func TestReplicaFreshness_FailedExchangeDoesNotMark(t *testing.T) {
	c := newPruneTestClient(t)
	c.SetMembersForTests(func() []PeerInfo { return []PeerInfo{{Name: "ghost", Addr: "127.0.0.1"}} })
	NewAntiEntropy(c, t.TempDir(), 0).RunOnce(context.Background())
	if ok, _ := c.ReplicaCaughtUp(); ok {
		t.Fatal("an anti-entropy exchange that failed must not mark the replica caught up")
	}
}
