package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_PartitionOneWay_ResolvedByTheNextHolder: node-2 holds the failover
// lease and raises partition_one_way for node-0, which every voter fails to
// reach while node-0 still reaches them. node-2's coordinator then stops — a
// daemon that dies or loses the lease — and the one-way case goes away while
// nobody holds the lease. node-3 takes the lease over and must resolve the row
// node-2 raised: it is the replicated row that says the condition is open,
// not the memory of the coordinator that wrote it (lab 1, 2026-10-16: a
// CRITICAL row stayed open for two and a half hours after its raiser was
// powered off).
//
// Mutation: drop syncOneWay — node-3 never resolves the row and the last wait
// goes red.
func TestFleet_PartitionOneWay_ResolvedByTheNextHolder(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, Relays: 5, RealGossip: true})
	target, a, b := c.Nodes[0], c.Nodes[2], c.Nodes[3]
	c.WaitConverged(t, convergeTimeout)
	genesisByTick(t, c, a)
	enableRecoveryClaims(t, c)
	s := newPPStack(t, c, ppOpts{latched: true,
		coordinators:     map[string]bool{a.Name: true, b.Name: true},
		lateCoordinators: map[string]bool{a.Name: true, b.Name: true},
	})
	stopA := s.startCoordinator(s.node(a), 0)
	eventually(t, time.Minute, "node-2 to hold the failover lease on every node", func() bool {
		for _, n := range c.Nodes {
			if h, _, err := corrosion.ReadLeaseRow(ctx, n.DB, "failover"); err != nil || h != a.Name {
				return false
			}
		}
		return true
	})

	// One way: no voter's probe reaches node-0; node-0's probes, and
	// replication both ways, get through.
	for _, o := range c.Nodes[1:] {
		c.SetLinkFault(o, target, LinkFault{BlockReady: true})
	}
	// node-0 then writes fresh healthy rows about the voters, after their
	// failing runs against it began: a short blip of its own probes, over.
	time.Sleep(8 * time.Second)
	for _, o := range c.Nodes[1:] {
		c.SetLinkFault(target, o, LinkFault{BlockReady: true})
	}
	time.Sleep(3 * time.Second)
	for _, o := range c.Nodes[1:] {
		c.SetLinkFault(target, o, LinkFault{})
	}

	raised := func(n *Node) (corrosion.HealthCondition, bool) {
		row, ok, err := corrosion.GetHealthCondition(ctx, n.DB, corrosion.PartitionPauseEvaluator,
			corrosion.CondPartitionOneWay, "host", target.Name)
		return row, err == nil && ok && row.Lifecycle != corrosion.ConditionResolved
	}
	eventually(t, 2*time.Minute, "node-2 to raise partition_one_way for node-0, replicated to node-3", func() bool {
		row, ok := raised(b)
		return ok && row.Reporter == a.Name
	})

	stopA()
	c.ClearLinkFaults()
	eventually(t, time.Minute, "the voters to reach node-0 again", func() bool {
		for _, o := range c.Nodes[1:] {
			if r, ok := readObserverRow(b, o, target); !ok || r.failures != 0 {
				return false
			}
		}
		return true
	})
	if _, ok := raised(b); !ok {
		t.Fatal("setup: partition_one_way was resolved while no coordinator ran")
	}

	s.startCoordinator(s.node(b), 0)
	eventually(t, 45*time.Second+2*time.Minute, "node-3 to resolve the partition_one_way node-2 raised", func() bool {
		row, ok, err := corrosion.GetHealthCondition(ctx, b.DB, corrosion.PartitionPauseEvaluator,
			corrosion.CondPartitionOneWay, "host", target.Name)
		return err == nil && ok && row.Lifecycle == corrosion.ConditionResolved && row.Reporter == b.Name
	})
}
