// Partition pause with a non-voter that reaches both halves of a split of the
// voters (lab 1 TestDrill1, 2026-10-14). node-6 there was the witness: outside
// the adopted voter generation, and in neither half of the cut, so it kept
// probing and replicating to both sides. Safety held — the minority paused
// and nothing ran twice — but the majority never recovered:
//
//   - its deadline re-check counted node-6's healthy probes of the paused
//     minority host as "the host answered since the fence";
//   - when the failover lease was held in the minority at the cut, its holder
//     kept renewing it, node-6 kept receiving the renewals, and every majority
//     takeover was refused on node-6's word that the lease was live.
package fleet

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// bridgeFleet is six nodes, voter generation 2 = n0..n4 (n5 removed, as
// node-6 was on lab 1), recovery claims enforced, pp-vm running on n0, and
// every node's partition-pause wiring. The scenario splits [n0 n1] from
// [n2 n3 n4]; n5 stays connected to both.
func bridgeFleet(t *testing.T, o ppOpts) (c *Cluster, s *ppStack, rs *runSampler) {
	t.Helper()
	ctx := context.Background()
	c = New(t, Options{Nodes: 6, IndependentReplicas: true, Relays: 6, RealGossip: true})
	owner := c.Nodes[0]
	insertVMPolicy(t, owner, "pp-vm", owner.Name, "restart-any")
	c.WaitConverged(t, convergeTimeout)
	owner.Virt.SetState("pp-vm", libvirtfake.StateRunning)
	genesisByTick(t, c, c.Nodes[2])
	if _, err := c.SelfClient(c.Nodes[2]).ChangeVoterConfig(ctx,
		&pb.ChangeVoterConfigRequest{Op: "rm", Host: c.Nodes[5].Name}); err != nil {
		t.Fatalf("voter rm %s: %v", c.Nodes[5].Name, err)
	}
	adoptAll(t, c, 2)
	for _, n := range c.Nodes {
		v, err := corrosion.VoterSet(ctx, n.DB)
		if err != nil || len(v) != 5 || v[c.Nodes[5].Name] {
			t.Fatalf("setup: %s's voter set is %v (%v), want n0..n4", n.Name, v, err)
		}
	}
	enableRecoveryClaims(t, c)
	o.latched = true
	s = newPPStack(t, c, o)
	rs = sampleRunning(t, c, "pp-vm")
	eventually(t, time.Minute, "the owner's pauser to be healed before the split", func() bool {
		return s.node(owner).pauser.HealedForTests()
	})
	return c, s, rs
}

// assertRecoveredOnce checks the safety half of a bridged scenario once the
// replacement runs on dest: the owner paused before the replacement started,
// the replacement started only after the wait, pp-vm never ran on two hosts
// at once, and no minority node fenced anything.
func assertRecoveredOnce(t *testing.T, c *Cluster, s *ppStack, rs *runSampler, dest *Node, minority []*Node) {
	t.Helper()
	owner := c.Nodes[0]
	susp, ok := firstEvent(owner, "suspend", "pp-vm")
	if !ok {
		t.Fatalf("%s never suspended pp-vm", owner.Name)
	}
	start, ok := firstEvent(dest, "start", "pp-vm")
	if !ok {
		t.Fatalf("%s runs pp-vm with no start event", dest.Name)
	}
	if !susp.When.Before(start.When) {
		t.Fatalf("the replacement started on %s at %s, before %s paused the original at %s",
			dest.Name, start.When.Format("15:04:05.000"), owner.Name, susp.When.Format("15:04:05.000"))
	}
	fences := s.fencesOf(owner.Name)
	if len(fences) == 0 {
		t.Fatalf("no coordinator fenced %s", owner.Name)
	}
	if w := ppWait(len(c.Nodes) - 1); start.When.Sub(fences[0].at) < w {
		t.Fatalf("%s started pp-vm %v after the fence decision; the wait is %v", dest.Name,
			start.When.Sub(fences[0].at), w)
	}
	rs.mu.Lock()
	maxRun, overlap := rs.max, rs.overlap
	rs.mu.Unlock()
	if maxRun > 1 {
		t.Fatalf("pp-vm ran on more than one host at once: %v", overlap)
	}
	if got := runningOn(c, "pp-vm"); len(got) != 1 || got[0] != dest.Name {
		t.Fatalf("pp-vm runs on %v, want only %s", got, dest.Name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.fence {
		for _, m := range minority {
			if f.by == m.Name {
				t.Fatalf("minority node %s fenced %s; a coordinator without the voter majority decides nothing", m.Name, f.target)
			}
		}
	}
}

// waitRecovered waits for some node outside the minority to run pp-vm.
func waitRecovered(t *testing.T, c *Cluster, minority []*Node) *Node {
	t.Helper()
	in := map[string]bool{}
	for _, m := range minority {
		in[m.Name] = true
	}
	var dest *Node
	eventually(t, ppRecoverBound, "the majority to start pp-vm's replacement", func() bool {
		for _, n := range c.Nodes {
			if in[n.Name] {
				continue
			}
			if st, ok := n.Virt.RawState("pp-vm"); ok && st == libvirtfake.StateRunning {
				dest = n
				return true
			}
		}
		return false
	})
	return dest
}

// TestFleet_PartitionPause_NonVoterReachingBothSidesDoesNotVetoRecovery: the
// majority holds the lease. n5 keeps probing the paused n0 healthy, and the
// minority's own voter n1 does too; neither shows that n0 holds a voter
// majority, so neither may veto the recovery after the wait.
//
// Mutation: count every observer again in the self-pause deadline check
// (retryPauseWait → fenceStillStands) — "recovering nothing ... observer
// node-5 saw the host answer after the fence", and the recovery wait times out.
func TestFleet_PartitionPause_NonVoterReachingBothSidesDoesNotVetoRecovery(t *testing.T) {
	c, s, rs := bridgeFleet(t, ppOpts{coordinators: map[string]bool{"node-2": true}})
	minority, majority := c.Nodes[:2], c.Nodes[2:5]
	c.SplitGossip(minority, majority)

	dest := waitRecovered(t, c, minority)
	assertRecoveredOnce(t, c, s, rs, dest, minority)
}

// TestFleet_LeaseHeldInTheMinority_MajorityTakesOverPastANonVoter: the
// failover lease is held by n1 at the cut. n1 has lost the voter majority, so
// it must stop renewing; once its lease lapses on n5, a majority coordinator
// takes it over and recovers n0's VM after the wait.
//
// Mutation: drop the quorum gate in front of the lease (acquireLeaseResult) —
// n1 keeps renewing, n5 keeps reporting the lease live for node-1, and no
// majority node ever holds it.
func TestFleet_LeaseHeldInTheMinority_MajorityTakesOverPastANonVoter(t *testing.T) {
	ctx := context.Background()
	c, s, rs := bridgeFleet(t, ppOpts{
		coordinators:     map[string]bool{"node-1": true, "node-2": true},
		lateCoordinators: map[string]bool{"node-2": true},
	})
	n1, n2 := c.Nodes[1], c.Nodes[2]
	eventually(t, time.Minute, "node-1 to hold the failover lease on every node", func() bool {
		for _, n := range c.Nodes {
			if h, _, err := corrosion.ReadLeaseRow(ctx, n.DB, "failover"); err != nil || h != n1.Name {
				return false
			}
		}
		return true
	})
	s.startCoordinator(s.node(n2), 0)
	minority, majority := c.Nodes[:2], c.Nodes[2:5]
	c.SplitGossip(minority, majority)

	eventually(t, 45*time.Second+time.Minute, "a majority coordinator to take the failover lease over", func() bool {
		h, _, err := corrosion.ReadLeaseRow(ctx, n2.DB, "failover")
		return err == nil && h == n2.Name
	})
	dest := waitRecovered(t, c, minority)
	assertRecoveredOnce(t, c, s, rs, dest, minority)
}
