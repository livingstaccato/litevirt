// Two liveness residuals of the lease gate a node without the voter majority
// stands behind (partition_pause_bridge_test.go):
//
//   - under region-scoped failover, a failover lease holder cut off from its
//     own region's majority still reaches another region's, so it kept the
//     cluster-wide reading and kept renewing; the hosts that reach it carried
//     the renewals to its own region's majority, which could never take the
//     lease to fence it;
//   - while no node holds the voter majority, no node holds the dual-run
//     detector's lease either, and no node recorded a dual run at all.
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// ppRegionGate is ppGate that can also answer for one region's voters, as
// the daemon's checker does: what the coordinator decides on under region
// scope.
type ppRegionGate struct{ ppGate }

func (g ppRegionGate) DecisionGateForRegion(ctx context.Context, region string) health.GateResult {
	return g.chk.DecisionGateForRegion(ctx, region)
}
func (g ppRegionGate) RegionQuorumProof(ctx context.Context, region string) (health.QuorumState, int, int) {
	return g.chk.RegionQuorumProof(ctx, region)
}

// TestFleet_RegionScope_LeaseHolderInItsRegionsMinorityHandsOver: region
// scope, regions a = n0..n2 and b = n3..n5, every node a voter. n0 holds the
// failover lease when its links to n1 and n2 fail; every other link works.
// n0 still counts the cluster's majority (itself and b) and region b's, but
// not region a's, so it can decide nothing about n0 itself, and it pauses
// n0's workloads. n1 and n2 are region a's majority and must fence n0; they
// can do so only once n0 lets the lease go, since b's hosts carry n0's
// renewals to them.
//
// Without recovery claims the majority then recovers pp-vm inside region a.
// With them, the takeover and the fence happen, but the claim forms no
// certificate: b's voters still reach n0 and refuse its eviction
// (recovery-claims.md §3.5.1), so pp-vm stays paused on n0 and nothing runs
// twice. That refusal is the claims' own rule, not the lease's.
//
// Mutation: drop the own-region clause from the failover lease gate — n0
// keeps renewing on the cluster reading and n1 never holds the lease (both
// arms go red).
func TestFleet_RegionScope_LeaseHolderInItsRegionsMinorityHandsOver(t *testing.T) {
	for _, claims := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-claims", true: "claims"}[claims], func(t *testing.T) {
			regionLeaseHandover(t, claims)
		})
	}
}

func regionLeaseHandover(t *testing.T, claims bool) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 6, IndependentReplicas: true, Relays: 6, RealGossip: true,
		RegionByIndex: []string{"a", "a", "a", "b", "b", "b"}})
	n0, n1, n3 := c.Nodes[0], c.Nodes[1], c.Nodes[3]
	for _, n := range c.Nodes {
		n.DB.SetClusterPolicyGate(func() bool { return true })
	}
	if err := corrosion.SetFailoverScope(ctx, n0.DB, corrosion.FailoverScopeRegion, "fleet"); err != nil {
		t.Fatalf("SetFailoverScope: %v", err)
	}
	insertVMPolicy(t, n0, "pp-vm", n0.Name, "restart-any")
	c.WaitConverged(t, convergeTimeout)
	n0.Virt.SetState("pp-vm", libvirtfake.StateRunning)
	genesisByTick(t, c, n1)
	if claims {
		enableRecoveryClaims(t, c)
	}
	s := newPPStack(t, c, ppOpts{
		latched:          true,
		coordinators:     map[string]bool{n0.Name: true, n1.Name: true},
		lateCoordinators: map[string]bool{n0.Name: true, n1.Name: true},
	})
	for _, pn := range s.nodes {
		pn.coord.Gate = ppRegionGate{ppGate{pn.chk}}
	}
	rs := sampleRunning(t, c, "pp-vm")
	eventually(t, time.Minute, "n0's pauser to be healed before the split", func() bool {
		return s.node(n0).pauser.HealedForTests()
	})
	s.startCoordinator(s.node(n0), 0)
	eventually(t, time.Minute, "node-0 to hold the failover lease on every node", func() bool {
		for _, n := range c.Nodes {
			if h, _, err := corrosion.ReadLeaseRow(ctx, n.DB, "failover"); err != nil || h != n0.Name {
				return false
			}
		}
		return true
	})
	s.startCoordinator(s.node(n1), 0)

	minority := []*Node{n0}
	c.SplitGossip(minority, c.Nodes[1:3])

	eventually(t, 45*time.Second+time.Minute, "region a's majority to take the failover lease over", func() bool {
		for _, n := range []*Node{n1, n3} {
			if h, _, err := corrosion.ReadLeaseRow(ctx, n.DB, "failover"); err != nil || h != n1.Name {
				return false
			}
		}
		return true
	})
	if !claims {
		dest := waitRecovered(t, c, minority)
		if dest != c.Nodes[1] && dest != c.Nodes[2] {
			t.Fatalf("pp-vm was recovered on %s, outside region a", dest.Name)
		}
		assertRecoveredOnce(t, c, s, rs, dest, minority)
		return
	}
	eventually(t, ppRecoverBound, "node-1 to fence node-0", func() bool {
		for _, f := range s.fencesOf(n0.Name) {
			if f.by == n1.Name {
				return true
			}
		}
		return false
	})
	time.Sleep(ppWait(len(c.Nodes)-1) + 10*time.Second)
	rs.mu.Lock()
	maxRun, overlap := rs.max, rs.overlap
	rs.mu.Unlock()
	if maxRun > 1 {
		t.Fatalf("pp-vm ran on more than one host at once: %v", overlap)
	}
	for _, f := range s.fencesOf(n0.Name) {
		if f.by == n0.Name {
			t.Fatalf("node-0 fenced itself; without its region's majority it decides nothing")
		}
	}
}

// checkerServerGate is the server gate with the node's real checker for the
// voter majority, which is what the dual-run detector's lease gate and its
// resolution read; every token is latched as for claims.
type checkerServerGate struct {
	claimsGate
	chk *health.Checker
}

func (g checkerServerGate) QuorumProof(ctx context.Context) (health.QuorumState, int, int) {
	return g.chk.QuorumProof(ctx)
}
func (g checkerServerGate) ExecutionGate(ctx context.Context) health.GateResult {
	return g.chk.ExecutionGate(ctx)
}
func (g checkerServerGate) DecisionGate(ctx context.Context) health.GateResult {
	return g.chk.DecisionGate(ctx)
}

// TestFleet_DualRun_RecordedWhileNoNodeHoldsTheMajority: four voters split
// 2|2, so no node holds the majority and none may hold the dual-run
// detector's lease. A VM then runs on both hosts of one half. The nodes of
// that half must still record it — positive evidence is recorded without
// quorum (dualrun_lifecycle.go) — and must not resolve it once one copy
// stops, as nothing without the majority proves absence.
//
// Mutation: drop the lease-less observe-only pass from RunDualRunDetector —
// no node records the dual run and the first wait times out.
func TestFleet_DualRun_RecordedWhileNoNodeHoldsTheMajority(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, Relays: 4, RealGossip: true})
	n0, n1 := c.Nodes[0], c.Nodes[1]
	insertVMPolicy(t, n0, "dr-vm", n0.Name, "restart-any")
	c.WaitConverged(t, convergeTimeout)
	n0.Virt.SetState("dr-vm", libvirtfake.StateRunning)
	genesisByTick(t, c, n0)

	chks := map[string]*health.Checker{}
	for _, n := range c.Nodes {
		chk := health.NewChecker(n.Name, n.PKIDir, n.DB)
		chk.SetPeerReadiness(n.Server.PeerReady)
		go chk.Start(ctx)
		chks[n.Name] = chk
		n.Server.SetGate(checkerServerGate{chk: chk})
	}
	eventually(t, 30*time.Second, "every node's checker to see the voter majority", func() bool {
		for _, chk := range chks {
			if st, _, _ := chk.QuorumProof(ctx); st != health.QuorumYes {
				return false
			}
		}
		return true
	})
	for _, n := range c.Nodes {
		go n.Server.RunDualRunDetector(ctx, 2*time.Second)
	}

	c.SplitGossip(c.Nodes[:2], c.Nodes[2:])
	eventually(t, time.Minute, "every node's checker to lose the voter majority", func() bool {
		for _, chk := range chks {
			if st, _, _ := chk.QuorumProof(ctx); st != health.QuorumNo {
				return false
			}
		}
		return true
	})
	n1.Virt.SetState("dr-vm", libvirtfake.StateRunning)

	eventually(t, time.Minute, "a node of the split half to record dr-vm's dual run", func() bool {
		for _, n := range []*Node{n0, n1} {
			if vmDualRunLifecycle(t, n, "dr-vm") != "" {
				return true
			}
		}
		return false
	})
	eventually(t, time.Minute, "the dual run to be confirmed by a node's own consecutive scans", func() bool {
		for _, n := range []*Node{n0, n1} {
			if vmDualRunLifecycle(t, n, "dr-vm") == corrosion.ConditionConfirmed {
				return true
			}
		}
		return false
	})

	// Nothing without the majority may prove the copy gone.
	n1.Virt.SetState("dr-vm", libvirtfake.StateShutdown)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range []*Node{n0, n1} {
			if vmDualRunLifecycle(t, n, "dr-vm") == "" {
				t.Fatalf("%s resolved dr-vm's dual run with no node holding the voter majority", n.Name)
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
}
