package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// regionGateFleet is a 3+2 cluster, east {e1,e2,e3} and west {w1,w2}, seen
// from `self`. The failover scope is set to `scope`.
func regionGateFleet(t *testing.T, self, scope string) (*Checker, *corrosion.Client) {
	t.Helper()
	ctx := context.Background()
	db := testCheckHostDB(t)
	regions := map[string]string{"e1": "east", "e2": "east", "e3": "east", "w1": "west", "w2": "west"}
	for _, h := range []string{"e1", "e2", "e3", "w1", "w2"} {
		gateHost(t, db, h, "active", "worker")
		if err := corrosion.UpdateHostRegion(ctx, db, h, regions[h]); err != nil {
			t.Fatalf("UpdateHostRegion %s: %v", h, err)
		}
	}
	db.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.SetFailoverScope(ctx, db, scope, "test"); err != nil {
		t.Fatalf("SetFailoverScope(%s): %v", scope, err)
	}
	return NewChecker(self, "/etc/litevirt/pki", db), db
}

// sitePartition is what w1 sees in a west/east partition: its own region up,
// every east host down.
var westSideOfPartition = map[string]bool{"w2": true, "e1": false, "e2": false, "e3": false}

// eastSideOfPartition is what e1 sees: east up, west down.
var eastSideOfPartition = map[string]bool{"e2": true, "e3": true, "w1": false, "w2": false}

// TestRegionQuorumProof counts only the region's voters, from this daemon's own
// probes.
func TestRegionQuorumProof(t *testing.T) {
	ctx := context.Background()
	c, _ := regionGateFleet(t, "e1", corrosion.FailoverScopeRegion)
	warm(c, eastSideOfPartition)
	if st, live, needed := c.RegionQuorumProof(ctx, "east"); st != QuorumYes || live != 3 || needed != 2 {
		t.Fatalf("east from inside east: state=%d live=%d needed=%d, want Yes/3/2", st, live, needed)
	}
	if st, live, needed := c.RegionQuorumProof(ctx, "west"); st != QuorumNo || live != 0 || needed != 2 {
		t.Fatalf("west from across the partition: state=%d live=%d needed=%d, want No/0/2", st, live, needed)
	}
	// A region with no voters has no quorum to prove.
	if st, _, _ := c.RegionQuorumProof(ctx, "nowhere"); st != QuorumNo {
		t.Fatalf("a region with no voters must not report quorum: state=%d", st)
	}
}

// TestExecutionGate_ClusterScope_MinorityStalls pins today's behaviour: with the
// cluster-wide scope the west minority (2 of 5) has no quorum and refuses.
func TestExecutionGate_ClusterScope_MinorityStalls(t *testing.T) {
	c, _ := regionGateFleet(t, "w1", corrosion.FailoverScopeCluster)
	warm(c, westSideOfPartition)
	if g := c.ExecutionGate(context.Background()); g.OK || g.Reason != ReasonNoQuorum {
		t.Fatalf("cluster scope, west minority: ExecutionGate=%+v, want refused no_quorum", g)
	}
}

// TestExecutionGate_RegionScope_CountsOwnRegion: with region scope the same
// west host has its own region's quorum and executes, because nothing outside
// west may recover west's workloads.
func TestExecutionGate_RegionScope_CountsOwnRegion(t *testing.T) {
	c, _ := regionGateFleet(t, "w1", corrosion.FailoverScopeRegion)
	warm(c, westSideOfPartition)
	if g := c.ExecutionGate(context.Background()); !g.OK {
		t.Fatalf("region scope, west with its own quorum: ExecutionGate=%+v, want OK", g)
	}
}

// TestExecutionGate_RegionScope_ClusterQuorumIsNotEnough: a host cut off from
// its own region but reaching the others has cluster-wide quorum and must still
// refuse. Its own region's majority may fence it.
func TestExecutionGate_RegionScope_ClusterQuorumIsNotEnough(t *testing.T) {
	c, _ := regionGateFleet(t, "e1", corrosion.FailoverScopeRegion)
	// e1 reaches both west hosts but neither east peer: 3 of 5 cluster-wide.
	warm(c, map[string]bool{"e2": false, "e3": false, "w1": true, "w2": true})
	if st, _, _ := c.QuorumProof(context.Background()); st != QuorumYes {
		t.Fatalf("precondition: e1 must hold cluster-wide quorum, got %d", st)
	}
	if g := c.ExecutionGate(context.Background()); g.OK {
		t.Fatalf("region scope: a host without its own region's quorum executed on cluster-wide quorum")
	}
}

// TestQuorumProof_StaysClusterWide: the cluster-wide proof (VIP demotion, the
// lease-term barrier, dual-run resolution) is not narrowed by the policy.
func TestQuorumProof_StaysClusterWide(t *testing.T) {
	c, _ := regionGateFleet(t, "w1", corrosion.FailoverScopeRegion)
	warm(c, westSideOfPartition)
	if st, live, needed := c.QuorumProof(context.Background()); st != QuorumNo || live != 2 || needed != 3 {
		t.Fatalf("QuorumProof under region scope: state=%d live=%d needed=%d, want No/2/3 (cluster-wide)", st, live, needed)
	}
}

// TestDecisionGateForRegion: the coordinator's region-scoped decide gate needs
// the TARGET region's quorum as this daemon probed it, whichever region the
// daemon is in.
func TestDecisionGateForRegion(t *testing.T) {
	ctx := context.Background()
	c, _ := regionGateFleet(t, "e1", corrosion.FailoverScopeRegion)
	warm(c, eastSideOfPartition)
	if g := c.DecisionGateForRegion(ctx, "east"); !g.OK {
		t.Fatalf("east deciding for east with east's quorum: %+v", g)
	}
	if g := c.DecisionGateForRegion(ctx, "west"); g.OK || g.Reason != ReasonNoQuorum {
		t.Fatalf("east deciding for west across the partition: %+v, want refused no_quorum", g)
	}
	// Healed: e1 reaches every west voter, so it may decide for west.
	warm(c, map[string]bool{"e2": true, "e3": true, "w1": true, "w2": true})
	if g := c.DecisionGateForRegion(ctx, "west"); !g.OK {
		t.Fatalf("east deciding for west with west reachable: %+v", g)
	}
}

// TestExecutionGate_UnknownScopeFailsClosed: a scope value this build does not
// implement refuses rather than guessing either way.
func TestExecutionGate_UnknownScopeFailsClosed(t *testing.T) {
	ctx := context.Background()
	c, db := regionGateFleet(t, "e1", corrosion.FailoverScopeCluster)
	warm(c, map[string]bool{"e2": true, "e3": true, "w1": true, "w2": true})
	if err := db.Execute(ctx, `INSERT INTO cluster_policies (key, value, set_by, updated_at, deleted_at)
	 VALUES (?, ?, ?, ?, NULL)
	 ON CONFLICT(key) DO UPDATE SET value = excluded.value, set_by = excluded.set_by,
	   updated_at = excluded.updated_at, deleted_at = NULL`, "failover_scope", "zone", "future", db.NowTS()); err != nil {
		t.Fatalf("seed unknown scope: %v", err)
	}
	if g := c.ExecutionGate(ctx); g.OK || g.Reason != ReasonNoQuorum {
		t.Fatalf("an unknown failover scope must fail the execution gate closed with no_quorum, got %+v", g)
	}
	if g := c.DecisionGateForRegion(ctx, "east"); g.OK {
		t.Fatalf("an unknown failover scope must fail the region decision gate closed")
	}
}
