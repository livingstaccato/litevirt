package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// TestFleet_PartitionPause_RegainGraceDoesNotStopRegionFailover is
// DeathInsideRegion/partitioned with the coordinator's quorum-regain grace
// wired to a REAL health.Checker, as the daemon wires it.
//
// The sites are cut, so east's survivors see east's majority and not the
// cluster's: the cluster-wide quorum reads No, and every other consumer of it
// (the VIP demoter, the dual-run detector, the lease-term barrier) keeps
// reading it. Under region scope east's majority is exactly the side that must
// fence its dead host. A grace stamped on the cluster-wide quorum would defer
// that fence for as long as the sites stay cut.
//
// Mutation: key the grace to the cluster-wide quorum whatever the scope (or
// wire the coordinator to the cluster scope) — no fence, and this goes red.
func TestFleet_PartitionPause_RegainGraceDoesNotStopRegionFailover(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c, east, west := siteFleet(t, corrosion.FailoverScopeRegion)
	loadEastSurvivors(t, c, east)
	victim := east[2]
	c.Isolate(victim)
	survivors := []*Node{east[0], east[1]}
	cutSites(c, east, west)
	reportDown(t, clock, survivors, append([]*Node{victim}, west...))
	reportDown(t, clock, west, east)
	c.WaitConverged(t, convergeTimeout, survivors...)

	cs := c.NewCoordinators(clock)
	for _, n := range survivors {
		chk := health.NewChecker(n.Name, n.PKIDir, n.DB)
		seen := map[string]bool{}
		for _, o := range c.Nodes {
			if o != n {
				seen[o.Name] = inSet(o.Name, survivors)
			}
		}
		chk.SeedPeersForTests(seen)
		// The other consumers of the cluster-wide quorum, which keep reading
		// No while the sites are cut, and the pauser's execution quorum.
		for i := 0; i < 3; i++ {
			if st, _, _ := chk.QuorumProof(ctx); st != health.QuorumNo {
				t.Fatalf("%s: setup: cluster-wide quorum %d, want No", n.Name, st)
			}
			if st, _, _ := chk.ExecutionQuorum(ctx); st != health.QuorumYes {
				t.Fatalf("%s: setup: east execution quorum %d, want Yes", n.Name, st)
			}
		}
		cs.ByNode[n.Name].QuorumRegain = chk.InQuorumRegainGraceFor
	}
	cs.Tick(ctx, east[0])
	c.WaitConverged(t, convergeTimeout, survivors...)
	if fenced := fencedTargets(cs); strings.Join(fenced, ",") != victim.Name {
		t.Fatalf("region scope with the regain grace wired: fenced %v, want exactly the dead east host %s", fenced, victim.Name)
	}
}
