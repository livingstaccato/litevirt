package failover

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// regionReadingGate reads the cluster-wide quorum as held (fakeFailoverGate)
// and each region's from region; a region not listed reads No.
type regionReadingGate struct {
	fakeFailoverGate
	region map[string]health.QuorumState
}

func (g regionReadingGate) RegionQuorumProof(_ context.Context, r string) (health.QuorumState, int, int) {
	if st, ok := g.region[r]; ok {
		return st, 2, 2
	}
	return health.QuorumNo, 1, 2
}

func (g regionReadingGate) DecisionGateForRegion(ctx context.Context, r string) health.GateResult {
	if st, _, _ := g.RegionQuorumProof(ctx, r); st == health.QuorumYes {
		return health.GateResult{OK: true}
	}
	return health.GateResult{Reason: health.ReasonNoQuorum}
}

// TestLease_RegionScope_OwnRegionLostStandsDown: under region scope a
// coordinator cut off from its own region's majority neither takes nor renews
// the failover lease, although it still holds the cluster-wide majority and
// another region's. Its own region's majority may need the lease to fence it,
// and hosts that reach both sides would keep its renewals live there.
//
// Mutation: drop health.LostOwnRegionQuorumUnder from lostEveryDecisionQuorum —
// the lease is taken on the cluster-wide reading and this goes red.
func TestLease_RegionScope_OwnRegionLostStandsDown(t *testing.T) {
	ctx := context.Background()
	db := regionFixture(t, corrosion.FailoverScopeRegion)
	c := newTestCoordinator("coordinator", db)

	c.Gate = regionReadingGate{region: map[string]health.QuorumState{"west": health.QuorumYes}}
	if held, err := c.acquireLeaseResult(ctx); held || !errors.Is(err, errLeaseNoQuorum) {
		t.Fatalf("own region east lost, cluster and west held: lease held=%v err=%v, want a stand-down", held, err)
	}
	if h, _, err := corrosion.ReadLeaseRow(ctx, db, failoverLeaseKey); err != nil || h != "" {
		t.Fatalf("a lease row names %q (%v) after the stand-down", h, err)
	}

	c.Gate = regionReadingGate{region: map[string]health.QuorumState{"east": health.QuorumYes, "west": health.QuorumYes}}
	if held, err := c.acquireLeaseResult(ctx); !held || err != nil {
		t.Fatalf("control: own region held: lease held=%v err=%v, want held", held, err)
	}
}

// TestLease_RegionScope_SmallOwnRegionKeepsTheLease: a region with fewer than
// three voters cannot fence its own hosts (region-scoped-failover.md §3), so
// no recovery there waits on the lease, and a holder that lost it keeps the
// lease for the regions it still reaches.
//
// Mutation: drop the three-voter bound in health.LostOwnRegionQuorumUnder — the
// coordinator stands down and this goes red.
func TestLease_RegionScope_SmallOwnRegionKeepsTheLease(t *testing.T) {
	ctx := context.Background()
	db := regionFixture(t, corrosion.FailoverScopeRegion)
	if err := corrosion.UpdateHostRegion(ctx, db, "e2", "west"); err != nil {
		t.Fatalf("UpdateHostRegion: %v", err)
	}
	c := newTestCoordinator("coordinator", db)
	c.Gate = regionReadingGate{region: map[string]health.QuorumState{"west": health.QuorumYes}}
	if held, err := c.acquireLeaseResult(ctx); !held || err != nil {
		t.Fatalf("own region east has two voters: lease held=%v err=%v, want held", held, err)
	}
}

// TestLease_ClusterScope_IgnoresTheOwnRegion: under the cluster scope a
// region decides nothing, so its reading does not move the lease.
//
// Mutation: drop the scope check in health.LostOwnRegionQuorumUnder — the
// coordinator stands down on its region's reading and this goes red.
func TestLease_ClusterScope_IgnoresTheOwnRegion(t *testing.T) {
	ctx := context.Background()
	db := regionFixture(t, corrosion.FailoverScopeCluster)
	c := newTestCoordinator("coordinator", db)
	c.Gate = regionReadingGate{region: map[string]health.QuorumState{"west": health.QuorumYes}}
	if held, err := c.acquireLeaseResult(ctx); !held || err != nil {
		t.Fatalf("cluster scope, cluster-wide majority held: lease held=%v err=%v, want held", held, err)
	}
}

// TestLease_RegionScope_OwnRegionInItsRegainGraceStandsDown: the failover
// lease holds a scope only on a Yes outside that scope's quorum-regain
// grace, and the scope for the own-region check is the region's, not the
// cluster's.
//
// Mutation: key the own-region reading's grace to the cluster scope in
// health.LostOwnRegionQuorumUnder — the grace is not seen and the lease is taken.
func TestLease_RegionScope_OwnRegionInItsRegainGraceStandsDown(t *testing.T) {
	ctx := context.Background()
	db := regionFixture(t, corrosion.FailoverScopeRegion)
	c := newTestCoordinator("coordinator", db)
	c.Gate = regionReadingGate{region: map[string]health.QuorumState{"east": health.QuorumYes, "west": health.QuorumYes}}
	c.QuorumRegain = func(_ context.Context, scope string) bool { return scope == health.RegionQuorumScope("east") }
	if held, err := c.acquireLeaseResult(ctx); held || !errors.Is(err, errLeaseNoQuorum) {
		t.Fatalf("own region east inside its regain grace: lease held=%v err=%v, want a stand-down", held, err)
	}
}
