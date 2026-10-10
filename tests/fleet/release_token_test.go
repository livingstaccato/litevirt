// Fleet scenario for the release token and its per-feature used bit
// (capabilities.ReleaseToken, health.Checker.RequireFeature): real checkers
// latching over real Pings, the used record travelling between independent
// replicas, and a used record for a token a node does not know quarantining
// that node over real replication.
package fleet

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// wireReleaseFeatures gives every node the daemon's release-feature wiring:
// the cluster_policies write gate (wireClusterPolicyGate) and the server's
// release-feature gate, both against the node's real checker. A feature
// branch's fleet test calls it after gateAll.
func wireReleaseFeatures(t *testing.T, c *Cluster, gates map[string]*health.Checker) {
	t.Helper()
	for _, n := range c.Nodes {
		g := gates[n.Name]
		n.DB.SetClusterPolicyGate(func() bool { return g.DurablyLatched(capabilities.FailoverScopeV1) })
		n.Server.SetReleaseFeatureGate(g)
	}
}

func featureUsedOn(t *testing.T, n *Node, token, feature string) bool {
	t.Helper()
	used, err := corrosion.ReleaseFeatureUsed(context.Background(), n.DB, token, feature)
	if err != nil {
		t.Fatalf("ReleaseFeatureUsed on %s: %v", n.Name, err)
	}
	return used
}

// TestFleet_ReleaseFeature_LatchRecordAndRollbackGuard walks the mechanism in
// the order a cluster meets it.
func TestFleet_ReleaseFeature_LatchRecordAndRollbackGuard(t *testing.T) {
	t.Cleanup(capabilities.OverrideFeaturesForTest(map[capabilities.Feature]capabilities.FeatureInfo{
		"widgets": {Token: capabilities.ReleaseToken, Description: "Widgets on every VM"},
		"gadgets": {Token: capabilities.ReleaseToken, Description: "Gadgets on every host"},
	}))
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 1126})
	gates := gateAll(t, c)
	wireReleaseFeatures(t, c, gates)
	a, b, old := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(ctx, capabilities.FailoverScopeV1) {
			t.Fatalf("%s: failover_scope_v1 did not latch", n.Name)
		}
	}
	c.WaitConverged(t, convergeTimeout)

	// 1. A host still on the previous build (modelled as one advertising
	// nothing, as a quarantined or older node does to this token): the
	// release token cannot latch, the feature is refused with the
	// operator-facing reason, and nothing is recorded anywhere.
	old.Server.SetWALQuarantined(func() bool { return true })
	err := a.Server.RequireReleaseFeature(ctx, "widgets")
	if status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "the cluster upgrade must finish first (widgets needs "+capabilities.ReleaseToken+")") {
		t.Fatalf("RequireReleaseFeature with %s on the old build: %v", old.Name, err)
	}
	if gates[a.Name].Latched(capabilities.ReleaseToken) {
		t.Fatalf("the release token latched across %s", old.Name)
	}

	// 2. Every host on this build: the token latches, the first use is
	// recorded on a and reaches every replica.
	old.Server.SetWALQuarantined(func() bool { return false })
	// eventually: the checker caches step 1's negative for capActiveNegTTL.
	var lastErr error
	eventually(t, 10*time.Second, "the first use to be accepted on a uniform fleet", func() bool {
		lastErr = a.Server.RequireReleaseFeature(ctx, "widgets")
		return lastErr == nil
	})
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if !featureUsedOn(t, n, capabilities.ReleaseToken, "widgets") {
			t.Fatalf("%s does not see the widgets use a recorded", n.Name)
		}
		if featureUsedOn(t, n, capabilities.ReleaseToken, "gadgets") {
			t.Fatalf("%s sees gadgets used; nothing used it", n.Name)
		}
	}
	// b, which never used it, now reads it as used and writes nothing more.
	if err := gates[b.Name].RequireFeature(ctx, "widgets"); err != nil {
		t.Fatalf("RequireFeature on %s for a feature already in use: %v", b.Name, err)
	}

	// 3. old is rolled back after the latch. The latch is monotone, so it
	// stays; but a FIRST use re-confirms every recipient, and is refused.
	// A feature already in use is not refused: its data is already out.
	old.Server.SetWALQuarantined(func() bool { return true })
	if err := a.Server.RequireReleaseFeature(ctx, "gadgets"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("first use of gadgets with %s rolled back: %v, want FailedPrecondition", old.Name, err)
	}
	if featureUsedOn(t, a, capabilities.ReleaseToken, "gadgets") {
		t.Fatal("gadgets was recorded while a recipient could not keep it")
	}
	if err := a.Server.RequireReleaseFeature(ctx, "widgets"); err != nil {
		t.Fatalf("a feature already in use was refused: %v", err)
	}
	old.Server.SetWALQuarantined(func() bool { return false })

	// 4. A node rolled back onto this build from a LATER one sees a use
	// recorded under a token it does not know. Modelled from the other side:
	// a records a use of a future token; every replica that applies it is
	// quarantined, and stops emitting replicated writes.
	const future = "release_2099_01_v1"
	if err := corrosion.RecordReleaseFeatureUse(ctx, a.DB, future, "sprockets", a.Name); err != nil {
		t.Fatalf("record a future token's use: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range []*Node{b, old} {
		if got := n.DB.ReleaseUseQuarantine(); !slices.Equal(got, []string{future}) {
			t.Fatalf("%s: ReleaseUseQuarantine = %v after the future use replicated, want [%s]", n.Name, got, future)
		}
		if err := corrosion.InsertProject(ctx, n.DB, corrosion.ProjectRecord{Name: "after-" + n.Name}); err == nil ||
			!strings.Contains(err.Error(), "quarantine") {
			t.Fatalf("%s accepted a replicated write after a use it cannot honour arrived: %v", n.Name, err)
		}
	}
}
