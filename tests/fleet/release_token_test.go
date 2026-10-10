// Fleet scenarios for the release token and its per-feature used bit
// (capabilities.ReleaseToken, health.Checker.WithFeature): real checkers
// latching over real Pings, the used record travelling between independent
// replicas and acknowledged over a real RPC, a used record for a token a node
// does not know quarantining that node over real replication, a rolled-back
// node held in probation until a voter majority has been asked, and an
// upgraded node refusing replication from a peer that cannot keep a used
// feature's data.
package fleet

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// wireReleaseFeatures gives every node the daemon's release-feature wiring:
// the cluster_policies write gate (wireClusterPolicyGate), the acknowledgement
// RPC a first use waits on, the server's release-feature gate, and the
// replication-source gate, all against the node's real checker. A feature
// branch's fleet test calls it after gateAll.
func wireReleaseFeatures(t *testing.T, c *Cluster, gates map[string]*health.Checker) {
	t.Helper()
	for _, n := range c.Nodes {
		n := n
		g := gates[n.Name]
		n.DB.SetClusterPolicyGate(func() bool { return g.DurablyLatched(capabilities.FailoverScopeV1) })
		g.SetReleaseUseConfirmer(n.Server.PeerHoldsReleaseFeatureUse)
		n.Server.SetReleaseFeatureGate(g)
		n.DB.SetReplicationSourceGate(n.Server.ReleasePeerAllowed)
		// The daemon's predicate: a rollback quarantine or a tripped use, never
		// a probation (N1).
		n.Server.SetWALQuarantined(n.DB.WALQuarantined)
		// A peer advertising a release token this build does not know: a
		// non-blocking look at its cluster_policies, never a probation (N2).
		// Synchronous here so a scenario can assert right after the Ping.
		g.SetUnknownReleaseTokenObserver(func(peer, tok string) {
			corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).OnUnknownReleaseToken(context.Background(), peer, tok)
		})
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

func releaseFeatures(t *testing.T) {
	t.Cleanup(capabilities.OverrideFeaturesForTest(map[capabilities.Feature]capabilities.FeatureInfo{
		"widgets": {Token: capabilities.ReleaseToken, Description: "Widgets on every VM"},
		"gadgets": {Token: capabilities.ReleaseToken, Description: "Gadgets on every host"},
	}))
}

// writeFeature runs a feature write on n through the gate; the write itself
// checks its grant, as a real writer of the feature's data does.
func writeFeature(ctx context.Context, n *Node, f capabilities.Feature) error {
	return n.Server.WithReleaseFeature(ctx, f, func(_ context.Context, g capabilities.FeatureGrant) error {
		return g.Check(f)
	})
}

func latchedFleet(t *testing.T, nodes int, seed int64) (*Cluster, map[string]*health.Checker) {
	t.Helper()
	ctx := context.Background()
	c := New(t, Options{Nodes: nodes, IndependentReplicas: true, FaultSeed: seed})
	gates := gateAll(t, c)
	wireReleaseFeatures(t, c, gates)
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(ctx, capabilities.FailoverScopeV1) {
			t.Fatalf("%s: failover_scope_v1 did not latch", n.Name)
		}
	}
	c.WaitConverged(t, convergeTimeout)
	return c, gates
}

// TestFleet_ReleaseFeature_LatchRecordAndRollbackGuard walks the mechanism in
// the order a cluster meets it.
func TestFleet_ReleaseFeature_LatchRecordAndRollbackGuard(t *testing.T) {
	releaseFeatures(t)
	ctx := context.Background()
	c, gates := latchedFleet(t, 3, 1126)
	a, b, old := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	// 1. A host still on the previous build (modelled as one advertising
	// nothing, as a quarantined or older node does to this token): the
	// release token cannot latch, the feature is refused with the
	// operator-facing reason, and nothing is recorded anywhere.
	old.Server.SetWALQuarantined(func() bool { return true })
	err := writeFeature(ctx, a, "widgets")
	if status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "the cluster upgrade must finish first (widgets needs "+capabilities.ReleaseToken+")") {
		t.Fatalf("WithReleaseFeature with %s on the old build: %v", old.Name, err)
	}
	if gates[a.Name].Latched(capabilities.ReleaseToken) {
		t.Fatalf("the release token latched across %s", old.Name)
	}

	// 2. Every host on this build: the token latches, the first use is
	// recorded on a, acknowledged by every recipient over the real RPC, and so
	// already on every replica when the write runs.
	old.Server.SetWALQuarantined(old.DB.WALQuarantined)
	var lastErr error
	eventually(t, 10*time.Second, "the first use to be accepted on a uniform fleet", func() bool {
		lastErr = writeFeature(ctx, a, "widgets")
		return lastErr == nil
	})
	for _, n := range c.Nodes {
		if !featureUsedOn(t, n, capabilities.ReleaseToken, "widgets") {
			t.Fatalf("%s does not hold the widgets record although a's write has run", n.Name)
		}
		if featureUsedOn(t, n, capabilities.ReleaseToken, "gadgets") {
			t.Fatalf("%s sees gadgets used; nothing used it", n.Name)
		}
	}
	if err := writeFeature(ctx, b, "widgets"); err != nil {
		t.Fatalf("a write on %s of a feature already in use: %v", b.Name, err)
	}

	// 3. old is rolled back after the latch. The latch is monotone, so it
	// stays; but a FIRST use re-confirms every recipient, and is refused.
	// A feature already in use is not refused: its data is already out.
	old.Server.SetWALQuarantined(func() bool { return true })
	if err := writeFeature(ctx, a, "gadgets"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("first use of gadgets with %s rolled back: %v, want FailedPrecondition", old.Name, err)
	}
	if featureUsedOn(t, a, capabilities.ReleaseToken, "gadgets") {
		t.Fatal("gadgets was recorded while a recipient could not keep it")
	}
	if err := writeFeature(ctx, a, "widgets"); err != nil {
		t.Fatalf("a feature already in use was refused: %v", err)
	}
	old.Server.SetWALQuarantined(old.DB.WALQuarantined)

	// 4. A node rolled back onto this build from a LATER one sees a use
	// recorded under a token it does not know. Modelled from the other side:
	// a records a use of a future token; every replica that applies it is
	// quarantined, and stops emitting replicated writes.
	const future = "release_2099_01_v1"
	if err := corrosion.RecordReleaseFeatureUse(ctx, a.DB, future, "sprockets", a.Name, false); err != nil {
		t.Fatalf("record a future token's use: %v", err)
	}
	for _, n := range []*Node{b, old} {
		eventually(t, convergeTimeout, n.Name+" to apply the future use", func() bool {
			return featureUsedOn(t, n, future, "sprockets")
		})
		if got := n.DB.ReleaseUseQuarantine(); !slices.Equal(got, []string{future}) {
			t.Fatalf("%s: ReleaseUseQuarantine = %v after the future use replicated, want [%s]", n.Name, got, future)
		}
		if err := corrosion.InsertProject(ctx, n.DB, corrosion.ProjectRecord{Name: "after-" + n.Name}); err == nil ||
			!strings.Contains(err.Error(), "quarantine") {
			t.Fatalf("%s accepted a replicated write after a use it cannot honour arrived: %v", n.Name, err)
		}
	}
}

// TestFleet_ReleaseFeature_ProbationHoldsARolledBackNode is C1. x has been
// rolled back onto this build below a LATER release token whose marker says
// safe_if_unused, and its own replica holds no use of it — it was away when
// the use was recorded. Feature data then reaches it from an origin that is
// not the recorder (cross-origin), with no record ahead of it on that stream.
// Probation keeps x from emitting a single replicated write until it has asked
// a voter majority, and that pull finds the use and quarantines it.
func TestFleet_ReleaseFeature_ProbationHoldsARolledBackNode(t *testing.T) {
	releaseFeatures(t)
	ctx := context.Background()
	c, _ := latchedFleet(t, 3, 1127)
	a, b, x := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	const future = "release_2099_01_v1"

	// Nothing used anywhere: one pull from a voter majority lifts probation.
	// The pull is exempt from the replication-source gate (N2): reading
	// cluster_policies for used records is harmless from any peer.
	x.DB.SetReplicationSourceGate(func(context.Context, string) error { return errors.New("refused") })
	x.DB.EnterReleaseProbation([]string{future})
	if err := corrosion.InsertProject(ctx, x.DB, corrosion.ProjectRecord{Name: "in-probation"}); err == nil ||
		!strings.Contains(err.Error(), "probation") {
		t.Fatalf("%s emitted a replicated write in probation: %v", x.Name, err)
	}
	lifted, err := corrosion.NewAntiEntropy(x.DB, x.PKIDir, 0).VerifyReleaseProbation(ctx)
	if err != nil || !lifted {
		t.Fatalf("VerifyReleaseProbation with nothing used: lifted=%v err=%v", lifted, err)
	}
	if err := corrosion.InsertProject(ctx, x.DB, corrosion.ProjectRecord{Name: "after-probation"}); err != nil {
		t.Fatalf("a write after probation lifted: %v", err)
	}
	x.DB.SetReplicationSourceGate(x.Server.ReleasePeerAllowed)

	// x restarts below the token again. a records a use of the future feature
	// while its stream to x (and to b, so b — on this build, in this harness —
	// is not quarantined by it before it writes) is held. Then b, which is not
	// the recorder, writes the feature's data, and b's stream reaches x: data
	// with no record ahead of it, the cross-origin path.
	x.DB.EnterReleaseProbation([]string{future})
	c.SetLinkFault(a, x, LinkFault{Block: true})
	c.SetLinkFault(a, b, LinkFault{Block: true})
	if err := corrosion.RecordReleaseFeatureUse(ctx, a.DB, future, "sprockets", a.Name, false); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertProject(ctx, b.DB, corrosion.ProjectRecord{Name: "sprocket-data"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, convergeTimeout, "x to apply b's data", func() bool {
		p, _ := corrosion.GetProject(ctx, x.DB, "sprocket-data")
		return p != nil
	})
	if featureUsedOn(t, x, future, "sprockets") {
		t.Fatal("setup: x holds the record; the cross-origin path was not exercised")
	}
	if err := corrosion.InsertProject(ctx, x.DB, corrosion.ProjectRecord{Name: "over-the-data"}); err == nil {
		t.Fatalf("%s emitted a replicated write while holding data it cannot keep and no record of it", x.Name)
	}

	// The pull from a majority finds the use: quarantined for good.
	c.ClearLinkFaults()
	lifted, err = corrosion.NewAntiEntropy(x.DB, x.PKIDir, 0).VerifyReleaseProbation(ctx)
	if lifted {
		t.Fatalf("probation lifted although a use of %s is recorded (err %v)", future, err)
	}
	if got := x.DB.ReleaseUseQuarantine(); !slices.Equal(got, []string{future}) {
		t.Fatalf("ReleaseUseQuarantine after the majority pull = %v, want [%s]", got, future)
	}
}

// TestFleet_ReleaseFeature_UpgradedNodesRefuseAPeerThatCannotKeepIt is I6. A
// host that was away for the latch and the first use comes back on a build
// with no release token at all, so nothing on its side can stop it. Its peers
// can: once a feature is used they back-pressure its replication instead of
// applying writes that would rewrite the feature's data away.
func TestFleet_ReleaseFeature_UpgradedNodesRefuseAPeerThatCannotKeepIt(t *testing.T) {
	releaseFeatures(t)
	ctx := context.Background()
	c, gates := latchedFleet(t, 3, 1128)
	a, _, old := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	var lastErr error
	eventually(t, 10*time.Second, "the first use", func() bool {
		lastErr = writeFeature(ctx, a, "widgets")
		return lastErr == nil
	})
	// old is now on an older build: it advertises no release token. Model it
	// by withholding its advertisement while it keeps writing.
	old.Server.SetWALQuarantined(func() bool { return true })
	// Past the receivers' reuse of an earlier answer about old
	// (grpcapi releasePeerCheckTTL, 5s): the window a restart shorter than that
	// would leave.
	time.Sleep(6 * time.Second)
	if err := corrosion.InsertProject(ctx, old.DB, corrosion.ProjectRecord{Name: "from-old"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second) // several push rounds
	if p, _ := corrosion.GetProject(ctx, a.DB, "from-old"); p != nil {
		t.Fatalf("%s applied a write from %s, which cannot keep a used feature's data", a.Name, old.Name)
	}
	// So far b had not latched the token, so it took old's pushes and relayed
	// them; a refused them by their ORIGIN. Now every upgraded node latches
	// (the HA monitor's job in production, while old still advertised it),
	// old rolls back again, and is refused by every push path — and
	// anti-entropy does not pull its rows either.
	old.Server.SetWALQuarantined(old.DB.WALQuarantined)
	for _, n := range c.Nodes[:2] {
		n := n
		eventually(t, 10*time.Second, n.Name+" to latch the release token", func() bool {
			return gates[n.Name].Enforced(ctx, capabilities.ReleaseToken)
		})
	}
	old.Server.SetWALQuarantined(func() bool { return true })
	time.Sleep(6 * time.Second)
	if err := corrosion.InsertProject(ctx, old.DB, corrosion.ProjectRecord{Name: "from-old-2"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	corrosion.NewAntiEntropy(a.DB, a.PKIDir, 0).RunOnce(ctx)
	if p, _ := corrosion.GetProject(ctx, a.DB, "from-old-2"); p != nil {
		t.Fatalf("%s took a row from %s by anti-entropy", a.Name, old.Name)
	}

	// Back on a build that keeps it: its writes flow again.
	old.Server.SetWALQuarantined(old.DB.WALQuarantined)
	eventually(t, 2*convergeTimeout, "old's writes to arrive once it advertises the token", func() bool {
		p, _ := corrosion.GetProject(ctx, a.DB, "from-old")
		p2, _ := corrosion.GetProject(ctx, a.DB, "from-old-2")
		return p != nil && p2 != nil
	})
}

// TestFleet_ReleaseFeature_ProbationIsNotQuarantine is N1. A host in release
// probation refuses its own replicated writes, but to its peers it is an
// ordinary member: it keeps advertising, its Ping never says wal_quarantined
// (which is what makes a peer record a rolled_back_latch isolation), and it
// says release_probation instead.
func TestFleet_ReleaseFeature_ProbationIsNotQuarantine(t *testing.T) {
	releaseFeatures(t)
	ctx := context.Background()
	c, _ := latchedFleet(t, 3, 1129)
	a, x := c.Nodes[0], c.Nodes[2]
	x.DB.EnterReleaseProbation([]string{"release_2099_01_v1"})
	resp, err := c.SelfClient(x).Ping(ctx, &pb.PingRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetWalQuarantined() || !resp.GetReleaseProbation() {
		t.Fatalf("%s Ping in probation: wal_quarantined=%v release_probation=%v, want false/true",
			x.Name, resp.GetWalQuarantined(), resp.GetReleaseProbation())
	}
	caps, _, err := a.Server.PeerCapabilities(ctx, x.Name)
	if err != nil || !slices.Contains(caps, capabilities.ReleaseToken) {
		t.Fatalf("%s sees %s advertising %v (err %v), want it to keep advertising", a.Name, x.Name, caps, err)
	}
}

// TestFleet_ReleaseFeature_ForwardRollRefusesNothing is N2. A feature of this
// release is in use. The first host upgraded to the next release is a
// NON-voter, and the hosts still on this release see it advertise a release
// token they do not know. That token cannot have a use — it cannot latch while
// they do not advertise it — so they look at its cluster_policies without
// stopping anything: no probation, no refused write. Only a use actually found
// there would quarantine them.
func TestFleet_ReleaseFeature_ForwardRollRefusesNothing(t *testing.T) {
	releaseFeatures(t)
	ctx := context.Background()
	c, gates := latchedFleet(t, 4, 1130)
	a, b, cc, next := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
	var lastErr error
	eventually(t, 10*time.Second, "the first use", func() bool {
		lastErr = writeFeature(ctx, a, "widgets")
		return lastErr == nil
	})
	// next becomes a non-voter (maintenance) and is "upgraded": the hosts on
	// this release see it advertise the next release's token.
	if err := corrosion.UpdateHostState(ctx, a.DB, next.Name, "maintenance"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	const nextToken = "release_2099_01_v1"
	for _, n := range []*Node{a, b, cc} {
		n := n
		gates[n.Name].SetPeerPinger(func(pctx context.Context, host string) ([]string, time.Time, error) {
			caps, wall, err := n.Server.PeerCapabilities(pctx, host)
			if host == next.Name && err == nil {
				caps = append(caps, nextToken)
			}
			return caps, wall, err
		})
		gates[n.Name].CapabilityActive(ctx, capabilities.ReleaseToken)
	}
	for i, n := range []*Node{a, b, cc} {
		if p := n.DB.ReleaseProbation(); len(p) != 0 {
			t.Fatalf("%s entered probation %v on a forward roll", n.Name, p)
		}
		if err := corrosion.InsertProject(ctx, n.DB, corrosion.ProjectRecord{Name: "during-roll-" + n.Name}); err != nil {
			t.Fatalf("%s refused a replicated write during a forward roll: %v", n.Name, err)
		}
		if err := writeFeature(ctx, n, "widgets"); err != nil {
			t.Fatalf("%s refused a feature write during a forward roll (%d): %v", n.Name, i, err)
		}
	}
	// The look is real: a use found on the advertising host does quarantine.
	c.SetLinkFault(next, a, LinkFault{Block: true})
	c.SetLinkFault(next, b, LinkFault{Block: true})
	c.SetLinkFault(next, cc, LinkFault{Block: true})
	if err := corrosion.RecordReleaseFeatureUse(ctx, next.DB, nextToken, "sprockets", next.Name, true); err != nil {
		t.Fatal(err)
	}
	// What the observer runs when a peer advertises an unknown release token.
	corrosion.NewAntiEntropy(a.DB, a.PKIDir, 0).OnUnknownReleaseToken(ctx, next.Name, nextToken)
	if got := a.DB.ReleaseUseQuarantine(); !slices.Equal(got, []string{nextToken}) {
		t.Fatalf("%s after finding a use on %s: ReleaseUseQuarantine = %v", a.Name, next.Name, got)
	}
}
