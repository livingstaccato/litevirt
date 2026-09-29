// Fleet scenarios for region-scoped failover (colonelpanik/litevirt#265,
// docs/design/region-scoped-failover.md).
//
// Five independent replicas in two sites: east = node-0, node-1, node-2 and
// west = node-3, node-4. A site partition is every replication link between the
// two sets blocked in both directions, so each site decides from its own
// replica with the other site's rows frozen, which is what a WAN failure looks
// like to the coordinator.
package fleet

import (
	"context"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/health"
)

var siteRegions = []string{"east", "east", "east", "west", "west"}

// siteFleet brings up the five-node, two-site cluster with vm-east on node-2
// and vm-west on node-3, sets the failover scope on every replica, and returns
// once every replica agrees.
func siteFleet(t *testing.T, scope string) (c *Cluster, east, west []*Node) {
	t.Helper()
	// Every node a relay: with the default three, west's two hosts are leaves
	// of east relays and cannot replicate to each other once the sites are
	// cut. See Options.Relays.
	c = New(t, Options{Nodes: 5, IndependentReplicas: true, FaultSeed: 265, RegionByIndex: siteRegions, Relays: 5})
	east, west = c.Nodes[:3], c.Nodes[3:]
	for _, n := range c.Nodes {
		// Every node runs this build, so failover_scope_v1 would latch; the
		// gate itself is exercised by the RPC scenarios below.
		n.DB.SetClusterPolicyGate(func() bool { return true })
	}
	insertVM(t, c.Nodes[0], "vm-east", east[2].Name)
	insertVM(t, c.Nodes[0], "vm-west", west[0].Name)
	if scope != corrosion.FailoverScopeCluster {
		if err := corrosion.SetFailoverScope(context.Background(), c.Nodes[0].DB, scope, "fleet"); err != nil {
			t.Fatalf("SetFailoverScope(%s): %v", scope, err)
		}
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		p, err := corrosion.GetFailoverScope(context.Background(), n.DB)
		if err != nil || p.Value != scope {
			t.Fatalf("%s reads failover scope %+v (err=%v), want %q", n.Name, p, err, scope)
		}
	}
	return c, east, west
}

// cutSites blocks replication between the two sites in both directions.
func cutSites(c *Cluster, east, west []*Node) {
	for _, e := range east {
		for _, w := range west {
			c.SetLinkFaultBoth(e, w, LinkFault{Block: true})
		}
	}
}

// reportDown has every observer publish its own failed probe of every target.
func reportDown(t *testing.T, clock *VirtualClock, observers, targets []*Node) {
	t.Helper()
	for _, o := range observers {
		for _, tg := range targets {
			if o != tg {
				PublishHealth(t, o, tg.Name, 5, clock.Now())
			}
		}
	}
}

func names(ns []*Node) []string {
	out := make([]string, len(ns))
	for i, n := range ns {
		out[i] = n.Name
	}
	return out
}

func fencedTargets(cs *Coordinators) []string {
	seen := map[string]bool{}
	for _, f := range cs.Fences() {
		seen[f.Target] = true
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func inSet(name string, ns []*Node) bool {
	for _, n := range ns {
		if n.Name == name {
			return true
		}
	}
	return false
}

// regionMetrics records what the coordinators report, per node.
type regionMetrics struct {
	mu       sync.Mutex
	attempts map[string]int
	regions  map[string]int // last RegionsWithoutQuorum per node
}

type nodeMetrics struct {
	node string
	m    *regionMetrics
}

func (n nodeMetrics) Attempt(p, r, e string) {
	n.m.mu.Lock()
	n.m.attempts[p+"|"+r+"|"+e]++
	n.m.mu.Unlock()
}
func (nodeMetrics) VMAction(string, string, string)        {}
func (nodeMetrics) ContainerAction(string, string, string) {}
func (nodeMetrics) StrandedWorkloads(int)                  {}
func (n nodeMetrics) RegionsWithoutQuorum(k int) {
	n.m.mu.Lock()
	n.m.regions[n.node] = k
	n.m.mu.Unlock()
}

func withRegionMetrics(cs *Coordinators) *regionMetrics {
	m := &regionMetrics{attempts: map[string]int{}, regions: map[string]int{}}
	for name, coord := range cs.ByNode {
		coord.Metrics = nodeMetrics{node: name, m: m}
	}
	return m
}

func (m *regionMetrics) count(phase, result, class string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.attempts[phase+"|"+result+"|"+class]
}

// TestFleet_RegionScopedFailover_SitePartition is the scenario #265 is about.
//
// With the cluster-wide scope the east majority fences both west hosts and
// moves vm-west east across the link that just failed. That is today's
// contract and it is pinned here, so a change to it is a decision rather than a
// side effect. With region scope nothing is fenced on either side and every
// replica still has vm-west on its west host.
func TestFleet_RegionScopedFailover_SitePartition(t *testing.T) {
	for _, scope := range []string{corrosion.FailoverScopeCluster, corrosion.FailoverScopeRegion} {
		t.Run(scope, func(t *testing.T) {
			ctx := context.Background()
			clock := NewVirtualClock(time.Now().UTC())
			c, east, west := siteFleet(t, scope)
			cutSites(c, east, west)
			reportDown(t, clock, east, west)
			reportDown(t, clock, west, east)
			c.WaitConverged(t, convergeTimeout, east...)
			c.WaitConverged(t, convergeTimeout, west...)

			cs := c.NewCoordinators(clock)
			m := withRegionMetrics(cs)
			// One coordinator per site: each side of a partition takes the
			// partition-local lease, which is what the CRDT lease does.
			cs.Tick(ctx, east[0], west[0])
			c.WaitConverged(t, convergeTimeout, east...)
			c.WaitConverged(t, convergeTimeout, west...)

			fenced := fencedTargets(cs)
			switch scope {
			case corrosion.FailoverScopeCluster:
				if want := names(west); strings.Join(fenced, ",") != strings.Join(want, ",") {
					t.Fatalf("cluster scope: the east majority must fence both west hosts (today's contract), fenced %v", fenced)
				}
				for _, n := range east {
					if vm := vmOn(t, n, "vm-west"); vm == nil || !inSet(vm.HostName, east) {
						t.Fatalf("cluster scope: %s must have moved vm-west east, has %+v", n.Name, vm)
					}
				}
			case corrosion.FailoverScopeRegion:
				if len(fenced) != 0 {
					t.Fatalf("region scope: a site partition fenced %v; the minority site's hosts must be left alone", fenced)
				}
				for _, n := range c.Nodes {
					if vm := vmOn(t, n, "vm-west"); vm == nil || vm.HostName != west[0].Name {
						t.Fatalf("region scope: %s moved vm-west (%+v); it must stay on %s", n.Name, vm, west[0].Name)
					}
					if vm := vmOn(t, n, "vm-east"); vm == nil || vm.HostName != east[2].Name {
						t.Fatalf("region scope: %s moved vm-east (%+v); it must stay on %s", n.Name, vm, east[2].Name)
					}
				}
				// West has two voters, so what east declines is reported as a
				// region too small to fence its own, the more actionable of the
				// two classes. region_scoped is the class for a region large
				// enough (internal/failover unit tests).
				if got := m.count(failover.PhaseQuorum, failover.ResultRefused, failover.ErrRegionTooSmall); got == 0 {
					t.Errorf("region scope: the east coordinator saw cluster-wide quorum on the west hosts and did not report declining it")
				}
			}
		})
	}
}

// loadEastSurvivors fills node-0 and node-1 so the placement scorer prefers the
// empty west hosts. A recovery that stays in east despite that is the region
// constraint, not a coincidence of scoring.
func loadEastSurvivors(t *testing.T, c *Cluster, east []*Node) {
	t.Helper()
	for _, n := range east[:2] {
		if err := corrosion.InsertVM(context.Background(), c.Nodes[0].DB, corrosion.VMRecord{
			Name: "load-" + n.Name, HostName: n.Name, Spec: `{}`, State: "running",
			CPUActual: 40, MemActual: 180000,
		}, nil, nil); err != nil {
			t.Fatalf("load %s: %v", n.Name, err)
		}
	}
	c.WaitConverged(t, convergeTimeout)
}

// TestFleet_RegionScopedFailover_DeathInsideRegion: a host that really dies is
// still fenced and recovered, by its own region's voters, and the recovery
// stays in that region even when the scorer would rather use the other site.
// It runs with the sites connected, and again with the east site partitioned
// from west while node-2 dies, where east holds only 2 of the 5 voters and a
// cluster-wide count could not recover anything.
func TestFleet_RegionScopedFailover_DeathInsideRegion(t *testing.T) {
	for _, tc := range []struct {
		name        string
		partitioned bool
		gated       bool // split_brain_gate_v1 enforced: recovery re-checks the decide gate
	}{
		{"connected", false, false},
		{"connected-gated", false, true},
		{"partitioned", true, false},
		{"partitioned-gated", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			clock := NewVirtualClock(time.Now().UTC())
			c, east, west := siteFleet(t, corrosion.FailoverScopeRegion)
			loadEastSurvivors(t, c, east)
			victim := east[2]
			c.Isolate(victim)
			survivors := []*Node{east[0], east[1]}
			if tc.partitioned {
				cutSites(c, east, west)
				reportDown(t, clock, survivors, append([]*Node{victim}, west...))
				reportDown(t, clock, west, east)
				c.WaitConverged(t, convergeTimeout, survivors...)
			} else {
				reportDown(t, clock, append(append([]*Node{}, survivors...), west...), []*Node{victim})
				c.WaitConverged(t, convergeTimeout, append(append([]*Node{}, survivors...), west...)...)
			}

			cs := c.NewCoordinators(clock)
			if tc.gated {
				reach := map[string][]*Node{}
				for _, n := range survivors {
					if tc.partitioned {
						reach[n.Name] = survivors
					} else {
						reach[n.Name] = append(append([]*Node{}, survivors...), west...)
					}
				}
				for _, n := range survivors {
					cs.ByNode[n.Name].Gate = newReachGate(n, reach[n.Name])
				}
			}
			cs.Tick(ctx, east[0])
			c.WaitConverged(t, convergeTimeout, survivors...)

			if fenced := fencedTargets(cs); strings.Join(fenced, ",") != victim.Name {
				t.Fatalf("region scope: fenced %v, want exactly the dead east host %s", fenced, victim.Name)
			}
			for _, n := range survivors {
				vm := vmOn(t, n, "vm-east")
				if vm == nil || vm.HostName == victim.Name {
					t.Fatalf("%s: vm-east was not recovered off the dead host: %+v", n.Name, vm)
				}
				if !inSet(vm.HostName, survivors) {
					t.Fatalf("%s: vm-east was recovered onto %s, outside its region; recovery must stay in east", n.Name, vm.HostName)
				}
			}
		})
	}
}

// TestFleet_RegionScopedFailover_ContainerRelocationStaysInRegion: a
// container's relocation target comes from the single-workload placement path,
// a different call from the VMs' batch, so it carries the region constraint
// separately. East's survivors are nearly full and west is empty, so an
// unconstrained pick would go west.
//
// It runs on the scenario-steered replicas (the default mode) with one
// coordinator deciding from one database. On independent replicas the
// relocation's replicated entry is refused by every receiver today — the
// guarded source delete is not the batch's final statement
// (RelocateContainerWithToken) — which stalls the stream on main whatever the
// failover scope, so it cannot carry this assertion.
func TestFleet_RegionScopedFailover_ContainerRelocationStaysInRegion(t *testing.T) {
	for _, scope := range []string{corrosion.FailoverScopeCluster, corrosion.FailoverScopeRegion} {
		t.Run(scope, func(t *testing.T) {
			ctx := context.Background()
			c := New(t, Options{Nodes: 5, RegionByIndex: siteRegions})
			east, west := c.Nodes[:3], c.Nodes[3:]
			db := east[0].DB
			db.SetClusterPolicyGate(func() bool { return true })
			if err := corrosion.SetFailoverScope(ctx, db, scope, "fleet"); err != nil {
				t.Fatalf("SetFailoverScope: %v", err)
			}
			for _, n := range east[:2] {
				if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
					Name: "load-" + n.Name, HostName: n.Name, Spec: `{}`, State: "running",
					CPUActual: 40, MemActual: 180000,
				}, nil, nil); err != nil {
					t.Fatalf("load %s: %v", n.Name, err)
				}
			}
			victim := east[2]
			if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{
				HostName: victim.Name, Name: "ct-east", Image: "docker.io/library/alpine:3.19",
				State: "running", OnHostFailure: "restart-any", MemMiB: 1024,
			}); err != nil {
				t.Fatalf("seed ct-east: %v", err)
			}
			if fences := fenceVictim(t, c, east[0], victim, east[0], east[1], west[0], west[1]); fences != 1 {
				t.Fatalf("fences = %d, want 1", fences)
			}
			var ctHost string
			for _, cand := range c.Nodes {
				if rec, err := corrosion.GetContainer(ctx, db, cand.Name, "ct-east"); err != nil {
					t.Fatalf("GetContainer: %v", err)
				} else if rec != nil {
					ctHost = cand.Name
				}
			}
			switch scope {
			case corrosion.FailoverScopeCluster:
				// The precondition that makes the region case mean something:
				// unconstrained, the empty west host wins.
				if !inSet(ctHost, west) {
					t.Fatalf("cluster scope: ct-east relocated to %q; the scorer should prefer an empty west host", ctHost)
				}
			case corrosion.FailoverScopeRegion:
				if !inSet(ctHost, east[:2]) {
					t.Fatalf("region scope: ct-east relocated to %q; its relocation must stay in east", ctHost)
				}
			}
		})
	}
}

// TestFleet_RegionScopedFailover_TooSmallRegionIsReported: west has two voters,
// so it cannot fence one of its own (the other is the only observer that
// counts, and it needs two). A west host that dies is NOT fenced by the three
// east voters that can see it, which is what the cluster-wide count would do;
// the coordinator reports the region instead of silently widening the quorum.
func TestFleet_RegionScopedFailover_TooSmallRegionIsReported(t *testing.T) {
	for _, scope := range []string{corrosion.FailoverScopeCluster, corrosion.FailoverScopeRegion} {
		t.Run(scope, func(t *testing.T) {
			ctx := context.Background()
			clock := NewVirtualClock(time.Now().UTC())
			c, east, west := siteFleet(t, scope)
			victim := west[1]
			c.Isolate(victim)
			observers := append(append([]*Node{}, east...), west[0])
			reportDown(t, clock, observers, []*Node{victim})
			c.WaitConverged(t, convergeTimeout, observers...)
			insertVM(t, east[0], "vm-west-2", victim.Name)
			c.WaitConverged(t, convergeTimeout, observers...)

			cs := c.NewCoordinators(clock)
			m := withRegionMetrics(cs)
			cs.Tick(ctx, east[0])
			c.WaitConverged(t, convergeTimeout, observers...)

			fenced := fencedTargets(cs)
			if scope == corrosion.FailoverScopeCluster {
				if strings.Join(fenced, ",") != victim.Name {
					t.Fatalf("cluster scope: four voters see %s down, it must be fenced; fenced %v", victim.Name, fenced)
				}
				if got := m.regions[east[0].Name]; got != 0 {
					t.Errorf("cluster scope: RegionsWithoutQuorum = %d, want 0 (nothing is region-scoped)", got)
				}
				return
			}
			if len(fenced) != 0 {
				t.Fatalf("region scope: %v fenced by voters outside its region; west cannot fence its own and must not be widened to the cluster", fenced)
			}
			if vm := vmOn(t, east[0], "vm-west-2"); vm == nil || vm.HostName != victim.Name {
				t.Fatalf("region scope: vm-west-2 moved (%+v); nothing may recover a west workload without west's quorum", vm)
			}
			if got := m.count(failover.PhaseQuorum, failover.ResultRefused, failover.ErrRegionTooSmall); got == 0 {
				t.Errorf("region scope: declining to fence in a two-voter region was not reported as %s", failover.ErrRegionTooSmall)
			}
			m.mu.Lock()
			got := m.regions[east[0].Name]
			m.mu.Unlock()
			if got != 1 {
				t.Errorf("region scope: RegionsWithoutQuorum = %d, want 1 (west)", got)
			}
		})
	}
}

// TestFleet_RegionScopedFailover_ChangeFromTheFarSide pins what a policy change
// that has not reached a node does: that node decides on the value in its own
// replica. Here `region` is written on the west side of an existing partition,
// so east never receives it and fences west exactly as before. This is why the
// operator command refuses to change the policy while any voter is
// unreachable (TestFleet_FailoverScopeCommand_*): a change made from one side
// of a partition protects nothing on the other.
func TestFleet_RegionScopedFailover_ChangeFromTheFarSide(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c, east, west := siteFleet(t, corrosion.FailoverScopeCluster)
	cutSites(c, east, west)
	if err := corrosion.SetFailoverScope(ctx, west[0].DB, corrosion.FailoverScopeRegion, "fleet"); err != nil {
		t.Fatalf("SetFailoverScope on the west side: %v", err)
	}
	reportDown(t, clock, east, west)
	reportDown(t, clock, west, east)
	c.WaitConverged(t, convergeTimeout, east...)
	c.WaitConverged(t, convergeTimeout, west...)
	if p, _ := corrosion.GetFailoverScope(ctx, east[0].DB); p.Region() {
		t.Fatalf("precondition: the west write reached east across the partition")
	}

	cs := c.NewCoordinators(clock)
	cs.Tick(ctx, east[0], west[0])
	if fenced := fencedTargets(cs); strings.Join(fenced, ",") != strings.Join(names(west), ",") {
		t.Fatalf("east, still on the cluster scope, must fence the west hosts it sees down; fenced %v", fenced)
	}
}

// ── a region-aware decide gate ──────────────────────────────────────────────

// reachGate stands in for a health.Checker whose probes reach exactly `reach`
// (plus itself), with split_brain_gate_v1 enforced. It counts quorum over the
// node's own replica's voter set, cluster-wide or per region, the way the
// checker does. The checker's own arithmetic is unit-tested in internal/health;
// this is what lets the coordinator's gated path run in a fleet.
type reachGate struct {
	self  *Node
	reach map[string]bool
}

func newReachGate(self *Node, reach []*Node) *reachGate {
	g := &reachGate{self: self, reach: map[string]bool{self.Name: true}}
	for _, n := range reach {
		g.reach[n.Name] = true
	}
	return g
}

func (g *reachGate) over(voters map[string]bool) (health.QuorumState, int, int) {
	live, needed := 0, len(voters)/2+1
	for v := range voters {
		if g.reach[v] {
			live++
		}
	}
	if live >= needed {
		return health.QuorumYes, live, needed
	}
	return health.QuorumNo, live, needed
}

func (g *reachGate) QuorumProof(ctx context.Context) (health.QuorumState, int, int) {
	v, err := corrosion.VoterSet(ctx, g.self.DB)
	if err != nil {
		return health.QuorumUnknown, 0, 0
	}
	return g.over(v)
}

func (g *reachGate) RegionQuorumProof(ctx context.Context, region string) (health.QuorumState, int, int) {
	vr, err := corrosion.VoterRegions(ctx, g.self.DB)
	if err != nil {
		return health.QuorumUnknown, 0, 0
	}
	return g.over(vr.In(region))
}

func gateFrom(st health.QuorumState) health.GateResult {
	if st == health.QuorumYes {
		return health.GateResult{OK: true}
	}
	return health.GateResult{Reason: health.ReasonNoQuorum}
}

func (g *reachGate) DecisionGate(ctx context.Context) health.GateResult {
	st, _, _ := g.QuorumProof(ctx)
	return gateFrom(st)
}

func (g *reachGate) DecisionGateForRegion(ctx context.Context, region string) health.GateResult {
	st, _, _ := g.RegionQuorumProof(ctx, region)
	return gateFrom(st)
}

func (g *reachGate) Enforced(context.Context, string) bool { return true }
func (g *reachGate) PeerSupportsFresh(_ context.Context, peer, _ string) bool {
	return g.reach[peer]
}

var (
	_ failover.FailoverGate = (*reachGate)(nil)
	_ failover.RegionGate   = (*reachGate)(nil)
)
