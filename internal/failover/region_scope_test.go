package failover

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// regionFixture is a 3+3 cluster: east = coordinator, e1, e2 and west = w1,
// w2, w3, six voters, so the cluster-wide quorum is 4 and each region's is 2.
// Both regions are large enough to fence their own hosts.
func regionFixture(t *testing.T, scope string) *corrosion.Client {
	t.Helper()
	ctx := context.Background()
	db := newTestDB(t)
	regions := map[string]string{
		"coordinator": "east", "e1": "east", "e2": "east",
		"w1": "west", "w2": "west", "w3": "west",
	}
	for _, h := range []string{"coordinator", "e1", "e2", "w1", "w2", "w3"} {
		ensureObserverHost(t, db, h)
		if err := corrosion.UpdateHostRegion(ctx, db, h, regions[h]); err != nil {
			t.Fatalf("UpdateHostRegion %s: %v", h, err)
		}
	}
	setScope(t, db, scope)
	return db
}

func setScope(t *testing.T, db *corrosion.Client, scope string) {
	t.Helper()
	db.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.SetFailoverScope(context.Background(), db, scope, "test"); err != nil {
		t.Fatalf("SetFailoverScope(%s): %v", scope, err)
	}
}

func regionHostState(t *testing.T, db *corrosion.Client, name string) string {
	t.Helper()
	h, err := corrosion.GetHost(context.Background(), db, name)
	if err != nil || h == nil {
		t.Fatalf("GetHost %s: %+v %v", name, h, err)
	}
	return h.State
}

// TestRegionScope_FenceCountsOnlyTheTargetsRegion: four voters report w3 down,
// which is a cluster-wide quorum, but only one of them is in west. Under region
// scope that is no quorum, and the refusal is reported as region_scoped (west
// has three voters, so it is not too small). A second west observer makes it a
// west quorum and w3 is fenced.
func TestRegionScope_FenceCountsOnlyTheTargetsRegion(t *testing.T) {
	ctx := context.Background()
	db := regionFixture(t, corrosion.FailoverScopeRegion)
	downObservers(t, db, "w3", "coordinator", "e1", "e2", "w1")

	c := newTestCoordinator("coordinator", db)
	fm := newFakeMetrics()
	c.Metrics = fm
	c.run(ctx)
	if got := regionHostState(t, db, "w3"); got != "active" {
		t.Fatalf("region scope: w3 is %q after three east voters and one west voter reported it; only west's voters may fence it", got)
	}
	if got := fm.attempts[foKey(PhaseQuorum, ResultRefused, ErrRegionScoped)]; got != 1 {
		t.Errorf("region_scoped refusals = %d, want 1 (attempts=%v)", got, fm.attempts)
	}
	if got := fm.attempts[foKey(PhaseQuorum, ResultRefused, ErrRegionTooSmall)]; got != 0 {
		t.Errorf("west has three voters and must not be reported too small (attempts=%v)", fm.attempts)
	}

	downObservers(t, db, "w3", "w2")
	c.run(ctx)
	if got := regionHostState(t, db, "w3"); got == "active" {
		t.Fatalf("region scope: w3 still active with two of west's three voters reporting it down")
	}
}

// TestRegionScope_ClusterScopeIsUnchanged: the same observations under the
// cluster scope fence w3, the behaviour every existing cluster has.
func TestRegionScope_ClusterScopeIsUnchanged(t *testing.T) {
	ctx := context.Background()
	db := regionFixture(t, corrosion.FailoverScopeCluster)
	downObservers(t, db, "w3", "coordinator", "e1", "e2", "w1")
	c := newTestCoordinator("coordinator", db)
	fm := newFakeMetrics()
	c.Metrics = fm
	c.run(ctx)
	if got := regionHostState(t, db, "w3"); got == "active" {
		t.Fatalf("cluster scope: four of six voters reported w3 down and it was not fenced")
	}
	if fm.regionsWithoutQuorum != 0 {
		t.Errorf("cluster scope must publish 0 regions without quorum, got %d", fm.regionsWithoutQuorum)
	}
}

// TestRegionScope_SingleRegionIsUnaffected: with every host in one region the
// region IS the cluster, so region scope fences on exactly the cluster count.
func TestRegionScope_SingleRegionIsUnaffected(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	for _, h := range []string{"coordinator", "h1", "h2", "h3", "h4"} {
		ensureObserverHost(t, db, h)
	}
	setScope(t, db, corrosion.FailoverScopeRegion)
	downObservers(t, db, "h4", "coordinator", "h1", "h2")
	c := newTestCoordinator("coordinator", db)
	c.run(ctx)
	if got := regionHostState(t, db, "h4"); got == "active" {
		t.Fatalf("single region under region scope: three of five voters reported h4 down and it was not fenced")
	}
}

// TestRegionScope_RecoverHostsCountsTheRegion: re-admitting an offline host
// takes a quorum of the same population that may fence it.
func TestRegionScope_RecoverHostsCountsTheRegion(t *testing.T) {
	ctx := context.Background()
	db := regionFixture(t, corrosion.FailoverScopeRegion)
	if err := corrosion.UpdateHostState(ctx, db, "w3", "offline"); err != nil {
		t.Fatalf("UpdateHostState: %v", err)
	}
	healthyObservers(t, db, "w3", "coordinator", "e1", "e2", "w1")
	c := newTestCoordinator("coordinator", db)
	c.run(ctx)
	if got := regionHostState(t, db, "w3"); got != "offline" {
		t.Fatalf("region scope: w3 re-admitted (%q) on east voters' word; only west's may re-admit it", got)
	}
	healthyObservers(t, db, "w3", "w2")
	c.run(ctx)
	if got := regionHostState(t, db, "w3"); got != "active" {
		t.Fatalf("region scope: w3 still %q with two of west's voters reporting it healthy", got)
	}
}

// TestRegionScope_UnknownScopeDecidesNothing: a scope this build does not
// implement fails the cycle closed instead of guessing either way.
func TestRegionScope_UnknownScopeDecidesNothing(t *testing.T) {
	ctx := context.Background()
	db := regionFixture(t, corrosion.FailoverScopeCluster)
	if err := db.Execute(ctx, `INSERT INTO cluster_policies (key, value, set_by, updated_at, deleted_at)
	 VALUES (?, ?, ?, ?, NULL)
	 ON CONFLICT(key) DO UPDATE SET value = excluded.value, set_by = excluded.set_by,
	   updated_at = excluded.updated_at, deleted_at = NULL`, "failover_scope", "zone", "future", db.NowTS()); err != nil {
		t.Fatalf("seed unknown scope: %v", err)
	}
	downObservers(t, db, "w3", "coordinator", "e1", "e2", "w1", "w2")
	c := newTestCoordinator("coordinator", db)
	c.run(ctx)
	if got := regionHostState(t, db, "w3"); got != "active" {
		t.Fatalf("an unknown failover scope must fence nothing; w3 is %q", got)
	}
}

// TestRegionScope_TooSmallRegionGauge: the gauge counts regions that hold a
// worker and have fewer than three voters.
func TestRegionScope_TooSmallRegionGauge(t *testing.T) {
	ctx := context.Background()
	db := regionFixture(t, corrosion.FailoverScopeRegion)
	// A two-host site and a witness-only site: only the first counts.
	for h, r := range map[string]string{"s1": "south", "s2": "south"} {
		ensureObserverHost(t, db, h)
		if err := corrosion.UpdateHostRegion(ctx, db, h, r); err != nil {
			t.Fatalf("UpdateHostRegion: %v", err)
		}
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "wit", Address: "10.0.7.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
		State: "active", Role: "witness", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost witness: %v", err)
	}
	if err := corrosion.UpdateHostRegion(ctx, db, "wit", "tiebreak"); err != nil {
		t.Fatalf("UpdateHostRegion: %v", err)
	}
	c := newTestCoordinator("coordinator", db)
	fm := newFakeMetrics()
	c.Metrics = fm
	c.run(ctx)
	if fm.regionsWithoutQuorum != 1 {
		t.Fatalf("regions without quorum = %d, want 1 (south; tiebreak holds no worker)", fm.regionsWithoutQuorum)
	}
}

// regionAwarePromoter records the region it was asked to keep the promotion in.
type regionAwarePromoter struct {
	dbPromoter
	regions []string
}

func (p *regionAwarePromoter) AutoPromoteReplicaInRegion(ctx context.Context, vmName, fenceEpoch string, leaseTerm int64, region string) error {
	p.regions = append(p.regions, region)
	return p.dbPromoter.AutoPromoteReplica(ctx, vmName, fenceEpoch, leaseTerm)
}

// TestRegionScope_AutoPromoteStaysInRegion: under region scope a promotion is
// asked to stay in the fenced host's region; a promoter that cannot promise
// that is not asked at all, and the VM falls through to the reschedule.
func TestRegionScope_AutoPromoteStaysInRegion(t *testing.T) {
	ctx := context.Background()
	c := &Coordinator{scope: quorumView{region: true, vr: corrosion.VoterRegionSets{
		RegionOf: map[string]string{"w3": "west"},
	}}}
	h := &corrosion.HostRecord{Name: "w3"}
	vm := corrosion.VMRecord{Name: "db", Spec: `{}`}

	plain := &dbPromoter{fail: true}
	c.Promoter = plain
	if err := c.autoPromote(ctx, h, vm, "", 0); err != errPromoterNotRegionScoped {
		t.Fatalf("a promoter that cannot stay in region: err=%v, want errPromoterNotRegionScoped", err)
	}
	if len(plain.promoted) != 0 {
		t.Fatalf("a promoter that cannot stay in region was asked to promote %v", plain.promoted)
	}

	aware := &regionAwarePromoter{dbPromoter: dbPromoter{fail: true}}
	c.Promoter = aware
	_ = c.autoPromote(ctx, h, vm, "", 0)
	if len(aware.regions) != 1 || aware.regions[0] != "west" {
		t.Fatalf("region-aware promoter asked for regions %v, want [west]", aware.regions)
	}

	// The per-VM opt-out lifts the region: the ordinary promote runs.
	vm.Spec = `{"labels":{"` + corrosion.LabelFailoverAnyRegion + `":"true"}}`
	aware.regions = nil
	_ = c.autoPromote(ctx, h, vm, "", 0)
	if len(aware.regions) != 0 || len(aware.promoted) != 2 {
		t.Fatalf("an opted-out VM must promote without a region: regions=%v promoted=%v", aware.regions, aware.promoted)
	}
}

// TestRegionScope_VMRecoveryRegion pins the three answers.
func TestRegionScope_VMRecoveryRegion(t *testing.T) {
	vr := corrosion.VoterRegionSets{RegionOf: map[string]string{"w3": "west"}}
	plainVM := corrosion.VMRecord{Spec: `{"on_host_failure":"restart-any"}`}
	anyVM := corrosion.VMRecord{Spec: `{"on_host_failure":"restart-any","labels":{"` + corrosion.LabelFailoverAnyRegion + `":"true"}}`}

	cluster := &Coordinator{scope: quorumView{vr: vr}}
	if got := cluster.vmRecoveryRegion("w3", plainVM); got != "" {
		t.Errorf("cluster scope constrains recovery to %q", got)
	}
	region := &Coordinator{scope: quorumView{region: true, vr: vr}}
	if got := region.vmRecoveryRegion("w3", plainVM); got != "west" {
		t.Errorf("region scope: recovery region %q, want west", got)
	}
	if got := region.vmRecoveryRegion("w3", anyVM); got != "" {
		t.Errorf("region scope, opted-out VM: recovery region %q, want none", got)
	}
	if got := region.containerRecoveryRegion("w3"); got != "west" {
		t.Errorf("region scope container: recovery region %q, want west", got)
	}
}

// clusterOnlyGate is a FailoverGate that predates region scoping.
type clusterOnlyGate struct{}

func (clusterOnlyGate) DecisionGate(context.Context) health.GateResult {
	return health.GateResult{OK: true}
}
func (clusterOnlyGate) QuorumProof(context.Context) (health.QuorumState, int, int) {
	return health.QuorumYes, 3, 2
}
func (clusterOnlyGate) Enforced(context.Context, string) bool                  { return true }
func (clusterOnlyGate) PeerSupportsFresh(context.Context, string, string) bool { return true }

// TestRegionScope_DecideGateRefusesAClusterOnlyGate: under region scope a gate
// that cannot answer the regional question refuses rather than being asked the
// cluster-wide one.
func TestRegionScope_DecideGateRefusesAClusterOnlyGate(t *testing.T) {
	ctx := context.Background()
	c := &Coordinator{Gate: clusterOnlyGate{}}
	if g := c.decideGate(ctx, "w3"); !g.OK {
		t.Fatalf("cluster scope: the cluster-wide gate must decide: %+v", g)
	}
	c.scope = quorumView{region: true, vr: corrosion.VoterRegionSets{RegionOf: map[string]string{"w3": "west"}}}
	if g := c.decideGate(ctx, "w3"); g.OK {
		t.Fatalf("region scope with a cluster-only gate: decided on the cluster-wide quorum")
	}
}
