package fleet

// Project incarnation adoption (corrosion/project_adoption.go,
// daemon.ProjectAdoptionPass) over real gRPC replication and real release
// gates: a project created before project_incarnation_v1 latched is given its
// stable incarnation once release_2027_01_v1 has latched, and no receiver,
// in any order, grants or bounds anything differently for it.

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/daemon"
	"github.com/litevirt/litevirt/internal/health"
)

const adoptedAcme = "aaf7986a22959ac3f46c6116c8dfa1ab8" // adoptedProjectIncarnation("/acme"), pinned in corrosion

// seedLegacyProjects writes, on n with its project gate unwired (the
// previous release), a project with an untagged grant, a pre-tagged grant and
// a bare-key quota.
func seedLegacyProjects(t *testing.T, n *Node, names ...string) {
	t.Helper()
	ctx := context.Background()
	for _, name := range names {
		if err := corrosion.InsertProject(ctx, n.DB, corrosion.ProjectRecord{Name: name}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.UpsertProjectQuota(ctx, n.DB, corrosion.ProjectQuotaRecord{ProjectName: name, VCPULimit: 8, MemMiBLimit: 4096}); err != nil {
			t.Fatal(err)
		}
		short := strings.TrimPrefix(name, "/")
		for _, b := range []struct{ id, role string }{{"untagged-" + short, "Operator"}, {"latched-" + short + "~p:pre", "Admin"}} {
			if err := corrosion.InsertRoleBinding(ctx, n.DB, corrosion.RoleBindingRecord{ID: b.id, Path: "/projects/" + short,
				Role: b.role, Principal: "user:bob@local", Propagate: true}); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// adoptionFleet: a 3-node cluster holding legacy projects, with
// project_incarnation_v1 and (unless withhold) release_2027_01_v1 latched.
func adoptionFleet(t *testing.T, seed int64, projects ...string) (*Cluster, map[string]*health.Checker) {
	t.Helper()
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: seed})
	seedLegacyProjects(t, c.Nodes[0], projects...)
	c.WaitConverged(t, convergeTimeout)
	gates := latchProjectIncarnation(t, c, nil, nil)
	wireReleaseFeatures(t, c, gates)
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(ctx, capabilities.FailoverScopeV1) {
			t.Fatalf("%s: failover_scope_v1 did not latch", n.Name)
		}
	}
	return c, gates
}

func adoptionPass(t *testing.T, n *Node, g *health.Checker, enabled bool, now time.Time) daemon.ProjectAdoptionPass {
	return daemon.ProjectAdoptionPass{
		DB: n.DB, Host: n.Name,
		Enabled:   func() bool { return enabled },
		Available: func() bool { return g.FeatureAvailable(capabilities.FeatureProjectAdoption) },
		Gate:      g.WithFeature,
		DataDir:   t.TempDir(),
		Now:       func() time.Time { return now },
	}
}

// aeRounds runs every node's anti-entropy pull rounds times.
func aeRounds(t *testing.T, c *Cluster, rounds int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < rounds; i++ {
		for _, n := range c.Nodes {
			corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
		}
	}
}

// fleetAdoptionView is what n grants and bounds for project: each live
// binding's role, held and clock, and the quota read.
func fleetAdoptionView(t *testing.T, n *Node, project string) string {
	t.Helper()
	ctx := context.Background()
	bs, err := corrosion.ListRoleBindings(ctx, n.DB)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, b := range bs {
		if strings.HasPrefix(b.Path, "/projects"+project) {
			out = append(out, fmt.Sprintf("%s=%s held=%v at=%s", b.ID, b.Role, b.Held, b.UpdatedAt))
		}
	}
	sort.Strings(out)
	q, err := corrosion.GetProjectQuota(ctx, n.DB, project)
	if err != nil {
		t.Fatal(err)
	}
	if q == nil {
		out = append(out, "quota=none")
	} else {
		out = append(out, fmt.Sprintf("quota=%d/%d", q.VCPULimit, q.MemMiBLimit))
	}
	return strings.Join(out, "\n")
}

func fleetProjectRow(t *testing.T, n *Node, name string) string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), `SELECT name, created_at, updated_at, deleted_at, incarnation FROM projects WHERE name = ?`, name)
	if err != nil || len(rows) != 1 {
		t.Fatalf("%s: projects row %s: %d rows, %v", n.Name, name, len(rows), err)
	}
	r := rows[0]
	return strings.Join([]string{r.String("name"), r.String("created_at"), r.String("updated_at"), r.String("deleted_at"), r.String("incarnation")}, "|")
}

// assertOneRow: every node holds the identical projects row for name and
// tracks no unresolved tie (re-review I-1, M-7).
func assertOneRow(t *testing.T, c *Cluster, name string) string {
	t.Helper()
	want := fleetProjectRow(t, c.Nodes[0], name)
	for _, n := range c.Nodes {
		if got := fleetProjectRow(t, n, name); got != want {
			t.Errorf("%s holds %s, %s holds %s", n.Name, got, c.Nodes[0].Name, want)
		}
		if k := n.DB.UnresolvedTieCount(); k != 0 {
			t.Errorf("%s tracks %d unresolved ties: %v", n.Name, k, n.DB.UnresolvedTieTables())
		}
	}
	return want
}

// Scenario A: two hosts adopt at once (both past the fallback delay) while
// every host is sampled. No sample on any host shows a grant or quota that
// differs from before; every host ends on the one adopted row; the feature
// is recorded used.
//
// Mutations: the alias dropped from projectBindingHeld or projectQuotaKey —
// red (a sample differs); a NowTS stamp — red (rows differ before AE settles
// them, or a tie).
func TestFleet_ProjectAdoption_TwoAdoptersChangeNothingAReceiverSees(t *testing.T) {
	ctx := context.Background()
	c, gates := adoptionFleet(t, 2701, "/acme")
	before := map[string]string{}
	for _, n := range c.Nodes {
		before[n.Name] = fleetAdoptionView(t, n, "/acme")
		if !strings.Contains(before[n.Name], "quota=8/4096") || strings.Contains(before[n.Name], "held=true") {
			t.Fatalf("fixture on %s:\n%s", n.Name, before[n.Name])
		}
	}
	for _, n := range c.Nodes {
		eventually(t, convergeTimeout, n.Name+" to latch release_2027_01_v1", func() bool {
			return gates[n.Name].Enforced(ctx, capabilities.Release202701V1)
		})
	}
	stop := make(chan struct{})
	var bad []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			for _, n := range c.Nodes {
				if v := fleetAdoptionView(t, n, "/acme"); v != before[n.Name] {
					mu.Lock()
					bad = append(bad, n.Name+":\n"+v)
					mu.Unlock()
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	later := time.Now().Add(365 * 24 * time.Hour)
	var pw sync.WaitGroup
	for _, n := range c.Nodes[:2] {
		pw.Add(1)
		go func(n *Node) {
			defer pw.Done()
			eventually(t, convergeTimeout, n.Name+" to adopt", func() bool {
				_, err := adoptionPass(t, n, gates[n.Name], true, later).Run(ctx)
				return err == nil
			})
		}(n)
	}
	pw.Wait()
	c.WaitConverged(t, convergeTimeout)
	close(stop)
	wg.Wait()
	if len(bad) > 0 {
		t.Fatalf("%d samples saw a grant or quota move during adoption; first:\n%s\nbefore:\n%s", len(bad), bad[0], before[strings.SplitN(bad[0], ":", 2)[0]])
	}
	row := assertOneRow(t, c, "/acme")
	if !strings.HasSuffix(row, "|"+adoptedAcme) {
		t.Fatalf("converged row %s, want the adopted incarnation", row)
	}
	for _, n := range c.Nodes {
		if !featureUsedOn(t, n, capabilities.Release202701V1, string(capabilities.FeatureProjectAdoption)) {
			t.Errorf("%s does not hold project_adoption's used record", n.Name)
		}
	}
}

// Scenario B: a host partitioned while the project is adopted takes it on
// heal, sees the same grants and quota throughout, and ends on the one row.
func TestFleet_ProjectAdoption_APartitionedHostHealsToTheSameRow(t *testing.T) {
	ctx := context.Background()
	c, gates := adoptionFleet(t, 2702, "/acme")
	a, b, cut := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	before := fleetAdoptionView(t, cut, "/acme")
	// The first use is acknowledged by every host before the cut.
	eventually(t, convergeTimeout, "the first use of project_adoption", func() bool {
		return gates[a.Name].WithFeature(ctx, capabilities.FeatureProjectAdoption,
			func(context.Context, capabilities.FeatureGrant) error { return nil }) == nil
	})
	c.Partition(a, cut)
	c.Partition(b, cut)
	if n, err := adoptionPass(t, a, gates[a.Name], true, time.Now().Add(365*24*time.Hour)).Run(ctx); err != nil || n != 1 {
		t.Fatalf("adopt on %s: %d %v", a.Name, n, err)
	}
	if got := fleetAdoptionView(t, cut, "/acme"); got != before {
		t.Fatalf("the cut host's view moved:\n%s", got)
	}
	c.Heal(a, cut)
	c.Heal(b, cut)
	aeRounds(t, c, 1)
	c.WaitConverged(t, convergeTimeout)
	if got := fleetAdoptionView(t, cut, "/acme"); got != before {
		t.Fatalf("after heal the cut host grants or bounds differently:\n%s\nbefore:\n%s", got, before)
	}
	if row := assertOneRow(t, c, "/acme"); !strings.HasSuffix(row, "|"+adoptedAcme) {
		t.Fatalf("row %s, want adopted", row)
	}
}

// Scenario C (re-review I-1): a host that saw the project deletes it while
// partitioned, after another host adopted it. On heal the hosts that took the
// adoption first hold the adopted tombstone and the deleter skips the older
// adoption, so the incarnation column is split at one updated_at. The alias
// tie rule converges every host to one deleted, adopted row with no
// unresolved tie, and the project's authority is retired everywhere.
//
// Mutation: the alias tie rule dropped — red (rows differ, an unresolved
// tie, WaitConverged times out).
func TestFleet_ProjectAdoption_ADeleteAfterTheAdoptionConvergesToOneRow(t *testing.T) {
	ctx := context.Background()
	c, gates := adoptionFleet(t, 2703, "/acme")
	a, b, del := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if _, err := corrosion.ClaimInitialProjectAuthority(ctx, a.DB, "/acme", a.Name); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	eventually(t, convergeTimeout, "the first use of project_adoption", func() bool {
		return gates[a.Name].WithFeature(ctx, capabilities.FeatureProjectAdoption,
			func(context.Context, capabilities.FeatureGrant) error { return nil }) == nil
	})
	c.Partition(a, del)
	c.Partition(b, del)
	if n, err := adoptionPass(t, a, gates[a.Name], true, time.Now()).Run(ctx); err != nil || n != 1 {
		t.Fatalf("adopt on the holder %s: %d %v", a.Name, n, err)
	}
	if err := corrosion.DeleteProject(ctx, del.DB, "/acme"); err != nil {
		t.Fatal(err)
	}
	c.Heal(a, del)
	c.Heal(b, del)
	// The WAL delivers both writes everywhere; a host that took the delete
	// first skips the older adoption, so only anti-entropy can meet the
	// split.
	aeRounds(t, c, 2)
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if _, err := corrosion.ReconcileOrphanedProjectAuthority(ctx, n.DB); err != nil {
			t.Fatal(err)
		}
	}
	c.WaitConverged(t, convergeTimeout)
	row := assertOneRow(t, c, "/acme")
	if f := strings.Split(row, "|"); f[3] == "" || f[4] != adoptedAcme {
		t.Fatalf("converged row %s, want deleted and adopted", row)
	}
	for _, n := range c.Nodes {
		if _, ok, err := corrosion.CurrentProjectAuthority(ctx, n.DB, "/acme"); err != nil || ok {
			t.Errorf("%s still holds live authority for the deleted project (err %v)", n.Name, err)
		}
	}
}

// Scenario E and the Q-B kill switch: with a host holding release_2027_01_v1
// off (a host on rc1), nothing is adopted and no use is recorded; with every
// host's flag off, the token latches and still nothing is used, so a rollback
// below it is not quarantined. Once a host adopts, a rollback that cannot
// keep project_adoption quarantines.
//
// Mutations: the pass asking the gate before the flag — red (a used record
// with every flag off).
func TestFleet_ProjectAdoption_RolloutAndTheKillSwitch(t *testing.T) {
	ctx := context.Background()
	c, gates := adoptionFleet(t, 2704, "/acme")
	later := time.Now().Add(365 * 24 * time.Hour)
	used := func(n *Node) bool {
		return featureUsedOn(t, n, capabilities.Release202701V1, string(capabilities.FeatureProjectAdoption))
	}

	// A host on the previous build (advertising nothing, as a quarantined or
	// older host does to this token): the token cannot latch, and the pass
	// writes nothing.
	old := c.Nodes[2]
	old.Server.SetWALQuarantined(func() bool { return true })
	for _, n := range c.Nodes[:2] {
		if gates[n.Name].Enforced(ctx, capabilities.Release202701V1) {
			t.Fatalf("%s: release_2027_01_v1 latched across %s", n.Name, old.Name)
		}
		if k, err := adoptionPass(t, n, gates[n.Name], true, later).Run(ctx); err != nil || k != 0 {
			t.Fatalf("%s adopted %d across a host on the previous build (err %v)", n.Name, k, err)
		}
	}
	old.Server.SetWALQuarantined(old.DB.WALQuarantined)

	// Every host's flag off: the token latches, nothing is used, and a
	// rollback below the token is not quarantined.
	for _, n := range c.Nodes {
		eventually(t, convergeTimeout, n.Name+" to latch release_2027_01_v1", func() bool {
			return gates[n.Name].Enforced(ctx, capabilities.Release202701V1)
		})
		if k, err := adoptionPass(t, n, gates[n.Name], false, later).Run(ctx); err != nil || k != 0 {
			t.Fatalf("%s adopted %d with its flag off (err %v)", n.Name, k, err)
		}
	}
	c.WaitConverged(t, convergeTimeout)
	withoutAdoption := func() func() {
		set := map[capabilities.Feature]capabilities.FeatureInfo{}
		for _, f := range capabilities.Features() {
			if f != capabilities.FeatureProjectAdoption {
				info, _ := capabilities.LookupFeature(f)
				set[f] = info
			}
		}
		return capabilities.OverrideFeaturesForTest(set)
	}
	for _, n := range c.Nodes {
		if used(n) {
			t.Fatalf("%s: project_adoption is used although every flag is off", n.Name)
		}
		if strings.HasSuffix(fleetProjectRow(t, n, "/acme"), "|"+adoptedAcme) {
			t.Fatalf("%s: adopted with every flag off", n.Name)
		}
		restore := withoutAdoption()
		q := daemon.BootRollbackCheck(ctx, t.TempDir(), n.DB)
		restore()
		if slices.ContainsFunc(q, func(s string) bool { return strings.Contains(s, capabilities.Release202701V1) }) {
			t.Fatalf("%s: a rollback below release_2027_01_v1 quarantines %v with nothing used", n.Name, q)
		}
	}

	// One host turns it on: it adopts, the feature is used, and a rollback
	// that cannot keep it quarantines.
	a := c.Nodes[0]
	eventually(t, convergeTimeout, a.Name+" to adopt", func() bool {
		k, err := adoptionPass(t, a, gates[a.Name], true, later).Run(ctx)
		return err == nil && k == 1
	})
	c.WaitConverged(t, convergeTimeout)
	n := c.Nodes[1]
	if !used(n) {
		t.Fatal("project_adoption is not used after an adoption")
	}
	restore := withoutAdoption()
	q := daemon.BootRollbackCheck(ctx, t.TempDir(), n.DB)
	restore()
	if !slices.ContainsFunc(q, func(s string) bool { return strings.Contains(s, capabilities.Release202701V1) }) {
		t.Fatalf("a rollback that cannot keep project_adoption quarantines %v, want release_2027_01_v1", q)
	}
}
