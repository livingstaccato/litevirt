// Fleet scenarios: a host's own reports on a row of their own
// (colonelpanik/litevirt#267, the runtime half).
//
// Once host_membership took the coordinator's columns away, hosts was left
// with two writer classes under one updated_at: the operator, who configures
// a host (region, role, fencing, labels), and the host's own daemon, which
// reports its version, schema version and resource totals. Two such writes
// made concurrently on two nodes cross on the wire, and a replica that applies
// the newer first refuses the older as stale. That needs two writers and a
// replica that sees them in the opposite order to the one that wrote last, so
// it is driven here, over real replication between independent replicas.
package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// splitRuntime is host_runtime_split_v1 latching on n: the gate opens and the
// node runs its first pass, as the daemon's split loop would.
func splitRuntime(t *testing.T, n *Node) corrosion.HostRuntimeReport {
	t.Helper()
	n.DB.SetHostRuntimeGate(func() bool { return true })
	rep, err := n.DB.SplitHostRuntime(context.Background())
	if err != nil {
		t.Fatalf("%s: runtime split pass: %v", n.Name, err)
	}
	if !n.DB.HostRuntimeLive() {
		t.Fatalf("%s: a complete runtime split pass did not make the node live", n.Name)
	}
	return rep
}

// assertNoRuntimeStatements fails when n's replication stream carries a
// host_runtime statement; with origin set, only the entries n itself wrote
// count (with three nodes every node relays its peers' entries too).
func assertNoRuntimeStatements(t *testing.T, n *Node, origin ...string) {
	t.Helper()
	query, args := `SELECT stmts FROM mutation_log`, []interface{}{}
	if len(origin) > 0 {
		query, args = query+` WHERE origin = ?`, []interface{}{origin[0]}
	}
	rows, err := n.DB.Query(context.Background(), query, args...)
	if err != nil {
		t.Fatalf("read %s mutation_log: %v", n.Name, err)
	}
	for _, r := range rows {
		if strings.Contains(r.String("stmts"), "host_runtime") {
			t.Fatalf("%s put a host_runtime statement on its replication stream before the latch. "+
				"A previous-release peer has no ledger entry for it, so its apply fails closed and its "+
				"watermark stalls:\n%s", n.Name, r.String("stmts"))
		}
	}
}

// concurrentVersionAndRegion has a write the subject's daemon owns (its own
// version report) and one the operator owns (a's region change for the
// subject) cross on the wire: every link is down while both are made, a's
// strictly later, and then the links heal. a is the replica that sees them in
// the opposite order: it holds the newer region change when the older version
// report arrives. It returns each node's resolved (version, region) of
// subject.
func concurrentVersionAndRegion(t *testing.T, split bool, seed int64) map[string][2]string {
	t.Helper()
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: seed})
	a, subject := c.Nodes[0], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)
	if split {
		for _, n := range c.Nodes {
			splitRuntime(t, n)
		}
		c.WaitConverged(t, convergeTimeout)
	}

	// No relay either: with three nodes every node relays.
	c.Isolate(a)
	c.Isolate(subject)
	if err := corrosion.UpdateHostStartup(ctx, subject.DB, subject.Name, "active", "v-267-runtime", 64, 262144, 500, true); err != nil {
		t.Fatalf("boot report on %s: %v", subject.Name, err)
	}
	time.Sleep(5 * time.Millisecond) // a's write is the newer one on every clock
	if err := corrosion.UpdateHostRegion(ctx, a.DB, subject.Name, "eu-267"); err != nil {
		t.Fatalf("region change on %s: %v", a.Name, err)
	}
	c.ClearLinkFaults()

	// The region change is the newer write: wait until every node holds it,
	// at which point each has applied or refused the version report.
	eventually(t, convergeTimeout, "the region change everywhere", func() bool {
		for _, n := range c.Nodes {
			if hostOn(t, n, subject.Name).Region != "eu-267" {
				return false
			}
		}
		return true
	})
	if split {
		// The runtime copy is the one that must converge. hosts itself still
		// diverges on a replica that refused the report's hosts half: that
		// half is the previous release's copy and keeps its shared clock.
		c.WaitConvergedExcept(t, convergeTimeout, []string{"hosts"})
	} else {
		time.Sleep(500 * time.Millisecond)
	}
	out := map[string][2]string{}
	for _, n := range c.Nodes {
		h := hostOn(t, n, subject.Name)
		out[n.Name] = [2]string{h.Version, h.Region}
	}
	return out
}

// TestFleet_HostRuntime_ConcurrentReportAndConfigBothSurvive: a host's boot
// report and an operator's region change for it, made concurrently on two
// nodes, both survive on every replica once runtime has its own row.
//
// The first subtest is the RED half and must keep failing to reproduce the
// loss: without it the second could pass on a scenario that never raced.
func TestFleet_HostRuntime_ConcurrentReportAndConfigBothSurvive(t *testing.T) {
	t.Run("before the split one replica loses the report", func(t *testing.T) {
		got := concurrentVersionAndRegion(t, false, 2673)
		lost := 0
		for _, vr := range got {
			if vr[0] != "v-267-runtime" {
				lost++
			}
		}
		if lost == 0 {
			t.Fatalf("every replica kept both writes with the shared hosts clock: %v. The scenario "+
				"did not race, so the post-split half proves nothing", got)
		}
	})

	t.Run("after the split both survive on every replica", func(t *testing.T) {
		for node, vr := range concurrentVersionAndRegion(t, true, 2674) {
			if vr[0] != "v-267-runtime" || vr[1] != "eu-267" {
				t.Errorf("%s holds version=%q region=%q, want v-267-runtime and eu-267: a write to one "+
					"column of the host was lost to a concurrent write to another", node, vr[0], vr[1])
			}
		}
	})
}

// TestFleet_HostRuntime_AnUnlatchedNeighboursReportIsAbsorbed: latches form per
// node, so for a while a neighbour on this build has not latched yet and
// reports to hosts alone — an entry with no host_runtime statement in it. The
// latched nodes, which already hold a copied host_runtime row for it, must take
// that report into the row they read, or they would serve the version and
// totals from before the neighbour's restart until its next one.
func TestFleet_HostRuntime_AnUnlatchedNeighboursReportIsAbsorbed(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2675})
	a, b, late := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)
	splitRuntime(t, a)
	splitRuntime(t, b)
	c.WaitConverged(t, convergeTimeout)
	for _, n := range []*Node{a, b} {
		if v := hostOn(t, n, late.Name).Version; v == "v-late-boot" {
			t.Fatalf("%s already reads the report it has not been sent; the rest is vacuous", n.Name)
		}
	}

	// The late node restarts on this build before its own latch has formed.
	if err := corrosion.UpdateHostStartup(ctx, late.DB, late.Name, "active", "v-late-boot", 48, 131072, 900, true); err != nil {
		t.Fatalf("boot report on %s: %v", late.Name, err)
	}
	assertNoRuntimeStatements(t, late, late.Name)
	eventually(t, convergeTimeout, "the late node's report on every latched node", func() bool {
		for _, n := range []*Node{a, b} {
			h := hostOn(t, n, late.Name)
			if h.Version != "v-late-boot" || h.DiskTotal != 900 || h.CPUTotal != 48 {
				return false
			}
		}
		return true
	})
	// And the row they read carries it, not just the hosts copy.
	for _, n := range []*Node{a, b} {
		if got := oldColumn(t, n, `SELECT version FROM host_runtime WHERE host_name = ?`, late.Name); got != "v-late-boot" {
			t.Errorf("%s: host_runtime.version = %q; the hosts-only report was not absorbed", n.Name, got)
		}
	}

	// Once the late node latches, its next report goes to both homes, and
	// every node — the late one included — reads it.
	splitRuntime(t, late)
	if err := corrosion.UpdateHostVersion(ctx, late.DB, late.Name, "v-late-live"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if v := hostOn(t, n, late.Name).Version; v != "v-late-live" {
			t.Errorf("%s reads the late node at %q after its live report, want v-late-live", n.Name, v)
		}
	}
}

// TestFleet_HostRuntime_NothingBeforeTheLatchAndTheOldColumnsStayCurrent: until
// the latch, no runtime writer puts a host_runtime statement on any stream —
// a previous-release peer cannot decode one — and readers read hosts. After
// it, every report is dual-written, so a node rolled back one release, which
// reads the hosts columns and nothing else, still reads every report.
func TestFleet_HostRuntime_NothingBeforeTheLatchAndTheOldColumnsStayCurrent(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2676})
	a, b := c.Nodes[0], c.Nodes[1]
	c.WaitConverged(t, convergeTimeout)

	if err := corrosion.UpdateHostStartup(ctx, a.DB, a.Name, "active", "v-pre", 8, 16, 32, true); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostResources(ctx, b.DB, b.Name, 4, 8, 12); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		assertNoRuntimeStatements(t, n)
		if h := hostOn(t, n, a.Name); h.Version != "v-pre" || h.DiskTotal != 32 {
			t.Errorf("%s reads %s before the latch as %+v", n.Name, a.Name, h)
		}
	}

	for _, n := range c.Nodes {
		splitRuntime(t, n)
	}
	c.WaitConverged(t, convergeTimeout)
	if err := corrosion.UpdateHostStartup(ctx, a.DB, a.Name, "active", "v-post", 8, 16, 64, true); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if got := oldColumn(t, n, `SELECT version FROM hosts WHERE name = ?`, a.Name); got != "v-post" {
			t.Errorf("%s: hosts.version = %q; a node rolled back one release would not see the report", n.Name, got)
		}
		if h := hostOn(t, n, a.Name); h.Version != "v-post" || h.DiskTotal != 64 {
			t.Errorf("%s reads %s after the latch as %+v", n.Name, a.Name, h)
		}
	}
}
