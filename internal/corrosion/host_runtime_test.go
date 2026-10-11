package corrosion

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"
)

func openRuntimeGate(c *Client) { c.SetHostRuntimeGate(func() bool { return true }) }

func runtimeCol(t *testing.T, c *Client, host, col string) string {
	t.Helper()
	return oneString(t, c, `SELECT CAST(`+col+` AS TEXT) AS v FROM host_runtime WHERE host_name = '`+host+`'`, "v")
}

func hostOf(t *testing.T, c *Client, host string) *HostRecord {
	t.Helper()
	h, err := GetHost(context.Background(), c, host)
	if err != nil || h == nil {
		t.Fatalf("GetHost %s: %+v %v", host, h, err)
	}
	return h
}

// splitRuntime opens the runtime gate on c and runs its first pass.
func splitRuntime(t *testing.T, c *Client) HostRuntimeReport {
	t.Helper()
	openRuntimeGate(c)
	rep, err := c.SplitHostRuntime(context.Background())
	if err != nil {
		t.Fatalf("runtime split pass: %v", err)
	}
	if !c.HostRuntimeLive() {
		t.Fatal("a complete runtime pass with the gate open did not make the node live")
	}
	return rep
}

// applyRuntimeAsReplicated runs stmts the way the WAL apply path does for one
// entry from a peer: applied, then the runtime absorb inside the same
// transaction.
func applyRuntimeAsReplicated(t *testing.T, c *Client, stmts ...Statement) {
	t.Helper()
	ctx := context.Background()
	c.mu.Lock()
	defer c.mu.Unlock()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s.SQL, s.Params...); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := absorbUnlatchedRuntimeWrite(ctx, tx, stmts); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// TestRuntimeRow_Resolve pins the read rule: a live host_runtime row is the
// answer, however new the hosts row is and whatever its copy says.
func TestRuntimeRow_Resolve(t *testing.T) {
	v1 := runtimeVals{Version: "v1", SchemaVersion: 64, CPU: someInt(8)}
	v2 := runtimeVals{Version: "v2", SchemaVersion: 65, CPU: someInt(16)}
	// colonelpanik/litevirt#267: this replica refused the hosts half of a
	// version report because a concurrent region change made its hosts row
	// newer. hosts.version is the stale value on the newer ROW.
	if got := (runtimeRow{hosts: v1, hostsTS: "2026-01-02T00:00:00Z", present: true, rt: v2}).resolve(); got != v2 {
		t.Errorf("a present host_runtime row lost to the hosts copy: %+v", got)
	}
	if got := (runtimeRow{hosts: v1, hostsTS: "2026-01-01T00:00:00Z"}).resolve(); got != v1 {
		t.Errorf("no host_runtime row must read the hosts columns: %+v", got)
	}
}

// TestUnlatchedRuntimeWrites: an entry's hosts runtime writes are absorbed only
// when the entry carries no host_runtime statement — what marks it as made by
// a node not writing host_runtime — with values read from the statements.
func TestUnlatchedRuntimeWrites(t *testing.T) {
	const ts = "2026-01-02T00:00:00Z"
	version := Statement{SQL: updateHostVersionSQL, Params: []interface{}{"v2", ts, "h1"}}
	resources := Statement{SQL: updateHostResourcesSQL, Params: []interface{}{4, 8, 16, ts, "h1"}}
	boot := Statement{SQL: hostStartupResourcesSQL, Params: []interface{}{"active", "v3", 65, 2, 4, 8, ts, "h1"}}
	bootBlank := Statement{SQL: hostStartupSQL, Params: []interface{}{"active", "", 65, ts, "h1"}}
	live := Statement{SQL: hostRuntimeVersionSQL, Params: runtimeParams("h1", runtimeVals{Version: "v2"}, ts)}
	region := Statement{SQL: `UPDATE hosts SET region = ?, updated_at = ? WHERE name = ?`, Params: []interface{}{"eu", ts, "h1"}}

	if host, gotTS, cols, ok := RuntimeWrite(version); !ok || host != "h1" || gotTS != ts || len(cols) != 1 || cols["version"] != "v2" {
		t.Errorf("a hosts-only version report: %s %s %v %v", host, gotTS, cols, ok)
	}
	if _, _, cols, ok := RuntimeWrite(resources); !ok || cols["cpu_total"] != int64(4) || cols["mem_total"] != int64(8) || cols["disk_total"] != int64(16) {
		t.Errorf("a hosts-only resource report: %v %v", cols, ok)
	}
	if _, _, cols, ok := RuntimeWrite(boot); !ok || cols["version"] != "v3" || cols["schema_version"] != int64(65) || cols["disk_total"] != int64(8) {
		t.Errorf("a hosts-only boot report: %v %v", cols, ok)
	}
	if _, _, cols, ok := RuntimeWrite(bootBlank); !ok || len(cols) != 1 || cols["schema_version"] != int64(65) {
		t.Errorf("a boot report with a blank version must leave the version out (COALESCE keeps it): %v %v", cols, ok)
	}
	if got := unlatchedRuntimeWrites([]Statement{version, live}); len(got) != 0 {
		t.Errorf("a live node's dual-write was taken for a hosts-only write: %+v", got)
	}
	if got := unlatchedRuntimeWrites([]Statement{region}); len(got) != 0 {
		t.Errorf("an operator write was taken for a runtime report: %+v", got)
	}
	insert := Statement{SQL: insertHostSQL, Params: []interface{}{
		"h9", "10.0.0.9", "root", 22, 7443, "active", "s", 64, 1024, 10, "", "v9", "worker", 0.0, 0.0, -1, -1, "ph", ts, ts}}
	if _, _, cols, ok := RuntimeWrite(insert); !ok || cols["version"] != "v9" || cols["cpu_total"] != int64(64) || cols["capacity_policy_hash"] != "ph" {
		t.Errorf("a hosts-only insert: %v %v", cols, ok)
	}
}

// TestHostRuntime_UnlatchedEmitsNothingAPreviousReleaseCannotDecode: until the
// gate opens, every runtime writer writes the hosts columns in their
// previous-release shapes, nothing naming host_runtime reaches the replication
// stream, and readers read hosts.
func TestHostRuntime_UnlatchedEmitsNothingAPreviousReleaseCannotDecode(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	if c.MayWriteHostRuntime() || c.HostRuntimeLive() {
		t.Fatal("the runtime gate is open on a client nobody wired; it must fail closed")
	}
	seedMembershipHosts(t, c, "h1", "h2")
	if err := UpdateHostStartup(ctx, c, "h1", "active", "v2", 4, 8, 16, true); err != nil {
		t.Fatal(err)
	}
	if err := UpdateHostVersion(ctx, c, "h2", "v3"); err != nil {
		t.Fatal(err)
	}
	if err := UpdateHostResources(ctx, c, "h2", 1, 2, 3); err != nil {
		t.Fatal(err)
	}
	if rep, err := c.SplitHostRuntime(ctx); err != nil || rep != (HostRuntimeReport{}) {
		t.Fatalf("an unlatched runtime pass did work: %+v err=%v", rep, err)
	}
	if log := mutationLogText(t, c); strings.Contains(log, "host_runtime") {
		t.Fatalf("an unlatched node put a host_runtime statement on the replication stream. A "+
			"previous-release peer has no ledger entry for it, so its apply fails closed:\n%s", log)
	}
	if n := tableCount(t, c, "host_runtime"); n != 0 {
		t.Fatalf("host_runtime holds %d rows before the latch", n)
	}
	if h := hostOf(t, c, "h1"); h.Version != "v2" || h.SchemaVersion != CurrentSchemaVersion || h.DiskTotal != 16 {
		t.Errorf("GetHost before the latch: %+v", h)
	}
	if h := hostOf(t, c, "h2"); h.Version != "v3" || h.CPUTotal != 1 {
		t.Errorf("GetHost before the latch: %+v", h)
	}
}

// TestHostRuntime_ThePassCopiesAtTheFloor: the first pass gives every host a
// host_runtime row stamped with the hosts row's instant moved back by the floor
// shift — the same on every node that copies the row, and older than any real
// report — and a second pass writes nothing.
func TestHostRuntime_ThePassCopiesAtTheFloor(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1", "h2")
	if err := UpdateHostStartup(ctx, c, "h1", "active", "v2", 4, 8, 16, true); err != nil {
		t.Fatal(err)
	}
	srcTS := hostsCol(t, c, "h1", "updated_at")
	if rep := splitRuntime(t, c); rep.Copied != 2 {
		t.Fatalf("first pass copied %d, want 2", rep.Copied)
	}
	at, err := time.Parse(time.RFC3339, srcTS)
	if err != nil {
		t.Fatalf("hosts updated_at %q unreadable: %v", srcTS, err)
	}
	want := at.Add(-membershipCopyFloorShift).UTC().Format(nowTSLayout)
	if got := runtimeCol(t, c, "h1", "updated_at"); got != want {
		t.Errorf("copied row updated_at = %q, want the floor %q of the hosts row's %q", got, want, srcTS)
	}
	if got := runtimeCol(t, c, "h1", "version"); got != "v2" {
		t.Errorf("copied version = %q", got)
	}
	if got := runtimeCol(t, c, "h1", "disk_total"); got != "16" {
		t.Errorf("copied disk_total = %q", got)
	}
	before := len(mutationLogText(t, c))
	if rep, err := c.SplitHostRuntime(ctx); err != nil || rep != (HostRuntimeReport{}) {
		t.Fatalf("second pass: %+v err=%v, want no work", rep, err)
	}
	if after := len(mutationLogText(t, c)); after != before {
		t.Error("an idempotent pass put statements on the replication stream")
	}
}

// TestHostRuntime_LiveWritersWriteBothHomes: after the split every runtime
// report is written to hosts AND host_runtime in one batch under one
// updated_at, and readers read host_runtime — also when this replica's hosts
// row is NEWER and holds an older value (the #267 case).
func TestHostRuntime_LiveWritersWriteBothHomes(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1")
	splitRuntime(t, c)

	if err := UpdateHostStartup(ctx, c, "h1", "active", "v5", 2, 4, 8, true); err != nil {
		t.Fatal(err)
	}
	for _, col := range []string{"version", "cpu_total", "disk_total", "schema_version"} {
		if h, r := hostsCol(t, c, "h1", col), runtimeCol(t, c, "h1", col); h != r {
			t.Errorf("%s: hosts %q, host_runtime %q after a live boot report", col, h, r)
		}
	}
	if h, r := hostsCol(t, c, "h1", "updated_at"), runtimeCol(t, c, "h1", "updated_at"); h != r {
		t.Errorf("the two halves of one report carry different clocks: hosts %q, host_runtime %q", h, r)
	}
	// One entry carries both halves: that is what marks it, on every
	// receiver, as a live writer's dual-write rather than a hosts-only report
	// to absorb (unlatched_origin.go).
	last := oneString(t, c, `SELECT stmts FROM mutation_log ORDER BY seq DESC LIMIT 1`, "stmts")
	if !strings.Contains(last, "UPDATE hosts SET state") || !strings.Contains(last, "INSERT INTO host_runtime") {
		t.Fatalf("a live boot report's entry does not carry both halves:\n%s", last)
	}

	// A blank version keeps the one the host has, in both homes.
	if err := UpdateHostStartup(ctx, c, "h1", "active", "", 0, 0, 0, false); err != nil {
		t.Fatal(err)
	}
	if got := runtimeCol(t, c, "h1", "version"); got != "v5" {
		t.Errorf("a blank boot version cleared host_runtime.version to %q", got)
	}
	if got := runtimeCol(t, c, "h1", "cpu_total"); got != "2" {
		t.Errorf("a boot report without resources changed cpu_total to %q", got)
	}

	// A version report does not carry the totals: the partial upsert leaves
	// them as they are.
	if err := UpdateHostVersion(ctx, c, "h1", "v6"); err != nil {
		t.Fatal(err)
	}
	if err := UpdateHostResources(ctx, c, "h1", 32, 64, 128); err != nil {
		t.Fatal(err)
	}
	if h := hostOf(t, c, "h1"); h.Version != "v6" || h.CPUTotal != 32 || h.DiskTotal != 128 {
		t.Errorf("GetHost after live reports: %+v", h)
	}

	// Stand in for this replica having REFUSED the hosts half of the version
	// report: a concurrent region change left hosts.version stale on a newer
	// hosts row. Set directly, so it is not a hosts-only write to absorb.
	if err := c.execLocal(ctx, `UPDATE hosts SET version = ?, region = ?, updated_at = ? WHERE name = ?`, "v-stale", "eu", c.NowTS(), "h1"); err != nil {
		t.Fatal(err)
	}
	if h := hostOf(t, c, "h1"); h.Version != "v6" || h.Region != "eu" {
		t.Errorf("GetHost = version %q region %q; the stale hosts.version came back, or the region was lost", h.Version, h.Region)
	}
	if rep, err := c.SplitHostRuntime(ctx); err != nil || rep.Copied != 0 {
		t.Fatalf("a pass after the region change: %+v %v; it carried the stale hosts.version across", rep, err)
	}
}

// TestHostRuntime_AbsorbsAHostsOnlyWrite: an entry from a node not writing
// host_runtime is carried into the row this node holds, stamped with the
// write's own updated_at, only when it is newer than the row; a gate-closed
// node updates a row it holds but never creates one.
func TestHostRuntime_AbsorbsAHostsOnlyWrite(t *testing.T) {
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1", "h2")
	splitRuntime(t, c)
	floor := runtimeCol(t, c, "h1", "updated_at")

	newer := c.NowTS()
	applyRuntimeAsReplicated(t, c, Statement{SQL: hostStartupResourcesSQL, Params: []interface{}{"active", "v-old-build", 64, 3, 6, 9, newer, "h1"}})
	if got := runtimeCol(t, c, "h1", "version"); got != "v-old-build" {
		t.Errorf("an unlatched neighbour's boot report was not absorbed: host_runtime.version = %q", got)
	}
	if got := runtimeCol(t, c, "h1", "updated_at"); got != newer {
		t.Errorf("absorbed row updated_at = %q, want the write's own %q", got, newer)
	}
	if h := hostOf(t, c, "h1"); h.Version != "v-old-build" || h.DiskTotal != 9 {
		t.Errorf("GetHost after the absorb: %+v", h)
	}
	if lwwOrder(floor, newer) >= 0 {
		t.Fatal("the floor copy is not older than a real write; the rest is vacuous")
	}

	// An OLDER hosts-only write is not taken.
	applyRuntimeAsReplicated(t, c, Statement{SQL: updateHostVersionSQL, Params: []interface{}{"v-older", "2000-01-01T00:00:00Z", "h1"}})
	if got := runtimeCol(t, c, "h1", "version"); got != "v-old-build" {
		t.Errorf("an older hosts-only write was absorbed over a newer row: %q", got)
	}

	// A dual-written entry is a live writer's: its own host_runtime half
	// applies, the absorb adds nothing.
	ts := c.NowTS()
	applyRuntimeAsReplicated(t, c,
		Statement{SQL: updateHostVersionSQL, Params: []interface{}{"v-live", ts, "h2"}},
		Statement{SQL: hostRuntimeVersionSQL, Params: runtimeParams("h2", runtimeVals{Version: "v-live"}, ts)})
	if got := runtimeCol(t, c, "h2", "version"); got != "v-live" {
		t.Errorf("a live dual-write: host_runtime.version = %q", got)
	}

	// Gate closed: an existing row is updated, a missing one is not created.
	d := newTestDB(t)
	seedMembershipHosts(t, d, "h1", "h2")
	splitRuntime(t, d)
	if _, err := d.db.Exec(`DELETE FROM host_runtime WHERE host_name = 'h2'`); err != nil {
		t.Fatal(err)
	}
	d.SetHostRuntimeGate(nil)
	ts = d.NowTS()
	applyRuntimeAsReplicated(t, d,
		Statement{SQL: updateHostVersionSQL, Params: []interface{}{"v-a", ts, "h1"}})
	applyRuntimeAsReplicated(t, d,
		Statement{SQL: updateHostVersionSQL, Params: []interface{}{"v-b", ts, "h2"}})
	if got := runtimeCol(t, d, "h1", "version"); got != "v-a" {
		t.Errorf("a gate-closed node did not update the host_runtime row it holds: %q", got)
	}
	if n := oneString(t, d, `SELECT CAST(COUNT(*) AS TEXT) AS n FROM host_runtime WHERE host_name = 'h2'`, "n"); n != "0" {
		t.Errorf("a gate-closed node created a host_runtime row (%s)", n)
	}
	if h := hostOf(t, d, "h2"); h.Version != "v-b" {
		t.Errorf("a host with no row must read the hosts columns: %q", h.Version)
	}
}

// TestHostRuntime_TheLocalPathAbsorbsItsOwnHostsOnlyWrite: a node whose gate
// is closed but which holds rows (a peer latched before it) updates its own
// row when it writes a report to hosts alone, or its readers would serve the
// value from before its own write.
func TestHostRuntime_TheLocalPathAbsorbsItsOwnHostsOnlyWrite(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1")
	splitRuntime(t, c)
	c.SetHostRuntimeGate(nil)
	if err := UpdateHostVersion(ctx, c, "h1", "v-local"); err != nil {
		t.Fatal(err)
	}
	if h := hostOf(t, c, "h1"); h.Version != "v-local" {
		t.Errorf("GetHost = %q after this node's own hosts-only report; the local path did not absorb it", h.Version)
	}
}

// TestHostRuntime_ReadmissionRetiresTheOldMachinesRow: a host re-admitted
// over its tombstone is a new machine. Its old host_runtime row is retired on
// the node that applies the re-admission, readers fall back to the hosts
// columns, and the new machine's first live report brings the row back whole.
func TestHostRuntime_ReadmissionRetiresTheOldMachinesRow(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1")
	splitRuntime(t, c)
	if err := UpdateHostStartup(ctx, c, "h1", "active", "v-old", 96, 512, 1000, true); err != nil {
		t.Fatal(err)
	}
	if err := DeleteHost(ctx, c, "h1"); err != nil {
		t.Fatal(err)
	}
	if err := AdmitHost(ctx, c, HostRecord{Name: "h1", Address: "10.0.0.10", State: "active", CertSerial: "new-serial"}); err != nil {
		t.Fatal(err)
	}
	var deleted sql.NullString
	if err := c.db.QueryRow(`SELECT deleted_at FROM host_runtime WHERE host_name = 'h1'`).Scan(&deleted); err != nil {
		t.Fatal(err)
	}
	if !deleted.Valid {
		t.Fatal("re-admission left the old machine's host_runtime row live; readers would serve its version and totals")
	}
	if rep, err := c.SplitHostRuntime(ctx); err != nil || rep.Copied != 0 {
		t.Fatalf("a pass revived the retired row: %+v %v", rep, err)
	}
	if err := UpdateHostStartup(ctx, c, "h1", "active", "v-new", 4, 8, 0, false); err != nil {
		t.Fatal(err)
	}
	if got := runtimeCol(t, c, "h1", "version"); got != "v-new" {
		t.Errorf("the new machine's first report: host_runtime.version = %q", got)
	}
	if h := hostOf(t, c, "h1"); h.Version != "v-new" || h.CPUTotal == 96 {
		t.Errorf("GetHost after the new machine's report: %+v; the old machine's totals came back", h)
	}
}

// TestHostRuntime_TheAbsorbNeverCreatesARow (review m-1): two latched nodes
// that hold no host_runtime row for a host, and whose hosts rows disagree on a
// column the write does not set, apply the same hosts-only report. Neither
// creates a row: a created row would take that column from its own hosts row
// under the write's one updated_at, and the two rows would tie on
// schema_version, which the resolver leaves unresolved. Each reads the report
// from its hosts columns, and the pass then copies at the floor of its own
// hosts row's clock.
func TestHostRuntime_TheAbsorbNeverCreatesARow(t *testing.T) {
	ctx := context.Background()
	ts := "2026-06-01T00:00:00.000000001Z"
	var nodes []*Client
	for i, sv := range []int{63, 64} {
		c := newTestDB(t)
		seedMembershipHosts(t, c, "h1")
		if err := c.execLocal(ctx, `UPDATE hosts SET schema_version = ? WHERE name = 'h1'`, sv); err != nil {
			t.Fatal(err)
		}
		splitRuntime(t, c)
		if _, err := c.db.Exec(`DELETE FROM host_runtime WHERE host_name = 'h1'`); err != nil {
			t.Fatal(err)
		}
		applyRuntimeAsReplicated(t, c, Statement{SQL: updateHostVersionSQL, Params: []interface{}{"v-unlatched", ts, "h1"}})
		if n := oneString(t, c, `SELECT CAST(COUNT(*) AS TEXT) AS n FROM host_runtime WHERE host_name = 'h1'`, "n"); n != "0" {
			t.Errorf("node %d: the absorb created a host_runtime row with the gate open; two such nodes "+
				"would hold different schema versions under one updated_at", i)
		}
		if h := hostOf(t, c, "h1"); h.Version != "v-unlatched" {
			t.Errorf("node %d: a host with no row must read the report from hosts: %q", i, h.Version)
		}
		nodes = append(nodes, c)
	}
	for i, c := range nodes {
		if _, err := c.SplitHostRuntime(ctx); err != nil {
			t.Fatal(err)
		}
		if got := runtimeCol(t, c, "h1", "version"); got != "v-unlatched" {
			t.Errorf("node %d: the pass copy = %q, want the report", i, got)
		}
		if got := runtimeCol(t, c, "h1", "updated_at"); lwwOrder(got, "2000-01-01T00:00:00Z") >= 0 {
			t.Errorf("node %d: the pass copy is stamped %q, not at the floor", i, got)
		}
	}
}
