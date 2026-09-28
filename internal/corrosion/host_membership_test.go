package corrosion

import (
	"context"
	"strings"
	"testing"
)

func openMembershipGate(c *Client) { c.SetHostMembershipGate(func() bool { return true }) }

func hostsCol(t *testing.T, c *Client, host, col string) string {
	t.Helper()
	return oneString(t, c, `SELECT `+col+` FROM hosts WHERE name = '`+host+`'`, col)
}

func membershipCol(t *testing.T, c *Client, host, col string) string {
	t.Helper()
	return oneString(t, c, `SELECT `+col+` FROM host_membership WHERE host_name = '`+host+`'`, col)
}

func resolvedState(t *testing.T, c *Client, host string) string {
	t.Helper()
	h, err := GetHost(context.Background(), c, host)
	if err != nil || h == nil {
		t.Fatalf("GetHost %s: %+v %v", host, h, err)
	}
	return h.State
}

func seedMembershipHosts(t *testing.T, c *Client, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := InsertHost(context.Background(), c, HostRecord{Name: n, Address: "10.0.0.9", State: "active", CertSerial: "s-" + n}); err != nil {
			t.Fatalf("InsertHost %s: %v", n, err)
		}
	}
}

// TestMembershipRow_Resolve pins the read rule: once live, the membership row
// is the answer, however new the hosts row is or whatever its copy says.
func TestMembershipRow_Resolve(t *testing.T) {
	const older, newer = "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"
	active := membershipVals{State: "active"}
	fenced := membershipVals{State: "fenced"}
	cases := []struct {
		name string
		row  membershipRow
		live bool
		want membershipVals
	}{
		{"not live reads the hosts columns, whatever the membership row says",
			membershipRow{hosts: active, hostsTS: older, memPresent: true, mem: fenced, memTS: newer}, false, active},
		{"no membership row falls back to the hosts columns",
			membershipRow{hosts: fenced, hostsTS: older}, true, fenced},
		{"live reads the membership row",
			membershipRow{hosts: active, hostsTS: older, memPresent: true, mem: fenced, memTS: newer}, true, fenced},
		// THE case #267 is about: this replica refused the hosts half of the
		// coordinator's fence because a concurrent version report made its hosts
		// row newer. hosts.state is the stale value on a newer ROW, so "the
		// newer copy wins" would undo the fence here.
		{"a newer hosts row holding a different state does not win",
			membershipRow{hosts: active, hostsTS: newer, memPresent: true, mem: fenced, memTS: older}, true, fenced},
	}
	for _, tc := range cases {
		if got := tc.row.resolve(tc.live); got != tc.want {
			t.Errorf("%s: resolve = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// TestUnlatchedMembershipWrites: an entry's hosts state and isolation writes
// are absorbed only when the entry carries no host_membership statement — that
// is what marks it as made by a node not writing host_membership — and their
// values are read from the statements themselves, literals included.
func TestUnlatchedMembershipWrites(t *testing.T) {
	const ts = "2026-01-02T00:00:00Z"
	state := Statement{SQL: updateHostStateSQL, Params: []interface{}{"fenced", ts, "h1"}}
	member := Statement{SQL: hostMembershipStateSQL, Params: []interface{}{"h1", "fenced", int64(0), "", ts}}
	iso := Statement{SQL: isolateHostSQL, Params: []interface{}{int64(3), IsolationManual, ts, "h1"}}
	clear := Statement{SQL: clearHostIsolationSQL, Params: []interface{}{ts, "h1", int64(3)}}
	version := Statement{SQL: `UPDATE hosts SET version = ?, updated_at = ? WHERE name = ?`, Params: []interface{}{"v2", ts, "h1"}}

	if got := unlatchedMembershipWrites([]Statement{state}); len(got) != 1 ||
		got[0] != (unlatchedMembershipWrite{host: "h1", ts: ts, hasState: true, state: "fenced"}) {
		t.Errorf("a hosts-only state write: %+v", got)
	}
	if got := unlatchedMembershipWrites([]Statement{iso}); len(got) != 1 ||
		got[0] != (unlatchedMembershipWrite{host: "h1", ts: ts, hasIso: true, epoch: 3, reason: IsolationManual}) {
		t.Errorf("a hosts-only isolation: %+v", got)
	}
	if got := unlatchedMembershipWrites([]Statement{clear}); len(got) != 1 ||
		got[0] != (unlatchedMembershipWrite{host: "h1", ts: ts, hasIso: true, epoch: 0, reason: ""}) {
		t.Errorf("a hosts-only isolation clear (literal values): %+v", got)
	}
	if got := unlatchedMembershipWrites([]Statement{state, member}); len(got) != 0 {
		t.Errorf("a live node's dual-write was taken for a hosts-only write: %+v", got)
	}
	if got := unlatchedMembershipWrites([]Statement{version}); len(got) != 0 {
		t.Errorf("a version report was taken for a state write: %+v", got)
	}
	insert := Statement{SQL: insertHostSQL, Params: []interface{}{
		"h9", "10.0.0.9", "root", 22, 7443, "active", "s", 0, 0, 0, "", "", "worker", 0.0, 0.0, -1, -1, "", ts, ts}}
	if got := unlatchedMembershipWrites([]Statement{insert}); len(got) != 1 || got[0].host != "h9" || got[0].state != "active" {
		t.Errorf("a hosts-only insert: %+v", got)
	}
}

// TestHostMembership_UnlatchedEmitsNothingAPreviousReleaseCannotDecode: until
// the gate opens, every state and isolation writer writes the hosts columns in
// their previous-release shapes, nothing naming host_membership reaches the
// replication stream, and readers read hosts.
func TestHostMembership_UnlatchedEmitsNothingAPreviousReleaseCannotDecode(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	if c.MayWriteHostMembership() || c.HostMembershipLive() {
		t.Fatal("the membership gate is open on a client nobody wired; it must fail closed")
	}
	seedMembershipHosts(t, c, "h1", "h2")
	if err := UpdateHostState(ctx, c, "h1", "draining"); err != nil {
		t.Fatal(err)
	}
	if err := UpdateHostStartup(ctx, c, "h2", "upgrading", "v2", 4, 8, 16, true); err != nil {
		t.Fatal(err)
	}
	if err := IsolateHost(ctx, c, "h2", "h1", IsolationManual); err != nil {
		t.Fatal(err)
	}
	epoch, _, err := HostIsolation(ctx, c, "h1")
	if err != nil || epoch == 0 {
		t.Fatalf("HostIsolation = %d, %v", epoch, err)
	}
	if err := ClearHostIsolation(ctx, c, "h1", epoch); err != nil {
		t.Fatal(err)
	}
	if rep, err := c.SplitHostMembership(ctx); err != nil || rep != (HostMembershipReport{}) {
		t.Fatalf("an unlatched split pass did work: %+v err=%v", rep, err)
	}

	if log := mutationLogText(t, c); strings.Contains(log, "host_membership") {
		t.Fatalf("an unlatched node put a host_membership statement on the replication stream. A "+
			"previous-release peer has no ledger entry for it, so its apply fails closed:\n%s", log)
	}
	if n := tableCount(t, c, "host_membership"); n != 0 {
		t.Fatalf("host_membership holds %d rows before the latch", n)
	}
	if got := hostsCol(t, c, "h1", "state"); got != "draining" {
		t.Errorf("hosts.state = %q; a previous-release reader would not see the drain", got)
	}
	if got := hostsCol(t, c, "h2", "state"); got != "upgrading" {
		t.Errorf("hosts.state = %q after the boot write", got)
	}
	if got := resolvedState(t, c, "h1"); got != "draining" {
		t.Errorf("GetHost state = %q before the latch", got)
	}
}

// TestHostMembership_ThePassCopiesWithTheHostsTimestamp: the first pass gives
// every host a membership row stamped with the hosts row's updated_at — so two
// nodes copying the same replicated row write the same membership row — and a
// second pass writes nothing.
func TestHostMembership_ThePassCopiesWithTheHostsTimestamp(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1", "h2")
	if err := UpdateHostState(ctx, c, "h1", "maintenance"); err != nil {
		t.Fatal(err)
	}
	if err := IsolateHost(ctx, c, "h1", "h2", IsolationManual); err != nil {
		t.Fatal(err)
	}
	srcTS := hostsCol(t, c, "h2", "updated_at")

	openMembershipGate(c)
	rep, err := c.SplitHostMembership(ctx)
	if err != nil || rep.Copied != 2 {
		t.Fatalf("first pass: %+v err=%v, want 2 copied", rep, err)
	}
	if !c.HostMembershipLive() {
		t.Fatal("a complete pass with the gate open did not make the node live")
	}
	if got := membershipCol(t, c, "h2", "updated_at"); got != srcTS {
		t.Errorf("copied row updated_at = %q, want the hosts row's %q (NowTS here makes every node's copy differ)", got, srcTS)
	}
	if got := membershipCol(t, c, "h1", "state"); got != "maintenance" {
		t.Errorf("copied state = %q", got)
	}
	if got := membershipCol(t, c, "h2", "isolation_epoch"); got == "0" {
		t.Errorf("copied isolation_epoch = %q; the isolation did not come across", got)
	}
	before := len(mutationLogText(t, c))
	if rep, err := c.SplitHostMembership(ctx); err != nil || rep != (HostMembershipReport{}) {
		t.Fatalf("second pass: %+v err=%v, want no work", rep, err)
	}
	if after := len(mutationLogText(t, c)); after != before {
		t.Error("an idempotent pass put statements on the replication stream")
	}
}

// TestHostMembership_LiveWritersWriteBothHomes: after the split every state and
// isolation change is written to hosts AND host_membership in one batch under
// one updated_at. The hosts half is what a node rolled back one release reads;
// nothing is cleared or frozen.
func TestHostMembership_LiveWritersWriteBothHomes(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1", "h2")
	openMembershipGate(c)
	if _, err := c.SplitHostMembership(ctx); err != nil {
		t.Fatal(err)
	}

	if err := UpdateHostState(ctx, c, "h1", "fenced"); err != nil {
		t.Fatal(err)
	}
	if got := hostsCol(t, c, "h1", "state"); got != "fenced" {
		t.Errorf("hosts.state = %q after a live fence; a node rolled back one release would read the host as live", got)
	}
	if got := membershipCol(t, c, "h1", "state"); got != "fenced" {
		t.Errorf("host_membership.state = %q after a live fence", got)
	}
	if h, m := hostsCol(t, c, "h1", "updated_at"), membershipCol(t, c, "h1", "updated_at"); h != m {
		t.Errorf("the two halves of one state write carry different clocks: hosts %q, membership %q", h, m)
	}
	if err := IsolateHost(ctx, c, "h2", "h1", IsolationRolledBackLatch); err != nil {
		t.Fatal(err)
	}
	if got := hostsCol(t, c, "h1", "isolation_epoch"); got == "0" {
		t.Error("a live isolation left hosts.isolation_epoch at 0; a rolled-back node would accept the isolated host's replication")
	}
	if got := membershipCol(t, c, "h1", "isolation_epoch"); got == "0" {
		t.Error("a live isolation left host_membership.isolation_epoch at 0")
	}
	if got := resolvedState(t, c, "h1"); got != "fenced" {
		t.Errorf("GetHost state = %q, want fenced", got)
	}
	voters, err := VoterSet(ctx, c)
	if err != nil || voters["h1"] {
		t.Errorf("VoterSet = %v %v; a fenced host must not vote", voters, err)
	}
	epoch, reason, err := HostIsolation(ctx, c, "h1")
	if err != nil || epoch == 0 || reason != IsolationRolledBackLatch {
		t.Fatalf("HostIsolation = %d %q %v", epoch, reason, err)
	}
	if err := IsolateHost(ctx, c, "h2", "h1", IsolationManual); err != ErrIsolationNotMonotone {
		t.Errorf("re-isolating an isolated host = %v, want ErrIsolationNotMonotone", err)
	}
	if err := ClearHostIsolation(ctx, c, "h1", epoch+1); err != ErrNoRowsAffected {
		t.Errorf("clearing a different epoch = %v, want ErrNoRowsAffected", err)
	}
	if err := ClearHostIsolation(ctx, c, "h1", epoch); err != nil {
		t.Fatal(err)
	}
	if e, _, _ := HostIsolation(ctx, c, "h1"); e != 0 {
		t.Errorf("isolation not cleared: %d", e)
	}
	if got := hostsCol(t, c, "h1", "isolation_epoch"); got != "0" {
		t.Errorf("the clear left hosts.isolation_epoch = %q", got)
	}

	// Stand in for this replica having REFUSED the hosts half of the fence: a
	// concurrent version report left hosts.state stale on a newer hosts row.
	if err := c.Execute(ctx, `UPDATE hosts SET state = ?, updated_at = ? WHERE name = ?`, "active", c.NowTS(), "h1"); err != nil {
		t.Fatal(err)
	}
	// A version report now: the hosts row is newer again and its state column
	// still says active. That is not a state write.
	if err := UpdateHostVersion(ctx, c, "h1", "v9"); err != nil {
		t.Fatal(err)
	}
	if got := resolvedState(t, c, "h1"); got != "fenced" {
		t.Errorf("after a version report GetHost state = %q; the stale hosts.state came back", got)
	}
	if rep, err := c.SplitHostMembership(ctx); err != nil || rep.Copied != 0 {
		t.Fatalf("a pass after a version report: %+v %v; it carried the stale hosts.state across", rep, err)
	}
	if got := resolvedState(t, c, "h1"); got != "fenced" {
		t.Errorf("after a pass GetHost state = %q", got)
	}

	// The boot write goes to both homes too.
	if err := UpdateHostStartup(ctx, c, "h2", "upgrading", "v3", 2, 4, 8, true); err != nil {
		t.Fatal(err)
	}
	if got := hostsCol(t, c, "h2", "state"); got != "upgrading" {
		t.Errorf("a live boot write left hosts.state = %q", got)
	}
	if got := hostsCol(t, c, "h2", "version"); got != "v3" {
		t.Errorf("a live boot write lost the version: %q", got)
	}
	if got := resolvedState(t, c, "h2"); got != "upgrading" {
		t.Errorf("boot state = %q", got)
	}
}

// applyAsReplicated runs stmts the way the apply path does for one entry from
// a peer: applied, then absorbed inside the same transaction.
func applyAsReplicated(t *testing.T, c *Client, stmts ...Statement) {
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
	c.absorbUnlatchedMembershipWrite(ctx, tx, stmts)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// TestHostMembership_AHostsOnlyWriteIsAbsorbed: a node whose own latch has not
// formed yet writes hosts.state alone. A latched node receiving that entry
// absorbs it into host_membership at once — per column group, stamped with the
// write's own updated_at, locally (not re-emitted) — and only when newer.
func TestHostMembership_AHostsOnlyWriteIsAbsorbed(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1", "h2")
	openMembershipGate(c)
	if _, err := c.SplitHostMembership(ctx); err != nil {
		t.Fatal(err)
	}
	if err := IsolateHost(ctx, c, "h2", "h1", IsolationManual); err != nil {
		t.Fatal(err)
	}
	before := len(mutationLogText(t, c))
	ts := c.NowTS()
	applyAsReplicated(t, c, Statement{SQL: updateHostStateSQL, Params: []interface{}{"maintenance", ts, "h1"}})
	if got := resolvedState(t, c, "h1"); got != "maintenance" {
		t.Errorf("GetHost state = %q after a hosts-only drain arrived", got)
	}
	if got := membershipCol(t, c, "h1", "updated_at"); got != ts {
		t.Errorf("absorbed row stamped %q, want the write's own %q", got, ts)
	}
	if e, _, _ := HostIsolation(ctx, c, "h1"); e == 0 {
		t.Error("absorbing the state undid the isolation recorded in host_membership")
	}
	if after := len(mutationLogText(t, c)); after != before {
		t.Error("the absorption was put on this node's replication stream; it is a local derived copy")
	}

	// An OLDER hosts-only write does not win.
	applyAsReplicated(t, c, Statement{SQL: updateHostStateSQL, Params: []interface{}{"offline", "2000-01-01T00:00:00Z", "h1"}})
	if got := resolvedState(t, c, "h1"); got != "maintenance" {
		t.Errorf("an older hosts-only write was absorbed: %q", got)
	}

	// A live node's dual-write, arriving as one entry, is taken from its
	// membership half — the hosts half is never absorbed separately.
	uts := c.NowTS()
	applyAsReplicated(t, c,
		Statement{SQL: updateHostStateSQL, Params: []interface{}{"draining", uts, "h2"}},
		Statement{SQL: hostMembershipStateSQL, Params: []interface{}{"h2", "fenced", int64(0), "", uts}})
	if got := resolvedState(t, c, "h2"); got != "fenced" {
		t.Errorf("GetHost state = %q; a dual-write entry's hosts half was absorbed over its membership half", got)
	}
}

// TestHostMembership_AnUnlatchedReceiverAbsorbsNothing: before its own latch a
// node writes nothing to host_membership, a hosts-only entry included.
func TestHostMembership_AnUnlatchedReceiverAbsorbsNothing(t *testing.T) {
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1")
	if _, err := c.writeMembershipRow(context.Background(), "h1", membershipVals{State: "active"}, "2000-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	applyAsReplicated(t, c, Statement{SQL: updateHostStateSQL, Params: []interface{}{"maintenance", c.NowTS(), "h1"}})
	if got := membershipCol(t, c, "h1", "state"); got != "active" {
		t.Errorf("an unlatched receiver absorbed a write into host_membership: %q", got)
	}
}

// TestHostMembership_LiveSurvivesARestart: the node's readers read
// host_membership from the first read after a restart — the daemon writes its
// boot state before anything else runs.
func TestHostMembership_LiveSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	c := &Client{dataDir: dir}
	if c.HostMembershipLive() {
		t.Fatal("live before any pass")
	}
	c.markHostMembershipLive()
	if !(&Client{dataDir: dir}).HostMembershipLive() {
		t.Fatal("a restarted client with the same data dir is not live; its boot state would go to the frozen hosts.state")
	}
}

// TestHostMembership_ACopyNeverOverwritesARowThatArrived: the pass's copy is
// guarded on the row still being absent. A peer's newer copy that lands
// between the pass's scan and its write must survive: the origin applies an
// upsert unconditionally, and its own older write would never be repaired.
func TestHostMembership_ACopyNeverOverwritesARowThatArrived(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1")
	const newer = "2030-01-01T00:00:00Z"
	if wrote, err := c.writeMembershipRow(ctx, "h1", membershipVals{State: "fenced"}, newer); err != nil || !wrote {
		t.Fatalf("first copy: %v %v", wrote, err)
	}
	wrote, err := c.writeMembershipRow(ctx, "h1", membershipVals{State: "active"}, "2000-01-01T00:00:00Z")
	if err != nil || wrote {
		t.Fatalf("a copy over an existing row: wrote=%v err=%v", wrote, err)
	}
	if got := membershipCol(t, c, "h1", "state"); got != "fenced" {
		t.Errorf("an older copy overwrote the row that was already there: %q", got)
	}
}
