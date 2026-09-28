package corrosion

import (
	"context"
	"strings"
	"testing"
	"time"
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

// TestMembershipRow_Resolve pins the one read rule every reader and the pass
// share.
func TestMembershipRow_Resolve(t *testing.T) {
	const older, newer = "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"
	active := membershipVals{State: "active"}
	fenced := membershipVals{State: "fenced"}
	isolated := membershipVals{State: "active", Epoch: 7, Reason: IsolationManual}
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
			membershipRow{hosts: active, hostsTS: older, memPresent: true, mem: fenced, memTS: newer, absPresent: true, abs: active}, true, fenced},
		// THE case #267 is about: this replica refused the hosts half of the
		// coordinator's fence because a concurrent version report made its hosts
		// row newer. hosts.state is the stale value — a newer ROW, not a newer
		// STATE — so "the newer copy wins" would undo the fence here.
		{"a newer hosts row whose state did not move is not a state write",
			membershipRow{hosts: active, hostsTS: newer, memPresent: true, mem: fenced, memTS: older, absPresent: true, abs: active}, true, fenced},
		{"a hosts state written since it was carried across, on a newer row, wins",
			membershipRow{hosts: membershipVals{State: "maintenance"}, hostsTS: newer, memPresent: true, mem: active, memTS: older, absPresent: true, abs: active},
			true, membershipVals{State: "maintenance"}},
		{"a moved hosts state on an OLDER row loses to the membership row",
			membershipRow{hosts: membershipVals{State: "maintenance"}, hostsTS: older, memPresent: true, mem: fenced, memTS: newer, absPresent: true, abs: active}, true, fenced},
		{"no absorbed record means no late write is recognised",
			membershipRow{hosts: membershipVals{State: "maintenance"}, hostsTS: newer, memPresent: true, mem: fenced, memTS: older}, true, fenced},
		{"a late state write does not undo an isolation recorded in host_membership",
			membershipRow{hosts: membershipVals{State: "maintenance"}, hostsTS: newer, memPresent: true, mem: isolated, memTS: older, absPresent: true, abs: active},
			true, membershipVals{State: "maintenance", Epoch: 7, Reason: IsolationManual}},
		{"a late isolation write does not undo a state recorded in host_membership",
			membershipRow{hosts: isolated, hostsTS: newer, memPresent: true, mem: fenced, memTS: older, absPresent: true, abs: active},
			true, membershipVals{State: "fenced", Epoch: 7, Reason: IsolationManual}},
	}
	for _, tc := range cases {
		if got := tc.row.resolve(tc.live, true); got != tc.want {
			t.Errorf("%s: resolve = %+v, want %+v", tc.name, got, tc.want)
		}
	}
	// Outside the absorb window the membership row wins outright: legacy
	// writers only exist during the roll, and the exception has a false
	// positive (host_membership.go) the steady state must not carry.
	late := membershipRow{hosts: membershipVals{State: "maintenance"}, hostsTS: newer, memPresent: true, mem: fenced, memTS: older, absPresent: true, abs: active}
	if got := late.resolve(true, false); got != fenced {
		t.Errorf("after the absorb window resolve = %+v, want the membership row %+v", got, fenced)
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
	// The record catches up with it first, as a pass would have.
	if err := c.Execute(ctx, `UPDATE hosts SET state = ?, updated_at = ? WHERE name = ?`, "active", c.NowTS(), "h1"); err != nil {
		t.Fatal(err)
	}
	if err := c.execLocal(ctx, absorbedUpsertSQL, "h1", "active", 0, ""); err != nil {
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
	if rep, err := c.SplitHostMembership(ctx); err != nil || rep.Absorbed != 0 {
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

// TestHostMembership_ALateHostsWriteIsCarriedAcross: a node whose own latch has
// not formed yet still writes hosts.state. A live node's readers see it at
// once and its next pass carries it into host_membership.
func TestHostMembership_ALateHostsWriteIsCarriedAcross(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1", "h2")
	openMembershipGate(c)
	if _, err := c.SplitHostMembership(ctx); err != nil {
		t.Fatal(err)
	}
	// Isolation recorded after the split lives in host_membership.
	if err := IsolateHost(ctx, c, "h2", "h1", IsolationManual); err != nil {
		t.Fatal(err)
	}
	// The unlatched neighbour's drain, as it arrives here: its previous-release
	// statement shape, with a newer updated_at.
	if err := c.Execute(ctx, `UPDATE hosts SET state = ?, updated_at = ? WHERE name = ?`, "maintenance", c.NowTS(), "h1"); err != nil {
		t.Fatal(err)
	}
	if got := resolvedState(t, c, "h1"); got != "maintenance" {
		t.Errorf("GetHost state = %q; a live reader ignored the late drain", got)
	}
	rep, err := c.SplitHostMembership(ctx)
	if err != nil || rep.Absorbed != 1 {
		t.Fatalf("pass: %+v %v, want the late write absorbed", rep, err)
	}
	if got := membershipCol(t, c, "h1", "state"); got != "maintenance" {
		t.Errorf("host_membership.state = %q after the pass", got)
	}
	if e, _, _ := HostIsolation(ctx, c, "h1"); e == 0 {
		t.Error("carrying the late state across undid the isolation recorded in host_membership")
	}
	// Carried across once; a later version report does not carry it again.
	if err := UpdateHostVersion(ctx, c, "h1", "v2"); err != nil {
		t.Fatal(err)
	}
	if err := UpdateHostState(ctx, c, "h1", "active"); err != nil {
		t.Fatal(err)
	}
	if err := UpdateHostVersion(ctx, c, "h1", "v3"); err != nil {
		t.Fatal(err)
	}
	if rep, _ := c.SplitHostMembership(ctx); rep.Absorbed != 0 {
		t.Errorf("the late write was carried across twice: %+v", rep)
	}
	if got := resolvedState(t, c, "h1"); got != "active" {
		t.Errorf("GetHost state = %q, want the later live write", got)
	}
}

// TestHostMembership_TheAbsorbWindowCloses: once the window after going live
// has passed, a hosts-column value that moved is no longer taken over the
// membership row, by readers or by the pass.
func TestHostMembership_TheAbsorbWindowCloses(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1")
	openMembershipGate(c)
	if _, err := c.SplitHostMembership(ctx); err != nil {
		t.Fatal(err)
	}
	c.hostMembershipLiveSince.Store(time.Now().Add(-2 * hostMembershipAbsorbWindow).UnixNano())
	if err := c.Execute(ctx, `UPDATE hosts SET state = ?, updated_at = ? WHERE name = ?`, "maintenance", c.NowTS(), "h1"); err != nil {
		t.Fatal(err)
	}
	if got := resolvedState(t, c, "h1"); got != "active" {
		t.Errorf("GetHost state = %q after the window; a moved hosts value was still taken", got)
	}
	if rep, _ := c.SplitHostMembership(ctx); rep.Absorbed != 0 {
		t.Errorf("a pass after the window carried a hosts value across: %+v", rep)
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
