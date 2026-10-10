package corrosion

import (
	"context"
	"strings"
	"testing"
)

// retireLive is a node that has latched host_membership_split_v1, completed
// its pass, and latched host_membership_retire_v1.
func retireLive(t *testing.T, c *Client) {
	t.Helper()
	openMembershipGate(c)
	if _, err := c.SplitHostMembership(context.Background()); err != nil || !c.HostMembershipLive() {
		t.Fatalf("split pass: %v live=%v", err, c.HostMembershipLive())
	}
	c.SetHostMembershipRetireGate(func() bool { return true })
}

// logSince is every entry logged after seq, one string per entry.
func logSince(t *testing.T, c *Client, seq int64) []string {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT stmts FROM mutation_log WHERE seq > ? ORDER BY seq`, seq)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.String("stmts"))
	}
	return out
}

func maxSeq(t *testing.T, c *Client) int64 {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT COALESCE(MAX(seq), 0) AS s FROM mutation_log`)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	return rows[0].Int64("s")
}

// TestHostMembershipRetire_NoHostsStatementAfterTheLatch: once the retire
// token has latched, a state change, a fence, an isolation and its clear put no
// hosts statement in their entries — only host_membership — and every reader
// still sees each of them.
func TestHostMembershipRetire_NoHostsStatementAfterTheLatch(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1", "h2")
	retireLive(t, c)
	from := maxSeq(t, c)
	hostsBefore := hostsCol(t, c, "h1", "updated_at")

	if err := UpdateHostState(ctx, c, "h1", "draining"); err != nil {
		t.Fatal(err)
	}
	if got := resolvedState(t, c, "h1"); got != "draining" {
		t.Errorf("resolved state after a retired drain = %q", got)
	}
	if err := RecordFenceWithState(ctx, c, FenceLogRecord{ID: "f1", HostName: "h1", Method: "ipmi", Result: "fenced"}, "fenced"); err != nil {
		t.Fatal(err)
	}
	if got := resolvedState(t, c, "h1"); got != "fenced" {
		t.Errorf("resolved state after a retired fence = %q", got)
	}
	if err := IsolateHost(ctx, c, "h2", "h1", "manual"); err != nil {
		t.Fatal(err)
	}
	cur, err := hostMembershipOf(ctx, c, "h1")
	if err != nil || cur == nil || cur.Epoch == 0 {
		t.Fatalf("isolation not recorded: %+v %v", cur, err)
	}
	if err := ClearHostIsolation(ctx, c, "h1", cur.Epoch); err != nil {
		t.Fatal(err)
	}
	if cur, _ := hostMembershipOf(ctx, c, "h1"); cur == nil || cur.Epoch != 0 {
		t.Errorf("isolation not cleared: %+v", cur)
	}

	entries := logSince(t, c, from)
	if len(entries) < 4 {
		t.Fatalf("expected the four writes to be logged, got %d entries", len(entries))
	}
	for _, e := range entries {
		if strings.Contains(e, "UPDATE hosts") {
			t.Errorf("a retired membership write still put a hosts statement on the stream:\n%s", e)
		}
		if !strings.Contains(e, "host_membership") {
			t.Errorf("a retired membership write did not write host_membership:\n%s", e)
		}
	}
	if got := hostsCol(t, c, "h1", "updated_at"); got != hostsBefore {
		t.Errorf("the hosts row's clock moved (%s -> %s) for a pure membership write", hostsBefore, got)
	}
}

// TestHostMembershipRetire_NeedsALiveNode: the retire gate alone changes
// nothing on a node that is not writing host_membership — there the hosts
// columns are the only copy.
func TestHostMembershipRetire_NeedsALiveNode(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1")
	c.SetHostMembershipRetireGate(func() bool { return true })
	if err := UpdateHostState(ctx, c, "h1", "maintenance"); err != nil {
		t.Fatal(err)
	}
	if got := hostsCol(t, c, "h1", "state"); got != "maintenance" {
		t.Errorf("hosts.state = %q on a node not writing host_membership; it is the only copy", got)
	}
}

// TestHostMembershipRetire_AFrozenNodeCreatesARowOnlyFromACompleteWrite: once
// the hosts copy is frozen, an absorb that would CREATE a membership row fills
// the columns the write did not set from that copy, stamped with the write's
// new time — which could resurrect a cleared isolation. So a row is created
// only from a write that carries everything: an INSERT INTO hosts, or one that
// sets both state and isolation.
func TestHostMembershipRetire_AFrozenNodeCreatesARowOnlyFromACompleteWrite(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1")
	retireLive(t, c)
	if err := c.execLocal(ctx, `DELETE FROM host_membership WHERE host_name = 'h1'`); err != nil {
		t.Fatal(err)
	}
	if err := c.execLocal(ctx, `UPDATE hosts SET isolation_epoch = 7, isolation_reason = 'manual' WHERE name = 'h1'`); err != nil {
		t.Fatal(err)
	}
	applyAsReplicated(t, c, Statement{SQL: updateHostStateSQL, Params: []interface{}{"draining", "2999-01-01T00:00:00Z", "h1"}})
	if n := oneString(t, c, `SELECT COUNT(*) AS n FROM host_membership WHERE host_name = 'h1'`, "n"); n != "0" {
		t.Errorf("a state-only hosts write created a membership row from the frozen copy's isolation")
	}
	applyAsReplicated(t, c, Statement{SQL: insertHostSQL, Params: []interface{}{
		"h9", "10.0.0.9", "", 0, 0, "active", "s-h9", 0, 0, 0, "", "", "worker", 0.0, 0.0, -1, -1, "", "2999-01-01T00:00:00Z", "2999-01-01T00:00:01Z"}})
	if got := membershipCol(t, c, "h9", "state"); got != "active" {
		t.Errorf("an INSERT INTO hosts did not create its membership row (state %q)", got)
	}
}

// TestHostMembershipRetire_AFrozenPassCopiesNothing: once retired, the hosts
// copy is no source: a pass leaves a missing row missing, and the host reads as
// unknown — never as the frozen 'active' — until its row arrives.
func TestHostMembershipRetire_AFrozenPassCopiesNothing(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1")
	retireLive(t, c)
	if err := c.execLocal(ctx, `DELETE FROM host_membership WHERE host_name = 'h1'`); err != nil {
		t.Fatal(err)
	}
	if rep, err := c.SplitHostMembership(ctx); err != nil || rep.Copied != 0 {
		t.Fatalf("pass = %+v err=%v; a retired node copied from the frozen hosts row", rep, err)
	}
	if got := resolvedState(t, c, "h1"); got != HostStateUnknown {
		t.Errorf("a host with no membership row on a retired node reads %q, want %q", got, HostStateUnknown)
	}
}

// TestHostMembershipRetire_AFrozenWriterNeverInsertsFromTheFrozenCopy
// (re-review m1): a state write on a retired node that has no membership row
// for the host must not insert one — the insert would take its isolation pair
// from the frozen hosts copy. It updates a row that exists elsewhere and
// changes nothing here.
func TestHostMembershipRetire_AFrozenWriterNeverInsertsFromTheFrozenCopy(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1")
	retireLive(t, c)
	if err := c.execLocal(ctx, `DELETE FROM host_membership WHERE host_name = 'h1'`); err != nil {
		t.Fatal(err)
	}
	if err := c.execLocal(ctx, `UPDATE hosts SET isolation_epoch = 7, isolation_reason = 'manual' WHERE name = 'h1'`); err != nil {
		t.Fatal(err)
	}
	from := maxSeq(t, c)
	if err := UpdateHostState(ctx, c, "h1", "draining"); err != nil {
		t.Fatal(err)
	}
	if err := RecordFenceWithState(ctx, c, FenceLogRecord{ID: "f-m1", HostName: "h1", Method: "ipmi", Result: "fenced"}, "fenced"); err != nil {
		t.Fatal(err)
	}
	if n := oneString(t, c, `SELECT COUNT(*) AS n FROM host_membership WHERE host_name = 'h1'`, "n"); n != "0" {
		t.Errorf("a frozen writer created h1's membership row from the frozen copy's isolation")
	}
	for _, e := range logSince(t, c, from) {
		if strings.Contains(e, "INSERT INTO host_membership") {
			t.Errorf("a frozen writer put an insert on the stream:\n%s", e)
		}
	}
}

// TestHostMembershipRetire_AFloorCopyDatesNothing (re-review m4): a split-pass
// copy is stamped at a floor and records no state change, so it is no "active
// since" boundary — HostActiveSince and HostFenceLife report none, as before
// the split, rather than a boundary forty years back.
func TestHostMembershipRetire_AFloorCopyDatesNothing(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1")
	openMembershipGate(c)
	if _, err := c.SplitHostMembership(ctx); err != nil {
		t.Fatal(err)
	}
	floor, ok := membershipCopyTS("2026-06-01T00:00:00Z")
	if !ok {
		t.Fatal("floor")
	}
	if err := c.execLocal(ctx, `UPDATE host_membership SET state = 'active', updated_at = ? WHERE host_name = 'h1'`, floor); err != nil {
		t.Fatal(err)
	}
	if at, ok, err := HostActiveSince(ctx, c, "h1"); err != nil || ok {
		t.Errorf("HostActiveSince = %v ok=%v err=%v; a floor copy is no boundary", at, ok, err)
	}
	if since, _, ok, err := HostFenceLife(ctx, c, "h1"); err != nil || ok {
		t.Errorf("HostFenceLife = %v ok=%v err=%v; a floor copy is no boundary", since, ok, err)
	}
}
