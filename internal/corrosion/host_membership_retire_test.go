package corrosion

import (
	"context"
	"strings"
	"testing"
	"time"
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

// TestHostMembershipRetire_AFloorCopyDatesItsHostsRow (re-review 2, N6): a
// split-pass copy is stamped at the floor — the copied hosts row's instant
// moved back by a fixed shift — and the readers undo the shift, so the "active
// since" boundary is that hosts row's time, as before the split, decoded from
// the copy's own stamp.
func TestHostMembershipRetire_AFloorCopyDatesItsHostsRow(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1")
	openMembershipGate(c)
	if _, err := c.SplitHostMembership(ctx); err != nil {
		t.Fatal(err)
	}
	const hostsTS = "2026-06-01T00:00:00Z"
	floor, ok := membershipCopyTS(hostsTS)
	if !ok {
		t.Fatal("floor")
	}
	if err := c.execLocal(ctx, `UPDATE host_membership SET state = 'active', updated_at = ? WHERE host_name = 'h1'`, floor); err != nil {
		t.Fatal(err)
	}
	want, _ := time.Parse(time.RFC3339, hostsTS)
	at, ok, err := HostActiveSince(ctx, c, "h1")
	if err != nil || !ok || !at.Equal(want) {
		t.Errorf("HostActiveSince = %v ok=%v err=%v, want %v (the copied hosts row's time)", at, ok, err, want)
	}
	since, _, ok, err := HostFenceLife(ctx, c, "h1")
	if err != nil || !ok || !since.Equal(want.Add(-fenceLifeSkew).Truncate(time.Second)) {
		t.Errorf("HostFenceLife = %v ok=%v err=%v, want %v less the skew", since, ok, err, want)
	}
}

// TestHostMembershipRetire_AReadmissionCreatesOrRevivesTheRow (re-review 2,
// N5): a re-admission from a node not writing host_membership yet rewrites the
// identity row whole. On a retired node it creates the host's missing
// membership row (a host removed before the split never had one) and revives a
// tombstoned one, keeping that row's isolation — otherwise the host reads
// unknown forever, as every later state write only updates an existing row.
func TestHostMembershipRetire_AReadmissionCreatesOrRevivesTheRow(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1", "h2")
	retireLive(t, c)
	for _, q := range []string{
		`UPDATE hosts SET deleted_at = '2026-01-01T00:00:00Z' WHERE name IN ('h1', 'h2')`,
		`DELETE FROM host_membership WHERE host_name = 'h1'`,
		`UPDATE host_membership SET deleted_at = '2026-01-01T00:00:00Z', isolation_epoch = 9, isolation_reason = 'manual' WHERE host_name = 'h2'`,
	} {
		if err := c.execLocal(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range []string{"h1", "h2"} {
		applyAsReplicated(t, c, Statement{SQL: readmitHostSQL, Params: []interface{}{
			"10.0.0.9", "root", 22, 7443, "joining", "new-" + h, "2999-01-01T00:00:00Z", h, "new-" + h}})
	}
	for _, h := range []string{"h1", "h2"} {
		if got := resolvedState(t, c, h); got != "joining" {
			t.Errorf("%s reads %q after its re-admission, want joining", h, got)
		}
	}
	if got := membershipCol(t, c, "h2", "isolation_epoch"); got != "9" {
		t.Errorf("h2's revived row has isolation_epoch %q, want the tombstone's 9", got)
	}
}

// TestHostMembershipRetire_AReadmissionWithoutTheRowNeverTiesTheRevive
// (re-review 3, R5): a retired node that lacks a host's tombstoned membership
// row takes a re-admission's isolation from its frozen hosts copy, which may
// be stale. Its row must not carry the re-admission's own timestamp — every
// node holding the tombstone revives it at that timestamp with the current
// epoch, and an equal timestamp with a different epoch is an unresolved tie.
// It takes a fresh epoch strictly above the one it has seen, at a stamp below
// the re-admission's, so the revived row replaces it everywhere.
func TestHostMembershipRetire_AReadmissionWithoutTheRowNeverTiesTheRevive(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h3")
	retireLive(t, c)
	const readmitTS = "2999-01-01T00:00:00.000000000Z"
	for _, q := range []string{
		`UPDATE hosts SET deleted_at = '2026-01-01T00:00:00Z', isolation_epoch = 3 WHERE name = 'h3'`,
		`DELETE FROM host_membership WHERE host_name = 'h3'`,
	} {
		if err := c.execLocal(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	applyAsReplicated(t, c, Statement{SQL: readmitHostSQL, Params: []interface{}{
		"10.0.0.9", "root", 22, 7443, "joining", "new-h3", readmitTS, "h3", "new-h3"}})
	if got := resolvedState(t, c, "h3"); got != "joining" {
		t.Errorf("h3 reads %q after its re-admission, want joining", got)
	}
	if got := membershipCol(t, c, "h3", "isolation_epoch"); got != "4" {
		t.Errorf("h3's row has isolation_epoch %s, want 4: strictly above the 3 this node has seen", got)
	}
	if ts := membershipCol(t, c, "h3", "updated_at"); lwwOrder(ts, readmitTS) >= 0 {
		t.Fatalf("h3's row is stamped %s, not below the re-admission's %s: it ties the revive elsewhere", ts, readmitTS)
	}

	// The revived row from a node that held the tombstone: current epoch 7.
	table := syncTable{Name: "host_membership", Columns: []string{
		"host_name", "state", "isolation_epoch", "isolation_reason", "updated_at", "deleted_at"}}
	if _, _, err := c.mergeChunk(table, [][]interface{}{{"h3", "joining", int64(7), "manual", readmitTS, nil}},
		buildMergeUpsertSQL(table.Name, table.Columns, []string{"host_name"}),
		[]string{"host_name"}, []int{0}, indexOf(table.Columns, "updated_at")); err != nil {
		t.Fatalf("mergeChunk: %v", err)
	}
	if got := membershipCol(t, c, "h3", "isolation_epoch"); got != "7" {
		t.Errorf("h3's isolation_epoch is %s after the revived row arrived, want its 7", got)
	}
	if n := c.UnresolvedTieCount(); n != 0 {
		t.Errorf("%d unresolved ties: the re-admission tied the revived row", n)
	}
}

// TestHostMembershipRetire_AReadmissionIsRecognisedByFingerprint (re-review
// 3, nit): the absorb recognises a re-admission the way host_readmit.go does
// — by its statement fingerprint — not by its exact text, so one recogniser
// decides both the reset and the revive.
func TestHostMembershipRetire_AReadmissionIsRecognisedByFingerprint(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h2")
	retireLive(t, c)
	for _, q := range []string{
		`UPDATE hosts SET deleted_at = '2026-01-01T00:00:00Z' WHERE name = 'h2'`,
		`UPDATE host_membership SET deleted_at = '2026-01-01T00:00:00Z', isolation_epoch = 9, isolation_reason = 'manual' WHERE host_name = 'h2'`,
	} {
		if err := c.execLocal(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	variant := strings.Replace(readmitHostSQL, "UPDATE hosts SET", "update hosts set", 1)
	if fp, err := FingerprintSQL(variant); err != nil || fp != readmitFingerprint {
		t.Fatalf("precondition: the variant's fingerprint %q (err %v) is not the re-admission's", fp, err)
	}
	applyAsReplicated(t, c, Statement{SQL: variant, Params: []interface{}{
		"10.0.0.9", "root", 22, 7443, "joining", "new-h2", "2999-01-01T00:00:00Z", "h2", "new-h2"}})
	if got := resolvedState(t, c, "h2"); got != "joining" {
		t.Errorf("h2 reads %q after a re-admission written in another form, want joining", got)
	}
}
