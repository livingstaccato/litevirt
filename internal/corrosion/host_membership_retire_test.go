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
