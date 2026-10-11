package corrosion

import (
	"context"
	"strings"
	"testing"
)

func lastEntry(t *testing.T, c *Client) string {
	t.Helper()
	return oneString(t, c, `SELECT stmts FROM mutation_log ORDER BY seq DESC LIMIT 1`, "stmts")
}

// TestHostRuntimeRetire_NoHostsStatementAfterTheLatch: once
// host_runtime_retire_v1 has latched on a live node, a version report and a
// resource report write host_runtime alone, and so does the boot report once
// host_membership_retire_v1 has latched too: none of them moves the hosts
// row's clock, and readers still read every report.
func TestHostRuntimeRetire_NoHostsStatementAfterTheLatch(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1")
	openMembershipGate(c)
	if _, err := c.SplitHostMembership(ctx); err != nil {
		t.Fatal(err)
	}
	c.SetHostMembershipRetireGate(func() bool { return true })
	splitRuntime(t, c)
	c.SetHostRuntimeRetireGate(func() bool { return true })
	before := hostsCol(t, c, "h1", "updated_at")

	if err := UpdateHostVersion(ctx, c, "h1", "v-r1"); err != nil {
		t.Fatal(err)
	}
	if e := lastEntry(t, c); strings.Contains(e, "UPDATE hosts") {
		t.Errorf("a retired version report still wrote hosts:\n%s", e)
	}
	if err := UpdateHostResources(ctx, c, "h1", 7, 14, 21); err != nil {
		t.Fatal(err)
	}
	if e := lastEntry(t, c); strings.Contains(e, "UPDATE hosts") {
		t.Errorf("a retired resource report still wrote hosts:\n%s", e)
	}
	if err := UpdateHostStartup(ctx, c, "h1", "upgrading", "v-r2", 8, 16, 24, true); err != nil {
		t.Fatal(err)
	}
	if e := lastEntry(t, c); strings.Contains(e, "UPDATE hosts") {
		t.Errorf("a boot report with both copies retired still wrote hosts:\n%s", e)
	}
	if after := hostsCol(t, c, "h1", "updated_at"); after != before {
		t.Errorf("hosts.updated_at moved %q -> %q: a report still shares the operator's clock", before, after)
	}
	h := hostOf(t, c, "h1")
	if h.Version != "v-r2" || h.DiskTotal != 24 || h.State != "upgrading" || h.SchemaVersion != CurrentSchemaVersion {
		t.Errorf("GetHost after retired reports: %+v", h)
	}
}

// TestHostRuntimeRetire_TheBootReportKeepsTheStateWhileMembershipIsNotRetired:
// with only the runtime copy retired, the boot report still writes the boot
// state to hosts — host_membership_retire_v1 decides that column — in the
// plain state statement, without the runtime columns.
func TestHostRuntimeRetire_TheBootReportKeepsTheStateWhileMembershipIsNotRetired(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1")
	splitRuntime(t, c)
	c.SetHostRuntimeRetireGate(func() bool { return true })
	if err := UpdateHostVersion(ctx, c, "h1", "v-before"); err != nil {
		t.Fatal(err)
	}
	frozen := hostsCol(t, c, "h1", "version")
	if err := UpdateHostStartup(ctx, c, "h1", "upgrading", "v-boot", 8, 16, 24, true); err != nil {
		t.Fatal(err)
	}
	if got := hostsCol(t, c, "h1", "state"); got != "upgrading" {
		t.Errorf("hosts.state = %q; the boot state must still reach hosts while membership is not retired", got)
	}
	if got := hostsCol(t, c, "h1", "version"); got != frozen {
		t.Errorf("hosts.version = %q, want the frozen %q: the retired boot report wrote the runtime columns", got, frozen)
	}
	if h := hostOf(t, c, "h1"); h.Version != "v-boot" || h.DiskTotal != 24 {
		t.Errorf("GetHost after the boot report: %+v", h)
	}
}

// TestHostRuntimeRetire_NeedsALiveNode: a node not writing host_runtime yet
// writes the hosts columns whatever the retire gate says.
func TestHostRuntimeRetire_NeedsALiveNode(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedMembershipHosts(t, c, "h1")
	c.SetHostRuntimeRetireGate(func() bool { return true })
	if err := UpdateHostVersion(ctx, c, "h1", "v-notlive"); err != nil {
		t.Fatal(err)
	}
	if got := hostsCol(t, c, "h1", "version"); got != "v-notlive" {
		t.Errorf("hosts.version = %q; a node that is not live dropped its only copy", got)
	}
	// The boot report decides its hosts statement from the retire gate too;
	// on a node that is not live it is still the whole report.
	if err := UpdateHostStartup(ctx, c, "h1", "active", "v-notlive-boot", 3, 6, 9, true); err != nil {
		t.Fatal(err)
	}
	if h := hostOf(t, c, "h1"); h.Version != "v-notlive-boot" || h.DiskTotal != 9 {
		t.Errorf("GetHost after a boot report on a node that is not live: %+v; the report was dropped", h)
	}
}
