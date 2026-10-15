package corrosion

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

func synfloodGrant(t *testing.T) capabilities.FeatureGrant {
	return capabilities.GrantForTest(t, capabilities.FeatureFirewallSynflood)
}

func setSynflood(t *testing.T, c *Client, scope string, p FirewallSynflood) {
	t.Helper()
	if err := SetFirewallSynflood(context.Background(), c, synfloodGrant(t), scope, p, "alice"); err != nil {
		t.Fatalf("set %s %+v: %v", scope, p, err)
	}
}

// putSynfloodRaw stores a value as a replica might receive it from another
// build, bypassing the writer's validation.
func putSynfloodRaw(t *testing.T, c *Client, scope, value string) {
	t.Helper()
	if err := c.Execute(context.Background(), clusterPolicyUpsertSQL, FirewallSynfloodKey(scope), value, "peer", c.NowTS()); err != nil {
		t.Fatal(err)
	}
}

// A policy written at either scope reads back as written, under the key and
// JSON value the spec names.
func TestFirewallSynflood_RoundTrip(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	openClusterPolicyGate(c)

	if got, err := ResolveFirewallSynflood(ctx, c, "h1"); err != nil || got.On() || got.Scope != "" {
		t.Fatalf("no row resolves to %+v, %v; want off from no scope", got, err)
	}

	setSynflood(t, c, FirewallSynfloodScopeCluster, FirewallSynflood{Mode: SynfloodOn, Rate: 300, Burst: 1500})
	got, err := ResolveFirewallSynflood(ctx, c, "h1")
	if err != nil || !got.On() || got.Rate != 300 || got.Burst != 1500 || got.Scope != FirewallSynfloodScopeCluster {
		t.Fatalf("cluster on resolves to %+v, %v", got, err)
	}
	rows, err := c.Query(ctx, `SELECT value, set_by FROM cluster_policies WHERE key = ?`, "firewall_synflood")
	if err != nil || len(rows) != 1 {
		t.Fatalf("cluster row: %v %v", rows, err)
	}
	if v := rows[0].String("value"); v != `{"mode":"on","rate":300,"burst":1500}` {
		t.Errorf("stored value %q", v)
	}
	if s := rows[0].String("set_by"); s != "alice" {
		t.Errorf("set_by %q", s)
	}

	setSynflood(t, c, "h2", FirewallSynflood{Mode: SynfloodOff})
	if rows, _ := c.Query(ctx, `SELECT value FROM cluster_policies WHERE key = ?`, "firewall_synflood/h2"); len(rows) != 1 {
		t.Fatalf("host row missing under firewall_synflood/h2")
	}
	got, err = ResolveFirewallSynflood(ctx, c, "h2")
	if err != nil || got.On() || got.Mode != SynfloodOff || got.Scope != "h2" {
		t.Fatalf("host off resolves to %+v, %v", got, err)
	}
	p, recorded, err := GetFirewallSynflood(ctx, c, "h2")
	if err != nil || !recorded || p.Mode != SynfloodOff {
		t.Fatalf("get h2 = %+v %v %v", p, recorded, err)
	}
}

// A host row wins over the cluster row, in both directions.
//
// Mutation: resolve the cluster row first.
func TestFirewallSynflood_HostOverridesCluster(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	openClusterPolicyGate(c)
	setSynflood(t, c, FirewallSynfloodScopeCluster, FirewallSynflood{Mode: SynfloodOn, Rate: 200, Burst: 1000})
	setSynflood(t, c, "h1", FirewallSynflood{Mode: SynfloodOff})
	setSynflood(t, c, "h2", FirewallSynflood{Mode: SynfloodOn, Rate: 50, Burst: 60})

	if got, err := ResolveFirewallSynflood(ctx, c, "h1"); err != nil || got.On() || got.Scope != "h1" {
		t.Errorf("h1 (host off over cluster on) = %+v, %v", got, err)
	}
	if got, err := ResolveFirewallSynflood(ctx, c, "h2"); err != nil || !got.On() || got.Rate != 50 || got.Burst != 60 || got.Scope != "h2" {
		t.Errorf("h2 (host on 50/60) = %+v, %v", got, err)
	}
	if got, err := ResolveFirewallSynflood(ctx, c, "h3"); err != nil || !got.On() || got.Rate != 200 || got.Scope != FirewallSynfloodScopeCluster {
		t.Errorf("h3 (no host row) = %+v, %v", got, err)
	}

	setSynflood(t, c, FirewallSynfloodScopeCluster, FirewallSynflood{Mode: SynfloodOff})
	if got, err := ResolveFirewallSynflood(ctx, c, "h2"); err != nil || !got.On() || got.Rate != 50 {
		t.Errorf("h2 (host on over cluster off) = %+v, %v", got, err)
	}
}

// "" is no row: a host's "" inherits the cluster's policy, and the cluster's
// "" is off.
func TestFirewallSynflood_EmptyInherits(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	openClusterPolicyGate(c)
	setSynflood(t, c, FirewallSynfloodScopeCluster, FirewallSynflood{Mode: SynfloodOn, Rate: 200, Burst: 1000})
	setSynflood(t, c, "h1", FirewallSynflood{Mode: SynfloodOff})
	setSynflood(t, c, "h1", FirewallSynflood{}) // inherit

	rows, err := c.Query(ctx, `SELECT value FROM cluster_policies WHERE key = ?`, "firewall_synflood/h1")
	if err != nil || len(rows) != 1 || rows[0].String("value") != "" {
		t.Fatalf("inherit stored %v, %v; want one row holding \"\"", rows, err)
	}
	if _, recorded, err := GetFirewallSynflood(ctx, c, "h1"); err != nil || recorded {
		t.Errorf("an inherited host reads recorded=%v, %v", recorded, err)
	}
	if got, err := ResolveFirewallSynflood(ctx, c, "h1"); err != nil || !got.On() || got.Scope != FirewallSynfloodScopeCluster {
		t.Errorf("inherited h1 = %+v, %v; want the cluster's on", got, err)
	}

	setSynflood(t, c, FirewallSynfloodScopeCluster, FirewallSynflood{})
	if got, err := ResolveFirewallSynflood(ctx, c, "h1"); err != nil || got.On() || got.Scope != "" {
		t.Errorf("cluster \"\" = %+v, %v; want off from no scope", got, err)
	}
}

// A row this build cannot read — not JSON, an unknown mode, or a rate or burst
// the renderer would refuse — reads ON at the defaults, with
// ErrUnreadableFirewallPolicy naming the key. A host's unreadable row does
// not fall through to the cluster's.
//
// Mutation: read garbage as off.
func TestFirewallSynflood_GarbageReadsOn(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ name, scope, value string }{
		{"not json", FirewallSynfloodScopeCluster, "on please"},
		{"unknown mode", FirewallSynfloodScopeCluster, `{"mode":"strict","rate":200,"burst":1000}`},
		{"rate zero", FirewallSynfloodScopeCluster, `{"mode":"on","rate":0,"burst":1000}`},
		{"burst too high", FirewallSynfloodScopeCluster, `{"mode":"on","rate":200,"burst":100001}`},
		{"host garbage over cluster off", "h1", `{"mode":`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t)
			openClusterPolicyGate(c)
			setSynflood(t, c, FirewallSynfloodScopeCluster, FirewallSynflood{Mode: SynfloodOff})
			putSynfloodRaw(t, c, tc.scope, tc.value)
			got, err := ResolveFirewallSynflood(ctx, c, "h1")
			if !errors.Is(err, ErrUnreadableFirewallPolicy) {
				t.Fatalf("err = %v, want ErrUnreadableFirewallPolicy", err)
			}
			if !strings.Contains(err.Error(), FirewallSynfloodKey(tc.scope)) {
				t.Errorf("err %q does not name the key %q", err, FirewallSynfloodKey(tc.scope))
			}
			if !got.On() || got.Rate != SynfloodDefaultRate || got.Burst != SynfloodDefaultBurst || got.Scope != tc.scope {
				t.Errorf("garbage resolves to %+v, want on at %d/%d from %s", got, SynfloodDefaultRate, SynfloodDefaultBurst, tc.scope)
			}
		})
	}
}

// The writer refuses without the firewall_synflood grant (another feature's
// grant does not cover it), and while the cluster_policies gate is closed;
// neither writes a row.
func TestFirewallSynflood_RefusedWithoutGrantOrGate(t *testing.T) {
	ctx := context.Background()
	on := FirewallSynflood{Mode: SynfloodOn, Rate: 200, Burst: 1000}

	c := testClient(t)
	openClusterPolicyGate(c)
	for name, g := range map[string]capabilities.FeatureGrant{
		"zero":  {},
		"other": capabilities.GrantForTest(t, capabilities.FeatureFirewallLog),
	} {
		err := SetFirewallSynflood(ctx, c, g, FirewallSynfloodScopeCluster, on, "alice")
		if !errors.Is(err, capabilities.ErrNoFeatureGrant) {
			t.Errorf("%s grant: err = %v, want ErrNoFeatureGrant", name, err)
		}
	}

	closed := testClient(t)
	if err := SetFirewallSynflood(ctx, closed, synfloodGrant(t), FirewallSynfloodScopeCluster, on, "alice"); !errors.Is(err, ErrClusterPolicyGateClosed) {
		t.Errorf("gate closed: err = %v, want ErrClusterPolicyGateClosed", err)
	}

	for _, cl := range []*Client{c, closed} {
		if rows, err := cl.Query(ctx, `SELECT key FROM cluster_policies WHERE key LIKE 'firewall_synflood%'`); err != nil || len(rows) != 0 {
			t.Errorf("a refused write left rows %v, %v", rows, err)
		}
	}
}

// The writer refuses a policy the renderer could not render, and a scope that
// would not round-trip through the key.
func TestFirewallSynflood_RefusesInvalid(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	openClusterPolicyGate(c)
	for _, tc := range []struct {
		name  string
		scope string
		p     FirewallSynflood
	}{
		{"rate 0", FirewallSynfloodScopeCluster, FirewallSynflood{Mode: SynfloodOn, Rate: 0, Burst: 1000}},
		{"rate 100001", FirewallSynfloodScopeCluster, FirewallSynflood{Mode: SynfloodOn, Rate: 100001, Burst: 1000}},
		{"burst 0", FirewallSynfloodScopeCluster, FirewallSynflood{Mode: SynfloodOn, Rate: 200, Burst: 0}},
		{"burst 100001", FirewallSynfloodScopeCluster, FirewallSynflood{Mode: SynfloodOn, Rate: 200, Burst: 100001}},
		{"unknown mode", FirewallSynfloodScopeCluster, FirewallSynflood{Mode: "strict", Rate: 200, Burst: 1000}},
		{"inherit with a rate", "h1", FirewallSynflood{Rate: 200}},
		{"empty scope", "", FirewallSynflood{Mode: SynfloodOff}},
		{"scope with a slash", "h1/x", FirewallSynflood{Mode: SynfloodOff}},
	} {
		if err := SetFirewallSynflood(ctx, c, synfloodGrant(t), tc.scope, tc.p, "alice"); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
	if rows, err := c.Query(ctx, `SELECT key FROM cluster_policies WHERE key LIKE 'firewall_synflood%'`); err != nil || len(rows) != 0 {
		t.Errorf("a refused write left rows %v, %v", rows, err)
	}
	// The bounds themselves are accepted.
	setSynflood(t, c, FirewallSynfloodScopeCluster, FirewallSynflood{Mode: SynfloodOn, Rate: 1, Burst: 100000})
	setSynflood(t, c, FirewallSynfloodScopeCluster, FirewallSynflood{Mode: SynfloodOn, Rate: 100000, Burst: 1})
}

// No host (host == "") resolves to the cluster's policy, as it does for a
// host with no row of its own (B1 review m-3).
func TestFirewallSynflood_NoHostResolvesCluster(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	openClusterPolicyGate(c)
	if got, err := ResolveFirewallSynflood(ctx, c, ""); err != nil || got.On() || got.Scope != "" {
		t.Fatalf("no row, no host = %+v, %v; want off from no scope", got, err)
	}
	setSynflood(t, c, FirewallSynfloodScopeCluster, FirewallSynflood{Mode: SynfloodOn, Rate: 300, Burst: 1500})
	got, err := ResolveFirewallSynflood(ctx, c, "")
	if err != nil || !got.On() || got.Rate != 300 || got.Burst != 1500 || got.Scope != FirewallSynfloodScopeCluster {
		t.Errorf("cluster on, no host = %+v, %v; want the cluster's on 300/1500", got, err)
	}
}

// A query error on the host's row is returned as it is: the cluster's row
// never stands in for a host row that could not be read (B1 review m-3).
//
// The host row's read is made to fail while the cluster row's still works:
// cluster_policies becomes a view whose value for that one key is json('{'),
// which SQLite refuses at run time.
//
// Mutation: fall through to the cluster row on any host error.
func TestFirewallSynflood_HostQueryErrorPropagates(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	openClusterPolicyGate(c)
	setSynflood(t, c, FirewallSynfloodScopeCluster, FirewallSynflood{Mode: SynfloodOn, Rate: 300, Burst: 1500})
	setSynflood(t, c, "h1", FirewallSynflood{Mode: SynfloodOff})
	for _, q := range []string{
		`ALTER TABLE cluster_policies RENAME TO cluster_policies_real`,
		`CREATE VIEW cluster_policies AS SELECT key,
			CASE WHEN key = 'firewall_synflood/h1' THEN json('{') ELSE value END AS value,
			set_by, updated_at, deleted_at FROM cluster_policies_real`,
	} {
		if _, err := c.db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := ResolveFirewallSynflood(ctx, c, "h2"); err != nil || !got.On() || got.Scope != FirewallSynfloodScopeCluster {
		t.Fatalf("the cluster row no longer reads: %+v, %v", got, err)
	}
	got, err := ResolveFirewallSynflood(ctx, c, "h1")
	if err == nil || errors.Is(err, ErrUnreadableFirewallPolicy) {
		t.Fatalf("h1 = %+v, %v; want the query error", got, err)
	}
	if got.On() || got.Scope == FirewallSynfloodScopeCluster {
		t.Errorf("h1 = %+v; the cluster row stood in for the host row", got)
	}
}
