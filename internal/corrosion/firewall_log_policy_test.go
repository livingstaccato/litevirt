package corrosion

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

func logGrant(t *testing.T) capabilities.FeatureGrant {
	return capabilities.GrantForTest(t, capabilities.FeatureFirewallLog)
}

func setLogPolicy(t *testing.T, c *Client, host string, p FirewallLogPolicy) {
	t.Helper()
	if err := SetFirewallLogPolicy(context.Background(), c, logGrant(t), host, p, "alice"); err != nil {
		t.Fatalf("set %q %+v: %v", host, p, err)
	}
}

func putLogPolicyRaw(t *testing.T, c *Client, host, value string) {
	t.Helper()
	if err := c.Execute(context.Background(), clusterPolicyUpsertSQL, FirewallLogPolicyKey(host), value, "peer", c.NowTS()); err != nil {
		t.Fatal(err)
	}
}

// C3 (B1's cases for firewall_log): a policy at either scope round-trips under
// the key and JSON the spec names; with no row the default verdict is not
// logged at the default budget (L-7); a host's row wins over the cluster's;
// "" inherits; a host named "cluster" has its own key, apart from the
// cluster's.
//
// Mutations: resolve the cluster row first — the host override loses, red;
// key a host as the bare scope — host "cluster" overwrites the cluster row,
// red; no row reads as on — red.
func TestFirewallLogPolicy_RoundTripAndOverride(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	openClusterPolicyGate(c)

	got, err := ResolveFirewallLogPolicy(ctx, c, "h1")
	if err != nil || got.On() || got.Rate != LogPolicyDefaultRate || got.Burst != LogPolicyDefaultBurst || got.Scope != "" {
		t.Fatalf("no row resolves to %+v, %v; want off at the default budget", got, err)
	}
	setLogPolicy(t, c, "", FirewallLogPolicy{Default: LogPolicyOn, Rate: 7, Burst: 20})
	rows, err := c.Query(ctx, `SELECT value, set_by FROM cluster_policies WHERE key = 'firewall_log'`)
	if err != nil || len(rows) != 1 || rows[0].String("value") != `{"default":"on","rate":7,"burst":20}` || rows[0].String("set_by") != "alice" {
		t.Fatalf("cluster row = %v, %v", rows, err)
	}
	got, err = ResolveFirewallLogPolicy(ctx, c, "h1")
	if err != nil || !got.On() || got.Rate != 7 || got.Burst != 20 || got.Scope != LogPolicyScopeCluster {
		t.Fatalf("cluster on resolves to %+v, %v", got, err)
	}

	setLogPolicy(t, c, "h1", FirewallLogPolicy{Default: LogPolicyOff, Rate: 3, Burst: 4})
	if rows, _ := c.Query(ctx, `SELECT value FROM cluster_policies WHERE key = 'firewall_log/h1'`); len(rows) != 1 {
		t.Fatal("host row missing under firewall_log/h1")
	}
	got, err = ResolveFirewallLogPolicy(ctx, c, "h1")
	if err != nil || got.On() || got.Rate != 3 || got.Burst != 4 || got.Scope != "h1" {
		t.Fatalf("host off resolves to %+v, %v", got, err)
	}
	if got, _ := ResolveFirewallLogPolicy(ctx, c, "h2"); !got.On() || got.Scope != LogPolicyScopeCluster {
		t.Errorf("h2 resolves to %+v, want the cluster policy", got)
	}

	// A host named "cluster" is a host.
	setLogPolicy(t, c, "cluster", FirewallLogPolicy{Default: LogPolicyOff, Rate: 9, Burst: 9})
	if got, _, _ := GetFirewallLogPolicy(ctx, c, ""); !got.On() || got.Rate != 7 {
		t.Errorf("the cluster row after host \"cluster\" wrote = %+v, want it unchanged", got)
	}

	// "" inherits.
	setLogPolicy(t, c, "h1", FirewallLogPolicy{})
	if got, _ := ResolveFirewallLogPolicy(ctx, c, "h1"); !got.On() || got.Scope != LogPolicyScopeCluster {
		t.Errorf("after inherit h1 resolves to %+v, want the cluster policy", got)
	}
	if _, recorded, _ := GetFirewallLogPolicy(ctx, c, "h1"); recorded {
		t.Error("an inherited host still has a row")
	}
}

// C3: a stored value this build cannot read — not JSON, an unknown default,
// a budget out of 1..10000 — reads as off at the default budget plus
// ErrUnreadableFirewallPolicy naming the key; a host's unreadable row does
// not fall through to the cluster's.
//
// Mutations: read garbage as on — red; take an out-of-range budget — red;
// fall through to the cluster row — red.
func TestFirewallLogPolicy_UnreadableReadsOff(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	openClusterPolicyGate(c)
	setLogPolicy(t, c, "", FirewallLogPolicy{Default: LogPolicyOn, Rate: 7, Burst: 20})
	for _, v := range []string{`{`, `{"default":"maybe","rate":5,"burst":10}`, `{"default":"on","rate":0,"burst":10}`,
		`{"default":"on","rate":5,"burst":10001}`, `{}`, `{"default":"on","rate":-1,"burst":10}`} {
		putLogPolicyRaw(t, c, "h1", v)
		got, err := ResolveFirewallLogPolicy(ctx, c, "h1")
		if !errors.Is(err, ErrUnreadableFirewallPolicy) {
			t.Errorf("%s: err = %v, want ErrUnreadableFirewallPolicy", v, err)
		}
		if got.On() || got.Rate != LogPolicyDefaultRate || got.Burst != LogPolicyDefaultBurst || got.Scope != "h1" {
			t.Errorf("%s resolves to %+v, want off at the default budget from h1", v, got)
		}
	}
}

// C3: the writer takes the firewall_log grant and the cluster-policy gate,
// and refuses a policy the renderer could not render (C1 m-3: a budget out
// of 1..10000), an inherit at the cluster scope, and a scope with "/".
//
// Mutations: skip the grant check — the synflood grant writes, red; skip the
// range check — rate 10001 writes, red.
func TestFirewallLogPolicy_WriterRefusals(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	on := FirewallLogPolicy{Default: LogPolicyOn, Rate: 5, Burst: 10}
	openClusterPolicyGate(c)
	if err := SetFirewallLogPolicy(ctx, c, capabilities.GrantForTest(t, capabilities.FeatureFirewallSynflood), "", on, "a"); err == nil {
		t.Error("written with the synflood grant")
	}
	if err := SetFirewallLogPolicy(ctx, c, capabilities.FeatureGrant{}, "", on, "a"); err == nil {
		t.Error("written with no grant")
	}
	for _, p := range []FirewallLogPolicy{
		{Default: LogPolicyOn, Rate: 10001, Burst: 10}, {Default: LogPolicyOn, Rate: 5, Burst: 0},
		{Default: "maybe", Rate: 5, Burst: 10}, {Rate: 5, Burst: 10},
	} {
		if err := SetFirewallLogPolicy(ctx, c, logGrant(t), "h1", p, "a"); err == nil {
			t.Errorf("%+v written", p)
		}
	}
	if err := SetFirewallLogPolicy(ctx, c, logGrant(t), "", FirewallLogPolicy{}, "a"); err == nil {
		t.Error("the cluster scope inherited")
	}
	if err := SetFirewallLogPolicy(ctx, c, logGrant(t), "a/b", on, "a"); err == nil {
		t.Error("a scope with / written")
	}
	c.SetClusterPolicyGate(func() bool { return false })
	if err := SetFirewallLogPolicy(ctx, c, logGrant(t), "", on, "a"); !errors.Is(err, ErrClusterPolicyGateClosed) {
		t.Errorf("gate closed: %v, want ErrClusterPolicyGateClosed", err)
	}
	if rows, _ := c.Query(ctx, `SELECT 1 FROM cluster_policies WHERE key LIKE 'firewall_log%'`); len(rows) != 0 {
		t.Errorf("rows written by refused writes: %d", len(rows))
	}
}
