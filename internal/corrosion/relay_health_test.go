package corrosion

import (
	"context"
	"errors"
	"testing"
)

// relayHealthClient is a schema'd client with five active hosts, a..e, and
// both demotion gates open unless closed says otherwise.
func relayHealthClient(t *testing.T, open bool) *Client {
	t.Helper()
	c := NewTestClientT(t)
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	for i, n := range []string{"a", "b", "c", "d", "e"} {
		if err := InsertHost(ctx, c, HostRecord{Name: n, Address: "10.0.0." + string(rune('1'+i)), State: "active"}); err != nil {
			t.Fatalf("InsertHost(%s): %v", n, err)
		}
	}
	if open {
		c.SetClusterPolicyGate(func() bool { return true })
		c.SetRelayHealthGate(func() bool { return true })
	}
	return c
}

func demote(t *testing.T, c *Client, host string, demoted bool) {
	t.Helper()
	if err := SetRelayDemotion(context.Background(), c, host,
		RelayDemotion{Demoted: demoted, Since: "2026-10-10T00:00:00Z", Reason: "test"}, "e"); err != nil {
		t.Fatalf("SetRelayDemotion(%s, %v): %v", host, demoted, err)
	}
}

// A host whose probes keep failing is demoted by the lease holder, and the
// replicated row must take it out of the relay set on every node while enough
// healthy hosts are eligible: "a" sorts first and was a relay by name alone.
// It stays a leaf with an assigned pair, so it keeps receiving replication.
//
// Mutation: RelayEligibleHosts ignoring the demotion rows — "a" is elected
// again, red.
func TestRelayEligibleHosts_DemotedHostIsNeverARelay(t *testing.T) {
	c := relayHealthClient(t, true)
	ctx := context.Background()
	cfg := RelayConfig{BaseRelays: 2, NodesPerRelay: 50} // R = 3 of 5

	before := ComputeRelays(peers("b", "c", "d", "e"), "a", cfg, RelayEligibleHosts(ctx, c))
	if !before.IsRelay("a") {
		t.Fatalf("precondition: relays = %v, want a (it sorts first)", before.Relays())
	}

	demote(t, c, "a", true)
	elig := RelayEligibleHosts(ctx, c)
	if elig["a"] {
		t.Fatalf("eligible = %v: a demoted host must not be relay-eligible", elig)
	}
	// From every vantage point, the same answer.
	all := []string{"a", "b", "c", "d", "e"}
	for _, self := range all {
		var others []string
		for _, n := range all {
			if n != self {
				others = append(others, n)
			}
		}
		rs := ComputeRelays(peers(others...), self, cfg, elig)
		if rs.IsRelay("a") {
			t.Fatalf("from %s relays = %v: the demoted host was elected while b..e are eligible", self, rs.Relays())
		}
		if got := rs.Relays(); len(got) != 3 || got[0] != "b" || got[1] != "c" || got[2] != "d" {
			t.Fatalf("from %s relays = %v, want [b c d] (name order is the tie-break)", self, got)
		}
		if pair := rs.AssignedRelays("a"); pair[0] == "" {
			t.Fatalf("from %s the demoted host has no assigned relays: it must stay a leaf, not be dropped", self)
		}
	}
}

// Restoring writes the row again with demoted=false; the host is eligible
// once more.
func TestRelayEligibleHosts_RestoredHostIsEligibleAgain(t *testing.T) {
	c := relayHealthClient(t, true)
	ctx := context.Background()
	demote(t, c, "a", true)
	if RelayEligibleHosts(ctx, c)["a"] {
		t.Fatal("precondition: a is demoted")
	}
	demote(t, c, "a", false)
	if !RelayEligibleHosts(ctx, c)["a"] {
		t.Fatal("a restored host must be relay-eligible again")
	}
}

// Every host demoted is not "no relays": the all-ineligible election still
// elects R relays by name order, so replication continues degraded instead of
// stopping. A replicated row must not be able to cause a cluster-wide outage.
func TestRelayEligibleHosts_EveryHostDemotedStillElectsRelays(t *testing.T) {
	c := relayHealthClient(t, true)
	ctx := context.Background()
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		demote(t, c, n, true)
	}
	elig := RelayEligibleHosts(ctx, c)
	if elig == nil {
		t.Fatal("eligibility read failed; want an empty (not nil) answer")
	}
	rs := ComputeRelays(peers("b", "c", "d", "e"), "a", RelayConfig{BaseRelays: 2, NodesPerRelay: 50}, elig)
	if got := rs.Relays(); len(got) != 3 {
		t.Fatalf("relays = %v, want 3 elected even with every host demoted", got)
	}
}

// A row whose value does not parse is not a demotion. The bytes replicate, so
// every node reads it the same way.
func TestListRelayDemotions_UnparseableValueIsNotADemotion(t *testing.T) {
	c := relayHealthClient(t, true)
	ctx := context.Background()
	if err := c.Execute(ctx, clusterPolicyUpsertSQL, RelayDemotedKeyPrefix+"a", "not json", "e", c.NowTS()); err != nil {
		t.Fatal(err)
	}
	if !RelayEligibleHosts(ctx, c)["a"] {
		t.Fatal("an unparseable demotion row must leave the host eligible")
	}
}

// No demotion row is written before relay_health_v1 has latched: a
// previous-release peer ignores the key and would elect a different relay
// set. The cluster_policies gate must hold as well — it proves every
// recipient decodes the shape.
//
// Mutation: SetRelayDemotion without the MayWriteRelayDemotion check — the
// row is written pre-latch, red.
func TestSetRelayDemotion_NothingWrittenBeforeTheLatch(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name          string
		policy, relay bool
	}{
		{"no gate wired", false, false},
		{"relay_health_v1 not latched", true, false},
		{"cluster_policies gate closed", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := relayHealthClient(t, false)
			if tc.policy {
				c.SetClusterPolicyGate(func() bool { return true })
			}
			if tc.relay {
				c.SetRelayHealthGate(func() bool { return true })
			}
			err := SetRelayDemotion(ctx, c, "a", RelayDemotion{Demoted: true}, "e")
			if !errors.Is(err, ErrRelayHealthGateClosed) {
				t.Fatalf("SetRelayDemotion = %v, want ErrRelayHealthGateClosed", err)
			}
			rows, err := c.Query(ctx, `SELECT key FROM cluster_policies WHERE key LIKE 'relay_demoted/%'`)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 0 {
				t.Fatalf("%d demotion row(s) written before the latch", len(rows))
			}
		})
	}
}
