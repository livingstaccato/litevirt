package metrics

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// litevirt_relay_role reports this node's relay election, one series per
// member: 1 for a relay, 0 for a leaf. It is how an operator sees, on every
// node, that a host demoted for failing probes is a leaf everywhere
// (colonelpanik/litevirt#175).
//
// Mutation: report every member as a relay (value 1 regardless) — the
// demoted host reads 1, red.
func TestCollect_RelayRoleReportsTheElection(t *testing.T) {
	db := initTestDB(t)
	members := []corrosion.PeerInfo{{Name: "b"}, {Name: "c"}, {Name: "d"}, {Name: "e"}}
	// "a" sorts first but is not eligible (demoted): b, c, d are the relays.
	elig := map[string]bool{"b": true, "c": true, "d": true, "e": true}
	rs := corrosion.ComputeRelays(members, "a", corrosion.RelayConfig{BaseRelays: 2, NodesPerRelay: 50}, elig)

	c := newCollector(db, nil, nil, "a")
	c.relayRoles = rs.Roles
	ch := make(chan prometheus.Metric, 400)
	c.Collect(ch)
	close(ch)

	got := map[string]float64{}
	for m := range ch {
		if !containsStr(m.Desc().String(), "litevirt_relay_role") {
			continue
		}
		var dm dto.Metric
		if err := m.Write(&dm); err != nil {
			t.Fatal(err)
		}
		for _, lp := range dm.GetLabel() {
			if lp.GetName() == "member" {
				got[lp.GetValue()] = dm.GetGauge().GetValue()
			}
		}
	}
	want := map[string]float64{"a": 0, "b": 1, "c": 1, "d": 1, "e": 0}
	if len(got) != len(want) {
		t.Fatalf("litevirt_relay_role series = %v, want %v", got, want)
	}
	for m, v := range want {
		if g, ok := got[m]; !ok || g != v {
			t.Errorf("litevirt_relay_role{member=%q} = %v (present %v), want %v", m, g, ok, v)
		}
	}
}

// Not wired (no replicator), not reported: an absent series is not a claim
// that every member is a leaf.
func TestCollect_RelayRoleAbsentWhenUnwired(t *testing.T) {
	db := initTestDB(t)
	c := newCollector(db, nil, nil, "a")
	ch := make(chan prometheus.Metric, 400)
	c.Collect(ch)
	close(ch)
	for m := range ch {
		if containsStr(m.Desc().String(), "litevirt_relay_role") {
			t.Fatal("litevirt_relay_role reported with no relay election wired")
		}
	}
}

// litevirt_relay_demoted and litevirt_relay_hold_seconds make demotions and
// holds visible: litevirt_relay_role reads 0 for every leaf, demoted or not,
// so it cannot say which host to restore, and a forgotten hold would switch
// demotion off for its host silently.
//
// Mutation: skip the hold series — no hold reported, red.
func TestCollect_RelayDemotionsAndHoldsAreVisible(t *testing.T) {
	db := initTestDB(t)
	db.SetClusterPolicyGate(func() bool { return true })
	db.SetRelayHealthGate(func() bool { return true })
	ctx := context.Background()
	if err := corrosion.SetRelayDemotion(ctx, db, "a", corrosion.RelayDemotion{Demoted: true, Reason: "probes"}, "lease"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.SetRelayDemotion(ctx, db, "b", corrosion.RelayDemotion{Demoted: false, Reason: "restored"}, "lease"); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if err := corrosion.SetRelayHold(ctx, db, "c", corrosion.RelayHold{Until: until, By: "admin"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.SetRelayHold(ctx, db, "d", corrosion.RelayHold{Until: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}, "admin"); err != nil {
		t.Fatal(err)
	}
	c := newCollector(db, nil, nil, "x")
	series := func(name string) map[string]float64 {
		ch := make(chan prometheus.Metric, 400)
		c.Collect(ch)
		close(ch)
		out := map[string]float64{}
		for m := range ch {
			if !strings.Contains(m.Desc().String(), `"`+name+`"`) {
				continue
			}
			var dm dto.Metric
			if err := m.Write(&dm); err != nil {
				t.Fatal(err)
			}
			for _, lp := range dm.GetLabel() {
				if lp.GetName() == "member" {
					out[lp.GetValue()] = dm.GetGauge().GetValue()
				}
			}
		}
		return out
	}
	if got := series("litevirt_relay_demoted"); len(got) != 1 || got["a"] != 1 {
		t.Errorf("litevirt_relay_demoted = %v, want only a=1 (b is restored)", got)
	}
	got := series("litevirt_relay_hold_seconds")
	if len(got) != 1 || got["c"] < 3500 || got["c"] > 3600 {
		t.Errorf("litevirt_relay_hold_seconds = %v, want only c≈3600 (d's hold has run out)", got)
	}
}
