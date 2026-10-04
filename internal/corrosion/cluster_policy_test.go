package corrosion

import (
	"context"
	"errors"
	"testing"
)

func openClusterPolicyGate(c *Client) { c.SetClusterPolicyGate(func() bool { return true }) }

// TestFailoverScope_DefaultsToCluster: no row is the cluster-wide scope, the
// behaviour every existing cluster has.
func TestFailoverScope_DefaultsToCluster(t *testing.T) {
	c := testClient(t)
	p, err := GetFailoverScope(context.Background(), c)
	if err != nil {
		t.Fatalf("GetFailoverScope: %v", err)
	}
	if p.Value != FailoverScopeCluster || p.Region() {
		t.Fatalf("no row must read as %q, got %+v", FailoverScopeCluster, p)
	}
}

// TestSetFailoverScope_RefusedUntilGateOpens: cluster_policies is a table a
// previous-release peer cannot decode, so nothing is written until the
// failover_scope_v1 latch opens the gate. An unwired gate is closed.
func TestSetFailoverScope_RefusedUntilGateOpens(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if err := SetFailoverScope(ctx, c, FailoverScopeRegion, "admin"); !errors.Is(err, ErrClusterPolicyGateClosed) {
		t.Fatalf("SetFailoverScope with the gate unwired: err=%v, want ErrClusterPolicyGateClosed", err)
	}
	c.SetClusterPolicyGate(func() bool { return false })
	if err := SetFailoverScope(ctx, c, FailoverScopeRegion, "admin"); !errors.Is(err, ErrClusterPolicyGateClosed) {
		t.Fatalf("SetFailoverScope with the gate closed: err=%v, want ErrClusterPolicyGateClosed", err)
	}
	if n := oneString(t, c, `SELECT count(*) AS n FROM cluster_policies`, "n"); n != "0" {
		t.Fatalf("a refused write left %s row(s) in cluster_policies", n)
	}
}

// TestSetFailoverScope_RoundTrip: the value, who set it, and a second write
// replacing the first.
func TestSetFailoverScope_RoundTrip(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	openClusterPolicyGate(c)
	if err := SetFailoverScope(ctx, c, FailoverScopeRegion, "alice"); err != nil {
		t.Fatalf("SetFailoverScope region: %v", err)
	}
	p, err := GetFailoverScope(ctx, c)
	if err != nil || p.Value != FailoverScopeRegion || !p.Region() || p.SetBy != "alice" || p.UpdatedAt == "" {
		t.Fatalf("after setting region: %+v err=%v", p, err)
	}
	if err := SetFailoverScope(ctx, c, FailoverScopeCluster, "bob"); err != nil {
		t.Fatalf("SetFailoverScope cluster: %v", err)
	}
	p, err = GetFailoverScope(ctx, c)
	if err != nil || p.Value != FailoverScopeCluster || p.Region() || p.SetBy != "bob" {
		t.Fatalf("after setting cluster: %+v err=%v", p, err)
	}
}

// TestSetFailoverScope_RejectsUnknownValue: only the two scopes this build
// implements can be written.
func TestSetFailoverScope_RejectsUnknownValue(t *testing.T) {
	c := testClient(t)
	openClusterPolicyGate(c)
	for _, v := range []string{"", "zone", "Region"} {
		if err := SetFailoverScope(context.Background(), c, v, "admin"); err == nil {
			t.Fatalf("SetFailoverScope(%q) was accepted", v)
		}
	}
}

// TestFailoverScope_UnknownStoredValueFailsClosed: a value this build does not
// know (a later release's scope, arriving by replication) is an error, never a
// silent fallback to the cluster-wide scope. Every caller fails closed on it.
func TestFailoverScope_UnknownStoredValueFailsClosed(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	openClusterPolicyGate(c)
	if err := c.Execute(ctx, clusterPolicyUpsertSQL, clusterPolicyFailoverScope, "zone", "future", c.NowTS()); err != nil {
		t.Fatalf("seed unknown value: %v", err)
	}
	if _, err := GetFailoverScope(ctx, c); !errors.Is(err, ErrUnknownFailoverScope) {
		t.Fatalf("GetFailoverScope over an unknown value: err=%v, want ErrUnknownFailoverScope", err)
	}
}

// TestVoterRegions partitions the voter set by region: non-voters are absent
// from every region, a host with no region is in "default", and the region map
// covers non-voters too (a fence target need not be a voter).
func TestVoterRegions(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedMembershipHosts(t, c, "e1", "e2", "e3", "w1", "w2", "d1")
	for h, r := range map[string]string{"e1": "east", "e2": "east", "e3": "east", "w1": "west", "w2": "west"} {
		if err := UpdateHostRegion(ctx, c, h, r); err != nil {
			t.Fatalf("UpdateHostRegion %s: %v", h, err)
		}
	}
	if err := UpdateHostState(ctx, c, "e3", "maintenance"); err != nil {
		t.Fatalf("UpdateHostState: %v", err)
	}
	vr, err := VoterRegions(ctx, c)
	if err != nil {
		t.Fatalf("VoterRegions: %v", err)
	}
	if got := vr.RegionOf["e3"]; got != "east" {
		t.Errorf("a non-voter's region must still be known: RegionOf[e3]=%q", got)
	}
	if got := vr.RegionOf["d1"]; got != "default" {
		t.Errorf("a host with no region label is in default: RegionOf[d1]=%q", got)
	}
	want := map[string][]string{"east": {"e1", "e2"}, "west": {"w1", "w2"}, "default": {"d1"}}
	for region, members := range want {
		got := vr.In(region)
		if len(got) != len(members) {
			t.Errorf("region %s voters = %v, want %v", region, got, members)
			continue
		}
		for _, m := range members {
			if !got[m] {
				t.Errorf("region %s voters = %v, missing %s", region, got, m)
			}
		}
	}
	if len(vr.Voters) != 5 {
		t.Errorf("Voters must be the whole VoterSet (5 hosts not in maintenance), got %v", vr.Voters)
	}
}
