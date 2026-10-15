package corrosion

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/hlc"
)

func haGrant(t *testing.T) capabilities.FeatureGrant {
	return capabilities.GrantForTest(t, capabilities.FeatureHADisarm)
}

// No row is armed: nothing writes a default row, so a cluster that never
// disarmed reads armed everywhere.
func TestHAPolicy_NoRowIsArmed(t *testing.T) {
	p, err := GetHAPolicy(context.Background(), testClient(t))
	if err != nil || p.State != HAArmed || p.Disarmed() || p.UpdatedAt != "" {
		t.Fatalf("no row: %+v err=%v, want armed", p, err)
	}
}

func TestHAPolicy_DisarmRoundTrips(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	openClusterPolicyGate(c)
	ts, err := SetHAPolicy(ctx, c, haGrant(t), HADisarmed, "core switch, CHG-1234", "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	p, err := GetHAPolicy(ctx, c)
	if err != nil || p.State != HADisarmed || !p.Disarmed() || p.Reason != "core switch, CHG-1234" ||
		p.SetBy != "alice" || p.UpdatedAt != ts || ts == "" {
		t.Fatalf("after disarm: %+v err=%v (stamped %q)", p, err, ts)
	}
	if _, err := SetHAPolicy(ctx, c, haGrant(t), HAArmed, "", "bob", ts); err != nil {
		t.Fatal(err)
	}
	if p, _ := GetHAPolicy(ctx, c); p.State != HAArmed || p.Disarmed() || p.SetBy != "bob" {
		t.Fatalf("after arm: %+v", p)
	}
}

// A value this build cannot read holds HA, never releases it.
func TestHAPolicy_UnreadableReadsDisarmed(t *testing.T) {
	ctx := context.Background()
	for name, value := range map[string]string{
		"garbled":       `{"state":`,
		"unknown state": `{"state":"half-armed"}`,
		"empty state":   `{}`,
	} {
		c := testClient(t)
		if err := c.Execute(ctx, clusterPolicyUpsertSQL, clusterPolicyHA, value, "x", c.NowTS()); err != nil {
			t.Fatal(err)
		}
		p, err := GetHAPolicy(ctx, c)
		if !errors.Is(err, ErrUnreadableHAPolicy) {
			t.Errorf("%s: err=%v, want ErrUnreadableHAPolicy", name, err)
		}
		if !p.Disarmed() || !p.Unreadable || p.State != HADisarmed {
			t.Errorf("%s: %+v, want an unreadable policy that reads disarmed", name, p)
		}
	}
}

func TestHAPolicy_WriterRefusesWithoutGrantOrGate(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if _, err := SetHAPolicy(ctx, c, haGrant(t), HADisarmed, "", "alice", ""); !errors.Is(err, ErrClusterPolicyGateClosed) {
		t.Fatalf("gate unwired: %v, want ErrClusterPolicyGateClosed", err)
	}
	openClusterPolicyGate(c)
	for name, g := range map[string]capabilities.FeatureGrant{
		"no grant":          {},
		"another feature's": capabilities.GrantForTest(t, capabilities.FeatureDrainFailback),
	} {
		if _, err := SetHAPolicy(ctx, c, g, HADisarmed, "", "alice", ""); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
			t.Errorf("%s: %v, want ErrNoFeatureGrant", name, err)
		}
	}
	if p, _ := GetHAPolicy(ctx, c); p.UpdatedAt != "" {
		t.Fatalf("a refused write left a row: %+v", p)
	}
}

// The stamp is strictly newer than the newest timestamp the caller saw, in
// either form, including one ahead of this node's clock (within the skew
// bound); a future-skewed one is refused rather than followed.
func TestHAPolicy_StampFollowsTheNewestSeen(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	for name, after := range map[string]string{
		"rfc3339 ahead": now.Add(2 * time.Second).UTC().Format(time.RFC3339Nano),
		"hlc ahead":     hlcString(now.Add(3 * time.Second)),
	} {
		c := testClient(t)
		openClusterPolicyGate(c)
		ts, err := SetHAPolicy(ctx, c, haGrant(t), HADisarmed, "", "alice", after)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !LWWNewer(ts, after) {
			t.Fatalf("%s: stamped %q, not newer than %q", name, ts, after)
		}
	}
	c := testClient(t)
	openClusterPolicyGate(c)
	skewed := now.Add(time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := SetHAPolicy(ctx, c, haGrant(t), HADisarmed, "", "alice", skewed); !errors.Is(err, ErrHAStampSkewed) {
		t.Fatalf("after a future-skewed stamp: %v, want ErrHAStampSkewed", err)
	}
}

func hlcString(at time.Time) string {
	return hlc.Timestamp{PhysicalMS: at.UnixMilli(), NodeID: "peer"}.String()
}
