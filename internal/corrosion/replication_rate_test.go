package corrosion

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

func rateGrant(t *testing.T) capabilities.FeatureGrant {
	return capabilities.GrantForTest(t, capabilities.FeatureReplicationRate)
}

// Every schedule key form round-trips through the record key: a VM's name, a
// fan-out sentinel, a container key (which holds '/'), and a repo holding '/'.
// Each pair reads back only its own rate.
//
// Mutation: drop the PathEscape of either part — "@ct:proj/name" and the
// "a/b" repo collide or fail to parse back.
func TestReplicationRate_RoundTripsEveryScheduleKey(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	openClusterPolicyGate(c)
	cases := []struct {
		schedule, repo string
		bps            int64
	}{
		{"web1", "dr", 1 << 20},
		{"@pool:fast", "dr", 2 << 20},
		{"@ct:proj/name", "dr", 3 << 20},
		{"@ct:proj", "name/dr", 4 << 20},
		{"web1", "/srv/backup/repo", 5 << 20},
	}
	for _, tc := range cases {
		if err := SetReplicationRate(ctx, c, rateGrant(t), tc.schedule, tc.repo, tc.bps, "alice"); err != nil {
			t.Fatalf("set %s/%s: %v", tc.schedule, tc.repo, err)
		}
	}
	for _, tc := range cases {
		got, err := GetReplicationRate(ctx, c, tc.schedule, tc.repo)
		if err != nil || got != tc.bps {
			t.Errorf("get %s/%s = %d, %v; want %d", tc.schedule, tc.repo, got, err, tc.bps)
		}
		s, r, ok := ParseReplicationRateKey(ReplicationRateKey(tc.schedule, tc.repo))
		if !ok || s != tc.schedule || r != tc.repo {
			t.Errorf("key of %s/%s parses back as %q %q %v", tc.schedule, tc.repo, s, r, ok)
		}
	}
	all, err := ListReplicationRates(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != len(cases) {
		t.Fatalf("list = %v, want %d entries", all, len(cases))
	}
	for _, tc := range cases {
		if all[ReplicationRateID{Schedule: tc.schedule, Repo: tc.repo}] != tc.bps {
			t.Errorf("list[%s/%s] = %d, want %d", tc.schedule, tc.repo, all[ReplicationRateID{Schedule: tc.schedule, Repo: tc.repo}], tc.bps)
		}
	}
	if got, _ := GetReplicationRate(ctx, c, "web2", "dr"); got != 0 {
		t.Errorf("a schedule with no row reads %d, want 0 (unlimited)", got)
	}
}

// Clearing writes an empty value (cluster_policies has no delete), which reads
// as no limit and is not listed.
func TestReplicationRate_ClearWritesEmpty(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	openClusterPolicyGate(c)
	if err := SetReplicationRate(ctx, c, rateGrant(t), "web1", "dr", 1<<20, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := SetReplicationRate(ctx, c, rateGrant(t), "web1", "dr", 0, "bob"); err != nil {
		t.Fatal(err)
	}
	rows, err := c.Query(ctx, `SELECT value FROM cluster_policies WHERE key = ?`, ReplicationRateKey("web1", "dr"))
	if err != nil || len(rows) != 1 || rows[0].String("value") != "" {
		t.Fatalf("cleared row = %v, %v; want one row with value \"\"", rows, err)
	}
	if got, _ := GetReplicationRate(ctx, c, "web1", "dr"); got != 0 {
		t.Errorf("cleared rate reads %d", got)
	}
	if all, _ := ListReplicationRates(ctx, c); len(all) != 0 {
		t.Errorf("a cleared rate is listed: %v", all)
	}
	if has, err := HasReplicationRate(ctx, c, "web1", "dr"); err != nil || has {
		t.Errorf("HasReplicationRate after clear = %v, %v", has, err)
	}
}

// The rate is replication_rate's data: no grant, another feature's grant, or a
// closed cluster-policy gate writes nothing.
//
// Mutations: drop the grant Check — the zero grant writes; drop the
// MayWriteClusterPolicy check — the closed gate writes.
func TestReplicationRate_RefusedWithoutGrantOrBeforeTheGate(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if err := SetReplicationRate(ctx, c, rateGrant(t), "web1", "dr", 1<<20, "alice"); !errors.Is(err, ErrClusterPolicyGateClosed) {
		t.Fatalf("before the gate: %v, want ErrClusterPolicyGateClosed", err)
	}
	openClusterPolicyGate(c)
	for name, g := range map[string]capabilities.FeatureGrant{
		"zero grant":        {},
		"another feature's": capabilities.GrantForTest(t, capabilities.FeatureVMLimits),
	} {
		if err := SetReplicationRate(ctx, c, g, "web1", "dr", 1<<20, "alice"); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
			t.Errorf("%s: %v, want ErrNoFeatureGrant", name, err)
		}
	}
	if err := SetReplicationRate(ctx, c, rateGrant(t), "web1", "dr", -1, "alice"); err == nil {
		t.Error("a negative rate was accepted")
	}
	if all, _ := ListReplicationRates(ctx, c); len(all) != 0 {
		t.Fatalf("a refused write landed: %v", all)
	}
}

// A value this build cannot read (a later release's) is no limit, never an
// error that stops the run.
func TestReplicationRate_UnreadableValueIsNoLimit(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	openClusterPolicyGate(c)
	if err := c.Execute(ctx, clusterPolicyUpsertSQL, ReplicationRateKey("web1", "dr"), "fast", "x", c.NowTS()); err != nil {
		t.Fatal(err)
	}
	if got, err := GetReplicationRate(ctx, c, "web1", "dr"); err != nil || got != 0 {
		t.Errorf("unreadable value = %d, %v; want 0, nil", got, err)
	}
}
