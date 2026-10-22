package corrosion

import (
	"context"
	"testing"
)

// TestClusterOfOneBut pins the alone test the founder's gates share: only
// hosts still joining that admitted accepts are let through, and only while
// there is no gossip member.
//
// Mutations: drop the gossip check, the joining check or the admitted call —
// each turns a "not alone" row below into "alone".
func TestClusterOfOneBut(t *testing.T) {
	ctx := context.Background()
	gossip := func(c *Client) {
		c.SetMembersForTests(func() []PeerInfo { return []PeerInfo{{Name: "h9", Addr: "10.0.0.9:7946"}} })
	}
	only := func(name string) func(HostRecord) bool {
		return func(h HostRecord) bool { return h.Name == name }
	}
	for _, tc := range []struct {
		name     string
		others   []HostRecord
		gossip   bool
		admitted func(HostRecord) bool
		want     bool
	}{
		{name: "only self", want: true, admitted: NoAdmission},
		{name: "only self, with a gossip member", gossip: true, admitted: NoAdmission},
		{name: "a joining host, any admission", want: true, admitted: AnyAdmission,
			others: []HostRecord{{Name: "h2", State: HostStateJoining}}},
		{name: "two joining hosts, any admission", want: true, admitted: AnyAdmission,
			others: []HostRecord{{Name: "h2", State: HostStateJoining}, {Name: "h3", State: HostStateJoining}}},
		{name: "a joining host, no admission", admitted: NoAdmission,
			others: []HostRecord{{Name: "h2", State: HostStateJoining}}},
		{name: "a joining host the decision is not about", admitted: only("h3"),
			others: []HostRecord{{Name: "h2", State: HostStateJoining}}},
		{name: "a joining host, with a gossip member", gossip: true, admitted: AnyAdmission,
			others: []HostRecord{{Name: "h2", State: HostStateJoining}}},
		{name: "a host that has booted", admitted: AnyAdmission,
			others: []HostRecord{{Name: "h2", State: "upgrading"}}},
		{name: "a joining host and a host in maintenance", admitted: AnyAdmission,
			others: []HostRecord{{Name: "h2", State: HostStateJoining}, {Name: "h3", State: "maintenance"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := schemaClient(t)
			for _, h := range append([]HostRecord{{Name: "h1", State: "active"}}, tc.others...) {
				h.Address = "10.0.0.1"
				if err := InsertHost(ctx, c, h); err != nil {
					t.Fatal(err)
				}
			}
			if tc.gossip {
				gossip(c)
			}
			got, err := ClusterOfOneBut(ctx, c, "h1", tc.admitted)
			if err != nil || got != tc.want {
				t.Fatalf("ClusterOfOneBut = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

// TestReplicaTrusted_JoiningHost: a replica that has not caught up is trusted
// beside hosts still joining while it has no gossip member, and not once one
// of them has booted or a gossip member exists. A sole host stays trusted
// whatever gossip shows, as before.
func TestReplicaTrusted_JoiningHost(t *testing.T) {
	ctx := context.Background()
	c := schemaClient(t)
	stale := func() (bool, string) { return false, "stale" }
	if err := InsertHost(ctx, c, HostRecord{Name: "h1", Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	c.SetMembersForTests(func() []PeerInfo { return []PeerInfo{{Name: "h9", Addr: "10.0.0.9:7946"}} })
	if ok, why := ReplicaTrusted(ctx, c, "h1", stale); !ok {
		t.Fatalf("a sole host with a gossip member: %s; want trusted, as before", why)
	}
	if err := InsertHost(ctx, c, HostRecord{Name: "h2", Address: "10.0.0.2", State: HostStateJoining}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := ReplicaTrusted(ctx, c, "h1", stale); ok {
		t.Fatal("trusted beside a joining host with a gossip member")
	}
	c.SetMembersForTests(func() []PeerInfo { return nil })
	if ok, why := ReplicaTrusted(ctx, c, "h1", stale); !ok {
		t.Fatalf("beside a joining host, with no gossip member: %s; want trusted", why)
	}
	if err := UpdateHostState(ctx, c, "h2", "active"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := ReplicaTrusted(ctx, c, "h1", stale); ok {
		t.Fatal("trusted beside a host that has booted")
	}
}
