package corrosion

import (
	"context"
	"testing"
)

// TestSeedFirewallEnforcement_NotFromAStaleReplica (re-review I-3): a replica
// that has not caught up with its peers, in a cluster it knows has other
// hosts, records nothing: it may simply not have seen the cluster's mode, or
// its workloads, yet — a joiner would flip a cluster to enforce, a rejoiner
// back to observe.
func TestSeedFirewallEnforcement_NotFromAStaleReplica(t *testing.T) {
	ctx := context.Background()
	c := nicGuardDB(t, true)
	for _, h := range []string{"h1", "h2"} {
		if err := InsertHost(ctx, c, HostRecord{Name: h, Address: "10.0.0.1", State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	if caught, _ := c.ReplicaCaughtUp(); caught {
		t.Fatal("a fresh test client reports a caught-up replica; the case below proves nothing")
	}
	if m, err := SeedFirewallEnforcement(ctx, c, FirewallEnforce, "h1"); err != nil || m != "" {
		t.Fatalf("seeded %q (err %v) from a replica that has not caught up with a cluster of two", m, err)
	}
}

// TestSeedFirewallEnforcement_SoleHostSeeds: a cluster whose only host is
// this one has no peer to catch up with, and seeds at once.
func TestSeedFirewallEnforcement_SoleHostSeeds(t *testing.T) {
	ctx := context.Background()
	c := nicGuardDB(t, true)
	if err := InsertHost(ctx, c, HostRecord{Name: "h1", Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if m, err := SeedFirewallEnforcement(ctx, c, FirewallEnforce, "h1"); err != nil || m != FirewallEnforce {
		t.Fatalf("sole host: %q, %v; want enforce", m, err)
	}
}

// TestSeedFirewallEnforcement_AnyOperatorWriteWins: the seed is stamped
// before any real write could be, so an operator's `lv firewall enforce`
// outranks it on every replica wherever and whenever either was written —
// and of two seeds, observe outranks enforce (failing open, as before).
func TestSeedFirewallEnforcement_AnyOperatorWriteWins(t *testing.T) {
	ctx := context.Background()
	c := nicGuardDB(t, true)
	earlier := c.NowTS() // an operator's write on another host, before the seed
	if m, err := SeedFirewallEnforcement(ctx, c, FirewallEnforce, ""); err != nil || m != FirewallEnforce {
		t.Fatalf("seed: %q, %v", m, err)
	}
	e, err := GetFirewallEnforcement(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if lwwOrder(e.UpdatedAt, earlier) >= 0 {
		t.Errorf("the seed (%s) outranks an operator write made before it (%s)", e.UpdatedAt, earlier)
	}
	if lwwOrder(seedTS(FirewallObserve), seedTS(FirewallEnforce)) <= 0 {
		t.Error("an observe seed must outrank an enforce seed")
	}
}
