package corrosion

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func nicGuardDB(t *testing.T, open bool) *Client {
	t.Helper()
	c := NewTestClientT(t)
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if open {
		c.SetClusterPolicyGate(func() bool { return true })
	}
	return c
}

// TestPutNICGuard_RefusedUntilGateOpens: the record lives in cluster_policies,
// whose statements stall a peer that cannot decode them, so it waits for the
// same latch every other writer of that table waits for.
func TestPutNICGuard_RefusedUntilGateOpens(t *testing.T) {
	c := nicGuardDB(t, false)
	err := PutNICGuard(context.Background(), c, NICGuardRecord{VMName: "vm", MAC: "52:54:00:aa:bb:cc", Mode: NICGuardOn}, "admin")
	if !errors.Is(err, ErrClusterPolicyGateClosed) {
		t.Fatalf("err = %v, want ErrClusterPolicyGateClosed", err)
	}
}

// TestPutNICGuard_RoundTrip: what is written is read back in canonical form,
// keyed by VM and lower-cased MAC, with who set it.
func TestPutNICGuard_RoundTrip(t *testing.T) {
	ctx := context.Background()
	c := nicGuardDB(t, true)
	if err := PutNICGuard(ctx, c, NICGuardRecord{
		VMName: "web-1", MAC: "52:54:00:AA:BB:CC", Mode: NICGuardOn,
		Allowed: []string{"10.0.0.250", " 10.0.1.7/24 ", "10.0.0.250", "2001:DB8::1"},
		Known:   []string{"fd00::5"}, AllowRouterAdvert: true,
	}, "alice"); err != nil {
		t.Fatalf("PutNICGuard: %v", err)
	}
	got, err := GetNICGuard(ctx, c, "web-1", "52:54:00:aa:bb:cc")
	if err != nil || got == nil {
		t.Fatalf("GetNICGuard = %v, %v", got, err)
	}
	if !got.Guarded() || got.SetBy != "alice" || !got.AllowRouterAdvert || got.AllowDHCPServer {
		t.Errorf("record = %+v", got)
	}
	if want := []string{"10.0.0.250", "10.0.1.0/24", "2001:db8::1"}; !reflect.DeepEqual(got.Allowed, want) {
		t.Errorf("Allowed = %v, want %v", got.Allowed, want)
	}
	all, err := ListNICGuards(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := all[NICGuardKey("web-1", "52:54:00:AA:BB:CC")]; !ok || len(all) != 1 {
		t.Errorf("ListNICGuards = %v", all)
	}
	// Overwrite with off.
	if err := PutNICGuard(ctx, c, NICGuardRecord{VMName: "web-1", MAC: "52:54:00:aa:bb:cc", Mode: NICGuardOff}, "bob"); err != nil {
		t.Fatal(err)
	}
	if got, _ := GetNICGuard(ctx, c, "web-1", "52:54:00:aa:bb:cc"); got == nil || got.Guarded() || len(got.Allowed) != 0 {
		t.Errorf("after off: %+v", got)
	}
}

// TestPutNICGuard_Refuses: every malformed field is refused before the write,
// because it would otherwise reach every host's renderer.
func TestPutNICGuard_Refuses(t *testing.T) {
	ctx := context.Background()
	c := nicGuardDB(t, true)
	many := make([]string, MaxNICGuardAddresses+1)
	for i := range many {
		many[i] = fmt.Sprintf("10.0.%d.1", i)
	}
	for name, r := range map[string]NICGuardRecord{
		"no vm":        {MAC: "52:54:00:aa:bb:cc", Mode: NICGuardOn},
		"slash in vm":  {VMName: "a/b", MAC: "52:54:00:aa:bb:cc", Mode: NICGuardOn},
		"bad mac":      {VMName: "vm", MAC: "zz", Mode: NICGuardOn},
		"unknown mode": {VMName: "vm", MAC: "52:54:00:aa:bb:cc", Mode: "strict"},
		"bad address":  {VMName: "vm", MAC: "52:54:00:aa:bb:cc", Mode: NICGuardOn, Allowed: []string{"10.0.0.1; drop"}},
		"zoned":        {VMName: "vm", MAC: "52:54:00:aa:bb:cc", Mode: NICGuardOn, Allowed: []string{"fe80::1%eth0"}},
		"too many":     {VMName: "vm", MAC: "52:54:00:aa:bb:cc", Mode: NICGuardOn, Allowed: many},
	} {
		if err := PutNICGuard(ctx, c, r, "x"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if all, _ := ListNICGuards(ctx, c); len(all) != 0 {
		t.Errorf("a refused record was written: %v", all)
	}
}

// TestListNICGuards_SkipsUnknownMode: a later release's mode arriving by
// replication leaves the NIC unguarded here rather than guessing.
func TestListNICGuards_SkipsUnknownMode(t *testing.T) {
	ctx := context.Background()
	c := nicGuardDB(t, true)
	if err := c.Execute(ctx, clusterPolicyUpsertSQL, NICGuardKey("vm", "52:54:00:aa:bb:cc"), `{"mode":"strict"}`, "future", c.NowTS()); err != nil {
		t.Fatal(err)
	}
	all, err := ListNICGuards(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 0 {
		t.Errorf("unknown mode decoded: %v", all)
	}
}

// TestNetworkSubnets reads the subnet out of the stored network definition.
func TestNetworkSubnets(t *testing.T) {
	ctx := context.Background()
	c := nicGuardDB(t, false)
	if err := UpsertNetwork(ctx, c, NetworkRecord{Name: "prod", Type: "bridge", Config: `{"Type":"bridge","Subnet":"10.9.0.0/24"}`}); err != nil {
		t.Fatal(err)
	}
	if err := UpsertNetwork(ctx, c, NetworkRecord{Name: "flat", Type: "bridge", Config: `{"Type":"bridge"}`}); err != nil {
		t.Fatal(err)
	}
	got, err := NetworkSubnets(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if got["prod"] != "10.9.0.0/24" || got["flat"] != "" {
		t.Errorf("NetworkSubnets = %v", got)
	}
}

// TestSeedFirewallEnforcement (ruling 1): a cluster with nothing in it yet
// enforces from the start; one that has workloads or rules starts observing;
// a recorded mode is never overwritten.
func TestSeedFirewallEnforcement(t *testing.T) {
	ctx := context.Background()
	fresh := nicGuardDB(t, true)
	if m, err := SeedFirewallEnforcement(ctx, fresh); err != nil || m != FirewallEnforce {
		t.Fatalf("fresh cluster: %q, %v; want enforce", m, err)
	}
	if m, _ := SeedFirewallEnforcement(ctx, fresh); m != "" {
		t.Errorf("a recorded mode was seeded again: %q", m)
	}

	upgraded := nicGuardDB(t, true)
	if err := InsertVM(ctx, upgraded, VMRecord{Name: "vm", HostName: "h", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if m, err := SeedFirewallEnforcement(ctx, upgraded); err != nil || m != FirewallObserve {
		t.Fatalf("cluster with a workload: %q, %v; want observe", m, err)
	}

	closed := nicGuardDB(t, false)
	if m, err := SeedFirewallEnforcement(ctx, closed); err != nil || m != "" {
		t.Errorf("gate closed: %q, %v; want nothing written", m, err)
	}
	if e, _ := GetFirewallEnforcement(ctx, closed); e.Mode != FirewallObserve || e.Recorded {
		t.Errorf("no row must read as observe, got %+v", e)
	}
}
