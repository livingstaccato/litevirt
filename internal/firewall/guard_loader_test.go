package firewall

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func on(allowed ...string) *corrosion.NICGuardRecord {
	return &corrosion.NICGuardRecord{VMName: "vm", MAC: "52:54:00:aa:bb:cc", Mode: corrosion.NICGuardOn, Allowed: allowed}
}

// TestResolveNICGuard pins which addresses a guarded NIC may send from.
func TestResolveNICGuard(t *testing.T) {
	cases := []struct {
		name           string
		rec            *corrosion.NICGuardRecord
		ip, subnet     string
		wantNil        bool
		wantV4, wantV6 []string
	}{
		{name: "no record is unguarded", rec: nil, ip: "10.0.0.5", wantNil: true},
		{name: "off is unguarded", rec: &corrosion.NICGuardRecord{Mode: corrosion.NICGuardOff}, ip: "10.0.0.5", wantNil: true},
		{name: "assigned address only, prefix length dropped", rec: on(), ip: "10.0.0.5/24", subnet: "10.0.0.0/24",
			wantV4: []string{"10.0.0.5"}},
		{name: "dynamic DHCP falls back to the subnet", rec: on(), subnet: "10.1.0.0/24",
			wantV4: []string{"10.1.0.0/24"}},
		{name: "allowed VIP joins the assigned address", rec: on("10.0.0.250", "2001:db8::/64"), ip: "10.0.0.5",
			wantV4: []string{"10.0.0.5", "10.0.0.250"}, wantV6: []string{"2001:db8::/64"}},
		{name: "nothing known leaves both families open", rec: on()},
		{name: "IPv6 subnet restricts IPv6 only", rec: on(), subnet: "fd00:1::/64",
			wantV6: []string{"fd00:1::/64"}},
		{name: "known static IPv6 beats the subnet", rec: &corrosion.NICGuardRecord{Mode: corrosion.NICGuardOn, Known: []string{"fd00:1::5"}},
			subnet: "fd00:1::/64", wantV6: []string{"fd00:1::5"}},
		{name: "garbage skipped", rec: on("not-an-ip"), ip: "garbage"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := ResolveNICGuard(c.rec, "52:54:00:AA:BB:CC", c.ip, c.subnet, nil, nil)
			if c.wantNil {
				if g != nil {
					t.Fatalf("got %+v, want unguarded", g)
				}
				return
			}
			if g == nil {
				t.Fatal("got unguarded, want a guard")
			}
			if g.MAC != "52:54:00:aa:bb:cc" {
				t.Errorf("MAC = %q", g.MAC)
			}
			if !reflect.DeepEqual(g.V4, c.wantV4) || !reflect.DeepEqual(g.V6, c.wantV6) {
				t.Errorf("V4=%v V6=%v, want V4=%v V6=%v", g.V4, g.V6, c.wantV4, c.wantV6)
			}
		})
	}
}

// TestCorrosionPlanLoader_GuardsRecordedNICsOnly: a NIC with an "on" record is
// rendered guarded with the address its NIC row carries; a NIC with no record
// — every NIC that predates guards — renders exactly as before.
func TestCorrosionPlanLoader_GuardsRecordedNICsOnly(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	db.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "new", HostName: "host-a", State: "running"},
		[]corrosion.InterfaceRecord{{VMName: "new", NetworkName: "prod", MAC: "52:54:00:00:00:01", IP: "10.0.0.10"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "old", HostName: "host-a", State: "running"},
		[]corrosion.InterfaceRecord{{VMName: "old", NetworkName: "prod", MAC: "52:54:00:00:00:02", IP: "10.0.0.11"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.PutNICGuard(ctx, db, capabilities.GrantForTest(t, capabilities.FeatureNICGuards), corrosion.NICGuardRecord{
		VMName: "new", MAC: "52:54:00:00:00:01", Mode: corrosion.NICGuardOn, Allowed: []string{"10.0.0.250"},
	}, "test"); err != nil {
		t.Fatalf("PutNICGuard: %v", err)
	}
	loader := CorrosionPlanLoader(db, "host-a", Plan{}, liveTaps(map[string]map[string]string{
		"new": {"52:54:00:00:00:01": "vnet1"},
		"old": {"52:54:00:00:00:02": "vnet2"},
	}))
	plan, err := loader(ctx)
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	byDev := map[string]NICBinding{}
	for _, n := range plan.NICs {
		byDev[n.NICDev] = n
	}
	if g := byDev["vnet2"].Guard; g != nil {
		t.Errorf("a NIC with no record was guarded: %+v", g)
	}
	g := byDev["vnet1"].Guard
	if g == nil {
		t.Fatal("the recorded NIC was not guarded")
	}
	if !reflect.DeepEqual(g.V4, []string{"10.0.0.10", "10.0.0.250"}) || g.ExcludeV4 != nil {
		t.Errorf("V4 = %v", g.V4)
	}
	out, err := Render(plan)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "iifname vnet1 jump guard_vnet1") || strings.Contains(out, "guard_vnet2") {
		t.Errorf("guard dispatch wrong:\n%s", out)
	}
}

// TestResolveNICGuard_SubnetExcludesOthers: a guest confined to its subnet
// (its exact address unknown) may still never claim the network's own
// addresses — network, broadcast, its router and reserved addresses — nor
// another NIC's assigned address; its own stays usable.
func TestResolveNICGuard_SubnetExcludesOthers(t *testing.T) {
	g := ResolveNICGuard(on(), "52:54:00:aa:bb:cc", "", "10.1.0.0/24", []string{"10.1.0.254", "fd00::1"},
		[]string{"10.1.0.7", "10.1.0.9", "192.168.5.5"})
	if g == nil || !reflect.DeepEqual(g.V4, []string{"10.1.0.0/24"}) {
		t.Fatalf("guard = %+v", g)
	}
	// The router is the network's configured one (.254), not the first host
	// (re-review I-9).
	want := []string{"10.1.0.0", "10.1.0.7", "10.1.0.9", "10.1.0.254", "10.1.0.255"}
	if !reflect.DeepEqual(g.ExcludeV4, want) {
		t.Errorf("ExcludeV4 = %v, want %v", g.ExcludeV4, want)
	}
	// An allowed link-local address is held as link-local, not as a global
	// restriction.
	g = ResolveNICGuard(on("fe80::1234"), "52:54:00:aa:bb:cc", "10.1.0.5", "", nil, nil)
	if g.V6 != nil || !reflect.DeepEqual(g.LinkLocal, []string{"fe80::1234"}) {
		t.Errorf("link-local allowance: V6=%v LinkLocal=%v", g.V6, g.LinkLocal)
	}
}

// TestCorrosionPlanLoader_ModeFromPolicyAndConntrack (rulings 1 and 6): with
// no policy recorded a host observes; a recorded enforce enforces; and a host
// without bridge conntrack renders the guards only, whatever the policy.
func TestCorrosionPlanLoader_ModeFromPolicyAndConntrack(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.SetClusterPolicyGate(func() bool { return true })
	load := func(ct bool) string {
		p, err := CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{BridgeConntrack: func() bool { return ct }})(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return p.NICMode
	}
	if m := load(true); m != NICModeObserve {
		t.Errorf("no policy: %q, want observe", m)
	}
	if err := corrosion.SetFirewallEnforcement(ctx, db, corrosion.FirewallEnforce, "t"); err != nil {
		t.Fatal(err)
	}
	if m := load(true); m != NICModeEnforce {
		t.Errorf("enforce policy: %q, want enforce", m)
	}
	if m := load(false); m != NICModeGuardsOnly {
		t.Errorf("no bridge conntrack: %q, want guards-only", m)
	}
}

// TestCorrosionPlanLoader_ARetiredRecordOverALiveNICGuards (review I1): a
// retired record of the running incarnation over a NIC whose row is live —
// a write order this replica saw out of order — renders the NIC guarded, not
// unguarded; one of another incarnation guards nothing.
func TestCorrosionPlanLoader_ARetiredRecordOverALiveNICGuards(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	db.SetClusterPolicyGate(func() bool { return true })
	for _, v := range []struct{ name, uuid, mac, ip string }{
		{"web", "u-1", "52:54:00:00:00:01", "10.0.0.10"},
		{"other", "u-2", "52:54:00:00:00:02", "10.0.0.11"},
	} {
		if err := corrosion.InsertVM(ctx, db,
			corrosion.VMRecord{Name: v.name, HostName: "host-a", State: "running", Spec: `{"name":"` + v.name + `","uuid":"` + v.uuid + `"}`},
			[]corrosion.InterfaceRecord{{VMName: v.name, NetworkName: "prod", MAC: v.mac, IP: v.ip}}, nil); err != nil {
			t.Fatal(err)
		}
		// Each NIC's record is retired; "other"'s was written for an
		// earlier incarnation.
		uuid := v.uuid
		if v.name == "other" {
			uuid = "u-old"
		}
		if err := corrosion.PutNICGuard(ctx, db, capabilities.GrantForTest(t, capabilities.FeatureNICGuards), corrosion.NICGuardRecord{
			VMName: v.name, MAC: v.mac, Mode: corrosion.NICGuardOff, VMUUID: uuid,
		}, "test"); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.RetireNICGuard(ctx, db, v.name, v.mac, "test"); err != nil {
			t.Fatal(err)
		}
	}
	plan, err := CorrosionPlanLoader(db, "host-a", Plan{}, liveTaps(map[string]map[string]string{
		"web":   {"52:54:00:00:00:01": "vnet1"},
		"other": {"52:54:00:00:00:02": "vnet2"},
	}))(ctx)
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	byDev := map[string]NICBinding{}
	for _, n := range plan.NICs {
		byDev[n.NICDev] = n
	}
	if g := byDev["vnet1"].Guard; g == nil || !reflect.DeepEqual(g.V4, []string{"10.0.0.10"}) {
		t.Errorf("a live NIC under its incarnation's retired record: guard %+v, want the default guard", g)
	}
	if g := byDev["vnet2"].Guard; g != nil {
		t.Errorf("another incarnation's retired record guarded a NIC: %+v", g)
	}
}

// TestCorrosionPlanLoader_RetiredRecordOverAnUnenforcedNetwork (re-review
// n6): on a network that cannot enforce a guard, a retired record guards
// nothing.
func TestCorrosionPlanLoader_RetiredRecordOverAnUnenforcedNetwork(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	db.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.UpsertNetwork(ctx, db, corrosion.NetworkRecord{Name: "vf", Type: "sriov", Config: `{"type":"sriov"}`}); err != nil {
		t.Fatal(err)
	}
	const mac = "52:54:00:00:00:03"
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "web", HostName: "host-a", State: "running", Spec: `{"name":"web","uuid":"u-1"}`},
		[]corrosion.InterfaceRecord{{VMName: "web", NetworkName: "vf", MAC: mac, IP: "10.0.0.12"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.PutNICGuard(ctx, db, capabilities.GrantForTest(t, capabilities.FeatureNICGuards), corrosion.NICGuardRecord{
		VMName: "web", MAC: mac, Mode: corrosion.NICGuardOn, VMUUID: "u-1", Network: "lan",
	}, "test"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.RetireNICGuard(ctx, db, "web", mac, "test"); err != nil {
		t.Fatal(err)
	}
	plan, err := CorrosionPlanLoader(db, "host-a", Plan{}, liveTaps(map[string]map[string]string{
		"web": {mac: "vnet3"},
	}))(ctx)
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	for _, n := range plan.NICs {
		if n.NICDev == "vnet3" && n.Guard != nil {
			t.Errorf("a NIC on an SR-IOV network was guarded under a retired record: %+v", n.Guard)
		}
	}
}
