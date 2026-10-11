package firewall

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestRender_TrunkNICPassesItsVLANs (re-review I-2): a NIC on litevirt's
// `trunk:` feature carries its configured VLANs in both modes. Its tagged
// frames are exempt from the VLAN rule; a VID it was not given, an 802.1ad
// outer tag and a doubled tag (whose inner payload no rule can see) are not;
// and its single-tagged IP traffic still meets its rules, which match the
// inner packet.
func TestRender_TrunkNICPassesItsVLANs(t *testing.T) {
	for _, mode := range []string{NICModeEnforce, NICModeObserve} {
		p := sgPlan(mode, true, Rule{Direction: Egress, Proto: "tcp", PortRange: "25", Action: Drop})
		p.NICs[0].TrunkVIDs = []int{101, 100}
		nic := nicPart(t, p)
		mustContainAll(t, nic, "set lv_vlan_ok {\n        type ifname\n        elements = { \"vnet1\" }")
		v := "drop"
		if mode == NICModeObserve {
			v = `counter comment "lv-wd vnet1 vlan trunk"`
		}
		pre := chainBody(t, nic, "prerouting")
		mustContainAll(t, pre,
			"iifname vnet1 ether type 8021ad "+v,
			// A VLAN the network does not allow never leaves, in either
			// mode: it is where a tenant would hop onto another's VLAN
			// (re-review R2-I1).
			"iifname vnet1 vlan id != { 100, 101 } drop",
			"iifname vnet1 vlan type { 8021q, 8021ad } "+v,
		)
		for _, hook := range []string{"forward", "output"} {
			mustContainAll(t, chainBody(t, nic, hook),
				"oifname vnet1 ether type 8021ad "+v,
				"oifname vnet1 vlan type { 8021q, 8021ad } "+v)
		}
		// Its rules still judge it: the egress chain exists and is dispatched.
		mustContainAll(t, chainBody(t, nic, "nic_out_vnet1"), "iifname vnet1 tcp dport 25")
	}
}

// TestRender_TrunkGuardHoldsEveryFrame (re-review R2-I1): a guarded trunk
// NIC's every frame — tagged or not — is held to its MAC, to its own MAC in
// ARP and in neighbour discovery, and may not answer DHCP or advertise itself
// as a router; only the address guards are the native (untagged) VLAN's, the
// addresses its guest uses on its other VLANs being no one's to know.
func TestRender_TrunkGuardHoldsEveryFrame(t *testing.T) {
	p := guardedPlan(&NICGuard{MAC: "52:54:00:aa:bb:cc", V4: []string{"10.0.0.5"}})
	p.NICs[0].TrunkVIDs = []int{100, 200}
	g := chainBody(t, nicPart(t, p), "guard_vnet3")
	ret := strings.Index(g, "ether type 8021q return")
	if ret < 0 {
		t.Fatalf("no native-VLAN boundary in a trunk guard:\n%s", g)
	}
	for _, every := range []string{
		"ether saddr != 52:54:00:aa:bb:cc drop",
		"meta protocol arp @nh,64,48 != 0x525400aabbcc drop",
		"meta l4proto udp th sport 67 drop",
		"meta l4proto udp th dport 68 drop",
		"meta l4proto udp th sport 547 drop",
		"meta l4proto udp th dport 546 drop",
		"icmpv6 type { nd-router-advert, nd-redirect } drop",
		"icmpv6 type nd-neighbor-solicit @th,192,16 0x0101 @th,208,48 != 0x525400aabbcc drop",
	} {
		if i := strings.Index(g, every); i < 0 || i > ret {
			t.Errorf("%q must hold tagged frames too (before the native-VLAN boundary):\n%s", every, g)
		}
	}
	if i := strings.Index(g, "ip saddr != { 10.0.0.5 } drop"); i < ret {
		t.Errorf("the address guard must hold the native VLAN only:\n%s", g)
	}
	if strings.Contains(g, "ether type { 8021q, 8021ad } drop") {
		t.Errorf("a trunk guard drops its own VLANs:\n%s", g)
	}
}

// TestRender_TrunkVIDsValidated: a VID outside 1-4094 is refused, so it can
// never reach nft and poison the whole ruleset.
func TestRender_TrunkVIDsValidated(t *testing.T) {
	p := sgPlan("", false)
	p.NICs[0].TrunkVIDs = []int{100, 4095}
	if _, _, err := RenderParts(p, true); err == nil {
		t.Fatal("VID 4095 accepted")
	}
}

// TestCorrosionPlanLoader_TrunkFromSpec (re-review I-2): the loader reads a
// NIC's trunk VLANs from its VM's spec — by MAC, or by position for a NIC the
// spec names no MAC for — and an access-mode NIC (one VLAN) is no trunk.
func TestCorrosionPlanLoader_TrunkFromSpec(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	spec := `{"name":"rt","network":[{"name":"prod","trunk":[100,101]},{"name":"lan","mac":"52:54:00:00:00:02","trunk":[300,301,302]},{"name":"dmz","trunk":[7]}]}`
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "rt", HostName: "host-a", State: "running", Spec: spec},
		[]corrosion.InterfaceRecord{
			{VMName: "rt", NetworkName: "prod", MAC: "52:54:00:00:00:01", Ordinal: 0},
			{VMName: "rt", NetworkName: "lan", MAC: "52:54:00:00:00:02", Ordinal: 1},
			{VMName: "rt", NetworkName: "dmz", MAC: "52:54:00:00:00:03", Ordinal: 2},
		}, nil); err != nil {
		t.Fatal(err)
	}
	plan, err := CorrosionPlanLoader(db, "host-a", Plan{}, liveTaps(map[string]map[string]string{
		"rt": {"52:54:00:00:00:01": "vnet1", "52:54:00:00:00:02": "vnet2", "52:54:00:00:00:03": "vnet3"},
	}))(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]int{}
	for _, n := range plan.NICs {
		got[n.NICDev] = n.TrunkVIDs
	}
	want := map[string][]int{"vnet1": {100, 101}, "vnet2": {300, 301, 302}, "vnet3": nil}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("trunk VIDs = %v, want %v", got, want)
	}
}

// TestCorrosionPlanLoader_TrunkVLANsTheNetworkAllows (re-review R2-I1): a trunk
// NIC created by this build (it has a guard record) carries only the VLANs its
// network allows (the network's allowed-vlans, set with network.update); the
// rest are reported, with the network, so a condition can name the command. A
// trunk that predates guards (no record) keeps carrying its own VLANs.
func TestCorrosionPlanLoader_TrunkVLANsTheNetworkAllows(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.UpsertNetwork(ctx, db, corrosion.NetworkRecord{Name: "core", Type: "bridge",
		Config: `{"Type":"bridge","Interface":"brcore","AllowedVLANs":[100]}`}); err != nil {
		t.Fatal(err)
	}
	for _, vm := range []struct{ name, mac string }{{"tenant", "52:54:00:00:00:01"}, {"legacy", "52:54:00:00:00:02"}} {
		spec := `{"name":"` + vm.name + `","uuid":"u-` + vm.name + `","network":[{"name":"core","trunk":[100,102]}]}`
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: vm.name, HostName: "host-a", State: "running", Spec: spec},
			[]corrosion.InterfaceRecord{{VMName: vm.name, NetworkName: "core", MAC: vm.mac}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.PutNICGuard(ctx, db, capabilities.GrantForTest(t, capabilities.FeatureNICGuards), corrosion.NICGuardRecord{VMName: "tenant", MAC: "52:54:00:00:00:01",
		Mode: corrosion.NICGuardOn, VMUUID: "u-tenant", Network: "core"}, "t"); err != nil {
		t.Fatal(err)
	}
	plan, err := CorrosionPlanLoader(db, "host-a", Plan{}, liveTaps(map[string]map[string]string{
		"tenant": {"52:54:00:00:00:01": "vnet1"}, "legacy": {"52:54:00:00:00:02": "vnet2"},
	}))(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]int{}
	for _, n := range plan.NICs {
		got[n.NICDev] = n.TrunkVIDs
	}
	if want := map[string][]int{"vnet1": {100}, "vnet2": {100, 102}}; !reflect.DeepEqual(got, want) {
		t.Errorf("trunk VIDs = %v, want %v", got, want)
	}
	if want := []BlockedTrunk{{Workload: "tenant", Network: "core", VIDs: []int{102}}}; !reflect.DeepEqual(plan.BlockedTrunks, want) {
		t.Errorf("blocked = %+v, want %+v", plan.BlockedTrunks, want)
	}
}
