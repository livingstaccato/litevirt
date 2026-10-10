package firewall

import (
	"context"
	"reflect"
	"strings"
	"testing"

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
			"iifname vnet1 vlan id != { 100, 101 } "+v,
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

// TestRender_TrunkGuardChecksOnlyNativeVLAN: a guarded trunk NIC's tagged
// frames are held to its MAC, and its address guards apply to the untagged
// (native) traffic only: the addresses it uses on its other VLANs are not
// litevirt's to know.
func TestRender_TrunkGuardChecksOnlyNativeVLAN(t *testing.T) {
	p := guardedPlan(&NICGuard{MAC: "52:54:00:aa:bb:cc", V4: []string{"10.0.0.5"}})
	p.NICs[0].TrunkVIDs = []int{100, 200}
	g := chainBody(t, nicPart(t, p), "guard_vnet3")
	mac, ret := strings.Index(g, "ether saddr != 52:54:00:aa:bb:cc drop"), strings.Index(g, "ether type 8021q return")
	ip := strings.Index(g, "ip saddr != { 10.0.0.5 } drop")
	if mac < 0 || ret < 0 || ip < 0 || !(mac < ret && ret < ip) {
		t.Fatalf("a trunk guard must check the MAC, then return tagged frames, then check addresses:\n%s", g)
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
