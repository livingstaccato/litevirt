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

// TestRender_AllowTagsGuardHoldsTaggedFramesToTheMAC: a guarded NIC allowed
// tags with --allow-vlan-tags (not a trunk) is held like a trunk. Its tagged
// frames are checked for what is knowable — the source MAC, its own MAC in ARP
// and neighbour discovery, no DHCP-server or router role — and then leave the
// chain: the addresses it uses inside a VLAN are not litevirt's to know, so the
// native-VLAN address guards must not judge a tagged frame's inner source (they
// dropped tagged IPv4 on any other subnet) and tagged ARP must not pass
// unchecked. Both tag types leave: the table-wide rule lets an 802.1ad outer tag
// through to this NIC too.
func TestRender_AllowTagsGuardHoldsTaggedFramesToTheMAC(t *testing.T) {
	p := guardedPlan(&NICGuard{MAC: "52:54:00:aa:bb:cc", V4: []string{"10.0.0.5"}})
	p.NICs[0].AllowVLANTags = true
	g := chainBody(t, nicPart(t, p), "guard_vnet3")
	ret := strings.Index(g, "vlan id != 0 return")
	if ret < 0 {
		t.Fatalf("no native-VLAN boundary in an allow-vlan-tags guard:\n%s", g)
	}
	for _, every := range []string{
		"ether saddr != 52:54:00:aa:bb:cc drop",
		"meta protocol arp @nh,64,48 != 0x525400aabbcc drop",
		"meta l4proto udp th sport 67 drop",
		"meta l4proto udp th dport 68 drop",
		"icmpv6 type { nd-router-advert, nd-redirect } drop",
		"ether type 8021ad drop",
		"meta protocol { 8021q, 8021ad } drop",
	} {
		if i := strings.Index(g, every); i < 0 || i > ret {
			t.Errorf("%q must hold tagged frames too (before the boundary):\n%s", every, g)
		}
	}
	for _, native := range []string{"ip saddr != { 10.0.0.5 } drop", "arp saddr ip != {"} {
		if i := strings.Index(g, native); i < ret {
			t.Errorf("%q must hold the native VLAN only:\n%s", native, g)
		}
	}
	if strings.Contains(g, "ether type { 8021q, 8021ad } drop") {
		t.Errorf("an allow-vlan-tags guard drops its own tags:\n%s", g)
	}
}

// TestRender_NoTagsGuardStillDropsTags pins the other side: without the
// allowance a guarded NIC still drops tagged frames and has no boundary.
func TestRender_NoTagsGuardStillDropsTags(t *testing.T) {
	g := chainBody(t, nicPart(t, guardedPlan(&NICGuard{MAC: "52:54:00:aa:bb:cc"})), "guard_vnet3")
	mustContainAll(t, g, "ether type { 8021q, 8021ad } drop")
	if strings.Contains(g, "return") {
		t.Errorf("a plain guard has a native-VLAN boundary:\n%s", g)
	}
}

// TestRender_AllowTagsGuardDropsDoubleTags: a guarded allow-vlan-tags NIC may
// not send a doubled tag (an 802.1ad outer tag, or an 802.1Q tag inside one):
// after the outer tag the kernel's protocol is 0x8100 and no raw ARP, DHCP, RA
// or ND check can find its header, so the frame is dropped before the boundary
// rather than waved through unchecked.
func TestRender_AllowTagsGuardDropsDoubleTags(t *testing.T) {
	p := guardedPlan(&NICGuard{MAC: "52:54:00:aa:bb:cc"})
	p.NICs[0].AllowVLANTags = true
	g := chainBody(t, nicPart(t, p), "guard_vnet3")
	ret := strings.Index(g, "vlan id != 0 return")
	for _, drop := range []string{"ether type 8021ad drop", "meta protocol { 8021q, 8021ad } drop"} {
		if i := strings.Index(g, drop); i < 0 || ret < 0 || i > ret {
			t.Errorf("%q must come before the boundary:\n%s", drop, g)
		}
	}
}

// TestRender_AllowTagsGuardTreatsVID0AsNative: a priority-tagged (VID 0) frame
// is native-VLAN traffic — the receive path and a vlan_filtering bridge treat
// it as untagged — so it must not leave the chain at the tagged boundary. It
// falls through to the native IPv4 and IPv6 guards, and its ARP sender address
// (which nft's arp expression cannot read inside a tag) is held by a raw match.
func TestRender_AllowTagsGuardTreatsVID0AsNative(t *testing.T) {
	p := guardedPlan(&NICGuard{MAC: "52:54:00:aa:bb:cc", V4: []string{"10.0.0.5", "10.0.2.0/24"}, ExcludeV4: []string{"10.0.0.99"}})
	p.NICs[0].AllowVLANTags = true
	g := chainBody(t, nicPart(t, p), "guard_vnet3")
	ret := strings.Index(g, "vlan id != 0 return")
	if ret < 0 {
		t.Fatalf("the boundary must skip VID 0:\n%s", g)
	}
	if strings.Contains(g, "ether type { 8021q, 8021ad } return") || strings.Contains(g, "ether type 8021q return") {
		t.Errorf("a boundary that returns VID 0 too lets a priority-tagged frame past the address guards:\n%s", g)
	}
	for _, want := range []string{
		"vlan id 0 meta protocol arp @nh,112,32 { 0x0a000063 } drop",
		"vlan id 0 meta protocol arp @nh,112,32 != { 0x00000000, 0x0a000005, 0x0a000200-0x0a0002ff } drop",
		"ip saddr != { 10.0.0.5, 10.0.2.0/24 } drop",
	} {
		if i := strings.Index(g, want); i < ret {
			t.Errorf("%q must follow the boundary (found at %d, boundary at %d):\n%s", want, i, ret, g)
		}
	}
}

// icmpv6LinkDependent reports the rules of a bridge-family ruleset whose ICMPv6
// match nft would compile with a link-layer dependency (lab 1 F3). In the
// bridge family nft gives `icmpv6 ...` an implicit `ether type ip6` check when
// nothing earlier in the rule has named the network protocol, and on a frame
// carrying a VLAN tag (VID 0 included) that field reads 0x8100: the rule never
// matches. `meta protocol ip6`, or any `ip6` header match, ahead of it names
// the protocol from the kernel's view, which a single tag does not hide.
func icmpv6LinkDependent(ruleset string) []string {
	var bad []string
	for _, line := range strings.Split(ruleset, "\n") {
		i := strings.Index(line, "icmpv6 ")
		if i < 0 {
			continue
		}
		before := " " + strings.TrimSpace(line[:i]) + " "
		if !strings.Contains(before, " meta protocol ip6 ") && !strings.Contains(before, " ip6 ") {
			bad = append(bad, strings.TrimSpace(line))
		}
	}
	return bad
}

// TestRender_GuardICMPv6MatchesInsideTags (lab 1 F3): every ICMPv6 match in the
// per-NIC table names the network protocol before it, so the RA and redirect
// drop, the ND length caps, the ND link-layer option checks and the NA target
// checks hold a single-tagged or priority-tagged (VID 0) frame as they hold an
// untagged one. A guard allowed tags (--allow-vlan-tags) and a trunk guard
// hold their tagged frames to the RA and ND rules before the boundary, and an
// allow-tags guard's VID-0 frames reach the NA target checks after it.
func TestRender_GuardICMPv6MatchesInsideTags(t *testing.T) {
	guard := func() *NICGuard {
		return &NICGuard{MAC: "52:54:00:aa:bb:cc", V4: []string{"10.0.0.5"}, V6: []string{"2001:db8::5"}, LinkLocal: []string{"fe80::99"}}
	}
	plain := guardedPlan(guard())
	allow := guardedPlan(guard())
	allow.NICs[0].AllowVLANTags = true
	trunk := guardedPlan(guard())
	trunk.NICs[0].TrunkVIDs = []int{100}
	for _, c := range []struct {
		name, boundary string
		p              Plan
	}{{"plain", "", plain}, {"allow-vlan-tags", "vlan id != 0 return", allow}, {"trunk", "ether type 8021q return", trunk}} {
		for _, mode := range []string{NICModeEnforce, NICModeObserve, NICModeGuardsOnly} {
			c.p.NICMode = mode
			nic := nicPart(t, c.p)
			if bad := icmpv6LinkDependent(nic); len(bad) > 0 {
				t.Errorf("%s, %s: ICMPv6 rules that miss every tagged frame:\n  %s", c.name, mode, strings.Join(bad, "\n  "))
			}
			if c.boundary == "" {
				continue
			}
			g := chainBody(t, nic, "guard_vnet3")
			ret := strings.Index(g, c.boundary)
			for _, before := range []string{
				"meta protocol ip6 icmpv6 type { nd-router-advert, nd-redirect } drop",
				"meta protocol ip6 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } @nh,32,16 > 32 drop",
				"meta protocol ip6 icmpv6 type nd-router-solicit @th,64,16 0x0101 @th,80,48 != 0x525400aabbcc drop",
				"meta protocol ip6 icmpv6 type nd-neighbor-solicit @th,192,16 0x0101 @th,208,48 != 0x525400aabbcc drop",
				"meta protocol ip6 icmpv6 type nd-neighbor-advert @th,192,16 0x0201 @th,208,48 != 0x525400aabbcc drop",
			} {
				if i := strings.Index(g, before); i < 0 || ret < 0 || i > ret {
					t.Errorf("%s, %s: %q must hold tagged frames (before %q):\n%s", c.name, mode, before, c.boundary, g)
				}
			}
			if c.name != "allow-vlan-tags" {
				continue
			}
			for _, after := range []string{
				"meta protocol ip6 icmpv6 type nd-neighbor-advert icmpv6 taddr fe80::/10 icmpv6 taddr != { fe80::5054:ff:feaa:bbcc, fe80::99 } drop",
				"meta protocol ip6 icmpv6 type nd-neighbor-advert icmpv6 taddr != {",
			} {
				if i := strings.Index(g, after); i < ret {
					t.Errorf("%s, %s: %q must judge VID 0 after the boundary (at %d, boundary %d):\n%s", c.name, mode, after, i, ret, g)
				}
			}
		}
	}
}
