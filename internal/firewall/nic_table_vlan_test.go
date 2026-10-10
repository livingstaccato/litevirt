package firewall

import (
	"strings"
	"testing"
)

// TestRender_TaggedToNICJudged (re-review I-1): a tagged frame sent TO a guest
// NIC from a port that is not one (the uplink, the LAN behind it) is dropped
// in the forward and output hooks before the non-IP accept, so it cannot carry
// its payload past the receiver's nic_in chain. A NIC that may carry tags is
// exempt.
func TestRender_TaggedToNICJudged(t *testing.T) {
	p := sgPlan("", true)
	nic := nicPart(t, p)
	const rule = "oifname @lv_nic_devs oifname != @lv_vlan_ok ether type { 8021q, 8021ad } drop"
	for _, hook := range []string{"forward", "output"} {
		body := chainBody(t, nic, hook)
		i, j := strings.Index(body, rule), strings.Index(body, "meta protocol != { ip, ip6 } accept")
		if i < 0 || j < 0 || i > j {
			t.Errorf("%s: %q must come before the non-IP accept:\n%s", hook, rule, body)
		}
	}

	// Observe: counted, not dropped.
	p.NICMode = NICModeObserve
	nic = nicPart(t, p)
	mustContainAll(t, chainBody(t, nic, "forward"),
		`oifname @lv_nic_devs oifname != @lv_vlan_ok ether type { 8021q, 8021ad } counter comment "lv-wd - vlan tagged-to-nic"`)
}

// TestRender_RoutedNDDropSparesBridged (re-review I-5): the inet forward drop
// of neighbour and router discovery matches only what a router forwarded (the
// hop limit is below 255 by then). With br_netfilter loaded, BRIDGED ND also
// traverses inet forward, still at 255, and must pass as it did before.
func TestRender_RoutedNDDropSparesBridged(t *testing.T) {
	inet, _, err := RenderParts(sgPlan("", false), true)
	if err != nil {
		t.Fatal(err)
	}
	fwd := chainBody(t, inet, "forward")
	mustContainAll(t, fwd, "ip6 hoplimit != 255 icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect } drop")
	if strings.Contains(fwd, "        icmpv6 type { nd-router-solicit") {
		t.Errorf("an unconditional ND drop in inet forward also drops bridged ND under br_netfilter:\n%s", fwd)
	}
}

// TestRender_GuardNDLengthCapped (re-review m-a): only the first ND option is
// checked against the guest's MAC, so a guarded NIC's solicitations and
// advertisements may carry no second option to smuggle a link-layer address
// in: their length is capped at the header plus one 8-byte option.
func TestRender_GuardNDLengthCapped(t *testing.T) {
	g := chainBody(t, nicPart(t, guardedPlan(&NICGuard{MAC: "52:54:00:aa:bb:cc"})), "guard_vnet3")
	mustContainAll(t, g,
		"icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } ip6 length > 32 drop",
		"icmpv6 type nd-router-solicit ip6 length > 16 drop",
	)
}
