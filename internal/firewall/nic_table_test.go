package firewall

import (
	"strings"
	"testing"
)

func sgPlan(mode string, deny bool, rules ...Rule) Plan {
	return Plan{
		NICMode:        mode,
		DefaultDeny:    deny,
		SecurityGroups: []SecurityGroup{{Name: "g", Rules: rules}},
		NICs: []NICBinding{
			{NICDev: "vnet1", VMName: "a", Bridge: "br0", SecurityGroups: []string{"g"}},
			{NICDev: "vnet2", VMName: "b", Bridge: "br0"},
		},
	}
}

func nicPart(t *testing.T, p Plan) string {
	t.Helper()
	_, nic, err := RenderParts(p, true)
	if err != nil {
		t.Fatalf("RenderParts: %v", err)
	}
	return nic
}

// TestRender_RejectIsDropInBridgeTable (review C1): the bridge family can
// reject only at prerouting and input; a reject reached from the forward or
// output hook makes the kernel refuse the whole table. Every tier's reject
// renders as drop there.
func TestRender_RejectIsDropInBridgeTable(t *testing.T) {
	p := sgPlan("", true, Rule{Direction: Ingress, Proto: "tcp", PortRange: "25", Action: Reject})
	p.ClusterRules = []Rule{{Direction: Egress, Proto: "udp", PortRange: "53", Action: Reject}}
	p.HostRules = []Rule{{Direction: Ingress, Proto: "icmp", Action: Reject}}
	p.NICs[0].ExtraRules = []Rule{{Direction: Egress, Proto: "tcp", PortRange: "22", Action: Reject}}
	nic := nicPart(t, p)
	if strings.Contains(nic, "reject") {
		t.Fatalf("the bridge table carries a reject:\n%s", nic)
	}
	mustContainAll(t, nic, "oifname vnet1 tcp dport 25 drop", "iifname vnet1 udp dport 53 drop",
		"oifname vnet1 ip protocol icmp drop", "iifname vnet1 tcp dport 22 drop")
}

// TestRender_PreambleIsScoped (review C2): DHCP is accepted ahead of the
// rules only toward a DHCP server on the link (broadcast, multicast, the
// managed gateway) — never "udp 68 → 67" to any address — and the ICMPv6
// accepted ahead of the rules is link-scoped (hop limit 255, link-local or
// multicast). ICMPv6 errors pass only as related traffic.
func TestRender_PreambleIsScoped(t *testing.T) {
	p := sgPlan("", true)
	p.Gateways = []string{"10.0.0.1"}
	nic := nicPart(t, p)
	for _, bad := range []string{
		"        udp sport 68 udp dport 67 accept\n",
		"        udp sport 67 udp dport 68 accept\n",
		"        udp sport 546 udp dport 547 accept\n",
		"destination-unreachable", "packet-too-big",
	} {
		if strings.Contains(nic, bad) {
			t.Errorf("unscoped preamble accept %q:\n%s", bad, nic)
		}
	}
	mustContainAll(t, nic,
		"iifname @lv_nic_devs udp sport 68 udp dport 67 ip daddr 255.255.255.255 accept",
		"udp sport 68 udp dport 67 ip daddr @lv_gw4 accept",
		"ip6 hoplimit 255 icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept",
		"elements = { 10.0.0.1 }",
	)
	inet, _, _ := RenderParts(p, true)
	if strings.Contains(inet, "destination-unreachable") {
		t.Errorf("inet forward accepts ICMPv6 errors by type:\n%s", inet)
	}
	if !strings.Contains(inet, "ip6 hoplimit != 255 icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect } drop") {
		t.Errorf("routed neighbour discovery is not dropped in inet forward:\n%s", inet)
	}
}

// TestRender_VLANDroppedOnEveryNIC (review C3): tagged frames from any guest
// NIC — guarded or not — are dropped ahead of everything, unless the NIC is an
// explicit trunk.
func TestRender_VLANDroppedOnEveryNIC(t *testing.T) {
	p := sgPlan("", false)
	p.NICs[1].AllowVLANTags = true
	nic := nicPart(t, p)
	mustContainAll(t, nic,
		`set lv_vlan_ok {`, `elements = { "vnet2" }`,
		"iifname != @lv_nic_devs accept\n        iifname != @lv_vlan_ok ether type { 8021q, 8021ad } drop",
	)
	pre := chainBody(t, nic, "prerouting")
	if strings.Index(pre, "8021q") > strings.Index(pre+"jump guard_", "jump guard_") {
		t.Errorf("the VLAN rule must come before any guard:\n%s", pre)
	}
}

// TestRender_RoutedTrafficKeepsTiersAndPolicy (ruling 5, review I1): inet
// forward never accepts by bridge name. It trusts only frames the bridge
// table judged (a mark set after a NIC's egress rules), hands routed traffic
// toward a guest bridge to that bridge's output hook with a mark, and judges
// everything else with the tiers and the default policy. At the output hook a
// marked frame toward a port that is not a guest NIC meets the tiers and the
// default policy (routed_to_port).
func TestRender_RoutedTrafficKeepsTiersAndPolicy(t *testing.T) {
	p := sgPlan("", true)
	p.ClusterRules = []Rule{{Direction: Ingress, Proto: "tcp", PortRange: "22", Action: Accept}}
	inet, nic, err := RenderParts(p, true)
	if err != nil {
		t.Fatal(err)
	}
	fwd := chainBody(t, inet, "forward")
	if strings.Contains(fwd, `iifname { "br0" } accept`) || strings.Contains(fwd, `oifname { "br0" } accept`) {
		t.Fatalf("inet forward accepts by bridge name:\n%s", fwd)
	}
	mustContainAll(t, fwd,
		"meta mark & 0x10000000 == 0x10000000 accept",
		`oifname { "br0" } meta mark set meta mark | 0x20000000 accept`,
		"jump cluster_default",
	)
	mustContainAll(t, chainBody(t, nic, "input"), "meta mark set meta mark | 0x10000000")
	mustContainAll(t, chainBody(t, nic, "output"),
		"oifname != @lv_nic_devs meta mark & 0x20000000 == 0x20000000 jump routed_to_port")
	mustContainAll(t, chainBody(t, nic, "routed_to_port"), "tcp dport 22 accept", "drop")

	// With the bridge table not in force, inet forward trusts nothing.
	inet, _, _ = RenderParts(p, false)
	if strings.Contains(inet, "meta mark") {
		t.Errorf("inet forward trusts marks of a bridge table that is not in force:\n%s", inet)
	}
}

// TestRender_BaseChainsScopedToNICs (review I2): the bridge base chains let
// frames between ports that are not guest NICs through first, untouched.
func TestRender_BaseChainsScopedToNICs(t *testing.T) {
	nic := nicPart(t, sgPlan("", true))
	for hook, first := range map[string]string{
		"forward": "iifname != @lv_nic_devs oifname != @lv_nic_devs accept",
		"input":   "iifname != @lv_nic_devs accept",
		"output":  "oifname != @lv_nic_devs accept",
	} {
		body := chainBody(t, nic, hook)
		if i, j := strings.Index(body, first), strings.Index(body, "ct state"); i < 0 || i > j {
			t.Errorf("%s: %q must come before any conntrack match:\n%s", hook, first, body)
		}
	}
}

// TestRender_ObserveDropsNothing (ruling 1, review I8): in observe mode the
// per-NIC chains count what they would drop and drop nothing; the inet table
// stays exactly what it was before per-NIC enforcement (no trust in marks).
func TestRender_ObserveDropsNothing(t *testing.T) {
	p := sgPlan(NICModeObserve, true, Rule{Direction: Ingress, Proto: "icmp", Action: Drop, Comment: "x"})
	inet, nic, err := RenderParts(p, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"nic_in_vnet1", "nic_out_vnet1", "forward", "input", "output"} {
		if body := chainBody(t, nic, c); strings.Contains(body, " drop") {
			t.Errorf("observe mode drops in %s:\n%s", c, body)
		}
	}
	mustContainAll(t, nic,
		`oifname vnet1 ip protocol icmp counter return comment "lv-wd vnet1 in sg:g#0"`,
		`counter comment "lv-wd vnet1 in default"`,
		`counter comment "lv-wd - vlan tagged"`,
	)
	if strings.Contains(inet, "meta mark") {
		t.Errorf("observe mode trusts bridge marks in inet forward:\n%s", inet)
	}
}

// TestRender_GuardsOnlyWithoutConntrack (ruling 6): without bridge conntrack
// only prerouting (VLAN rule, guards) is rendered: no ct expression, which the
// kernel would refuse, and no per-NIC rules that would judge replies as new.
func TestRender_GuardsOnlyWithoutConntrack(t *testing.T) {
	p := sgPlan(NICModeGuardsOnly, true)
	p.NICs[0].Guard = &NICGuard{MAC: "52:54:00:00:00:01"}
	inet, nic, err := RenderParts(p, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(nic, "ct state") || strings.Contains(nic, "chain forward") || strings.Contains(nic, "nic_in_") {
		t.Fatalf("guards-only renders more than prerouting:\n%s", nic)
	}
	mustContainAll(t, nic, "chain prerouting {", "jump guard_vnet1", "chain guard_vnet1 {")
	if strings.Contains(inet, "meta mark") {
		t.Errorf("guards-only trusts bridge marks:\n%s", inet)
	}
}

// TestRender_OwnServicesAllowedExplicitly (ruling 1): dnsmasq's DHCP and DNS
// at the managed gateways, and the host's load balancer to its backends, are
// allowed by generated rules naming them.
func TestRender_OwnServicesAllowedExplicitly(t *testing.T) {
	p := sgPlan("", true)
	p.Gateways = []string{"10.0.0.1", "fd00::1"}
	p.LBBackends = []LBBackend{{Addr: "10.0.0.20", Port: 8080}, {Addr: "10.0.0.21", Port: 8080}}
	p.LBSources = []string{"10.0.0.1", "192.0.2.10"}
	nic := nicPart(t, p)
	mustContainAll(t, chainBody(t, nic, "input"),
		"ip daddr @lv_gw4 udp dport 53 accept", "ip6 daddr @lv_gw6 tcp dport 53 accept")
	mustContainAll(t, chainBody(t, nic, "output"),
		"ip saddr @lv_gw4 udp sport 67 udp dport 68 accept",
		"ip saddr @lv_lb_src4 ip daddr . tcp dport @lv_lb4 accept")
	// haproxy on another host reaches a backend here through the forward
	// hook, from that host's address (re-review m-d).
	mustContainAll(t, chainBody(t, nic, "forward"),
		"iifname != @lv_nic_devs ip saddr @lv_lb_src4 ip daddr . tcp dport @lv_lb4 accept")
	mustContainAll(t, nic, "elements = { 10.0.0.20 . 8080, 10.0.0.21 . 8080 }",
		"elements = { 10.0.0.1, 192.0.2.10 }", "elements = { fd00::1 }")
}

// TestRender_GuardDHCPServerByDestination (review I7): a rogue server can
// answer from any source port, so the guard also drops what a guest sends to
// the client ports.
func TestRender_GuardDHCPServerByDestination(t *testing.T) {
	g := chainBody(t, nicPart(t, guardedPlan(&NICGuard{MAC: "52:54:00:aa:bb:cc"})), "guard_vnet3")
	mustContainAll(t, g, "ether type ip udp dport 68 drop", "ether type ip6 udp dport 546 drop")
}

// TestRender_GuardLinkLocal (review I6): link-local addresses are always held
// — the EUI-64 one from the MAC plus listed ones — for the source, for the
// target of a neighbour advertisement and for the link-layer address options,
// even when global IPv6 is unrestricted.
func TestRender_GuardLinkLocal(t *testing.T) {
	g := chainBody(t, nicPart(t, guardedPlan(&NICGuard{MAC: "52:54:00:aa:bb:cc", LinkLocal: []string{"fe80::99"}})), "guard_vnet3")
	mustContainAll(t, g,
		"ip6 saddr fe80::/10 ip6 saddr != { fe80::5054:ff:feaa:bbcc, fe80::99 } drop",
		"icmpv6 type nd-neighbor-advert icmpv6 taddr fe80::/10 icmpv6 taddr != { fe80::5054:ff:feaa:bbcc, fe80::99 } drop",
		"icmpv6 type nd-neighbor-solicit @th,192,16 0x0101 @th,208,48 != 0x525400aabbcc drop",
		"icmpv6 type nd-neighbor-advert @th,192,16 0x0201 @th,208,48 != 0x525400aabbcc drop",
	)
}

// TestRender_GuardExclusions (review C4): addresses excluded from a subnet
// allowance are dropped ahead of it, for IP and for ARP.
func TestRender_GuardExclusions(t *testing.T) {
	g := chainBody(t, nicPart(t, guardedPlan(&NICGuard{MAC: "52:54:00:aa:bb:cc",
		V4: []string{"10.1.0.0/24"}, ExcludeV4: []string{"10.1.0.1", "10.1.0.7"}})), "guard_vnet3")
	mustContainAll(t, g, "arp saddr ip { 10.1.0.1, 10.1.0.7 } drop", "ip saddr { 10.1.0.1, 10.1.0.7 } drop")
	if strings.Index(g, "ip saddr { 10.1.0.1") > strings.Index(g, "ip saddr != { 10.1.0.0/24 } drop") {
		t.Errorf("exclusions must precede the subnet allowance:\n%s", g)
	}
}

// TestParseWouldDrops reads observe counters from nft's JSON.
func TestParseWouldDrops(t *testing.T) {
	js := `{"nftables":[{"metainfo":{}},{"rule":{"family":"bridge","chain":"nic_in_vnet1","comment":"lv-wd vnet1 in sg:g#0","expr":[{"counter":{"packets":3,"bytes":252}},{"return":null}]}},{"rule":{"comment":"other","expr":[]}}]}`
	got, err := parseWouldDrops([]byte(js))
	if err != nil || len(got) != 1 || got[0].Device != "vnet1" || got[0].Side != "in" || got[0].Rule != "sg:g#0" || got[0].Packets != 3 {
		t.Fatalf("parseWouldDrops = %+v, %v", got, err)
	}
}
