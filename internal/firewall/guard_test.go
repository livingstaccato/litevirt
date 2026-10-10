package firewall

import (
	"strings"
	"testing"
)

func guardedPlan(g *NICGuard) Plan {
	return Plan{NICs: []NICBinding{{NICDev: "vnet3", VMName: "web-1", Guard: g}}}
}

// TestRender_NoGuardNoBridgeTable: a plan without a guarded NIC renders no
// bridge table at all, so hosts that guard nothing load exactly what they
// loaded before this feature.
func TestRender_NoGuardNoBridgeTable(t *testing.T) {
	out, err := Render(Plan{NICs: []NICBinding{{NICDev: "vnet3", VMName: "web-1"}}})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(out, "table bridge") {
		t.Errorf("an unguarded plan rendered a bridge table:\n%s", out)
	}
}

// TestRender_GuardMACAndIPv4: a guarded NIC gets a bridge-family chain hooked
// at prerouting, so it sees every frame the guest sends — to another guest on
// the same bridge, to the uplink and to the host — before anything else. It
// drops a foreign source MAC, guest-tagged VLAN frames (their payload cannot be
// checked), ARP that claims another MAC or IP, and IPv4 from any address it
// was not given, while still letting a DHCP client ask for one.
func TestRender_GuardMACAndIPv4(t *testing.T) {
	out, err := Render(guardedPlan(&NICGuard{MAC: "52:54:00:AA:BB:CC", V4: []string{"10.0.0.5"}}))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContainAll(t, out,
		"table bridge litevirt-nic {",
		"chain prerouting {",
		"type filter hook prerouting priority -300; policy accept;",
		"iifname vnet3 jump guard_vnet3",
		"chain guard_vnet3 {",
		"ether saddr != 52:54:00:aa:bb:cc drop",
		"ether type { 8021q, 8021ad } drop",
		"arp saddr ether != 52:54:00:aa:bb:cc drop",
		"arp saddr ip != { 0.0.0.0, 10.0.0.5 } drop",
		"ip saddr 0.0.0.0 ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept",
		"ip saddr != { 10.0.0.5 } drop",
	)
	// The DHCP-discover accept must come before the source check, or a guest
	// with no address yet can never get one.
	if strings.Index(out, "udp dport 67 accept") > strings.Index(out, "ip saddr != { 10.0.0.5 } drop") {
		t.Errorf("DHCP discover accept must precede the IPv4 source drop:\n%s", out)
	}
	// IPv6 is not restricted when no IPv6 address space is known.
	if strings.Contains(out, "ip6 saddr !=") {
		t.Errorf("IPv6 restricted with nothing known about it:\n%s", out)
	}
}

// TestRender_GuardDHCPAndRAServers: by default a guarded guest may not answer
// DHCP (v4 or v6) or advertise itself as a router, and its redirects are
// dropped too; each is allowed only when asked for.
func TestRender_GuardDHCPAndRAServers(t *testing.T) {
	out, err := Render(guardedPlan(&NICGuard{MAC: "52:54:00:aa:bb:cc", V4: []string{"10.0.0.5"}}))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	g := chainBody(t, out, "guard_vnet3")
	mustContainAll(t, g,
		"ether type ip udp sport 67 drop",
		"ether type ip6 udp sport 547 drop",
		"icmpv6 type { nd-router-advert, nd-redirect } drop",
	)
	// Both drops must precede the DHCP-client accept, so the accept can never
	// let a server reply through.
	if strings.Index(g, "udp sport 67 drop") > strings.Index(g, "udp sport 68 udp dport 67 accept") {
		t.Errorf("DHCP server drop must come first:\n%s", g)
	}

	out, err = Render(guardedPlan(&NICGuard{MAC: "52:54:00:aa:bb:cc", AllowDHCPServer: true, AllowRouterAdvert: true}))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	g = chainBody(t, out, "guard_vnet3")
	for _, s := range []string{"udp sport 67 drop", "udp sport 547 drop", "nd-router-advert"} {
		if strings.Contains(g, s) {
			t.Errorf("allowed guard still renders %q:\n%s", s, g)
		}
	}
}

// TestRender_GuardIPv6AndNDP: with IPv6 restricted the guest may send from its
// addresses, any link-local address and the unspecified address (duplicate
// address detection), and a neighbour advertisement may only claim one of
// those — the IPv6 analogue of ARP spoofing.
func TestRender_GuardIPv6AndNDP(t *testing.T) {
	out, err := Render(guardedPlan(&NICGuard{MAC: "52:54:00:aa:bb:cc", V6: []string{"2001:db8::5", "2001:db8:1::/64"}}))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContainAll(t, out,
		"ip6 saddr != { 2001:db8:1::/64, 2001:db8::5, ::, fe80::/10 } drop",
		"icmpv6 type nd-neighbor-advert icmpv6 taddr != { 2001:db8:1::/64, 2001:db8::5, fe80::/10 } drop",
	)
	if strings.Contains(out, "arp saddr ip !=") || strings.Contains(out, "ip saddr != {") {
		t.Errorf("IPv4 restricted with nothing known about it:\n%s", out)
	}
}

// TestRender_GuardOverlappingAllowed: an anonymous interval set refuses
// overlapping elements, which would take the whole ruleset down; a covered
// element is dropped instead.
func TestRender_GuardOverlappingAllowed(t *testing.T) {
	out, err := Render(guardedPlan(&NICGuard{MAC: "52:54:00:aa:bb:cc", V4: []string{"10.0.0.5", "10.0.0.0/24", "10.0.0.5/32"}}))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "ip saddr != { 10.0.0.0/24 } drop") {
		t.Errorf("overlap not collapsed:\n%s", out)
	}
}

// TestRender_GuardValidation: a malformed MAC or address would poison the
// atomic ruleset, so it is refused.
func TestRender_GuardValidation(t *testing.T) {
	for _, g := range []*NICGuard{
		{MAC: ""},
		{MAC: "not-a-mac"},
		{MAC: "52:54:00:aa:bb:cc", V4: []string{"2001:db8::1"}},
		{MAC: "52:54:00:aa:bb:cc", V6: []string{"10.0.0.1"}},
		{MAC: "52:54:00:aa:bb:cc", V4: []string{"10.0.0.1; drop"}},
	} {
		if _, err := Render(guardedPlan(g)); err == nil {
			t.Errorf("guard %+v rendered; want a validation error", g)
		}
	}
}

// TestRender_GuardDeterministic: two NICs in either order render the same
// bytes, so the applier's change cache keeps working.
func TestRender_GuardDeterministic(t *testing.T) {
	a := NICBinding{NICDev: "vnet1", Guard: &NICGuard{MAC: "52:54:00:00:00:01", V4: []string{"10.0.0.1"}}}
	b := NICBinding{NICDev: "vnet2", Guard: &NICGuard{MAC: "52:54:00:00:00:02", V4: []string{"10.0.0.2"}}}
	x, err := Render(Plan{NICs: []NICBinding{a, b}})
	if err != nil {
		t.Fatal(err)
	}
	y, err := Render(Plan{NICs: []NICBinding{b, a}})
	if err != nil {
		t.Fatal(err)
	}
	if x != y {
		t.Errorf("render depends on NIC order:\n%s\n---\n%s", x, y)
	}
}
