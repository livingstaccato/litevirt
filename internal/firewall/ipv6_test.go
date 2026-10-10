package firewall

import (
	"strings"
	"testing"
)

// TestRender_IPv6CIDRRendersAsIP6: an IPv6 CIDR in a rule renders with the
// ip6 matcher (an `ip saddr <v6>` line would poison the whole atomic ruleset),
// on the side the direction says, and an IPv4 rule beside it is unchanged.
func TestRender_IPv6CIDRRendersAsIP6(t *testing.T) {
	out, err := Render(Plan{
		SecurityGroups: []SecurityGroup{{
			Name: "web",
			Rules: []Rule{
				{Direction: Ingress, Proto: "tcp", PortRange: "443", CIDR: "2001:db8::/32", Action: Accept},
				{Direction: Egress, Proto: "udp", PortRange: "53", CIDR: "2001:db8:53::1", Action: Accept},
				{Direction: Ingress, Proto: "tcp", PortRange: "443", CIDR: "192.168.0.0/16", Action: Accept},
			},
		}},
		NICs: []NICBinding{{NICDev: "tap0", VMName: "web-1", SecurityGroups: []string{"web"}}},
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContainAll(t, out,
		"oifname tap0 tcp dport 443 ip6 saddr 2001:db8::/32 accept",
		"iifname tap0 udp dport 53 ip6 daddr 2001:db8:53::1 return",
		"oifname tap0 tcp dport 443 ip saddr 192.168.0.0/16 accept",
	)
	if strings.Contains(out, "ip saddr 2001:") || strings.Contains(out, "ip daddr 2001:") {
		t.Errorf("an IPv6 CIDR was rendered with the IPv4 matcher:\n%s", out)
	}
}

// TestRender_ICMPv6Proto: icmpv6 (and its /etc/protocols name ipv6-icmp) is a
// protocol that matches IPv6 only; icmp stays IPv4's.
func TestRender_ICMPv6Proto(t *testing.T) {
	for _, proto := range []string{"icmpv6", "ipv6-icmp"} {
		out, err := Render(Plan{ClusterRules: []Rule{{Direction: Ingress, Proto: proto, Action: Accept}}})
		if err != nil {
			t.Fatalf("Render %s: %v", proto, err)
		}
		if !strings.Contains(out, "meta l4proto ipv6-icmp accept") {
			t.Errorf("proto %s: want `meta l4proto ipv6-icmp accept`:\n%s", proto, out)
		}
	}
	out, err := Render(Plan{ClusterRules: []Rule{{Direction: Ingress, Proto: "icmpv6", CIDR: "fd00::/8", Action: Drop}}})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "meta l4proto ipv6-icmp ip6 saddr fd00::/8 drop") {
		t.Errorf("icmpv6 with an IPv6 CIDR:\n%s", out)
	}
}

// TestRender_RefusesFamilyMismatch: icmp is IPv4 and icmpv6 is IPv6, so a rule
// that pairs either with the other family's CIDR can match nothing and nft
// refuses it outright. Refused at validation, never emitted.
func TestRender_RefusesFamilyMismatch(t *testing.T) {
	for _, r := range []Rule{
		{Direction: Ingress, Proto: "icmp", CIDR: "2001:db8::/32", Action: Accept},
		{Direction: Ingress, Proto: "icmpv6", CIDR: "10.0.0.0/8", Action: Accept},
		{Direction: Ingress, Proto: "tcp", CIDR: "2001:db8::/300", Action: Accept},
		{Direction: Ingress, Proto: "tcp", CIDR: "not-an-address:", Action: Accept},
	} {
		if _, err := Render(Plan{ClusterRules: []Rule{r}}); err == nil {
			t.Errorf("rule %+v rendered; want a validation error", r)
		}
	}
}

// TestRender_OtherProtoWithIPv6CIDR: a non-tcp/udp protocol paired with an
// IPv6 CIDR uses meta l4proto, because `ip protocol` next to `ip6 saddr`
// names two network protocols and nft refuses the line. The IPv4 form keeps
// the `ip protocol` it always rendered.
func TestRender_OtherProtoWithIPv6CIDR(t *testing.T) {
	out, err := Render(Plan{ClusterRules: []Rule{
		{Direction: Egress, Proto: "gre", CIDR: "2001:db8::/32", Action: Drop},
		{Direction: Egress, Proto: "gre", CIDR: "10.0.0.0/8", Action: Drop},
	}})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContainAll(t, out,
		"meta l4proto gre ip6 daddr 2001:db8::/32 drop",
		"ip protocol gre ip daddr 10.0.0.0/8 drop",
	)
}

// TestRender_IPv6IPSetSplitsByFamily: nft sets are typed, so a named list
// holding both families renders as the IPv4 set it always was plus an
// ipv6_addr companion <name>_v6, and a rule that references it matches
// either.
func TestRender_IPv6IPSetSplitsByFamily(t *testing.T) {
	out, err := Render(Plan{
		IPSets: []IPSet{{Name: "admins", CIDRs: []string{"10.0.0.0/8", "2001:db8::/32", "2001:db8:1::/48"}}},
		SecurityGroups: []SecurityGroup{{
			Name:  "ssh",
			Rules: []Rule{{Direction: Ingress, Proto: "tcp", PortRange: "22", CIDR: "@admins", Action: Accept}},
		}},
		NICs: []NICBinding{{NICDev: "tap0", VMName: "vm", SecurityGroups: []string{"ssh"}}},
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContainAll(t, out,
		"set admins {\n        type ipv4_addr\n        flags interval\n        elements = { 10.0.0.0/8 }",
		// The /48 sits inside the /32, and an interval set refuses the overlap.
		"set admins_v6 {\n        type ipv6_addr\n        flags interval\n        elements = { 2001:db8::/32 }",
		"oifname tap0 tcp dport 22 ip saddr @admins accept",
		"oifname tap0 tcp dport 22 ip6 saddr @admins_v6 accept",
	)
	if strings.Contains(out, "2001:db8:1::/48") {
		t.Errorf("a covered element was rendered into an interval set:\n%s", out)
	}
}

// TestRender_IPv4OnlySetUnchanged: a set with no IPv6 element renders
// byte-for-byte as before — no companion set, one rule line.
func TestRender_IPv4OnlySetUnchanged(t *testing.T) {
	out, err := Render(Plan{
		IPSets:       []IPSet{{Name: "office", CIDRs: []string{"10.0.0.0/8"}}},
		ClusterRules: []Rule{{Direction: Ingress, Proto: "tcp", PortRange: "22", CIDR: "@office", Action: Accept}},
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(out, "office_v6") || strings.Contains(out, "ip6 saddr") {
		t.Errorf("an IPv4-only set grew an IPv6 companion:\n%s", out)
	}
}

// TestRender_IPSetCompanionNameCollision: a declared set named like another
// set's IPv6 companion would make nft refuse the whole ruleset with "set
// exists", so it is caught at validation with both names in the error.
func TestRender_IPSetCompanionNameCollision(t *testing.T) {
	_, err := Render(Plan{IPSets: []IPSet{
		{Name: "a", CIDRs: []string{"2001:db8::/32"}},
		{Name: "a_v6", CIDRs: []string{"10.0.0.0/8"}},
	}})
	if err == nil || !strings.Contains(err.Error(), "a_v6") {
		t.Fatalf("want a collision error naming a_v6, got %v", err)
	}
}

// TestRender_IPSetFamilyOnlyRules: a set-referencing icmp rule cannot match an
// IPv6 address and an icmpv6 rule cannot match an IPv4 one, so each renders
// only the line for its own family.
func TestRender_IPSetFamilyOnlyRules(t *testing.T) {
	out, err := Render(Plan{
		IPSets: []IPSet{{Name: "mon", CIDRs: []string{"10.0.0.0/8", "fd00::/8"}}},
		ClusterRules: []Rule{
			{Direction: Ingress, Proto: "icmp", CIDR: "@mon", Action: Accept},
			{Direction: Ingress, Proto: "icmpv6", CIDR: "@mon", Action: Accept},
		},
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContainAll(t, out,
		"ip protocol icmp ip saddr @mon accept",
		"meta l4proto ipv6-icmp ip6 saddr @mon_v6 accept",
	)
	for _, bad := range []string{"ip protocol icmp ip6", "ipv6-icmp ip saddr"} {
		if strings.Contains(out, bad) {
			t.Errorf("rendered a cross-family line containing %q:\n%s", bad, out)
		}
	}
}

// The ICMPv6 a network needs is accepted link-scoped in the per-NIC table
// and as related traffic in inet forward, never by type to any address:
// TestRender_PreambleIsScoped.
