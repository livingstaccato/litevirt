package corrosion

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

func ipv6FWDB(t *testing.T) *Client {
	t.Helper()
	c := NewTestClientT(t)
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := InsertSecurityGroup(context.Background(), c, SecurityGroup{ID: "sg", Name: "sg"}); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestIPv6FirewallWrites_NeedAFirewallIPv6Grant: an IPv6 rule or ip-set
// element makes a peer on an older build refuse its whole firewall plan, so
// it is the release feature firewall_ipv6: every writer refuses one without
// that feature's grant (none, or another feature's), and writes it with one.
// The IPv4 forms need no grant, as on main.
func TestIPv6FirewallWrites_NeedAFirewallIPv6Grant(t *testing.T) {
	ctx := context.Background()
	c := ipv6FWDB(t)
	writes := func(g capabilities.FeatureGrant, id string) map[string]func() error {
		return map[string]func() error{
			"sg rule v6 cidr": func() error {
				return InsertSGRuleWithGrant(ctx, c, g, SGRule{ID: id + "r1", SGID: "sg", Direction: "ingress", Proto: "tcp", CIDR: "2001:db8::/32"})
			},
			"sg rule icmpv6": func() error {
				return InsertSGRuleWithGrant(ctx, c, g, SGRule{ID: id + "r2", SGID: "sg", Direction: "ingress", Proto: "icmpv6"})
			},
			"cluster rule v6": func() error {
				return InsertClusterFirewallRuleWithGrant(ctx, c, g, FirewallRule{ID: id + "c1", Direction: "ingress", CIDR: "fd00::/8"})
			},
			"host rule v6": func() error {
				return InsertHostFirewallRuleWithGrant(ctx, c, g, FirewallRule{ID: id + "h1", HostName: "h", Direction: "egress", CIDR: "::/0"})
			},
			"ipset v6 element": func() error {
				return InsertIPSetWithGrant(ctx, c, g, IPSet{ID: id + "s1", Name: id + "s", CIDRs: []string{"10.0.0.0/8", "2001:db8::/32"}})
			},
		}
	}
	for _, g := range []capabilities.FeatureGrant{{}, capabilities.GrantForTest(t, capabilities.FeatureNICGuards)} {
		for name, w := range writes(g, "no") {
			if err := w(); !errors.Is(err, ErrFirewallIPv6GateClosed) {
				t.Errorf("%s with grant %q: %v, want ErrFirewallIPv6GateClosed", name, g.Feature(), err)
			}
		}
	}
	if err := InsertSGRule(ctx, c, SGRule{ID: "v4", SGID: "sg", Direction: "ingress", Proto: "tcp", CIDR: "10.0.0.0/8"}); err != nil {
		t.Errorf("an IPv4 rule with no grant: %v", err)
	}
	if err := InsertIPSet(ctx, c, IPSet{ID: "v4s", Name: "v4s", CIDRs: []string{"10.0.0.0/8"}}); err != nil {
		t.Errorf("an IPv4 ip set with no grant: %v", err)
	}
	for name, w := range writes(capabilities.GrantForTest(t, capabilities.FeatureFirewallIPv6), "ok") {
		if err := w(); err != nil {
			t.Errorf("%s with a firewall_ipv6 grant: %v", name, err)
		}
	}
}

// TestIPv6FirewallWrites_MalformedRefused: even with a grant a malformed IPv6
// value, or a family mismatch, is refused — written, it would stop every
// host's renderer.
func TestIPv6FirewallWrites_MalformedRefused(t *testing.T) {
	ctx := context.Background()
	c := ipv6FWDB(t)
	g := capabilities.GrantForTest(t, capabilities.FeatureFirewallIPv6)
	for name, err := range map[string]error{
		"bad v6 prefix": InsertSGRuleWithGrant(ctx, c, g, SGRule{ID: "a", SGID: "sg", Direction: "ingress", CIDR: "2001:db8::/129"}),
		"zoned":         InsertSGRuleWithGrant(ctx, c, g, SGRule{ID: "b", SGID: "sg", Direction: "ingress", CIDR: "fe80::1%eth0"}),
		"icmp with v6":  InsertClusterFirewallRuleWithGrant(ctx, c, g, FirewallRule{ID: "c", Direction: "ingress", Proto: "icmp", CIDR: "2001:db8::/32"}),
		"icmpv6 with v4": InsertClusterFirewallRuleWithGrant(ctx, c, g, FirewallRule{ID: "d", Direction: "ingress", Proto: "icmpv6",
			CIDR: "10.0.0.0/8"}),
		"bad set element": InsertIPSetWithGrant(ctx, c, g, IPSet{ID: "e", Name: "e", CIDRs: []string{"2001:zz::/32"}}),
	} {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
