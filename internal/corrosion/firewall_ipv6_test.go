package corrosion

import (
	"context"
	"errors"
	"testing"
)

func ipv6FWDB(t *testing.T, open bool) *Client {
	t.Helper()
	c := NewTestClientT(t)
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if open {
		c.SetFirewallIPv6Gate(func() bool { return true })
	}
	if err := InsertSecurityGroup(context.Background(), c, SecurityGroup{ID: "sg", Name: "sg"}); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestIPv6FirewallWrites_GatedUntilLatch: an IPv6 rule or ip-set element makes
// a peer on an older build refuse its whole firewall plan, so every writer
// refuses one until firewall_ipv6_v1 has latched — and the IPv4 forms are
// unaffected either way.
func TestIPv6FirewallWrites_GatedUntilLatch(t *testing.T) {
	ctx := context.Background()
	c := ipv6FWDB(t, false)
	writes := map[string]func() error{
		"sg rule v6 cidr": func() error {
			return InsertSGRule(ctx, c, SGRule{ID: "r1", SGID: "sg", Direction: "ingress", Proto: "tcp", CIDR: "2001:db8::/32"})
		},
		"sg rule icmpv6": func() error {
			return InsertSGRule(ctx, c, SGRule{ID: "r2", SGID: "sg", Direction: "ingress", Proto: "icmpv6"})
		},
		"cluster rule v6": func() error {
			return InsertClusterFirewallRule(ctx, c, FirewallRule{ID: "c1", Direction: "ingress", CIDR: "fd00::/8"})
		},
		"host rule v6": func() error {
			return InsertHostFirewallRule(ctx, c, FirewallRule{ID: "h1", HostName: "h", Direction: "egress", CIDR: "::/0"})
		},
		"ipset v6 element": func() error {
			return InsertIPSet(ctx, c, IPSet{ID: "s1", Name: "s", CIDRs: []string{"10.0.0.0/8", "2001:db8::/32"}})
		},
	}
	for name, w := range writes {
		if err := w(); !errors.Is(err, ErrFirewallIPv6GateClosed) {
			t.Errorf("%s with the gate closed: %v, want ErrFirewallIPv6GateClosed", name, err)
		}
	}
	if err := InsertSGRule(ctx, c, SGRule{ID: "v4", SGID: "sg", Direction: "ingress", Proto: "tcp", CIDR: "10.0.0.0/8"}); err != nil {
		t.Errorf("IPv4 rule refused with the gate closed: %v", err)
	}

	c.SetFirewallIPv6Gate(func() bool { return true })
	for name, w := range writes {
		if err := w(); err != nil {
			t.Errorf("%s with the gate open: %v", name, err)
		}
	}
}

// TestIPv6FirewallWrites_MalformedRefused: with the gate open a malformed
// IPv6 value, or a family mismatch, is still refused — written, it would stop
// every host's renderer.
func TestIPv6FirewallWrites_MalformedRefused(t *testing.T) {
	ctx := context.Background()
	c := ipv6FWDB(t, true)
	for name, err := range map[string]error{
		"bad v6 prefix": InsertSGRule(ctx, c, SGRule{ID: "a", SGID: "sg", Direction: "ingress", CIDR: "2001:db8::/129"}),
		"zoned":         InsertSGRule(ctx, c, SGRule{ID: "b", SGID: "sg", Direction: "ingress", CIDR: "fe80::1%eth0"}),
		"icmp with v6":  InsertClusterFirewallRule(ctx, c, FirewallRule{ID: "c", Direction: "ingress", Proto: "icmp", CIDR: "2001:db8::/32"}),
		"icmpv6 with v4": InsertClusterFirewallRule(ctx, c, FirewallRule{ID: "d", Direction: "ingress", Proto: "icmpv6",
			CIDR: "10.0.0.0/8"}),
		"bad set element": InsertIPSet(ctx, c, IPSet{ID: "e", Name: "e", CIDRs: []string{"2001:zz::/32"}}),
	} {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestSetFirewallIPv6Gate_FailsClosedWhenUnset: an unwired client refuses.
func TestSetFirewallIPv6Gate_FailsClosedWhenUnset(t *testing.T) {
	c := NewTestClientT(t)
	if c.MayWriteFirewallIPv6() {
		t.Fatal("unwired gate is open")
	}
	c.SetFirewallIPv6Gate(func() bool { return true })
	if !c.MayWriteFirewallIPv6() {
		t.Fatal("wired open gate is closed")
	}
	c.SetFirewallIPv6Gate(nil)
	if c.MayWriteFirewallIPv6() {
		t.Fatal("cleared gate is open")
	}
}
