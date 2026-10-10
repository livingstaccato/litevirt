package corrosion

// IPv6 firewall rules (firewall_ipv6_v1).
//
// A security-group, cluster or host rule may name an IPv6 CIDR or the icmpv6
// protocol, and an ip set may hold IPv6 elements. They replicate in the
// statement shapes those tables always had, so every peer DECODES them — but a
// peer on a build that predates IPv6 rendering refuses the whole plan when
// one reaches its renderer, and stops applying its firewall until it is
// upgraded. So none is written until firewall_ipv6_v1 has durably latched,
// which cannot happen while any replication recipient runs such a build.

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// ErrFirewallIPv6GateClosed is returned by a write of an IPv6 rule or ip-set
// element before firewall_ipv6_v1 has durably latched on this node.
var ErrFirewallIPv6GateClosed = errors.New("IPv6 firewall rules are not writable until firewall_ipv6_v1 has latched on every host " +
	"(a host on an older build cannot render them and would stop applying its firewall); upgrade every host first")

// SetFirewallIPv6Gate injects the predicate that permits writing IPv6
// firewall rules and ip-set elements, wired at daemon start to the durable
// firewall_ipv6_v1 latch. Nil-safe and FAIL CLOSED: an unset gate refuses
// every IPv6 write, which is what every earlier build did.
func (c *Client) SetFirewallIPv6Gate(fn func() bool) {
	if fn == nil {
		c.firewallIPv6Gate.Store(nil)
		return
	}
	c.firewallIPv6Gate.Store(&fn)
}

// MayWriteFirewallIPv6 reports whether this node may write IPv6 firewall
// rules (nil-safe, fail closed).
func (c *Client) MayWriteFirewallIPv6() bool {
	fn := c.firewallIPv6Gate.Load()
	return fn != nil && (*fn)()
}

// isIPv6Proto reports whether proto is ICMPv6, which exists only in IPv6.
func isIPv6Proto(proto string) bool {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "icmpv6", "ipv6-icmp":
		return true
	}
	return false
}

// checkFirewallRuleFamily refuses a rule this build or an older peer could not
// render. An IPv6 CIDR must parse (a malformed one would stop every host's
// renderer), must not be paired with IPv4's icmp, and — like icmpv6 — may only
// be written once the IPv6 gate is open. An IPv4 CIDR is left alone, as it
// always was, except that icmpv6 cannot match one.
func (c *Client) checkFirewallRuleFamily(cidr, proto string) error {
	cidr = strings.TrimSpace(cidr)
	v6 := isIPv6CIDR(cidr) || (strings.Contains(cidr, ":") && !strings.HasPrefix(cidr, "@"))
	if v6 {
		if !validIPv6AddrOrPrefix(cidr) {
			return fmt.Errorf("%q is not an IPv6 address or prefix", cidr)
		}
		if strings.EqualFold(strings.TrimSpace(proto), "icmp") {
			return fmt.Errorf("proto icmp is IPv4-only and cannot match IPv6 CIDR %q; use icmpv6", cidr)
		}
	} else if cidr != "" && !strings.HasPrefix(cidr, "@") && isIPv6Proto(proto) {
		return fmt.Errorf("proto %s is IPv6-only and cannot match IPv4 CIDR %q", proto, cidr)
	}
	if (v6 || isIPv6Proto(proto)) && !c.MayWriteFirewallIPv6() {
		return ErrFirewallIPv6GateClosed
	}
	return nil
}

// checkIPSetFamily refuses an IPv6 ip-set element that does not parse, and
// any IPv6 element while the gate is closed.
func (c *Client) checkIPSetFamily(cidrs []string) error {
	for _, e := range cidrs {
		e = strings.TrimSpace(e)
		if !strings.Contains(e, ":") {
			continue
		}
		if !validIPv6AddrOrPrefix(e) {
			return fmt.Errorf("ip set element %q is not an IPv6 address or prefix", e)
		}
		if !c.MayWriteFirewallIPv6() {
			return ErrFirewallIPv6GateClosed
		}
	}
	return nil
}

// validIPv6AddrOrPrefix reports whether s is an IPv6 address or prefix with
// no zone, the forms nft accepts in an ip6 match or an ipv6_addr set.
func validIPv6AddrOrPrefix(s string) bool {
	if p, err := netip.ParsePrefix(s); err == nil {
		return !p.Addr().Is4() && p.Addr().Zone() == ""
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return !a.Is4() && a.Zone() == ""
	}
	return false
}
