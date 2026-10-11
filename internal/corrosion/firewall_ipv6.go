package corrosion

// IPv6 firewall rules: the release feature firewall_ipv6
// (capabilities.FeatureFirewallIPv6).
//
// A security-group, cluster or host rule may name an IPv6 CIDR or the icmpv6
// protocol, and an ip set may hold IPv6 elements. They replicate in the
// statement shapes those tables always had, so every peer DECODES them — but a
// peer on a build that predates IPv6 rendering refuses the whole plan when
// one reaches its renderer, and stops applying its firewall until it is
// upgraded. So an IPv6 row is written only by the ...WithGrant writers, with
// a grant from the release-feature gate: the release token has latched (no
// such peer remains) and the use is recorded ahead of the row. An IPv4 row
// needs no grant, as on main; the writers without a grant refuse an IPv6 one.

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// ErrFirewallIPv6GateClosed is returned by a write of an IPv6 rule or ip-set
// element without a firewall_ipv6 grant.
var ErrFirewallIPv6GateClosed = errors.New("IPv6 firewall rules are written only through the release feature firewall_ipv6 " +
	"(the cluster upgrade must finish first: a host on an older build cannot render them and would stop applying its firewall)")

// isIPv6Proto reports whether proto is ICMPv6, which exists only in IPv6.
func isIPv6Proto(proto string) bool {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "icmpv6", "ipv6-icmp":
		return true
	}
	return false
}

func looksIPv6CIDR(cidr string) bool {
	cidr = strings.TrimSpace(cidr)
	return isIPv6CIDR(cidr) || (strings.Contains(cidr, ":") && !strings.HasPrefix(cidr, "@"))
}

// FirewallRuleFamily validates a rule naming cidr and proto as its writer
// does (firewallRuleFamily) and reports whether it is an IPv6 rule, whose
// write is the release feature firewall_ipv6: a caller refuses a malformed
// rule before it asks the release gate for anything.
func FirewallRuleFamily(cidr, proto string) (v6 bool, err error) {
	return firewallRuleFamily(cidr, proto)
}

// IPSetFamily is FirewallRuleFamily for an ip set's elements.
func IPSetFamily(cidrs []string) (v6 bool, err error) {
	return ipSetFamily(cidrs)
}

// firewallRuleFamily refuses a rule this build or an older peer could not
// render — an IPv6 CIDR that does not parse (it would stop every host's
// renderer), IPv4's icmp with an IPv6 CIDR, icmpv6 with an IPv4 CIDR — and
// reports whether the rule is IPv6.
func firewallRuleFamily(cidr, proto string) (v6 bool, err error) {
	cidr = strings.TrimSpace(cidr)
	v6cidr := looksIPv6CIDR(cidr)
	if v6cidr {
		if !validIPv6AddrOrPrefix(cidr) {
			return false, fmt.Errorf("%q is not an IPv6 address or prefix", cidr)
		}
		if strings.EqualFold(strings.TrimSpace(proto), "icmp") {
			return false, fmt.Errorf("proto icmp is IPv4-only and cannot match IPv6 CIDR %q; use icmpv6", cidr)
		}
	} else if cidr != "" && !strings.HasPrefix(cidr, "@") && isIPv6Proto(proto) {
		return false, fmt.Errorf("proto %s is IPv6-only and cannot match IPv4 CIDR %q", proto, cidr)
	}
	return v6cidr || isIPv6Proto(proto), nil
}

// ipSetFamily refuses an IPv6 ip-set element that does not parse, and reports
// whether the set holds one.
func ipSetFamily(cidrs []string) (v6 bool, err error) {
	for _, e := range cidrs {
		e = strings.TrimSpace(e)
		if !strings.Contains(e, ":") {
			continue
		}
		if !validIPv6AddrOrPrefix(e) {
			return false, fmt.Errorf("ip set element %q is not an IPv6 address or prefix", e)
		}
		v6 = true
	}
	return v6, nil
}

// noIPv6Grant is the error a writer returns for an IPv6 row its grant does
// not cover.
func noIPv6Grant(err error) error {
	return fmt.Errorf("%w (%v)", ErrFirewallIPv6GateClosed, err)
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
