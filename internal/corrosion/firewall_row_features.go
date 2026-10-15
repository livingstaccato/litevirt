package corrosion

// The release features a firewall rule row's data needs. A rule row may need
// several at once — an IPv6 rule that logs (firewall_ipv6 and firewall_log),
// or one matching a tag group (firewall_tag_groups) — and its writer takes one
// grant per feature, checking each the row needs (capabilities DECISION 0-E).
// Every value below rides the INSERT shapes the rule tables always had.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// logActionSuffix marks a stored rule action as logged ("drop+log"). Only the
// server's own writers produce it; API readers see the plain verdict plus a
// log flag.
const logActionSuffix = "+log"

// tagCIDRPrefix marks a rule cidr matching a tag group's member addresses
// ("tag:<name>").
const tagCIDRPrefix = "tag:"

// ErrFirewallLogGateClosed is returned by a write of a logged rule without a
// firewall_log grant.
var ErrFirewallLogGateClosed = errors.New("logged firewall rules are written only through the release feature firewall_log " +
	"(the cluster upgrade must finish first: a host on an older build cannot render them and would stop applying its firewall)")

// ErrFirewallTagGroupsGateClosed is returned by a write of a rule matching a
// tag group without a firewall_tag_groups grant.
var ErrFirewallTagGroupsGateClosed = errors.New("firewall rules matching a tag group are written only through the release feature firewall_tag_groups " +
	"(the cluster upgrade must finish first: a host on an older build cannot render them and would stop applying its firewall)")

// isLoggedAction reports whether a stored rule action carries the log suffix.
func isLoggedAction(action string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(action)), logActionSuffix)
}

// isTagCIDR reports whether cidr is exactly one tag-group reference,
// "tag:<name>" with a name holding no ':', space, ',' or brace. Anything else
// is judged as an address (and an IPv6-looking one must parse as one).
func isTagCIDR(cidr string) bool {
	cidr = strings.TrimSpace(cidr)
	if !strings.HasPrefix(cidr, tagCIDRPrefix) {
		return false
	}
	name := cidr[len(tagCIDRPrefix):]
	return name != "" && !strings.ContainsAny(name, ": \t,{}")
}

// FirewallRowFeatures validates a rule naming cidr, proto and action as its
// writer does, and returns the release features its write needs, in the
// order their gates nest: firewall_ipv6, then firewall_log, then
// firewall_tag_groups. A caller refuses a malformed rule before it asks any
// gate for anything.
func FirewallRowFeatures(cidr, proto, action string) ([]capabilities.Feature, error) {
	return firewallRowFeatures(cidr, proto, action)
}

func firewallRowFeatures(cidr, proto, action string) ([]capabilities.Feature, error) {
	var out []capabilities.Feature
	tag := isTagCIDR(cidr)
	if !tag {
		v6, err := firewallRuleFamily(cidr, proto)
		if err != nil {
			return nil, err
		}
		if v6 {
			out = append(out, capabilities.FeatureFirewallIPv6)
		}
	}
	if isLoggedAction(action) {
		out = append(out, capabilities.FeatureFirewallLog)
	}
	if tag {
		out = append(out, capabilities.FeatureFirewallTagGroups)
	}
	return out, nil
}

// noLogGrant is the error a writer returns for a logged rule its gLog grant
// does not cover.
func noLogGrant(err error) error {
	return fmt.Errorf("%w (%v)", ErrFirewallLogGateClosed, err)
}

// noTagGrant is the error a writer returns for a tag-group rule its gTag grant
// does not cover.
func noTagGrant(err error) error {
	return fmt.Errorf("%w (%v)", ErrFirewallTagGroupsGateClosed, err)
}
