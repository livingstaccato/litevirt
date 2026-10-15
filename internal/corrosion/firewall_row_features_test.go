package corrosion

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// FirewallRowFeatures names every release feature a rule row needs, in the
// order the gates nest; a tag reference is not judged as an IPv6 address, and
// anything that only looks like one is.
func TestFirewallRowFeatures(t *testing.T) {
	v6, lg, tg := capabilities.FeatureFirewallIPv6, capabilities.FeatureFirewallLog, capabilities.FeatureFirewallTagGroups
	for _, tc := range []struct {
		cidr, proto, action string
		want                []capabilities.Feature
		bad                 bool
	}{
		{"10.0.0.0/8", "tcp", "accept", nil, false},
		{"", "all", "", nil, false},
		{"2001:db8::/32", "tcp", "drop", []capabilities.Feature{v6}, false},
		{"10.0.0.0/8", "tcp", "drop+log", []capabilities.Feature{lg}, false},
		{"2001:db8::/32", "tcp", "DROP+LOG", []capabilities.Feature{v6, lg}, false},
		{"tag:web", "tcp", "accept", []capabilities.Feature{tg}, false},
		{"tag:web", "tcp", "reject+log", []capabilities.Feature{lg, tg}, false},
		{"tag:", "tcp", "accept", nil, true},
		{"tag:a:b", "tcp", "accept", nil, true},
		{"2001:db8::/129", "tcp", "accept", nil, true},
	} {
		got, err := FirewallRowFeatures(tc.cidr, tc.proto, tc.action)
		if tc.bad {
			if err == nil {
				t.Errorf("%q/%q/%q: accepted as %v, want refused", tc.cidr, tc.proto, tc.action, got)
			}
			continue
		}
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("%q/%q/%q = %v, %v; want %v", tc.cidr, tc.proto, tc.action, got, err, tc.want)
		}
	}
}

// Each grant alone (capabilities DECISION 0-E, review I-4): every rule writer
// refuses a row needing a feature its own grant for that feature does not
// cover — a logged row with only the IPv6 grant, an IPv6 row with only the log
// grant, a tag row with both of those — and writes the row once every feature
// it needs has its grant.
//
// Mutations: check the log feature against g (the IPv6 grant) — the
// IPv6-only row with only gLog is written and goes red; drop the tag check —
// the tag row with no gTag is written and goes red; check any one grant for
// any feature — red.
func TestFirewallRuleWriters_EachFeatureNeedsItsOwnGrant(t *testing.T) {
	ctx := context.Background()
	c := ipv6FWDB(t)
	gV6 := capabilities.GrantForTest(t, capabilities.FeatureFirewallIPv6)
	gLog := capabilities.GrantForTest(t, capabilities.FeatureFirewallLog)
	gTag := capabilities.GrantForTest(t, capabilities.FeatureFirewallTagGroups)
	none := capabilities.FeatureGrant{}
	n := 0
	writers := map[string]func(g, gl, gt capabilities.FeatureGrant, cidr, action string) error{
		"sg": func(g, gl, gt capabilities.FeatureGrant, cidr, action string) error {
			n++
			return InsertSGRuleWithGrant(ctx, c, g, gl, gt, SGRule{ID: fmt.Sprint("s", n), SGID: "sg", Direction: "ingress", Proto: "tcp", CIDR: cidr, Action: action})
		},
		"cluster": func(g, gl, gt capabilities.FeatureGrant, cidr, action string) error {
			n++
			return InsertClusterFirewallRuleWithGrant(ctx, c, g, gl, gt, FirewallRule{ID: fmt.Sprint("c", n), Direction: "ingress", Proto: "tcp", CIDR: cidr, Action: action})
		},
		"host": func(g, gl, gt capabilities.FeatureGrant, cidr, action string) error {
			n++
			return InsertHostFirewallRuleWithGrant(ctx, c, g, gl, gt, FirewallRule{ID: fmt.Sprint("h", n), HostName: "h", Direction: "ingress", Proto: "tcp", CIDR: cidr, Action: action})
		},
	}
	for name, w := range writers {
		refused := []struct {
			what         string
			g, gl, gt    capabilities.FeatureGrant
			cidr, action string
			want         error
		}{
			{"logged row, only the IPv6 grant", gV6, none, none, "10.0.0.0/8", "drop+log", ErrFirewallLogGateClosed},
			{"IPv6 logged row, only the IPv6 grant", gV6, none, none, "2001:db8::/32", "drop+log", ErrFirewallLogGateClosed},
			{"IPv6 row, only the log grant", none, gLog, none, "2001:db8::/32", "drop", ErrFirewallIPv6GateClosed},
			{"IPv6 row, the log grant in the IPv6 slot", gLog, gLog, none, "2001:db8::/32", "drop", ErrFirewallIPv6GateClosed},
			{"logged row, the IPv6 grant in the log slot", none, gV6, none, "10.0.0.0/8", "drop+log", ErrFirewallLogGateClosed},
			{"tag row, the IPv6 and log grants", gV6, gLog, none, "tag:web", "accept", ErrFirewallTagGroupsGateClosed},
			{"tag row, the log grant in the tag slot", none, none, gLog, "tag:web", "accept", ErrFirewallTagGroupsGateClosed},
		}
		for _, r := range refused {
			if err := w(r.g, r.gl, r.gt, r.cidr, r.action); !errors.Is(err, r.want) {
				t.Errorf("%s: %s: %v, want %v", name, r.what, err, r.want)
			}
		}
		for _, ok := range []struct {
			what         string
			g, gl, gt    capabilities.FeatureGrant
			cidr, action string
		}{
			{"IPv4 row, no grant", none, none, none, "10.0.0.0/8", "accept"},
			{"logged row, the log grant", none, gLog, none, "10.0.0.0/8", "drop+log"},
			{"IPv6 logged row, both grants", gV6, gLog, none, "2001:db8::/32", "drop+log"},
			{"tag row, the tag grant", none, none, gTag, "tag:web", "accept"},
		} {
			if err := w(ok.g, ok.gl, ok.gt, ok.cidr, ok.action); err != nil {
				t.Errorf("%s: %s: %v", name, ok.what, err)
			}
		}
	}
}
