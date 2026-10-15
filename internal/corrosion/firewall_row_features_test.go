package corrosion

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/firewall/rulefield"
)

// firewallRowFeatures (the stored-row classifier the writers use) names every
// release feature a rule row needs, in the order the gates nest; a tag
// reference is not judged as an IPv6 address, and anything that only looks
// like one is.
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
		got, err := firewallRowFeatures(tc.cidr, tc.proto, tc.action)
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
			{"IPv6 row, only the log grant", none, gLog, none, "2001:db8::/32", "drop", ErrFirewallIPv6GateClosed},
			{"IPv6 row, the log grant in the IPv6 slot", gLog, gLog, none, "2001:db8::/32", "drop", ErrFirewallIPv6GateClosed},
		}
		for _, r := range refused {
			if err := w(r.g, r.gl, r.gt, r.cidr, r.action); !errors.Is(err, r.want) {
				t.Errorf("%s: %s: %v, want %v", name, r.what, err, r.want)
			}
		}
		// A logged action and a tag-group cidr fail the field grammar on this
		// build, whatever the grants: nothing renders them yet.
		for _, r := range []struct {
			what         string
			cidr, action string
		}{
			{"logged row", "10.0.0.0/8", "drop+log"},
			{"IPv6 logged row", "2001:db8::/32", "drop+log"},
			{"tag row", "tag:web", "accept"},
		} {
			var fe *rulefield.FieldError
			if err := w(gV6, gLog, gTag, r.cidr, r.action); !errors.As(err, &fe) {
				t.Errorf("%s: %s, every grant: %v, want a field-grammar refusal", name, r.what, err)
			}
		}
		for _, ok := range []struct {
			what         string
			g, gl, gt    capabilities.FeatureGrant
			cidr, action string
		}{
			{"IPv4 row, no grant", none, none, none, "10.0.0.0/8", "accept"},
			{"IPv6 row, the IPv6 grant", gV6, none, none, "2001:db8::/32", "drop"},
		} {
			if err := w(ok.g, ok.gl, ok.gt, ok.cidr, ok.action); err != nil {
				t.Errorf("%s: %s: %v", name, ok.what, err)
			}
		}
	}
}

// A client's rule (FirewallRowFeatures, the handler and stack entry) may not
// carry a "+" in its action, and may not name a tag-group cidr while this
// build renders none: either would be stored and make every host refuse its
// plan. Ordinary IPv4 and IPv6 rules pass as before.
//
// Mutations: drop the "+" refusal — drop+log is classified, red; drop the
// tag refusal — tag:web is classified, red.
func TestFirewallRowFeatures_RefusesClientLogAndTagForms(t *testing.T) {
	for _, tc := range []struct{ cidr, action string }{
		{"10.0.0.0/8", "drop+log"},
		{"10.0.0.0/8", "accept+"},
		{"2001:db8::/32", "REJECT+LOG"},
		{"tag:web", "accept"},
		{"tag:web", "drop"},
	} {
		got, err := FirewallRowFeatures(tc.cidr, "tcp", tc.action)
		if !errors.Is(err, ErrFirewallRuleFormUnsupported) || !strings.Contains(err.Error(), "not supported") {
			t.Errorf("client rule %q/%q = %v, %v; want ErrFirewallRuleFormUnsupported", tc.cidr, tc.action, got, err)
		}
	}
	if got, err := FirewallRowFeatures("2001:db8::/32", "tcp", "drop"); err != nil ||
		!slices.Equal(got, []capabilities.Feature{capabilities.FeatureFirewallIPv6}) {
		t.Errorf("a client IPv6 rule = %v, %v; want firewall_ipv6", got, err)
	}
	if got, err := FirewallRowFeatures("10.0.0.0/8", "tcp", "accept"); err != nil || len(got) != 0 {
		t.Errorf("a client IPv4 rule = %v, %v; want no feature", got, err)
	}
}
