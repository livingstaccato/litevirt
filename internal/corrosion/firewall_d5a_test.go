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

// D5a (m-9): a tag-group cidr is its own form, never judged as an IPv6 CIDR,
// in any case; anything else holding ':' still is.
//
// Mutation: drop the tag-prefix exclusion from looksIPv6CIDR — tag:web looks
// IPv6, red.
func TestLooksIPv6CIDR_TagIsNotIPv6(t *testing.T) {
	for cidr, want := range map[string]bool{
		"tag:web": false, "TAG:web": false, " tag:db_2": false, "tag:a:b": false,
		"2001:db8::/32": true, "::1": true, "fe80::1%eth0": true, "x:y": true, "@set": false, "10.0.0.0/8": false,
	} {
		if got := looksIPv6CIDR(cidr); got != want {
			t.Errorf("looksIPv6CIDR(%q) = %v, want %v", cidr, got, want)
		}
	}
	// A malformed tag form is still refused by the classifier, as its own
	// form rather than as an address.
	for _, cidr := range []string{"tag:a:b", "TAG:web", "tag:Web", "tag:web-1"} {
		if _, err := firewallRowFeatures(cidr, "tcp", "accept"); err == nil || !strings.Contains(err.Error(), "not a tag-group cidr") {
			t.Errorf("firewallRowFeatures(%q) = %v, want refused as a tag-group cidr", cidr, err)
		}
	}
}

// D5a: on this build (its own rulefield extensions, no test stand-in) every
// rule writer takes a tag-group cidr only with the firewall_tag_groups grant,
// and a client's tag cidr is classified, not refused as unsupported.
//
// Mutations: leave rulefield's TagCIDR nil — the row with gTag is refused by
// the grammar, red; drop the gTag check from a writer — the row without it
// is written, red; keep the client tag refusal — FirewallRowFeatures refuses
// tag:web, red.
func TestTagRule_NeedsTagGrant(t *testing.T) {
	ctx := context.Background()
	c := ipv6FWDB(t)
	gV6 := capabilities.GrantForTest(t, capabilities.FeatureFirewallIPv6)
	gTag := capabilities.GrantForTest(t, capabilities.FeatureFirewallTagGroups)
	none := capabilities.FeatureGrant{}
	n := 0
	writers := map[string]func(g, gt capabilities.FeatureGrant, cidr string) error{
		"sg": func(g, gt capabilities.FeatureGrant, cidr string) error {
			n++
			return InsertSGRuleWithGrant(ctx, c, g, none, gt, SGRule{ID: fmt.Sprint("s", n), SGID: "sg", Direction: "ingress", Proto: "tcp", CIDR: cidr, Action: "drop"})
		},
		"cluster": func(g, gt capabilities.FeatureGrant, cidr string) error {
			n++
			return InsertClusterFirewallRuleWithGrant(ctx, c, g, none, gt, FirewallRule{ID: fmt.Sprint("c", n), Direction: "ingress", Proto: "tcp", CIDR: cidr, Action: "accept"})
		},
		"host": func(g, gt capabilities.FeatureGrant, cidr string) error {
			n++
			return InsertHostFirewallRuleWithGrant(ctx, c, g, none, gt, FirewallRule{ID: fmt.Sprint("h", n), HostName: "h", Direction: "ingress", Proto: "tcp", CIDR: cidr, Action: "accept"})
		},
	}
	for name, w := range writers {
		if err := w(gV6, none, "tag:web"); !errors.Is(err, ErrFirewallTagGroupsGateClosed) {
			t.Errorf("%s: tag:web without gTag: %v, want ErrFirewallTagGroupsGateClosed", name, err)
		}
		if err := w(none, gTag, "tag:web"); err != nil {
			t.Errorf("%s: tag:web with gTag: %v", name, err)
		}
		// m-C: a tag group's set, or any lv_* set, is never referenced
		// directly, whatever the grants.
		for _, cidr := range []string{"@lv_tg_web", "!= @lv_tg_web", "@lv_tg_web_v6", "@lv_gw4", "!= @lv_office"} {
			var fe *rulefield.FieldError
			if err := w(gV6, gTag, cidr); !errors.As(err, &fe) {
				t.Errorf("%s: %s: %v, want a field-grammar refusal", name, cidr, err)
			}
		}
	}
	got, err := FirewallRowFeatures("tag:web", "tcp", "drop")
	if err != nil || !slices.Equal(got, []capabilities.Feature{capabilities.FeatureFirewallTagGroups}) {
		t.Errorf("a client tag:web = %v, %v; want firewall_tag_groups", got, err)
	}
}

// D5a: an ip set named lv_* is refused by its writer, whatever the grant.
//
// Mutation: drop the reserved-prefix check from rulefield.SetName — red.
func TestInsertIPSet_RefusesReservedName(t *testing.T) {
	ctx := context.Background()
	c := ipv6FWDB(t)
	g := capabilities.GrantForTest(t, capabilities.FeatureFirewallIPv6)
	for _, name := range []string{"lv_gw4", "lv_tg_web", "lv_tg_web_v6", "lv_office"} {
		err := InsertIPSetWithGrant(ctx, c, g, IPSet{ID: name, Name: name, CIDRs: []string{"10.0.0.1"}})
		if err == nil || !strings.Contains(err.Error(), `"lv_"`) {
			t.Errorf("ip set %s: %v, want refused naming the reserved prefix", name, err)
		}
	}
	if err := InsertIPSetWithGrant(ctx, c, g, IPSet{ID: "o", Name: "office", CIDRs: []string{"10.0.0.1"}}); err != nil {
		t.Errorf("ip set office: %v", err)
	}
	if sets, err := ListIPSets(ctx, c); err != nil || len(sets) != 1 {
		t.Errorf("sets = %+v, %v; want office only", sets, err)
	}
}
