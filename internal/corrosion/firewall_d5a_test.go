package corrosion

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"unicode"

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

// D5a (0-F): firewall_tag_groups' data is present when this replica holds a
// group row or a firewall-tags row with a value, or a live rule of any tier
// whose cidr is a tag-group reference in any case — as an older entry daemon
// stores one verbatim. A removed row, an emptied one, or a tombstoned rule is
// not data.
//
// Mutations: probe only the group rows — a tags row or a tag rule is not
// found, red; ignore deleted_at on rules — the tombstoned rule counts, red;
// count an emptied row — red.
func TestFirewallTagGroupsDataPresent(t *testing.T) {
	ctx := context.Background()
	fresh := func() *Client {
		c := ipv6FWDB(t)
		openClusterPolicyGate(c)
		return c
	}
	present := func(c *Client) bool {
		t.Helper()
		ok, err := FirewallTagGroupsDataPresent(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	c := fresh()
	if present(c) {
		t.Fatal("an empty replica has data")
	}
	// Removed and emptied rows, unrelated policies and rules, and a
	// tombstoned tag rule are not data.
	mustExec(t, c, clusterPolicyUpsertSQL, FirewallTagGroupKeyPrefix+"web", "", "a", "t")
	mustExec(t, c, clusterPolicyUpsertSQL, FirewallTagsKeyPrefix+"vm/"+strings.Repeat("a", 32), "", "a", "t")
	mustExec(t, c, clusterPolicyUpsertSQL, "firewall_tag", "x", "a", "t")
	mustExec(t, c, clusterPolicyUpsertSQL, "firewall_tagz/x", "x", "a", "t")
	if err := InsertClusterFirewallRule(ctx, c, FirewallRule{ID: "v4", Direction: "ingress", Proto: "tcp", CIDR: "10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	mustExec(t, c, `INSERT INTO cluster_firewall_rules (id, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at, deleted_at)
		VALUES ('gone', 'ingress', 'tcp', '', 'tag:web', 'drop', 100, '', '', 't', 't', 't')`)
	if present(c) {
		t.Fatal("removed rows, other keys or a tombstoned rule counted as data")
	}

	for what, write := range map[string]func(c *Client){
		"group row": func(c *Client) {
			mustExec(t, c, clusterPolicyUpsertSQL, FirewallTagGroupKeyPrefix+"web", `{"match":{"role":"web"}}`, "a", "t")
		},
		"tags row": func(c *Client) {
			mustExec(t, c, clusterPolicyUpsertSQL, FirewallTagsKeyPrefix+"ct/"+strings.Repeat("b", 32), `{"tags":{"role":"web"}}`, "a", "t")
		},
		"unreadable group row": func(c *Client) {
			mustExec(t, c, clusterPolicyUpsertSQL, FirewallTagGroupKeyPrefix+"Bad", `{`, "a", "t")
		},
		"cluster rule": func(c *Client) {
			mustExec(t, c, `INSERT INTO cluster_firewall_rules (id, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
				VALUES ('c', 'ingress', 'tcp', '', 'tag:web', 'accept', 100, '', '', 't', 't')`)
		},
		"host rule, upper case": func(c *Client) {
			mustExec(t, c, `INSERT INTO host_firewall_rules (id, host_name, direction, proto, port_range, cidr, action, priority, comment, created_at, updated_at)
				VALUES ('h', 'node-0', 'ingress', 'tcp', '', 'TAG:Web', 'drop', 100, '', 't', 't')`)
		},
		"cluster rule, after a newline (m-3)": func(c *Client) {
			mustExec(t, c, `INSERT INTO cluster_firewall_rules (id, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
				VALUES ('c', 'ingress', 'tcp', '', char(10, 13, 11, 12) || 'tag:web', 'drop', 100, '', '', 't', 't')`)
		},
		// strings.TrimSpace takes Unicode white space too (D5a re-review m-c).
		"cluster rule, after U+0085 and U+00A0": func(c *Client) {
			mustExec(t, c, `INSERT INTO cluster_firewall_rules (id, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
				VALUES ('c', 'ingress', 'tcp', '', char(133, 160) || 'tag:web', 'drop', 100, '', '', 't', 't')`)
		},
		"sg rule, after U+3000 and U+2028": func(c *Client) {
			mustExec(t, c, `INSERT INTO sg_rules (id, sg_id, direction, proto, port_range, cidr, action, priority, created_at, updated_at)
				VALUES ('s', 'sg', 'ingress', 'tcp', '', char(12288, 8232) || 'tag:web', 'drop', 100, 't', 't')`)
		},
		"sg rule, padded": func(c *Client) {
			mustExec(t, c, `INSERT INTO sg_rules (id, sg_id, direction, proto, port_range, cidr, action, priority, created_at, updated_at)
				VALUES ('s', 'sg', 'ingress', 'tcp', '', ' tag:web', 'drop', 100, 't', 't')`)
		},
	} {
		c := fresh()
		write(c)
		if !present(c) {
			t.Errorf("%s: not found", what)
		}
	}
}

// The probe trims what strings.TrimSpace trims, so it sees every cidr the
// loader's tagRef reads as a tag-group reference (D5a re-review m-c).
func TestTagCIDRTrimSet_IsUnicodeSpace(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if unicode.IsSpace(r) != strings.ContainsRune(tagCIDRTrimSet, r) {
			t.Errorf("U+%04X: unicode.IsSpace %v, in the trim set %v", r, unicode.IsSpace(r), !unicode.IsSpace(r))
		}
	}
}

// D5a review m-4: FirewallRuleFamily validates as the writers do: a
// tag-group cidr is not IPv6, and a malformed tag: form is refused, as
// firewallRowFeatures refuses it.
//
// Mutation: FirewallRuleFamily calls firewallRuleFamily alone — tag:a:b
// returns no error, red.
func TestFirewallRuleFamily_TagForms(t *testing.T) {
	if v6, err := FirewallRuleFamily("tag:web", "tcp"); v6 || err != nil {
		t.Errorf("tag:web = %v, %v; want not IPv6", v6, err)
	}
	for _, cidr := range []string{"tag:a:b", "TAG:web", "tag:web-1"} {
		if _, err := FirewallRuleFamily(cidr, "tcp"); err == nil || !strings.Contains(err.Error(), "not a tag-group cidr") {
			t.Errorf("%s: %v, want refused as a tag-group cidr", cidr, err)
		}
	}
	if v6, err := FirewallRuleFamily("2001:db8::/32", "tcp"); !v6 || err != nil {
		t.Errorf("2001:db8::/32 = %v, %v; want IPv6", v6, err)
	}
}
