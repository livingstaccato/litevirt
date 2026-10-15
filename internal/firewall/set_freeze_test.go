package firewall

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall/rulefield"
)

// TestCollapseSetElements_MergesOverlappingIntervals (fw-grammar re-review 3
// N-1): nft refuses an interval set whose elements overlap or touch
// ("conflicting intervals specified", checked with nft -c 1.1.6 for every
// overlapping input below, in table inet and table bridge), and the whole
// ruleset with it. A set whose elements overlap renders them merged; any
// other set renders exactly as before.
//
// Mutation: skip the merge (return the collapsed elements as they are) —
// every overlapping case keeps both elements, red.
func TestCollapseSetElements_MergesOverlappingIntervals(t *testing.T) {
	for _, c := range []struct {
		name     string
		in, want []string
	}{
		// Unchanged: no two elements overlap once nested prefixes are dropped.
		{"disjoint", []string{"10.0.0.0/24", "10.1.0.1-10.1.0.9", " 10.2.0.0/16"}, []string{" 10.2.0.0/16", "10.0.0.0/24", "10.1.0.1-10.1.0.9"}},
		{"nested prefixes", []string{"10.1.0.0/16", "10.0.0.0/8", "172.16.0.1"}, []string{"10.0.0.0/8", "172.16.0.1"}},
		{"unmasked prefix covers an address", []string{"10.0.0.1/8", "10.0.0.5"}, []string{"10.0.0.1/8"}},
		{"adjacent", []string{"10.0.0.1-10.0.0.5", "10.0.0.6-10.0.0.9"}, []string{"10.0.0.1-10.0.0.5", "10.0.0.6-10.0.0.9"}},
		{"identical pieces", []string{"10.3.0.1,10.3.0.1"}, []string{"10.3.0.1,10.3.0.1"}},
		{"dns name", []string{"gw.example.com", "10.0.0.0/8"}, []string{"10.0.0.0/8", "gw.example.com"}},
		{"single-address range", []string{"10.0.0.1-10.0.0.1"}, []string{"10.0.0.1-10.0.0.1"}},
		// Merged.
		{"prefix and range inside it", []string{"10.0.0.0/8", "10.0.0.1-10.0.0.5"}, []string{"10.0.0.0/8"}},
		{"overlapping ranges", []string{"10.0.0.1-10.0.0.5", "10.0.0.3-10.0.0.9"}, []string{"10.0.0.1-10.0.0.9"}},
		{"touching ranges", []string{"10.0.0.1-10.0.0.5", "10.0.0.5-10.0.0.9"}, []string{"10.0.0.1-10.0.0.9"}},
		{"spaced range and an address", []string{"10.0.0.1 - 10.0.0.5", "10.0.0.3"}, []string{"10.0.0.1-10.0.0.5"}},
		{"range spelling of a prefix", []string{"10.0.0.0-10.255.255.255", "10.0.0.3"}, []string{"10.0.0.0/8"}},
		{"merge to an unaligned range", []string{"10.0.0.0/25", "10.0.0.100-10.0.0.200"}, []string{"10.0.0.0-10.0.0.200"}},
		{"merge to an aligned prefix", []string{"10.0.0.0-10.0.0.200", "10.0.0.128/25"}, []string{"10.0.0.0/24"}},
		{"inside a stored comma element", []string{"10.3.0.1-10.3.0.9, 10.3.0.0/24", "10.4.0.1"}, []string{"10.3.0.0/24", "10.4.0.1"}},
		{"dns name kept beside a merge", []string{"gw.example.com", "10.0.0.0/8", "10.0.0.1-10.0.0.9"}, []string{"10.0.0.0/8", "gw.example.com"}},
		{"ipv6 prefix and range", []string{"fd00::/8", "fd00::1-fd00::5"}, []string{"fd00::/8"}},
		{"ipv6 ranges", []string{"2001:db8::1-2001:db8::5", "2001:db8::3-2001:db8::9"}, []string{"2001:db8::1-2001:db8::9"}},
		{"everything", []string{"0.0.0.0-255.255.255.255", "10.0.0.0/8"}, []string{"0.0.0.0/0"}},
	} {
		if got := collapseSetElements(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: collapseSetElements(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

// TestRender_SameNameRowsMergingIntoAnOverlap: two rows of one name that are
// fine alone overlap once mergeIPSets unions them.
func TestRender_SameNameRowsMergingIntoAnOverlap(t *testing.T) {
	out := renderSetsOnly(t, []IPSet{
		{Name: "office", CIDRs: []string{"10.0.0.1-10.0.0.5"}},
		{Name: "office", CIDRs: []string{"10.0.0.3-10.0.0.9", "fd00::1"}},
		{Name: "office", CIDRs: []string{"fd00::/8"}},
	})
	for _, want := range []string{"elements = { 10.0.0.1-10.0.0.9 }", "elements = { fd00::/8 }"} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q:\n%s", want, out)
		}
	}
}

// freezeLoader is a loader over a database the caller fills with raw rows, as
// a peer replicates them.
func freezeLoader(t *testing.T) (*corrosion.Client, func() (Plan, string)) {
	t.Helper()
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	loader := CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{})
	return db, func() (Plan, string) {
		t.Helper()
		plan, err := loader(ctx)
		if err != nil {
			t.Fatalf("loader failed the pass: %v", err)
		}
		out, err := Render(plan)
		if err != nil {
			t.Fatalf("Render refused the plan: one row froze every host's firewall: %v", err)
		}
		return plan, out
	}
}

func rawSet(t *testing.T, db *corrosion.Client, id, name, cidrsJSON string) {
	t.Helper()
	rawRow(t, db, `INSERT INTO ip_sets (id, name, cidrs, stack_name, created_at, updated_at)
		VALUES (?, ?, ?, '', '2026-10-15T00:00:00Z', 1)`, id, name, cidrsJSON)
}

func rawClusterRule(t *testing.T, db *corrosion.Client, id, proto, port, cidr, action string) {
	t.Helper()
	rawRow(t, db, `INSERT INTO cluster_firewall_rules
		(id, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
		VALUES (?, 'ingress', ?, ?, ?, ?, 100, '', '', '2026-10-15T00:00:00Z', 1)`, id, proto, port, cidr, action)
}

func invalidRow(plan Plan, table, id string) (InvalidRow, bool) {
	for _, r := range plan.InvalidRows {
		if r.Table == table && r.ID == id {
			return r, true
		}
	}
	return InvalidRow{}, false
}

// TestLoader_CompanionClashLeavesOutTheCompanion (fw-grammar re-review 3
// N-2): a set named x_v6 beside a set x with IPv6 elements made validate
// refuse the whole plan, freezing every host. The row named x_v6 is left out
// and reported; x renders with its IPv6 companion, and a rule referencing
// x_v6 is left out (it would name the companion).
//
// Mutation: do not leave the colliding row out — Render refuses the plan, red.
func TestLoader_CompanionClashLeavesOutTheCompanion(t *testing.T) {
	db, load := freezeLoader(t)
	rawSet(t, db, "s-x", "x", `["10.0.0.0/8", "fd00::/8"]`)
	rawSet(t, db, "s-xv6", "x_v6", `["10.9.0.0/16"]`)
	// y holds no IPv6 element, so y_v6 is an ordinary set, as it always was.
	rawSet(t, db, "s-y", "y", `["10.1.0.0/16"]`)
	rawSet(t, db, "s-yv6", "y_v6", `["10.2.0.0/16"]`)
	rawClusterRule(t, db, "r-x", "tcp", "22", "@x", "accept")
	rawClusterRule(t, db, "r-xv6", "tcp", "23", "@x_v6", "drop")
	rawClusterRule(t, db, "r-yv6", "tcp", "24", "@y_v6", "drop")
	plan, out := load()
	r, ok := invalidRow(plan, "ip_sets", "s-xv6")
	if !ok || r.Handling != HandlingSetLeftOutCompanion {
		t.Fatalf("the x_v6 row is not reported as left out: %+v\n%v", r, plan.InvalidRows)
	}
	if _, ok := invalidRow(plan, "cluster_firewall_rules", "r-xv6"); !ok {
		t.Errorf("the rule on @x_v6 is not reported")
	}
	if strings.Count(out, "set x_v6 {") != 1 || strings.Contains(out, "10.9.0.0/16") {
		t.Errorf("want only x's IPv6 companion, without the colliding row's elements:\n%s", out)
	}
	for _, want := range []string{"ip saddr @x accept", "ip6 saddr @x_v6 accept", "ip saddr @y_v6 drop", "set y_v6 {"} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "dport 23") {
		t.Errorf("the rule on @x_v6 rendered:\n%s", out)
	}
	if _, ok := invalidRow(plan, "ip_sets", "s-yv6"); ok {
		t.Errorf("y_v6 reported, but y holds no IPv6 element")
	}
}

// TestLoader_SetNamesNftRefusesLeftOut (fw-grammar re-review 3 m-c): a set an
// older peer named with a name nft cannot read (digit or '-' first, longer
// than 255 bytes, a keyword, a ':' that is not address-shaped) is left out and
// reported instead of freezing every host; a rule referencing one is left
// out.
//
// Mutation: RenderSetName accepting any word — Render emits `set 1office {`,
// which the kernel netns corpus test shows nft refusing; here the rows are not
// reported, red.
func TestLoader_SetNamesNftRefusesLeftOut(t *testing.T) {
	db, load := freezeLoader(t)
	long := strings.Repeat("a", 256)
	bad := map[string]string{"s-1": "1office", "s-2": "-a", "s-3": long, "s-4": "drop", "s-5": "office:prod"}
	for id, name := range bad {
		rawSet(t, db, id, name, `["10.0.0.1"]`)
	}
	rawSet(t, db, "s-ok", "dead:beef", `["10.0.0.2"]`)
	rawClusterRule(t, db, "r-drop", "tcp", "22", "@drop", "accept")
	plan, out := load()
	for id := range bad {
		if r, ok := invalidRow(plan, "ip_sets", id); !ok || r.Handling != HandlingSetLeftOut {
			t.Errorf("set %s (%q) not left out: %+v", id, shown(bad[id]), r)
		}
	}
	if _, ok := invalidRow(plan, "cluster_firewall_rules", "r-drop"); !ok {
		t.Error("the rule on @drop is not reported")
	}
	if !strings.Contains(out, "set dead:beef {") {
		t.Errorf("an address-shaped name nft reads was left out:\n%s", out)
	}
	for _, name := range bad {
		if strings.Contains(out, "set "+name+" {") {
			t.Errorf("set %q rendered", shown(name))
		}
	}
}

func shown(s string) string {
	if len(s) > 20 {
		return s[:20] + "…"
	}
	return s
}

// TestLoader_CompanionNameTooLongLeavesOutIPv6: a 253-byte set name with IPv6
// elements would render a 256-byte companion, which nft refuses. Its IPv6
// elements are left out (reported); its IPv4 ones render, and a negated rule
// on it is left out, as for any set that lost elements.
//
// Mutation: skip the companion-name check — Render emits the 256-byte name,
// and the elements are not reported, red.
func TestLoader_CompanionNameTooLongLeavesOutIPv6(t *testing.T) {
	db, load := freezeLoader(t)
	name := strings.Repeat("a", 253)
	rawSet(t, db, "s-long", name, `["10.0.0.0/8", "fd00::/8"]`)
	rawClusterRule(t, db, "r-neg", "tcp", "22", "!= @"+name, "drop")
	plan, out := load()
	if r, ok := invalidRow(plan, "ip_sets", "s-long"); !ok || r.Handling != HandlingElementsLeftOut {
		t.Errorf("the IPv6 elements are not reported left out: %+v", r)
	}
	if _, ok := invalidRow(plan, "cluster_firewall_rules", "r-neg"); !ok {
		t.Error("the negated rule on a set that lost elements is not reported")
	}
	if strings.Contains(out, name+rulefield.IPv6SetSuffix) || strings.Contains(out, "fd00::/8") {
		t.Errorf("the overlong companion rendered:\n%s", out)
	}
	if !strings.Contains(out, "set "+name+" {") {
		t.Errorf("the IPv4 set is missing:\n%s", out)
	}
}

// TestLoader_UnresolvablePortLeftOut (fw-0.4 review I-3): a rule whose port
// nft cannot resolve on this host (a name missing from its services database,
// a number past 65535, a range nft reads backwards) is left out and reported
// instead of freezing every host; every other rule renders.
//
// Mutation: drop the PortUnresolvable check from quarantine.unreadable — the
// rows render (`dport bogus`), red.
func TestLoader_UnresolvablePortLeftOut(t *testing.T) {
	defer rulefield.SetServicesForTest(map[string]uint64{"ssh": 22, "http": 80})()
	db, load := freezeLoader(t)
	rawClusterRule(t, db, "r-ok", "tcp", "SSH", "10.0.0.0/8", "accept")
	rawClusterRule(t, db, "r-num", "udp", "026", "", "accept")
	bad := map[string]string{"r-bogus": "bogus", "r-list": "{ ssh, bogus }", "r-big": "70000", "r-oct": "9-010", "r-back": "http - ssh"}
	for id, port := range bad {
		rawClusterRule(t, db, id, "tcp", port, "10.0.0.0/8", "drop")
	}
	// The port of an esp rule is never written.
	rawClusterRule(t, db, "r-esp", "esp", "bogus", "", "accept")
	plan, out := load()
	for id, port := range bad {
		if r, ok := invalidRow(plan, "cluster_firewall_rules", id); !ok || r.Handling != HandlingLeftOut {
			t.Errorf("rule %s (port %q) not left out: %+v", id, port, r)
		}
		if strings.Contains(out, "dport "+port+" ") {
			t.Errorf("port %q rendered:\n%s", port, out)
		}
	}
	for _, want := range []string{"tcp dport ssh ip saddr 10.0.0.0/8 accept", "udp dport 026 accept", "ip protocol esp accept"} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q:\n%s", want, out)
		}
	}
}

// freezeLong is a 253-byte set name: its IPv6 companion would be 256 bytes.
var freezeLong = strings.Repeat("l", 253)

// loadFreezePlan is a plan the loader builds from raw rows holding every input
// that used to make nft refuse the whole ruleset (fw-grammar re-review 3 N-1,
// N-2, m-c; fw-0.4 review I-3), beside rows that must keep rendering. The
// kernel netns corpus test loads its rendering with nft -c.
func loadFreezePlan(t *testing.T) Plan {
	t.Helper()
	db, _ := freezeLoader(t)
	// N-1: overlapping elements in one row, and two rows of one name that
	// overlap once merged.
	rawSet(t, db, "s-ovl", "ovl", `["10.0.0.0/8", "10.0.0.1-10.0.0.5", "10.0.0.3-10.0.0.9", "11.20.0.0/24"]`)
	rawSet(t, db, "s-ovl2a", "ovl2", `["10.21.0.1-10.21.0.5"]`)
	rawSet(t, db, "s-ovl2b", "ovl2", `["10.21.0.5-10.21.0.9", "10.21.0.7"]`)
	// N-2: x_v6 beside x with IPv6 elements.
	rawSet(t, db, "s-x", "x", `["10.30.0.0/16", "fd00::/8"]`)
	rawSet(t, db, "s-xv6", "x_v6", `["10.31.0.0/16"]`)
	// m-c and the keyword names, and a companion name too long.
	rawSet(t, db, "s-digit", "1office", `["10.40.0.1"]`)
	rawSet(t, db, "s-dash", "-a", `["10.40.0.2"]`)
	rawSet(t, db, "s-kw", "drop", `["10.40.0.3"]`)
	rawSet(t, db, "s-256", strings.Repeat("a", 256), `["10.40.0.4"]`)
	rawSet(t, db, "s-colon", "office:prod", `["10.40.0.5"]`)
	rawSet(t, db, "s-addr", "dead:beef", `["10.40.0.6"]`)
	rawSet(t, db, "s-long", freezeLong, `["10.41.0.0/16", "fd01::/16"]`)
	// Round 0b: user sets named like the bridge table's internal ones.
	rawSet(t, db, "s-resv-gw4", "lv_gw4", `["10.99.0.0/16"]`)
	rawSet(t, db, "s-resv-nic", "lv_nic_devs", `["10.98.0.1"]`)
	// Round 1: an operator keyword (review I-1), elements nft cannot read
	// (m-2), a dotted-quad name nft reads (m-1), a main-era lv_ set (I-5).
	rawSet(t, db, "s-ne", "ne", `["10.60.0.1"]`)
	rawSet(t, db, "s-badelem", "badelem", `["10.61.0.1", "10.61.0.5-10.61.0.1", "10.61.0.0/33", "10.61.0.256"]`)
	rawSet(t, db, "s-quad", "1.2.3.4", `["10.62.0.1"]`)
	rawSet(t, db, "s-lvfoo", "lv_foo", `["10.63.0.0/16"]`)
	for _, r := range [][5]string{
		{"r-ovl", "tcp", "22", "@ovl", "accept"},
		{"r-ovl2", "tcp", "22", "!= @ovl2", "drop"},
		{"r-x", "tcp", "22", "@x", "accept"},
		{"r-xneg", "udp", "53", "!= @x", "drop"},
		{"r-xv6", "tcp", "23", "@x_v6", "drop"},
		{"r-kw", "tcp", "24", "@drop", "accept"},
		{"r-addr", "tcp", "25", "@dead:beef", "accept"},
		{"r-long", "tcp", "26", "@" + freezeLong, "accept"},
		{"r-longneg", "tcp", "27", "!= @" + freezeLong, "drop"},
		// I-3: ports nft cannot resolve.
		{"r-bogus", "tcp", "nosuchservice-lv", "10.50.0.0/16", "drop"},
		{"r-bogus-list", "udp", "{ ssh, nosuchservice-lv }", "10.50.0.0/16", "drop"},
		{"r-big", "tcp", "70000", "10.50.0.0/16", "drop"},
		{"r-octal", "tcp", "9-010", "10.50.0.0/16", "drop"},
		{"r-ssh", "TCP", "SSH", "10.51.0.0/16", "accept"},
		// Round 1: protocols nft cannot resolve (I-2), ordering operators
		// before a list, range or prefix (I-3), a ddp-only service (I-4),
		// IPv4 cidrs nft cannot read (m-2), and rules that keep rendering.
		{"r-proto", "bogus", "", "10.64.0.0/16", "drop"},
		{"r-proto-alias", "ipsec-esp", "", "10.64.0.0/16", "drop"},
		{"r-proto-big", "0400", "", "10.64.0.0/16", "drop"},
		{"r-rel-port", "tcp", "< { 80, 443 }", "10.65.0.0/16", "drop"},
		{"r-rel-cidr", "tcp", "22", "< 10.65.0.0/16", "drop"},
		{"r-rel-proto", "< { 6, 17 }", "", "10.65.0.0/16", "drop"},
		{"r-ddp", "tcp", "rtmp", "10.66.0.0/16", "drop"},
		{"r-back", "tcp", "22", "10.67.0.5-10.67.0.1", "drop"},
		{"r-33", "tcp", "22", "10.67.0.0/33", "drop"},
		{"r-octet", "tcp", "22", "10.67.0.256", "drop"},
		{"r-quad", "tcp", "28", "@1.2.3.4", "accept"},
		{"r-lvfoo", "tcp", "29", "@lv_foo", "drop"},
		{"r-esp", "esp", "", "10.68.0.0/16", "accept"},
		{"r-lt", "tcp", "< 1024", "< 10.69.0.1", "accept"},
	} {
		rawClusterRule(t, db, r[0], r[1], r[2], r[3], r[4])
	}
	if err := corrosion.InsertSecurityGroup(context.Background(), db, corrosion.SecurityGroup{ID: "sg-1", Name: "web"}); err != nil {
		t.Fatal(err)
	}
	rawRow(t, db, `INSERT INTO sg_rules (id, sg_id, direction, proto, port_range, cidr, action, priority, created_at, updated_at)
		VALUES ('sg-ovl', 'sg-1', 'ingress', 'tcp', '80', '@ovl', 'accept', 10, '2026-10-15T00:00:00Z', 1),
		       ('sg-bogus', 'sg-1', 'ingress', 'tcp', 'nosuchservice-lv', '', 'drop', 20, '2026-10-15T00:00:00Z', 1)`)
	plan, err := CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{})(context.Background())
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	// What must keep rendering is not reported.
	for _, id := range []string{"s-quad", "s-lvfoo", "r-quad", "r-lvfoo", "r-esp", "r-lt"} {
		for _, r := range plan.InvalidRows {
			if r.ID == id {
				t.Errorf("row %s reported: %+v", id, r)
			}
		}
	}
	// Non-vacuous: every freeze row reached the loader and was handled.
	for _, id := range []string{"s-xv6", "s-digit", "s-dash", "s-kw", "s-256", "s-colon", "s-long", "s-resv-gw4", "s-resv-nic",
		"r-xv6", "r-kw", "r-longneg", "r-bogus", "r-bogus-list", "r-big", "r-octal", "sg-bogus",
		"s-ne", "s-badelem", "r-proto", "r-proto-alias", "r-proto-big", "r-rel-port", "r-rel-cidr", "r-rel-proto",
		"r-ddp", "r-back", "r-33", "r-octet"} {
		found := false
		for _, r := range plan.InvalidRows {
			found = found || r.ID == id
		}
		if !found {
			t.Errorf("freeze row %s is not reported: the corpus does not hold it", id)
		}
	}
	return plan
}

// TestLoadFreezePlan_Renders: the plan renders, merged where elements overlap,
// with no freeze row as written and every other row in place. The kernel netns
// corpus test proves nft loads it.
func TestLoadFreezePlan_Renders(t *testing.T) {
	plan := loadFreezePlan(t)
	plan.NICs = []NICBinding{{NICDev: "tap0", VMName: "vm", SecurityGroups: []string{"web"}}}
	out, err := Render(plan)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"elements = { 10.0.0.0/8, 11.20.0.0/24 }", "elements = { 10.21.0.1-10.21.0.9 }",
		"set dead:beef {", "ip saddr @x accept", "ip6 saddr @x_v6 accept", "tcp dport ssh ip saddr 10.51.0.0/16 accept",
		"set " + freezeLong + " {",
		"set 1.2.3.4 {", "tcp dport 29 ip saddr @lv_foo drop", "elements = { 10.63.0.0/16 }",
		"ip protocol esp ip saddr 10.68.0.0/16 accept", "tcp dport < 1024 ip saddr < 10.69.0.1 accept",
		"elements = { 10.61.0.1 }",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q in the rendering", shown(want))
		}
	}
	for _, bad := range []string{"10.31.0.0/16", "set 1office", "set -a", "set drop", "set office:prod", "nosuchservice-lv",
		"dport 70000", "dport 9-010", freezeLong + "_v6", "fd01::/16",
		"set ne {", "10.61.0.5-10.61.0.1", "10.61.0.256", "bogus", "ipsec-esp", "0400", "< { 80, 443 }", "< 10.65.0.0/16",
		"< { 6, 17 }", "rtmp", "10.67."} {
		if strings.Contains(out, bad) {
			t.Errorf("%q rendered", shown(bad))
		}
	}
}

// TestLoader_ReservedSetNamesLeftOut (fw-set-freeze round 0b): a stored user
// set named lv_* is never rendered. lv_nic_devs (type ifname in the bridge
// table) would make nft refuse that table; lv_gw4 would merge its elements
// into the guests' gateway set. Each is left out and reported, a rule
// referencing one is left out, and the internal sets render exactly as
// without them.
//
// Any other lv_ name (lv_foo), which writers refuse now but a main-era
// cluster may hold, renders as it did, so a deny rule on it keeps denying
// (review I-5); so does a reserved-prefix tag-group name, left out.
//
// Mutation: render a reserved-name set (drop the collision check from
// userSetName) — the bridge table declares lv_gw4 twice, its elements merged
// in, red. Leave out every lv_ set — lv_foo and its drop rule vanish, red.
func TestLoader_ReservedSetNamesLeftOut(t *testing.T) {
	db, _ := freezeLoader(t)
	rawSet(t, db, "s-gw4", "lv_gw4", `["10.99.0.0/16"]`)
	rawSet(t, db, "s-nic", "lv_nic_devs", `["10.98.0.1"]`)
	rawSet(t, db, "s-lb", "lv_lb4", `["10.97.0.1"]`)
	rawSet(t, db, "s-tg", "lv_tg_web", `["10.96.0.1"]`)
	rawSet(t, db, "s-foo", "lv_foo", `["10.95.0.0/16"]`)
	rawClusterRule(t, db, "r-gw4", "tcp", "53", "@lv_gw4", "accept")
	rawClusterRule(t, db, "r-foo", "tcp", "22", "@lv_foo", "drop")
	plan, err := CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{})(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"s-gw4", "s-nic", "s-lb", "s-tg"} {
		if r, ok := invalidRow(plan, "ip_sets", id); !ok || r.Handling != HandlingSetLeftOut || !strings.Contains(r.Reason, `"lv_"`) {
			t.Errorf("set %s not left out as reserved: %+v", id, r)
		}
	}
	for _, r := range plan.InvalidRows {
		if r.ID == "s-foo" || r.ID == "r-foo" {
			t.Errorf("%s reported: %+v", r.ID, r)
		}
	}
	if _, ok := invalidRow(plan, "cluster_firewall_rules", "r-gw4"); !ok {
		t.Error("the rule on @lv_gw4 is not reported")
	}
	plan.Gateways = []string{"10.88.0.1"}
	plan.NICs = []NICBinding{{NICDev: "tap0", VMName: "vm"}}
	out, err := Render(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"lv_gw4", "lv_nic_devs", "lv_lb4"} {
		if n := strings.Count(out, "set "+name+" {"); n > 1 {
			t.Errorf("set %s declared %d times", name, n)
		}
	}
	for _, want := range []string{"tcp dport 22 ip saddr @lv_foo drop", "elements = { 10.95.0.0/16 }"} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q: a deny rule on a main-era lv_ set must keep denying", want)
		}
	}
	for _, bad := range []string{"10.99.0.0/16", "10.98.0.1", "10.97.0.1", "10.96.0.1", "dport 53 ip saddr @lv_gw4"} {
		if strings.Contains(out, bad) {
			t.Errorf("%q rendered", bad)
		}
	}
	if !strings.Contains(out, "elements = { 10.88.0.1 }") {
		t.Errorf("the gateway set lost its element:\n%s", out)
	}
}
