package firewall

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// rawRow writes a firewall row past the writers' grammar check, as a peer on
// an older build replicates one.
func rawRow(t *testing.T, db *corrosion.Client, sql string, args ...any) {
	t.Helper()
	if err := db.Execute(context.Background(), sql, args...); err != nil {
		t.Fatalf("raw insert: %v", err)
	}
}

// unboundedDrops are the rendered tier-chain drops (inet cluster_default /
// host_overrides) with no address match: a quarantined row must never become
// one (review C-1: a bare drop takes down all forwarded traffic).
func unboundedDrops(script string) []string {
	var out []string
	in := false
	for _, line := range strings.Split(script, "\n") {
		l := strings.TrimSpace(line)
		switch {
		case l == "chain cluster_default {" || l == "chain host_overrides {":
			in = true
		case l == "}":
			in = false
		case in && (strings.HasSuffix(l, " drop") || l == "drop" || strings.Contains(l, " drop comment ")) &&
			!strings.Contains(l, "saddr") && !strings.Contains(l, "daddr"):
			out = append(out, l)
		}
	}
	return out
}

// TestLoader_InvalidRowsFailClosed (finding F-1, rolling upgrade; review C-1,
// C-2, I-2): rows an older peer wrote that cannot be rendered safely never
// reach the script as written and never fail the pass — every other rule
// still applies — and never render anything the row did not ask for. Such a
// row alone is held fail-static: its last rendering on this host, or left out
// when there is none. A reference to a set that does not exist (plain or
// negated) renders against an empty set, and a set with an unreadable element
// renders without it. No quarantined row ever becomes a drop without an
// address match.
func TestLoader_InvalidRowsFailClosed(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	const now = "2026-10-15T00:00:00Z"
	cluster := func(id, dir, proto, port, cidr, action, comment string) {
		rawRow(t, db, `INSERT INTO cluster_firewall_rules
			(id, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, 100, ?, '', ?, 1)`, id, dir, proto, port, cidr, action, comment, now)
	}
	var loader PlanLoader // kept across passes: it remembers what it rendered
	load := func() (Plan, string) {
		t.Helper()
		plan, err := loader(ctx)
		if err != nil {
			t.Fatalf("loader failed the pass on a bad row: %v", err)
		}
		out, err := Render(plan)
		if err != nil {
			t.Fatalf("Render refused the plan: one bad row stopped the host's firewall: %v", err)
		}
		if strings.Contains(strings.ToUpper(nftOutsideStrings(out)), injectMark) || strings.Contains(out, "0.0.0.0/0") {
			t.Fatalf("a bad row reached the script as written:\n%s", out)
		}
		if d := unboundedDrops(out); len(d) > 0 {
			t.Fatalf("a drop with no address match was rendered: %q\n%s", d, out)
		}
		// Re-review C-1: "not in an empty set" is every address, so no
		// negated reference may name a set the loader declared empty.
		declared := map[string]bool{}
		for _, set := range plan.IPSets {
			declared[set.Name] = true
		}
		for _, set := range plan.IPSets {
			if len(set.CIDRs) > 0 {
				continue
			}
			for _, neg := range []string{"!= @" + set.Name, "!=@" + set.Name} {
				if strings.Contains(out, neg+" ") {
					t.Fatalf("a negated reference to the empty set %s was rendered (it matches everything):\n%s", set.Name, out)
				}
			}
		}
		// Re-review m-2: no element list nft refuses.
		if strings.Contains(out, "elements = { ,") || strings.Contains(out, "elements = {  }") {
			t.Fatalf("an element list nft refuses was rendered:\n%s", out)
		}
		return plan, out
	}
	clock := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

	// A row that will turn unreadable after it has been rendered once.
	cluster("flip", "ingress", "tcp", "8080", "198.51.100.0/24", "drop", "")
	// A drop on a set that is deleted after it has been rendered once.
	rawRow(t, db, `INSERT INTO ip_sets (id, name, cidrs, stack_name, created_at, updated_at)
		VALUES ('set-del', 'blocklist', '["203.0.113.0/24"]', '', ?, 1)`, now)
	cluster("del-drop", "ingress", "all", "", "@blocklist", "drop", "")
	// Negated references (allowlist by drop, blocklist by accept): one whose
	// row an older peer rewrites to name a missing set, one whose set is
	// deleted.
	rawRow(t, db, `INSERT INTO ip_sets (id, name, cidrs, stack_name, created_at, updated_at)
		VALUES ('set-office', 'office', '["10.20.0.0/16"]', '', ?, 1), ('set-office2', 'office2', '["10.21.0.0/16"]', '', ?, 1)`, now, now)
	cluster("neg-flip", "ingress", "tcp", "22", "!= @office", "drop", "")
	cluster("neg-del", "ingress", "tcp", "23", "!= @office2", "accept", "")
	loader = CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{Now: func() time.Time { return clock }})
	if _, out := load(); !strings.Contains(out, "tcp dport 8080 ip saddr 198.51.100.0/24 drop") ||
		!strings.Contains(out, "ip saddr @blocklist drop") || !strings.Contains(out, "tcp dport 22 ip saddr != @office drop") ||
		!strings.Contains(out, "tcp dport 23 ip saddr != @office2 accept") {
		t.Fatalf("first pass:\n%s", out)
	}
	rawRow(t, db, `UPDATE cluster_firewall_rules SET cidr = '!= @nooffice' WHERE id = 'neg-flip'`)
	if err := corrosion.DeleteIPSet(ctx, db, "set-office2"); err != nil {
		t.Fatal(err)
	}

	// Now the bad rows an older peer writes.
	rawRow(t, db, `UPDATE cluster_firewall_rules SET port_range = ? WHERE id = 'flip'`, "8080; "+injectMark)
	if err := corrosion.DeleteIPSet(ctx, db, "set-del"); err != nil {
		t.Fatal(err)
	}
	cluster("good", "ingress", "tcp", "443", "", "accept", "web")
	cluster("bad-accept", "ingress", "tcp", "22\n        ip saddr 0.0.0.0/0", "", "accept", "")
	cluster("bad-drop", "ingress", "tcp", "25; "+injectMark, "192.0.2.0/24", "drop", "")
	cluster("bad-verdict", "egress", "udp", "53", "198.51.100.7", "drop\n"+injectMark, "")
	cluster("allow-all", "ingress", "all", "", "", "allow", "") // meant "accept everything"
	rawRow(t, db, `INSERT INTO ip_sets (id, name, cidrs, stack_name, created_at, updated_at)
		VALUES ('set-bad', 'blocked', ?, '', ?, 1)`, `["198.18.0.0/15", "203.0.113.0/24 } `+injectMark+`", "", ",10.0.0.9", " , "]`, now)
	cluster("set-drop", "ingress", "tcp", "3389", "@blocked", "drop", "")
	cluster("missing", "ingress", "all", "", "@never", "drop", "")
	cluster("neg-missing", "ingress", "tcp", "22", "!= @gone", "accept", "") // blocklist by accept
	cluster("neg-drop", "ingress", "tcp", "24", "!=@gone2", "drop", "")      // allowlist by drop
	// Re-review 2 I-1: sets that lost elements to quarantine, all or some.
	rawRow(t, db, `INSERT INTO ip_sets (id, name, cidrs, stack_name, created_at, updated_at)
		VALUES ('set-allbad', 'allbad', ?, '', ?, 1), ('set-somebad', 'somebad', ?, '', ?, 1)`,
		`["10.40.0.0/16 }", ",10.41.0.1"]`, now, `["10.30.0.0/16", "10.31.0.0/16 ;x"]`, now)
	cluster("neg-allbad", "ingress", "tcp", "25", "!= @allbad", "drop", "")     // allowlist by drop
	cluster("neg-somebad", "ingress", "tcp", "26", "!= @somebad", "accept", "") // blocklist by accept
	cluster("pos-somebad", "ingress", "tcp", "27", "@somebad", "drop", "")      // positive: fewer elements narrow it
	// Re-review 2 I-2 and m-a: set references nft refuses, from an older peer.
	cluster("lt-set", "ingress", "tcp", "28", "< @office", "accept", "")
	cluster("ge-set", "ingress", "tcp", "29", "ge @office", "drop", "")
	cluster("mask-set", "ingress", "tcp", "30", "& 255.0.0.0 != @office", "drop", "")
	cluster("brace-set", "ingress", "tcp", "31", "{ @office }", "accept", "")
	cluster("negbrace-set", "ingress", "tcp", "32", "!= { @office }", "drop", "")
	rawRow(t, db, `INSERT INTO host_firewall_rules
		(id, host_name, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
		VALUES ('host-bad', 'host-a', 'in', ?, '8080', '203.0.113.7', 'drop', 100, '', '', ?, 1)`, "esp\n"+injectMark, now)
	sgID := "sg-1"
	if err := corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: sgID, Name: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertSGRule(ctx, db, corrosion.SGRule{ID: "sg-good", SGID: sgID, Direction: "ingress", Proto: "tcp", PortRange: "80", Action: "accept"}); err != nil {
		t.Fatal(err)
	}
	rawRow(t, db, `INSERT INTO sg_rules (id, sg_id, direction, proto, port_range, cidr, action, priority, created_at, updated_at)
		VALUES ('sg-bad', ?, 'ingress', 'esp; `+injectMark+`', '', '', 'accept', 200, ?, 1)`, sgID, now)

	plan, out := load()
	mustContainAll(t, out,
		`tcp dport 443 accept comment "web"`,           // the good rule still applies
		"tcp dport 8080 ip saddr 198.51.100.0/24 drop", // flip: its last rendering
		"ip saddr @blocklist drop",                     // deleted set: empty set, matches nothing
		"tcp dport 3389 ip saddr @blocked drop",        // set with a bad element: rendered without it
		"elements = { 198.18.0.0/15 }",                 // ...keeping its good one
		"ip saddr @never drop",                         // never existed: empty set
		"tcp dport 22 ip saddr != @office drop",        // neg-flip: kept as last rendered (office still exists)
	)
	mustContainAll(t, out, "tcp dport 27 ip saddr @somebad drop", "elements = { 10.30.0.0/16 }")
	for _, gone := range []string{"@gone", "@gone2", "@nooffice", "@office2", "10.0.0.9", "@allbad",
		"!= @somebad", "dport 28 ", "dport 29 ", "dport 30 ", "dport 31 ", "dport 32 "} {
		if strings.Contains(out, gone) {
			t.Errorf("%s rendered: a negated reference to a missing set (or a bad element) reached the script:\n%s", gone, out)
		}
	}
	for _, empty := range []string{"blocklist", "never"} {
		i := strings.Index(out, "set "+empty+" {")
		if i < 0 {
			t.Fatalf("set %s not declared:\n%s", empty, out)
		}
		if body := out[i : i+strings.Index(out[i:], "}")]; strings.Contains(body, "elements") {
			t.Errorf("set %s should be empty: %q", empty, body)
		}
	}
	for _, gone := range []string{"192.0.2.0/24", "198.51.100.7", "203.0.113.7", "203.0.113.0/24"} {
		if strings.Contains(out, gone) {
			t.Errorf("%s rendered: a row left out still reached the script:\n%s", gone, out)
		}
	}
	if len(plan.HostRules) != 0 {
		t.Errorf("host rules = %+v, want the unreadable one left out", plan.HostRules)
	}
	var web SecurityGroup
	for _, sg := range plan.SecurityGroups {
		if sg.Name == "web" {
			web = sg
		}
	}
	if len(web.Rules) != 1 || web.Rules[0].PortRange != "80" {
		t.Errorf("security group web = %+v, want only its good rule", web.Rules)
	}

	immediate := map[string]string{
		"cluster_firewall_rules/flip":         HandlingKeptLast,
		"cluster_firewall_rules/neg-flip":     HandlingKeptLast,
		"cluster_firewall_rules/neg-del":      HandlingLeftOut,
		"cluster_firewall_rules/bad-accept":   HandlingLeftOut,
		"cluster_firewall_rules/bad-drop":     HandlingLeftOut,
		"cluster_firewall_rules/bad-verdict":  HandlingLeftOut,
		"cluster_firewall_rules/allow-all":    HandlingLeftOut,
		"cluster_firewall_rules/neg-missing":  HandlingLeftOut,
		"cluster_firewall_rules/neg-drop":     HandlingLeftOut,
		"cluster_firewall_rules/neg-allbad":   HandlingLeftOut,
		"cluster_firewall_rules/neg-somebad":  HandlingLeftOut,
		"cluster_firewall_rules/lt-set":       HandlingLeftOut,
		"cluster_firewall_rules/ge-set":       HandlingLeftOut,
		"cluster_firewall_rules/mask-set":     HandlingLeftOut,
		"cluster_firewall_rules/brace-set":    HandlingLeftOut,
		"cluster_firewall_rules/negbrace-set": HandlingLeftOut,
		"ip_sets/set-allbad":                  HandlingElementsLeftOut,
		"ip_sets/set-somebad":                 HandlingElementsLeftOut,
		"ip_sets/set-bad":                     HandlingElementsLeftOut,
		"host_firewall_rules/host-bad":        HandlingLeftOut,
		"sg_rules/sg-bad":                     HandlingLeftOut,
	}
	check := func(plan Plan, want map[string]string) map[string]InvalidRow {
		t.Helper()
		got := map[string]InvalidRow{}
		for _, r := range plan.InvalidRows {
			got[r.Table+"/"+r.ID] = r
		}
		for k, v := range want {
			if got[k].Handling != v {
				t.Errorf("invalid row %s: handling %q, want %q", k, got[k].Handling, v)
			}
		}
		if len(got) != len(want) {
			t.Errorf("invalid rows = %v, want exactly %v", got, want)
		}
		return got
	}
	// Re-review m-1: a rule on a missing set is rendered against the empty set
	// at once, but named by the condition only once that has lasted
	// emptySetGrace; everything else is named at once.
	got := check(plan, immediate)
	if got["cluster_firewall_rules/allow-all"].Action != "allow" {
		t.Errorf("the stored action is not reported: %+v", got["cluster_firewall_rules/allow-all"])
	}
	clock = clock.Add(emptySetGrace / 2)
	plan, _ = load()
	check(plan, immediate)
	clock = clock.Add(emptySetGrace)
	plan, out = load()
	later := map[string]string{
		"cluster_firewall_rules/del-drop": HandlingEmptySet,
		"cluster_firewall_rules/missing":  HandlingEmptySet,
	}
	for k, v := range immediate {
		later[k] = v
	}
	check(plan, later)
	if !strings.Contains(out, "ip saddr @blocklist drop") {
		t.Errorf("third pass:\n%s", out)
	}
}

// TestRender_RefusesBareLists: nft refuses a bare comma list ("not
// bitmask"), so a plan holding one never applied; it is refused at validation,
// never emitted.
func TestRender_RefusesBareLists(t *testing.T) {
	for _, r := range []Rule{
		{Direction: Ingress, Proto: "tcp", PortRange: "80,443", Action: Accept},
		{Direction: Ingress, Proto: "tcp,udp", Action: Accept},
		{Direction: Ingress, Proto: "all", CIDR: "10.0.0.0/8,192.168.0.0/16", Action: Drop},
	} {
		if _, err := Render(Plan{ClusterRules: []Rule{r}}); err == nil {
			t.Errorf("rule %+v rendered; want a validation error", r)
		}
	}
}

// TestRender_BracedListsRender: the list forms nft accepts are passed through.
func TestRender_BracedListsRender(t *testing.T) {
	out, err := Render(Plan{ClusterRules: []Rule{
		{Direction: Ingress, Proto: "tcp", PortRange: "{ 80, 443 }", CIDR: "{ 10.0.0.0/8, 192.168.0.0/16 }", Action: Accept},
	}})
	if err != nil {
		t.Fatal(err)
	}
	mustContainAll(t, out, "tcp dport { 80, 443 } ip saddr { 10.0.0.0/8, 192.168.0.0/16 } accept")
}

// TestQuoteComment: a double quote never ends the nft string, and the text is
// cut to nft's limit.
func TestQuoteComment(t *testing.T) {
	// Review I-1: a megabyte comment from an older peer is cut in linear
	// time, not one rune per pass.
	huge := strings.Repeat("é\x01", 1<<19) // 1.5 MB, every rune escaped or multi-byte
	start := time.Now()
	if q := quoteComment(huge); len(q)-2 > 128 {
		t.Errorf("quoted comment is %d bytes", len(q)-2)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("quoting a 1.5 MB comment took %v", d)
	}
	if got := quoteComment(`a"b`); got != `"a'b"` {
		t.Errorf("quoteComment(a\"b) = %s", got)
	}
	long := strings.Repeat("é", 100) // 200 bytes
	q := quoteComment(long)
	if len(q)-2 > 128 {
		t.Errorf("quoted comment is %d bytes, nft allows 128", len(q)-2)
	}
}

// TestLoader_CompatRowsAreValid: no row that applies today is reported, left
// out or widened (TestRenderCompatGolden pins how they render).
func TestLoader_CompatRowsAreValid(t *testing.T) {
	if inv := loadCompatPlan(t).InvalidRows; len(inv) != 0 {
		t.Fatalf("rows that apply today were quarantined: %+v", inv)
	}
}

// TestLoader_KeptRenderingRecheckedUnderThisPassSets (re-review 2 m-b): a
// row's last rendering is kept only if it is still renderable now. Here it
// referenced x_v6 while x had no IPv6 element; x then gains one, so x_v6 is
// x's companion and the kept rendering would declare it twice.
func TestLoader_KeptRenderingRecheckedUnderThisPassSets(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	const now = "2026-10-15T00:00:00Z"
	rawRow(t, db, `INSERT INTO ip_sets (id, name, cidrs, stack_name, created_at, updated_at)
		VALUES ('set-x', 'x', '["10.0.0.0/8"]', '', ?, 1)`, now)
	rawRow(t, db, `INSERT INTO cluster_firewall_rules
		(id, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
		VALUES ('r', 'ingress', 'tcp', '22', '@x_v6', 'accept', 100, '', '', ?, 1)`, now)
	loader := CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{})
	for pass := 1; pass <= 2; pass++ {
		plan, err := loader(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Render(plan); err != nil {
			t.Fatalf("pass %d: the plan was refused: %v", pass, err)
		}
		if pass == 1 {
			rawRow(t, db, `UPDATE ip_sets SET cidrs = '["10.0.0.0/8", "fd00::/8"]' WHERE id = 'set-x'`)
			rawRow(t, db, `UPDATE cluster_firewall_rules SET port_range = '22; x' WHERE id = 'r'`)
			continue
		}
		if len(plan.ClusterRules) != 0 {
			t.Errorf("the kept rendering was rendered though x_v6 is now x's companion: %+v", plan.ClusterRules)
		}
	}
}

// TestRender_NegatedSetSplitsPerFamily: a negated reference to a set with IPv6
// elements holds IPv6 traffic too, one line per family, as a positive one
// does.
func TestRender_NegatedSetSplitsPerFamily(t *testing.T) {
	for _, cidr := range []string{"!= @office", "!=@office", "ne @office", "== @office"} {
		out, err := Render(Plan{
			IPSets:       []IPSet{{Name: "office", CIDRs: []string{"10.0.0.0/8", "fd00::/8"}}},
			ClusterRules: []Rule{{Direction: Ingress, Proto: "tcp", PortRange: "22", CIDR: cidr, Action: Drop}},
		})
		if err != nil {
			t.Fatalf("%s: %v", cidr, err)
		}
		mustContainAll(t, out, "tcp dport 22 ip saddr "+cidr+" drop", "tcp dport 22 ip6 saddr "+cidr+"_v6 drop")
	}
}

// TestRender_RefusesSetOperators (re-review 2 I-2, m-a): nft refuses a set
// compared with <, <=, >, >= (or the word forms), and a set reference in
// braces or behind a mask; the renderer refuses them rather than emit them.
func TestRender_RefusesSetOperators(t *testing.T) {
	for _, cidr := range []string{"< @s", "<= @s", "> @s", ">= @s", "lt @s", "le @s", "gt @s", "ge @s", "<@s",
		"{ @s }", "!= { @s }", "& 255.0.0.0 != @s", "& 255.0.0.0 @s"} {
		_, err := Render(Plan{
			IPSets:       []IPSet{{Name: "s", CIDRs: []string{"10.0.0.0/8"}}},
			ClusterRules: []Rule{{Direction: Ingress, Proto: "all", CIDR: cidr, Action: Drop}},
		})
		if err == nil {
			t.Errorf("%q rendered; nft refuses it", cidr)
		}
	}
}
