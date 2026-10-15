package firewall

import (
	"context"
	"strings"
	"testing"

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

// TestLoader_InvalidRowsFailClosed (finding F-1, rolling upgrade): rows an
// older peer wrote that fail the grammar never reach the script as written,
// never fail the pass — every other rule still applies — and never admit
// anything the row did not: an accept is left out, a drop is rendered with
// its unreadable matches removed (it drops more, never less), and an ip set
// with a bad element is left out whole, so a drop that references it drops
// everything its other matches cover.
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
	// A good rule that must keep applying.
	cluster("good", "ingress", "tcp", "443", "", "accept", "web")
	// An accept carrying an injection: left out.
	cluster("bad-accept", "ingress", "tcp", "22\n        ip saddr 0.0.0.0/0", "", "accept", "")
	// A drop with a bad port: rendered as a drop of all tcp from its CIDR.
	cluster("bad-drop", "ingress", "tcp", "25; "+injectMark, "192.0.2.0/24", "drop", "")
	// A drop whose verdict is unreadable: rendered as a drop.
	cluster("bad-verdict", "egress", "udp", "53", "198.51.100.0/24", "drop\n"+injectMark, "")
	// A drop referencing a set that has a bad element: the set is left out,
	// the drop loses its CIDR match.
	rawRow(t, db, `INSERT INTO ip_sets (id, name, cidrs, stack_name, created_at, updated_at)
		VALUES ('set-bad', 'blocked', ?, '', ?, 1)`, `["203.0.113.0/24 } `+injectMark+`"]`, now)
	cluster("set-drop", "ingress", "tcp", "3389", "@blocked", "drop", "")
	// A host rule with a bad proto and a drop: a drop of everything from
	// its CIDR. Its direction is never written as text: "in" is read as
	// ingress, as it always was.
	rawRow(t, db, `INSERT INTO host_firewall_rules
		(id, host_name, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
		VALUES ('host-bad', 'host-a', 'in', ?, '8080', '203.0.113.7', 'drop', 100, '', '', ?, 1)`, "esp\n"+injectMark, now)
	// A security-group accept with a bad proto: left out; the group's good
	// rule stays.
	sgID := "sg-1"
	if err := corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: sgID, Name: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertSGRule(ctx, db, corrosion.SGRule{ID: "sg-good", SGID: sgID, Direction: "ingress", Proto: "tcp", PortRange: "80", Action: "accept"}); err != nil {
		t.Fatal(err)
	}
	rawRow(t, db, `INSERT INTO sg_rules (id, sg_id, direction, proto, port_range, cidr, action, priority, created_at, updated_at)
		VALUES ('sg-bad', ?, 'ingress', 'esp; `+injectMark+`', '', '', 'accept', 200, ?, 1)`, sgID, now)

	plan, err := CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{})(ctx)
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
	mustContainAll(t, out,
		`tcp dport 443 accept comment "web"`,         // the good rule still applies
		"tcp ip saddr 192.0.2.0/24 drop",             // bad port: wider drop
		"udp dport 53 ip daddr 198.51.100.0/24 drop", // bad verdict: drop
		"tcp dport 3389 drop",                        // unknown set: drop without the CIDR
	)
	if strings.Contains(out, "set blocked") {
		t.Errorf("a set with a bad element was rendered:\n%s", out)
	}
	// The bad host rule drops everything from its address.
	if len(plan.HostRules) != 1 || plan.HostRules[0] != (Rule{Direction: Ingress, Proto: "all", CIDR: "203.0.113.7", Action: Drop}) {
		t.Errorf("host rule with a bad proto: %+v, want a drop of all from 203.0.113.7", plan.HostRules)
	}
	// The bad accepts are left out.
	for _, r := range plan.ClusterRules {
		if r.Action == Accept && r.PortRange != "443" {
			t.Errorf("a bad accept was rendered: %+v", r)
		}
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

	got := map[string]string{}
	for _, r := range plan.InvalidRows {
		got[r.Table+"/"+r.ID] = r.Handling
	}
	want := map[string]string{
		"cluster_firewall_rules/bad-accept":  HandlingLeftOut,
		"cluster_firewall_rules/bad-drop":    HandlingWidened,
		"cluster_firewall_rules/bad-verdict": HandlingWidened,
		"cluster_firewall_rules/set-drop":    HandlingWidened,
		"ip_sets/set-bad":                    HandlingSetLeftOut,
		"host_firewall_rules/host-bad":       HandlingWidened,
		"sg_rules/sg-bad":                    HandlingLeftOut,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("invalid row %s: handling %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("invalid rows = %v, want exactly %v", got, want)
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
