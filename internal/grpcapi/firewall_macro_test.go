package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A File that reaches the deploy with a macro unexpanded (built by a caller,
// not parsed) is expanded there, to the same rows and priorities the parser
// gives: priority (i+1)*10 for every row of rule i.
func TestPersistStackFirewall_ExpandsMacroRows(t *testing.T) {
	ctx := context.Background()
	s := newFWTestServer(t)
	f := &compose.File{
		Name: "m",
		SecurityGroups: map[string]compose.SecurityGroupDef{"web": {Rules: []compose.FirewallRuleDef{
			{Direction: "ingress", Proto: "tcp", Port: "22", Action: "accept"},
			{Direction: "ingress", Macro: "dns", Action: "accept"},
			{Direction: "ingress", Proto: "tcp", Port: "8080", Action: "accept"},
		}}},
		FirewallDefaults: &compose.FirewallDefaultsDef{ClusterRules: []compose.FirewallRuleDef{
			{Direction: "egress", Macro: "Web", Action: "accept"},
		}},
	}
	if err := s.persistStackFirewall(ctx, f); err != nil {
		t.Fatal(err)
	}
	sgs, _ := corrosion.ListSecurityGroups(ctx, s.db, "m")
	if len(sgs) != 1 {
		t.Fatalf("groups = %+v", sgs)
	}
	rules, _ := corrosion.ListSGRules(ctx, s.db, sgs[0].ID)
	type row struct {
		proto, port string
		prio        int
	}
	got := map[row]bool{}
	for _, r := range rules {
		got[row{r.Proto, r.PortRange, r.Priority}] = true
	}
	for _, w := range []row{{"tcp", "22", 10}, {"udp", "53", 20}, {"tcp", "53", 20}, {"tcp", "8080", 30}} {
		if !got[w] {
			t.Errorf("missing sg row %+v; have %+v", w, rules)
		}
	}
	if len(rules) != 4 {
		t.Errorf("sg rows = %d, want 4", len(rules))
	}
	cr, _ := corrosion.ListClusterFirewallRules(ctx, s.db)
	if len(cr) != 2 {
		t.Fatalf("cluster rows = %+v", cr)
	}
	for _, r := range cr {
		if r.Priority != 10 || r.Comment != "macro Web" || r.Proto != "tcp" {
			t.Errorf("cluster row = %+v", r)
		}
	}
}

// A macro the deploy refuses (a port beside it, an unknown name) is refused
// before any gate is asked and before the stack's earlier rows are torn down.
func TestPersistStackFirewall_MacroRefusalsTouchNothing(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	g := &relGate{t: t, open: true}
	s.SetReleaseFeatureGate(g)
	good, err := compose.ParseBytes([]byte(`name: m
firewall:
  cluster-rules:
    - { direction: ingress, macro: SSH, action: accept }
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.persistStackFirewall(ctx, good); err != nil {
		t.Fatal(err)
	}
	before, _ := corrosion.ListClusterFirewallRules(ctx, s.db)
	if len(before) != 1 {
		t.Fatalf("rows = %+v", before)
	}
	g.used, g.calls = nil, 0
	for name, rule := range map[string]compose.FirewallRuleDef{
		"port":    {Direction: "ingress", Macro: "SSH", Port: "2222", Action: "accept"},
		"unknown": {Direction: "ingress", Macro: "Nope", Action: "accept"},
		// A grammar refusal on the second rule of the file: no row of the
		// first (a whole macro) may be written. The first rule needs the IPv6
		// gate, so an expansion that ran after the gate loop would ask it.
		"cidr": {Direction: "ingress", Macro: "DNS", CIDR: "2001:db8::/32 }", Action: "accept"},
	} {
		bad := &compose.File{Name: "m", FirewallDefaults: &compose.FirewallDefaultsDef{
			ClusterRules: []compose.FirewallRuleDef{{Direction: "ingress", Macro: "Web", CIDR: "2001:db8::/32", Action: "accept"}, rule},
		}}
		if err := s.persistStackFirewall(ctx, bad); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), "cluster") {
			t.Errorf("%s: %v", name, err)
		}
		after, _ := corrosion.ListClusterFirewallRules(ctx, s.db)
		if len(after) != 1 || after[0].ID != before[0].ID {
			t.Errorf("%s: rows after a refusal = %+v, want the earlier row only", name, after)
		}
	}
	if g.calls != 0 {
		t.Errorf("a refused macro asked the gate %d time(s)", g.calls)
	}
}
