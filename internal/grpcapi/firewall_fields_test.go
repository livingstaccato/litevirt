package grpcapi

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
)

// TestFirewallWriters_RefuseUngrammaticalFields (finding F-1): every gRPC
// writer of a rule or an ip set refuses a field that would add nft syntax to
// every host's ruleset or stop it applying, as InvalidArgument naming the
// field and value, and stores nothing.
func TestFirewallWriters_RefuseUngrammaticalFields(t *testing.T) {
	s := testServer(t)
	ctx := adminCtxWithEngine(t, s)
	sg, err := s.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "web"})
	if err != nil {
		t.Fatal(err)
	}
	bad := []struct {
		name, field, value string
		rule               *pb.FirewallRule
	}{
		{"port newline", "port", "22 accept\n", &pb.FirewallRule{Direction: "ingress", Proto: "tcp", Port: "22 accept\n"}},
		{"proto semicolon", "proto", "tcp;", &pb.FirewallRule{Direction: "ingress", Proto: "tcp;"}},
		{"cidr brace", "cidr", "10.0.0.0/8 }", &pb.FirewallRule{Direction: "ingress", Cidr: "10.0.0.0/8 }"}},
		{"action allow", "action", "allow", &pb.FirewallRule{Direction: "ingress", Action: "allow"}},
		{"comment quote", "comment", `x"; accept; #`, &pb.FirewallRule{Direction: "ingress", Comment: `x"; accept; #`}},
		{"bare port list", "port", "80,443", &pb.FirewallRule{Direction: "ingress", Proto: "tcp", Port: "80,443"}},
		{"port out of range", "port", "70000", &pb.FirewallRule{Direction: "ingress", Proto: "tcp", Port: "70000"}},
		{"set compared with <", "cidr", "< @office", &pb.FirewallRule{Direction: "ingress", Cidr: "< @office"}},
		// fw-0.4 review I-3: nft cannot resolve these, and refuses every
		// host's ruleset over one.
		{"unknown service", "port", "nosuchservice-lv", &pb.FirewallRule{Direction: "ingress", Proto: "tcp", Port: "nosuchservice-lv"}},
		{"range nft reads backwards", "port", "9-010", &pb.FirewallRule{Direction: "ingress", Proto: "udp", Port: "9-010"}},
	}
	wantRefused := func(t *testing.T, err error, field, value string) {
		t.Helper()
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("got %v, want InvalidArgument", err)
		}
		if msg := status.Convert(err).Message(); !strings.Contains(msg, field) || !strings.Contains(msg, strconv.Quote(value)) {
			t.Errorf("message %q does not name %s %q", msg, field, value)
		}
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			_, err := s.CreateClusterFirewallRule(ctx, &pb.CreateClusterFirewallRuleRequest{Rule: c.rule})
			wantRefused(t, err, c.field, c.value)
			hr := &pb.FirewallRule{HostName: "host-a", Direction: c.rule.Direction, Proto: c.rule.Proto,
				Port: c.rule.Port, Cidr: c.rule.Cidr, Action: c.rule.Action, Comment: c.rule.Comment}
			_, err = s.CreateHostFirewallRule(ctx, &pb.CreateHostFirewallRuleRequest{Rule: hr})
			wantRefused(t, err, c.field, c.value)
			if c.field != "comment" { // a security-group rule has no comment
				_, err = s.AddSecurityGroupRule(ctx, &pb.AddSecurityGroupRuleRequest{Rule: &pb.SecurityGroupRule{
					SgId: sg.Id, Direction: c.rule.Direction, Proto: c.rule.Proto, Port: c.rule.Port,
					Cidr: c.rule.Cidr, Action: c.rule.Action,
				}})
				wantRefused(t, err, c.field, c.value)
			}
		})
	}
	for name, req := range map[string]*pb.CreateIpSetRequest{
		"set name":    {Name: "s {\n}", Cidrs: []string{"10.0.0.0/8"}},
		"set element": {Name: "s", Cidrs: []string{"10.0.0.0/8 }\nx"}},
		"keyword":     {Name: "drop", Cidrs: []string{"10.0.0.0/8"}},
	} {
		_, err := s.CreateIpSet(ctx, req)
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: got %v, want InvalidArgument", name, err)
		}
	}

	bg := context.Background()
	if rows, _ := corrosion.ListClusterFirewallRules(bg, s.db); len(rows) != 0 {
		t.Errorf("cluster rules stored: %+v", rows)
	}
	if rows, _ := corrosion.ListHostFirewallRules(bg, s.db, "host-a"); len(rows) != 0 {
		t.Errorf("host rules stored: %+v", rows)
	}
	if rows, _ := corrosion.ListSGRules(bg, s.db, sg.Id); len(rows) != 0 {
		t.Errorf("security-group rules stored: %+v", rows)
	}
	if rows, _ := corrosion.ListIPSets(bg, s.db); len(rows) != 0 {
		t.Errorf("ip sets stored: %+v", rows)
	}

	// Every form nft accepts in the renderer's position is still written.
	for _, r := range []*pb.FirewallRule{
		{Direction: "ingress", Proto: "TCP", Port: "{ 80, 443 }"},
		{Direction: "ingress", Proto: "tcp", Port: "!= 22", Cidr: "10.0.0.1-10.0.0.9", Action: "drop"},
		{Direction: "ingress", Proto: "tcp", Port: "< 1024", Cidr: "!= 10.0.0.0/8", Action: "reject"},
		{Direction: "egress", Proto: "udp", Port: "53", Cidr: "gw.example.com", Comment: strings.Repeat("c", 127)},
		{Direction: "in", Proto: "esp"},
		{Direction: "ingress", Proto: "tcp", Port: "{ 80, 443, }"},
		{Direction: "ingress", Proto: "tcp", Port: "0x16"},
		{Direction: "ingress", Proto: "tcp", Port: "ssh - http"},
		{Direction: "ingress", Cidr: "& 255.0.0.0 == 10.0.0.0"},
	} {
		if _, err := s.CreateClusterFirewallRule(ctx, &pb.CreateClusterFirewallRuleRequest{Rule: r}); err != nil {
			t.Errorf("rule %+v refused: %v", r, err)
		}
	}
	// `lv firewall ipset add NAME --cidr 10.0.0.1,10.0.0.2` keeps working
	// (review C-2), stored one element per entry.
	set, err := s.CreateIpSet(ctx, &pb.CreateIpSetRequest{Name: "office", Cidrs: []string{"10.0.0.1,10.0.0.2", "10.9.0.0/16,"}})
	if err != nil {
		t.Fatalf("CreateIpSet with a comma list: %v", err)
	}
	if got := strings.Join(set.Cidrs, "|"); got != "10.0.0.1|10.0.0.2|10.9.0.0/16" {
		t.Errorf("stored elements %q", got)
	}
}

// TestStackFirewall_GrammarBeforeTeardown (review m-1): a stack whose new
// config holds a refused field is refused before any of its rows are torn
// down.
func TestStackFirewall_GrammarBeforeTeardown(t *testing.T) {
	s := testServer(t)
	ctx := adminCtxWithEngine(t, s)
	parse := func(rules string) *compose.File {
		t.Helper()
		// ParseStored: the daemon's own check is under test; the compose
		// validator would refuse first.
		f, err := compose.ParseStored([]byte("name: st\nsecurity-groups:\n  web:\n    rules:\n" + rules))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return f
	}
	if err := s.persistStackFirewall(ctx, parse(`      - {direction: ingress, proto: tcp, port: "80", action: accept}
`)); err != nil {
		t.Fatal(err)
	}
	before, _ := corrosion.ListSecurityGroups(ctx, s.db, "st")
	err := s.persistStackFirewall(ctx, parse(`      - {direction: ingress, proto: tcp, port: "443", action: accept}
      - {direction: ingress, proto: tcp, port: "22; flush ruleset", action: accept}
`))
	if err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("a stack with a refused port: %v", err)
	}
	after, _ := corrosion.ListSecurityGroups(ctx, s.db, "st")
	if len(before) != 1 || len(after) != 1 || after[0].ID != before[0].ID {
		t.Fatalf("the refused redeploy tore the stack's firewall down: before %+v, after %+v", before, after)
	}
	if rules, _ := corrosion.ListSGRules(ctx, s.db, after[0].ID); len(rules) != 1 || rules[0].PortRange != "80" {
		t.Errorf("the refused redeploy changed the stack's rules: %+v", rules)
	}
}

// TestRecordFirewallState_InvalidRows: rows the loader did not render as
// written raise firewall.rule.invalid, naming each row and the command that
// removes it, and resolve it once they are gone.
func TestRecordFirewallState_InvalidRows(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	s.RecordFirewallState(ctx, firewall.AppliedState{InvalidRows: []firewall.InvalidRow{
		{Table: "cluster_firewall_rules", ID: "r1", Action: "drop", Reason: "bad port", Handling: firewall.HandlingKeptLast},
		{Table: "sg_rules", ID: "r2", Action: "allow", Reason: "bad action", Handling: firewall.HandlingLeftOut},
	}})
	row, ok, err := corrosion.GetHealthCondition(ctx, s.db, FirewallEvaluator, CondFirewallInvalidRows, "host", s.hostName)
	if err != nil || !ok || row.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("condition not raised: %+v %v %v", row, ok, err)
	}
	for _, want := range []string{"lv firewall cluster-rule rm r1", "lv sg rule-rm r2", "bad port", firewall.HandlingLeftOut,
		firewall.HandlingKeptLast, `stored action "allow"`} {
		if !strings.Contains(row.Evidence, want) {
			t.Errorf("evidence %q lacks %q", row.Evidence, want)
		}
	}
	s.RecordFirewallState(ctx, firewall.AppliedState{})
	row, _, _ = corrosion.GetHealthCondition(ctx, s.db, FirewallEvaluator, CondFirewallInvalidRows, "host", s.hostName)
	if row.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("condition not resolved once the rows are gone: %+v", row)
	}
}

// TestIpSet_CompanionClashRefusedBeforeAnyGate (fw-grammar re-review 3 N-2):
// CreateIpSet and a stack deploy refuse a set named <x>_v6 beside a set x
// with IPv6 elements as InvalidArgument, before the release gate is asked and,
// for a stack, before its rows are torn down.
//
// Mutation: drop the IPSetCompanionClash check from CreateIpSet (the writer
// still refuses, but after the gate: calls != 0) or from the stack preflight
// (the stack's earlier set is torn down) — red.
func TestIpSet_CompanionClashRefusedBeforeAnyGate(t *testing.T) {
	s := testServer(t)
	g := &relGate{t: t, open: true}
	s.SetReleaseFeatureGate(g)
	ctx := adminCtxWithEngine(t, s)
	if _, err := s.CreateIpSet(ctx, &pb.CreateIpSetRequest{Name: "office", Cidrs: []string{"10.0.0.0/8", "fd00::/8"}}); err != nil {
		t.Fatal(err)
	}
	calls := g.calls
	_, err := s.CreateIpSet(ctx, &pb.CreateIpSetRequest{Name: "office_v6", Cidrs: []string{"2001:db8::/32"}})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(status.Convert(err).Message(), "office_v6") {
		t.Errorf("office_v6 beside office: %v, want InvalidArgument naming it", err)
	}
	if g.calls != calls {
		t.Errorf("the release gate was asked for a refused set (%d calls)", g.calls-calls)
	}

	parse := func(body string) *compose.File {
		t.Helper()
		f, err := compose.ParseStored([]byte("name: st\nipsets:\n" + body))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return f
	}
	if err := s.persistStackFirewall(ctx, parse("  lab:\n    cidrs: [\"10.5.0.0/16\"]\n")); err != nil {
		t.Fatal(err)
	}
	// The redeploy's own lab is replaced, so a lab_v6 beside the new lab
	// (IPv6) is judged against the new config, and office_v6 against the live
	// office.
	for _, body := range []string{
		"  lab:\n    cidrs: [\"fd00::/8\"]\n  lab_v6:\n    cidrs: [\"10.6.0.0/16\"]\n",
		"  office_v6:\n    cidrs: [\"10.7.0.0/16\"]\n",
	} {
		err := s.persistStackFirewall(ctx, parse(body))
		if err == nil || !strings.Contains(err.Error(), "_v6") {
			t.Errorf("stack %q: %v, want refused", body, err)
		}
		sets, _ := corrosion.ListIPSets(context.Background(), s.db)
		var names []string
		for _, set := range sets {
			names = append(names, set.Name)
		}
		if strings.Join(names, ",") != "lab,office" {
			t.Errorf("a refused deploy changed the sets: %v", names)
		}
	}
	// The stack's own earlier lab_v6 does not clash with its redeploy.
	if err := s.persistStackFirewall(ctx, parse("  lab_v6:\n    cidrs: [\"10.6.0.0/16\"]\n")); err != nil {
		t.Fatal(err)
	}
	if err := s.persistStackFirewall(ctx, parse("  lab:\n    cidrs: [\"fd00::/8\"]\n")); err != nil {
		t.Errorf("a redeploy replacing the stack's own lab_v6: %v", err)
	}
}
