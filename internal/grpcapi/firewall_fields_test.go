package grpcapi

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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
	} {
		if _, err := s.CreateClusterFirewallRule(ctx, &pb.CreateClusterFirewallRuleRequest{Rule: r}); err != nil {
			t.Errorf("rule %+v refused: %v", r, err)
		}
	}
}

// TestRecordFirewallState_InvalidRows: rows the loader did not render as
// written raise firewall.rule.invalid, naming each row and the command that
// removes it, and resolve it once they are gone.
func TestRecordFirewallState_InvalidRows(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	s.RecordFirewallState(ctx, firewall.AppliedState{InvalidRows: []firewall.InvalidRow{
		{Table: "cluster_firewall_rules", ID: "r1", Reason: "bad port", Handling: firewall.HandlingWidened},
		{Table: "sg_rules", ID: "r2", Reason: "bad proto", Handling: firewall.HandlingLeftOut},
	}})
	row, ok, err := corrosion.GetHealthCondition(ctx, s.db, FirewallEvaluator, CondFirewallInvalidRows, "host", s.hostName)
	if err != nil || !ok || row.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("condition not raised: %+v %v %v", row, ok, err)
	}
	for _, want := range []string{"lv firewall cluster-rule rm r1", "lv sg rule-rm r2", "bad port", firewall.HandlingLeftOut} {
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
