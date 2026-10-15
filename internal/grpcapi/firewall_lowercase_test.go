package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The rule handlers and the stack deploy store proto, port and action lower
// case (spec §0.4, review I-1), and a handler replies with what it stored:
// nft resolves a service name only in lower case, so `--port SSH` would
// otherwise stop every host's firewall from applying.
//
// Mutations: a handler builds its row without NormaliseRule — its reply keeps
// `SSH`, red; the stack writes its rows as parsed — red only if the writer
// does not lowercase either, so the writer test covers that half.
func TestRuleWrites_StoreAndReplyLowercase(t *testing.T) {
	s := testServer(t)
	ctx := adminCtxWithEngine(t, s)
	bg := context.Background()
	sg, err := s.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "web"})
	if err != nil {
		t.Fatal(err)
	}
	lower := func(what, proto, port, action string) {
		t.Helper()
		if proto != "tcp" || port != "ssh" || action != "drop" {
			t.Errorf("%s = %q %q %q, want tcp ssh drop", what, proto, port, action)
		}
	}
	rule := &pb.FirewallRule{Direction: "ingress", Proto: "TCP", Port: "SSH", Cidr: "10.0.0.0/8", Action: "DROP"}
	cr, err := s.CreateClusterFirewallRule(ctx, &pb.CreateClusterFirewallRuleRequest{Rule: rule})
	if err != nil {
		t.Fatal(err)
	}
	lower("cluster rule reply", cr.GetProto(), cr.GetPort(), cr.GetAction())
	hrule := &pb.FirewallRule{HostName: s.hostName, Direction: "ingress", Proto: "TCP", Port: "SSH", Cidr: "10.0.0.0/8", Action: "DROP"}
	hr, err := s.CreateHostFirewallRule(ctx, &pb.CreateHostFirewallRuleRequest{Rule: hrule})
	if err != nil {
		t.Fatal(err)
	}
	lower("host rule reply", hr.GetProto(), hr.GetPort(), hr.GetAction())
	sr, err := s.AddSecurityGroupRule(ctx, &pb.AddSecurityGroupRuleRequest{Rule: &pb.SecurityGroupRule{
		SgId: sg.GetId(), Direction: "ingress", Proto: "TCP", Port: "SSH", Cidr: "10.0.0.0/8", Action: "DROP"}})
	if err != nil {
		t.Fatal(err)
	}
	lower("sg rule reply", sr.GetProto(), sr.GetPort(), sr.GetAction())

	f, err := compose.ParseStored([]byte(`
name: lcstack
security-groups:
  web2:
    rules:
      - {direction: ingress, proto: TCP, port: SSH, cidr: "10.0.0.0/8", action: DROP}
firewall:
  cluster-rules:
    - {direction: ingress, proto: TCP, port: SSH, cidr: "10.1.0.0/16", action: DROP}
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.persistStackFirewall(bg, f); err != nil {
		t.Fatal(err)
	}
	rules, _ := corrosion.ListClusterFirewallRules(bg, s.db)
	for _, r := range rules {
		lower("stored cluster rule "+r.ID, r.Proto, r.PortRange, r.Action)
	}
	hrs, _ := corrosion.ListHostFirewallRules(bg, s.db, "")
	for _, r := range hrs {
		lower("stored host rule "+r.ID, r.Proto, r.PortRange, r.Action)
	}
	groups, err := corrosion.ListSecurityGroups(bg, s.db, "")
	if err != nil || len(groups) != 2 {
		t.Fatalf("security groups = %v, %v", groups, err)
	}
	for _, g := range groups {
		srs, _ := corrosion.ListSGRules(bg, s.db, g.ID)
		if len(srs) != 1 {
			t.Fatalf("security group %s rules = %v", g.Name, srs)
		}
		lower("stored sg rule in "+g.Name, srs[0].Proto, srs[0].PortRange, srs[0].Action)
	}
}
