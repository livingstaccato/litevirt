package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall/rulefield"
)

// spyGrammarCIDR is a cidr the test's grammar extension refuses. It is an
// IPv6 prefix, so an entry that skipped the grammar would ask the
// firewall_ipv6 gate before the writer's own check refused it.
const spyGrammarCIDR = "2001:db8::77/128"

// spyGrammar installs a rulefield.RuleExtensions.TagCIDR that refuses
// spyGrammarCIDR. Only the write grammar (rulefield.Rule) consults
// RuleExtensions, so an entry refusing that cidr ran it.
func spyGrammar(t *testing.T) {
	rulefield.SetExtensionsForTest(t, rulefield.Extensions{
		TagCIDR: func(cidr string) (bool, error) {
			if cidr == spyGrammarCIDR {
				return true, &rulefield.FieldError{Field: "cidr", Value: cidr, Reason: "refused by the test's grammar extension"}
			}
			return false, nil
		},
	})
}

// The write grammar (spec §0.4) is one function, rulefield.Rule, and every
// client entry for a rule runs it — with the extensions C2 and D5 fill in
// rulefield.RuleExtensions — before any release gate is asked or anything is
// stored or torn down: the cluster, host and security-group rule handlers,
// the stack deploy (security-group and cluster rules) and the compose
// validator.
//
// Mutations: a handler, the stack deploy or the compose validator skips the
// grammar call, or rulefield.Rule stops consulting RuleExtensions — the spy
// cidr reaches a gate (or parses), red.
func TestRuleGrammar_OneFunctionAtEveryClientEntry(t *testing.T) {
	s := testServer(t)
	g := &relGate{t: t, open: true}
	s.SetReleaseFeatureGate(g)
	ctx := adminCtxWithEngine(t, s)
	bg := context.Background()
	sg, err := s.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "web"})
	if err != nil {
		t.Fatal(err)
	}
	stack := func(sgCIDR, clusterCIDR string) []byte {
		return []byte(`
name: fwstack
security-groups:
  web2:
    rules:
      - {direction: ingress, proto: tcp, port: "80", cidr: "` + sgCIDR + `", action: accept}
firewall:
  cluster-rules:
    - {direction: ingress, proto: tcp, port: "22", cidr: "` + clusterCIDR + `", action: drop}
`)
	}
	// An earlier deploy of the stack, whose rows a refused one must keep.
	f, err := compose.ParseStored(stack("10.0.0.0/8", "10.1.0.0/16"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.persistStackFirewall(bg, f); err != nil {
		t.Fatal(err)
	}
	before, err := corrosion.ListClusterFirewallRules(bg, s.db)
	if err != nil || len(before) != 1 {
		t.Fatalf("stack rules = %v, %v", before, err)
	}
	g.used, g.calls = nil, 0

	spyGrammar(t)
	rule := func() *pb.FirewallRule {
		return &pb.FirewallRule{Direction: "ingress", Proto: "tcp", Port: "22", Cidr: spyGrammarCIDR, Action: "drop"}
	}
	handlers := map[string]func() error{
		"cluster rule": func() error {
			_, err := s.CreateClusterFirewallRule(ctx, &pb.CreateClusterFirewallRuleRequest{Rule: rule()})
			return err
		},
		"host rule": func() error {
			r := rule()
			r.HostName = s.hostName
			_, err := s.CreateHostFirewallRule(ctx, &pb.CreateHostFirewallRuleRequest{Rule: r})
			return err
		},
		"sg rule": func() error {
			_, err := s.AddSecurityGroupRule(ctx, &pb.AddSecurityGroupRuleRequest{Rule: &pb.SecurityGroupRule{
				SgId: sg.GetId(), Direction: "ingress", Proto: "tcp", Port: "22", Cidr: spyGrammarCIDR, Action: "drop"}})
			return err
		},
	}
	for what, h := range handlers {
		if err := h(); status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "test's grammar extension") {
			t.Errorf("%s: %v, want InvalidArgument from the grammar", what, err)
		}
	}
	for what, data := range map[string][]byte{
		"stack security-group rule": stack(spyGrammarCIDR, "10.1.0.0/16"),
		"stack cluster rule":        stack("10.0.0.0/8", spyGrammarCIDR),
	} {
		f, err := compose.ParseStored(data)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.persistStackFirewall(bg, f); err == nil || !strings.Contains(err.Error(), "test's grammar extension") {
			t.Errorf("%s: %v, want refused by the grammar", what, err)
		}
		if _, err := compose.ParseBytes(data); err == nil || !strings.Contains(err.Error(), "test's grammar extension") {
			t.Errorf("compose validator, %s: %v, want refused by the grammar", what, err)
		}
	}
	if g.calls != 0 {
		t.Errorf("a rule the grammar refuses asked the gate %d time(s) (%v)", g.calls, g.used)
	}
	if rules, err := corrosion.ListHostFirewallRules(bg, s.db, ""); err != nil || len(rules) != 0 {
		t.Errorf("host rules stored = %v, %v; want none", rules, err)
	}
	if rules, err := corrosion.ListSGRules(bg, s.db, sg.GetId()); err != nil || len(rules) != 0 {
		t.Errorf("sg rules stored = %v, %v; want none", rules, err)
	}
	after, err := corrosion.ListClusterFirewallRules(bg, s.db)
	if err != nil || len(after) != 1 || after[0].ID != before[0].ID {
		t.Errorf("cluster rules after the refusals = %v, %v; want only the stack's earlier rule", after, err)
	}
}
