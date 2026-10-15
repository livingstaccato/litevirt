package grpcapi

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// writeFirewallRow asks one gate per release feature the row needs, nested
// with IPv6 outermost (capabilities DECISION 0-E), and hands the writer each
// feature's grant in its own slot. A fake gate records the calls.
//
// Mutations: ask only the first feature's gate — the later uses are not
// recorded, red; nest log outside IPv6 — the recorded order is wrong, red;
// hand the IPv6 grant to every slot — the slot check fails, red.
func TestWriteFirewallRow_AsksEveryGateTheRowNeeds(t *testing.T) {
	s := testServer(t)
	g := &relGate{t: t, open: true}
	s.SetReleaseFeatureGate(g)

	// An IPv6 logged row (the server's own; a client cannot send one yet).
	var seen firewallGrants
	write := func(_ context.Context, gs firewallGrants) error {
		seen = gs
		return nil
	}
	need := []capabilities.Feature{capabilities.FeatureFirewallLog, capabilities.FeatureFirewallIPv6}
	if err := s.writeFirewallRow(context.Background(), need, nil, write); err != nil {
		t.Fatal(err)
	}
	if want := []capabilities.Feature{capabilities.FeatureFirewallIPv6, capabilities.FeatureFirewallLog}; !slices.Equal(g.used, want) {
		t.Errorf("gates asked = %v, want %v (IPv6 outermost)", g.used, want)
	}
	if seen.IPv6.Check(capabilities.FeatureFirewallIPv6) != nil || seen.Log.Check(capabilities.FeatureFirewallLog) != nil {
		t.Errorf("grants handed to the write = %+v, want IPv6 and log in their slots", seen)
	}

	// All three, named in any order.
	g.used = nil
	need = []capabilities.Feature{capabilities.FeatureFirewallTagGroups, capabilities.FeatureFirewallLog, capabilities.FeatureFirewallIPv6}
	if err := s.writeFirewallRow(context.Background(), need, nil, write); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(g.used, []capabilities.Feature{capabilities.FeatureFirewallIPv6, capabilities.FeatureFirewallLog, capabilities.FeatureFirewallTagGroups}) {
		t.Errorf("gates asked = %v, want ipv6, log, tag", g.used)
	}
	if seen.IPv6.Check(capabilities.FeatureFirewallIPv6) != nil || seen.Log.Check(capabilities.FeatureFirewallLog) != nil ||
		seen.Tag.Check(capabilities.FeatureFirewallTagGroups) != nil {
		t.Errorf("grants handed to the write = %+v, want each feature's in its slot", seen)
	}

	// A row needing nothing asks no gate.
	g.used = nil
	if err := s.writeFirewallRow(context.Background(), nil, nil, func(context.Context, firewallGrants) error { return nil }); err != nil || len(g.used) != 0 {
		t.Errorf("a row needing no feature: %v, gates asked %v", err, g.used)
	}
	// A feature no firewall writer takes is refused before any gate.
	if err := s.writeFirewallRow(context.Background(), []capabilities.Feature{capabilities.FeatureNICGuards}, nil,
		func(context.Context, firewallGrants) error { return nil }); err == nil || len(g.used) != 0 {
		t.Errorf("a row needing nic_guards: %v, gates asked %v; want refused before any gate", err, g.used)
	}
}

// A client's logged action or tag-group cidr is refused by every rule handler
// at any latch state — InvalidArgument, "not supported yet" — before any gate
// is asked, and nothing reaches storage: no renderer on this build renders
// either. An IPv6 rule after the latch is written through its gate as before.
//
// Mutations: drop the "+" refusal in FirewallRowFeatures — after the latch
// the logged rule is stored, red; drop the tag refusal — the tag rule is
// stored, red.
func TestRuleHandlers_RefuseClientLogAndTagForms(t *testing.T) {
	s := testServer(t)
	g := &relGate{t: t}
	s.SetReleaseFeatureGate(g)
	ctx := adminCtxWithEngine(t, s)
	sg, err := s.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "web"})
	if err != nil {
		t.Fatal(err)
	}
	writes := func(cidr, action string) map[string]func() error {
		rule := func() *pb.FirewallRule {
			return &pb.FirewallRule{Direction: "ingress", Proto: "tcp", Port: "22", Cidr: cidr, Action: action}
		}
		return map[string]func() error{
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
					SgId: sg.GetId(), Direction: "ingress", Proto: "tcp", Port: "22", Cidr: cidr, Action: action}})
				return err
			},
		}
	}
	for _, latched := range []bool{false, true} {
		g.open = latched
		for _, form := range []struct{ cidr, action string }{
			{"10.0.0.0/8", "drop+log"},
			{"2001:db8::/32", "accept+log"},
			{"tag:web", "accept"},
		} {
			for what, w := range writes(form.cidr, form.action) {
				if err := w(); status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "not supported") {
					t.Errorf("latched=%v: %s %s/%s: %v, want InvalidArgument \"not supported\"", latched, what, form.cidr, form.action, err)
				}
			}
		}
	}
	if len(g.used) != 0 || g.calls != 0 {
		t.Errorf("a refused client form asked the gate %d time(s) (%v)", g.calls, g.used)
	}
	bg := context.Background()
	if rules, err := corrosion.ListClusterFirewallRules(bg, s.db); err != nil || len(rules) != 0 {
		t.Errorf("cluster rules stored = %v, %v; want none", rules, err)
	}
	if rules, err := corrosion.ListHostFirewallRules(bg, s.db, ""); err != nil || len(rules) != 0 {
		t.Errorf("host rules stored = %v, %v; want none", rules, err)
	}
	if rules, err := corrosion.ListSGRules(bg, s.db, sg.GetId()); err != nil || len(rules) != 0 {
		t.Errorf("sg rules stored = %v, %v; want none", rules, err)
	}
	// After the latch an IPv6 rule still goes through its gate.
	if _, err := s.CreateClusterFirewallRule(ctx, &pb.CreateClusterFirewallRuleRequest{Rule: &pb.FirewallRule{
		Direction: "ingress", Proto: "tcp", Port: "22", Cidr: "2001:db8::/32", Action: "drop"}}); err != nil {
		t.Errorf("an IPv6 rule after the latch: %v", err)
	}
	if !slices.Equal(g.used, []capabilities.Feature{capabilities.FeatureFirewallIPv6}) {
		t.Errorf("uses recorded = %v, want firewall_ipv6", g.used)
	}
}

// A compose stack holding a client logged action or a tag-group cidr is
// refused before its old rows are torn down, at any latch state, and no gate
// is asked; the stack's existing rows stay.
//
// Mutation: drop either refusal — the stack is persisted (after the latch) or
// refused only by the gate after asking it, red.
func TestStackFirewall_RefusesClientLogAndTagForms(t *testing.T) {
	s := testServer(t)
	g := &relGate{t: t}
	s.SetReleaseFeatureGate(g)
	bg := context.Background()
	parse := func(cidr, action string) *compose.File {
		t.Helper()
		// ParseStored: the daemon's own refusal is under test; the compose
		// validator refuses both forms first (its field grammar).
		f, err := compose.ParseStored([]byte(`
name: fwstack
security-groups:
  web:
    rules:
      - {direction: ingress, proto: tcp, port: "80", cidr: "10.0.0.0/8", action: accept}
firewall:
  cluster-rules:
    - {direction: ingress, proto: tcp, port: "22", cidr: "` + cidr + `", action: "` + action + `"}
`))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return f
	}
	if err := s.persistStackFirewall(bg, parse("10.1.0.0/16", "accept")); err != nil {
		t.Fatal(err)
	}
	before, err := corrosion.ListClusterFirewallRules(bg, s.db)
	if err != nil || len(before) != 1 {
		t.Fatalf("stack rules = %v, %v", before, err)
	}
	for _, latched := range []bool{false, true} {
		g.open = latched
		for _, form := range []struct{ cidr, action string }{{"10.0.0.0/8", "drop+log"}, {"tag:web", "accept"}} {
			err := s.persistStackFirewall(bg, parse(form.cidr, form.action))
			if !errors.Is(err, corrosion.ErrFirewallRuleFormUnsupported) {
				t.Errorf("latched=%v: stack with %s/%s: %v, want ErrFirewallRuleFormUnsupported", latched, form.cidr, form.action, err)
			}
		}
	}
	if g.calls != 0 {
		t.Errorf("a refused stack asked the gate %d time(s) (%v)", g.calls, g.used)
	}
	after, err := corrosion.ListClusterFirewallRules(bg, s.db)
	if err != nil || len(after) != 1 || after[0].ID != before[0].ID {
		t.Errorf("stack rules after the refusals = %v, %v; want the old rule kept", after, err)
	}
}
