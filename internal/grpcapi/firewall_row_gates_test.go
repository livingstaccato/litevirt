package grpcapi

import (
	"context"
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
// Mutations: ask only the first feature's gate — the log use is not recorded
// and the row is refused (no gLog), red; nest log outside IPv6 — the recorded
// order is wrong, red; hand the IPv6 grant to every slot — the writer's log
// check fails, red.
func TestWriteFirewallRow_AsksEveryGateTheRowNeeds(t *testing.T) {
	s := testServer(t)
	g := &relGate{t: t, open: true}
	s.SetReleaseFeatureGate(g)
	ctx := adminCtxWithEngine(t, s)

	// Through the handler: an IPv6 logged cluster rule.
	r, err := s.CreateClusterFirewallRule(ctx, &pb.CreateClusterFirewallRuleRequest{Rule: &pb.FirewallRule{
		Direction: "ingress", Proto: "tcp", Port: "22", Cidr: "2001:db8::/32", Action: "drop+log"}})
	if err != nil {
		t.Fatalf("an IPv6 logged rule after the latch: %v", err)
	}
	want := []capabilities.Feature{capabilities.FeatureFirewallIPv6, capabilities.FeatureFirewallLog}
	if !slices.Equal(g.used, want) {
		t.Errorf("gates asked = %v, want %v (IPv6 outermost)", g.used, want)
	}
	if got, gerr := corrosion.GetClusterFirewallRule(context.Background(), s.db, r.GetId()); gerr != nil || got == nil {
		t.Errorf("the rule was not written: %v, %v", got, gerr)
	}

	// Directly: the write sees each grant in its own slot, whatever order
	// the features were named in.
	g.used = nil
	var seen firewallGrants
	need := []capabilities.Feature{capabilities.FeatureFirewallTagGroups, capabilities.FeatureFirewallLog, capabilities.FeatureFirewallIPv6}
	if err := s.writeFirewallRow(context.Background(), need, nil, func(_ context.Context, gs firewallGrants) error {
		seen = gs
		return nil
	}); err != nil {
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

// Before the latch a logged or tag-group rule is refused with the release
// text and nothing is written; an ordinary IPv4 rule never touches the gate.
func TestWriteFirewallRow_LogAndTagRefusedBeforeTheLatch(t *testing.T) {
	s := testServer(t)
	g := &relGate{t: t}
	s.SetReleaseFeatureGate(g)
	ctx := adminCtxWithEngine(t, s)
	sg, err := s.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "web"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		cidr, action string
		feature      capabilities.Feature
	}{
		{"10.0.0.0/8", "drop+log", capabilities.FeatureFirewallLog},
		{"tag:web", "accept", capabilities.FeatureFirewallTagGroups},
	} {
		_, err := s.AddSecurityGroupRule(ctx, &pb.AddSecurityGroupRuleRequest{Rule: &pb.SecurityGroupRule{
			SgId: sg.GetId(), Direction: "ingress", Proto: "tcp", Cidr: tc.cidr, Action: tc.action}})
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), fwReleaseRefusal(tc.feature)) {
			t.Errorf("%s %s before the latch: %v, want the %s release refusal", tc.cidr, tc.action, err, tc.feature)
		}
	}
	if _, err := s.AddSecurityGroupRule(ctx, &pb.AddSecurityGroupRuleRequest{Rule: &pb.SecurityGroupRule{
		SgId: sg.GetId(), Direction: "ingress", Proto: "tcp", Cidr: "10.0.0.0/8", Action: "drop"}}); err != nil {
		t.Errorf("an IPv4 rule before the latch: %v", err)
	}
	if len(g.used) != 0 {
		t.Errorf("uses recorded = %v, want none", g.used)
	}
	rules, err := corrosion.ListSGRules(context.Background(), s.db, sg.GetId())
	if err != nil || len(rules) != 1 {
		t.Errorf("rules stored = %v, %v; want only the IPv4 one", rules, err)
	}
}

// A stack takes every feature its rows need before the old rows are torn
// down, then once more ahead of each row that needs it.
func TestWriteFirewallRow_StackTakesEveryFeatureFirst(t *testing.T) {
	s := testServer(t)
	g := &relGate{t: t, open: true}
	s.SetReleaseFeatureGate(g)
	f, err := compose.ParseBytes([]byte(`
name: logstack
security-groups:
  web:
    rules:
      - {direction: ingress, proto: tcp, port: "80", cidr: "tag:web", action: accept}
firewall:
  cluster-rules:
    - {direction: ingress, proto: tcp, port: "22", cidr: "2001:db8::/32", action: "drop+log"}
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := s.persistStackFirewall(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	v6, lg, tg := capabilities.FeatureFirewallIPv6, capabilities.FeatureFirewallLog, capabilities.FeatureFirewallTagGroups
	want := []capabilities.Feature{v6, lg, tg, tg, v6, lg}
	if !slices.Equal(g.used, want) {
		t.Errorf("uses recorded = %v, want %v: each feature before the teardown, then per row", g.used, want)
	}
}
