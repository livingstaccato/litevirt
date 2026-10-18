package grpcapi

import (
	"context"
	"slices"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// C2: log=true on each rule handler goes through the firewall_log gate. Before
// the latch it is refused with the release text and nothing is stored; after
// it the row is stored with the server's "+log" suffix (an empty action as
// "accept+log"), and every reply — the create's and the list's — carries the
// plain verdict and log, never the suffix. An IPv6 logged rule asks both gates,
// IPv6 outermost.
//
// Mutations: ignore log — nothing is logged and no gate asked, red; store the
// suffix but skip the log gate — the closed gate does not refuse, red; reply
// with the stored action — "drop+log" in the reply, red.
func TestRuleHandlers_LogGoesThroughTheLogGate(t *testing.T) {
	s := testServer(t)
	g := &relGate{t: t}
	s.SetReleaseFeatureGate(g)
	ctx := adminCtxWithEngine(t, s)
	sg, err := s.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "web"})
	if err != nil {
		t.Fatal(err)
	}
	type reply struct {
		action string
		log    bool
	}
	writes := map[string]func(cidr, action string) (reply, error){
		"cluster rule": func(cidr, action string) (reply, error) {
			r, err := s.CreateClusterFirewallRule(ctx, &pb.CreateClusterFirewallRuleRequest{Rule: &pb.FirewallRule{
				Direction: "ingress", Proto: "tcp", Port: "22", Cidr: cidr, Action: action, Log: true}})
			return reply{r.GetAction(), r.GetLog()}, err
		},
		"host rule": func(cidr, action string) (reply, error) {
			r, err := s.CreateHostFirewallRule(ctx, &pb.CreateHostFirewallRuleRequest{Rule: &pb.FirewallRule{
				HostName: s.hostName, Direction: "ingress", Proto: "tcp", Port: "22", Cidr: cidr, Action: action, Log: true}})
			return reply{r.GetAction(), r.GetLog()}, err
		},
		"sg rule": func(cidr, action string) (reply, error) {
			r, err := s.AddSecurityGroupRule(ctx, &pb.AddSecurityGroupRuleRequest{Rule: &pb.SecurityGroupRule{
				SgId: sg.GetId(), Direction: "ingress", Proto: "tcp", Port: "22", Cidr: cidr, Action: action, Log: true}})
			return reply{r.GetAction(), r.GetLog()}, err
		},
	}
	bg := context.Background()
	stored := func() []string {
		var out []string
		cr, _ := corrosion.ListClusterFirewallRules(bg, s.db)
		for _, r := range cr {
			out = append(out, r.Action)
		}
		hr, _ := corrosion.ListHostFirewallRules(bg, s.db, "")
		for _, r := range hr {
			out = append(out, r.Action)
		}
		sr, _ := corrosion.ListSGRules(bg, s.db, sg.GetId())
		for _, r := range sr {
			out = append(out, r.Action)
		}
		return out
	}

	g.open = false
	for what, w := range writes {
		g.used = nil
		if _, err := w("10.0.0.0/8", "drop"); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("before the latch: %s: %v, want FailedPrecondition", what, err)
		}
	}
	if got := stored(); len(got) != 0 {
		t.Fatalf("rows stored before the latch: %v", got)
	}
	if g.calls != 3 {
		t.Errorf("gate asked %d times before the latch, want once per handler", g.calls)
	}

	g.open = true
	for what, w := range writes {
		g.used = nil
		got, err := w("10.0.0.0/8", "DROP")
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if got != (reply{"drop", true}) {
			t.Errorf("%s reply = %+v, want drop with log", what, got)
		}
		if !slices.Equal(g.used, []capabilities.Feature{capabilities.FeatureFirewallLog}) {
			t.Errorf("%s: gates asked %v, want firewall_log", what, g.used)
		}
		g.used = nil
		if got, err := w("2001:db8::/32", ""); err != nil || got != (reply{"accept", true}) {
			t.Errorf("%s IPv6 with no action: %+v, %v; want accept with log", what, got, err)
		}
		if !slices.Equal(g.used, []capabilities.Feature{capabilities.FeatureFirewallIPv6, capabilities.FeatureFirewallLog}) {
			t.Errorf("%s IPv6: gates asked %v, want ipv6 then log", what, g.used)
		}
	}
	got := stored()
	slices.Sort(got)
	if want := []string{"accept+log", "accept+log", "accept+log", "drop+log", "drop+log", "drop+log"}; !slices.Equal(got, want) {
		t.Errorf("stored actions = %v, want %v", got, want)
	}

	lists := map[string]func() []reply{
		"cluster": func() []reply {
			r, err := s.ListClusterFirewallRules(ctx, &pb.ListClusterFirewallRulesRequest{})
			if err != nil {
				t.Fatal(err)
			}
			var out []reply
			for _, x := range r.GetRules() {
				out = append(out, reply{x.GetAction(), x.GetLog()})
			}
			return out
		},
		"host": func() []reply {
			r, err := s.ListHostFirewallRules(ctx, &pb.ListHostFirewallRulesRequest{})
			if err != nil {
				t.Fatal(err)
			}
			var out []reply
			for _, x := range r.GetRules() {
				out = append(out, reply{x.GetAction(), x.GetLog()})
			}
			return out
		},
		"sg": func() []reply {
			r, err := s.ListSecurityGroups(ctx, &pb.ListSecurityGroupsRequest{IncludeRules: true})
			if err != nil {
				t.Fatal(err)
			}
			var out []reply
			for _, x := range r.GetRules() {
				out = append(out, reply{x.GetAction(), x.GetLog()})
			}
			return out
		},
	}
	for what, l := range lists {
		got := l()
		if len(got) != 2 {
			t.Errorf("%s list = %+v, want two rules", what, got)
		}
		for _, r := range got {
			if !r.log || (r.action != "drop" && r.action != "accept") {
				t.Errorf("%s list reply %+v, want the plain verdict with log", what, r)
			}
		}
	}
}

// C2 (0-F): the use sweep probes firewall_log's data: a logged rule an older
// entry daemon stored verbatim, with no recorded use, has its use recorded.
//
// Mutation: leave releaseUseProbes without the log probe — red.
func TestReleaseUseSweep_LogProbe(t *testing.T) {
	s, g, _, _ := sweepServer(t, "")
	g.open = true
	ctx := context.Background()
	s.sweepReleaseUses(ctx, releaseUseProbes)
	if len(g.used) != 0 {
		t.Fatalf("with no data the sweep recorded %v", g.used)
	}
	if err := s.db.Execute(ctx, `INSERT INTO host_firewall_rules (id, host_name, direction, proto, port_range, cidr, action, priority, comment, created_at, updated_at)
		VALUES ('h', 'node-0', 'ingress', 'tcp', '', '', 'drop+log', 100, '', 't', 't')`); err != nil {
		t.Fatal(err)
	}
	s.sweepReleaseUses(ctx, releaseUseProbes)
	if !slices.Contains(g.used, capabilities.FeatureFirewallLog) {
		t.Errorf("uses recorded = %v, want firewall_log", g.used)
	}
}
