package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Cluster and host rules, ip sets and default policies are global rows every
// host enforces, as a stack's firewall is, so writing them directly needs
// sg.write at the cluster root too: an Operator, bound at / with sg.read
// only, can neither turn the cluster default-deny off nor add or remove a
// rule or ip set, and is told which grant it lacks. Admin and NetworkAdmin
// keep every write.
//
// Mutation: gate any one handler on the operator role again — its Operator
// case, red.
func TestFirewallRPCs_NeedSGWriteAtTheRoot(t *testing.T) {
	ctx := context.Background()
	s, opal, ada := stackFirewallFixture(t)
	if err := corrosion.InsertUser(ctx, s.db, "nora", "operator", "x"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
		ID: "nora", Path: "/", Role: "NetworkAdmin", Principal: "user:nora@local", Propagate: true,
	}); err != nil {
		t.Fatal(err)
	}
	engine := auth.NewEngine(s.db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	s.SetAuthEngine(engine)
	nora := userCtx("nora", "operator")

	rule := func() *pb.FirewallRule {
		return &pb.FirewallRule{Direction: "ingress", Proto: "tcp", Port: "22", Action: "accept"}
	}
	adminRule, err := s.CreateClusterFirewallRule(ada, &pb.CreateClusterFirewallRuleRequest{Rule: rule()})
	if err != nil {
		t.Fatalf("the Admin adds a cluster rule: %v", err)
	}
	hr := rule()
	hr.HostName = s.hostName
	adminHostRule, err := s.CreateHostFirewallRule(ada, &pb.CreateHostFirewallRuleRequest{Rule: hr})
	if err != nil {
		t.Fatalf("the Admin adds a host rule: %v", err)
	}
	adminSet, err := s.CreateIpSet(ada, &pb.CreateIpSetRequest{Name: "office", Cidrs: []string{"10.1.0.0/16"}})
	if err != nil {
		t.Fatalf("the Admin adds an ip set: %v", err)
	}

	writes := []struct {
		name string
		call func(ctx context.Context) error
	}{
		{"default-deny off", func(ctx context.Context) error {
			_, err := s.SetFirewallDefault(ctx, &pb.SetFirewallDefaultRequest{DefaultDeny: false})
			return err
		}},
		{"cluster-rule add", func(ctx context.Context) error {
			_, err := s.CreateClusterFirewallRule(ctx, &pb.CreateClusterFirewallRuleRequest{Rule: rule()})
			return err
		}},
		{"cluster-rule rm", func(ctx context.Context) error {
			_, err := s.DeleteClusterFirewallRule(ctx, &pb.DeleteClusterFirewallRuleRequest{Id: adminRule.Id})
			return err
		}},
		{"host-rule add", func(ctx context.Context) error {
			_, err := s.CreateHostFirewallRule(ctx, &pb.CreateHostFirewallRuleRequest{Rule: hr})
			return err
		}},
		{"host-rule rm", func(ctx context.Context) error {
			_, err := s.DeleteHostFirewallRule(ctx, &pb.DeleteHostFirewallRuleRequest{Id: adminHostRule.Id})
			return err
		}},
		{"ipset add", func(ctx context.Context) error {
			_, err := s.CreateIpSet(ctx, &pb.CreateIpSetRequest{Name: "lab", Cidrs: []string{"10.2.0.0/16"}})
			return err
		}},
		{"ipset rm", func(ctx context.Context) error {
			_, err := s.DeleteIpSet(ctx, &pb.DeleteIpSetRequest{Id: adminSet.Id})
			return err
		}},
	}
	for _, w := range writes {
		t.Run("operator/"+w.name, func(t *testing.T) {
			wantGrantHint(t, "an Operator's "+w.name, w.call(opal))
		})
	}
	if d, _ := corrosion.GetFirewallDefault(ctx, s.db, "cluster"); d == nil || !d.DefaultDeny {
		t.Errorf("the cluster default after the Operator's writes = %+v, want deny", d)
	}
	if r, _ := corrosion.GetClusterFirewallRule(ctx, s.db, adminRule.Id); r == nil {
		t.Error("the Operator removed a cluster rule")
	}
	if r, _ := corrosion.GetHostFirewallRule(ctx, s.db, adminHostRule.Id); r == nil {
		t.Error("the Operator removed a host rule")
	}
	if set, _ := corrosion.GetIPSet(ctx, s.db, adminSet.Id); set == nil {
		t.Error("the Operator removed an ip set")
	}
	// A NetworkAdmin at the root holds sg.write, and keeps every write.
	for _, w := range writes {
		if err := w.call(nora); err != nil {
			t.Errorf("a NetworkAdmin's %s: %v", w.name, err)
		}
	}
}

// With no role bindings at all, the legacy operator role still writes the
// firewall, and a viewer is still refused.
func TestFirewallRPCs_LegacyRolesWithoutBindings(t *testing.T) {
	s := testServer(t)
	if _, err := s.SetFirewallDefault(userCtx("op", "operator"), &pb.SetFirewallDefaultRequest{DefaultDeny: true}); err != nil {
		t.Fatalf("a legacy operator sets the default-deny: %v", err)
	}
	_, err := s.SetFirewallDefault(userCtx("vi", "viewer"), &pb.SetFirewallDefaultRequest{DefaultDeny: false})
	wantSGCode(t, "a legacy viewer turns the default-deny off", err, codes.PermissionDenied)
}
