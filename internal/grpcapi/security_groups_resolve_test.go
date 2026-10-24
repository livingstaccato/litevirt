package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func addSG(t *testing.T, s *Server, id, name, stack string) {
	t.Helper()
	if err := corrosion.InsertSecurityGroup(context.Background(), s.db, corrosion.SecurityGroup{ID: id, Name: name, StackName: stack}); err != nil {
		t.Fatal(err)
	}
}

func ruleAdd(s *Server, ctx context.Context, ref string) (*pb.SecurityGroupRule, error) {
	return s.AddSecurityGroupRule(ctx, &pb.AddSecurityGroupRuleRequest{Rule: &pb.SecurityGroupRule{
		SgId: ref, Direction: "ingress", Proto: "tcp", Port: "22",
	}})
}

// `lv sg rule-add <name>` used to store the name in sg_id, a rule no group
// owned and the firewall never rendered. A name resolves to the group's id.
func TestAddSecurityGroupRule_NameResolvesToGroupID(t *testing.T) {
	s := testServer(t)
	ctx := adminCtxWithEngine(t, s)
	addSG(t, s, "sg-aaa", "web", "")

	got, err := ruleAdd(s, ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	if got.SgId != "sg-aaa" {
		t.Errorf("rule sg_id = %q, want the group id sg-aaa", got.SgId)
	}
	rules, err := corrosion.ListSGRules(context.Background(), s.db, "sg-aaa")
	if err != nil || len(rules) != 1 {
		t.Fatalf("rules under the group id = %v (err %v), want 1", rules, err)
	}
	if byName, _ := corrosion.ListSGRules(context.Background(), s.db, "web"); len(byName) != 0 {
		t.Errorf("a rule was stored under the NAME: %v", byName)
	}
	// An id still works.
	if got, err := ruleAdd(s, ctx, "sg-aaa"); err != nil || got.SgId != "sg-aaa" {
		t.Errorf("rule-add by id = %v, %v", got, err)
	}
}

func TestAddSecurityGroupRule_UnknownGroupIsNotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtxWithEngine(t, s)
	addSG(t, s, "sg-aaa", "web", "")

	_, err := ruleAdd(s, ctx, "nope")
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
	rows, _ := s.db.Query(context.Background(), `SELECT id FROM sg_rules`)
	if len(rows) != 0 {
		t.Errorf("a rule was stored for a nonexistent group: %d rows", len(rows))
	}
}

func TestAddSecurityGroupRule_AmbiguousNameIsRefused(t *testing.T) {
	s := testServer(t)
	ctx := adminCtxWithEngine(t, s)
	addSG(t, s, "sg-aaa", "web", "")
	addSG(t, s, "sg-bbb", "web", "shop")

	_, err := ruleAdd(s, ctx, "web")
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
	// The id of either still works.
	if _, err := ruleAdd(s, ctx, "sg-bbb"); err != nil {
		t.Errorf("rule-add by id: %v", err)
	}
}
