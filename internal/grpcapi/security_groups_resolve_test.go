package grpcapi

import (
	"context"
	"strings"
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

// A rule an older client stored with the group's name in sg_id is read as the
// group's own, so it applies and shows up under the group; no row is rewritten.
func TestSecurityGroupLegacyNameRule_ReadAsGroupsOwn(t *testing.T) {
	s := testServer(t)
	ctx := adminCtxWithEngine(t, s)
	bg := context.Background()
	addSG(t, s, "sg-aaa", "web", "")
	if err := corrosion.InsertSGRule(bg, s.db, corrosion.SGRule{ID: "legacy", SGID: "web", Direction: "ingress", Proto: "tcp", PortRange: "80"}); err != nil {
		t.Fatal(err)
	}

	resp, err := s.ListSecurityGroups(ctx, &pb.ListSecurityGroupsRequest{IncludeRules: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Rules) != 1 || resp.Rules[0].Id != "legacy" || resp.Rules[0].SgId != "sg-aaa" {
		t.Fatalf("rules = %v, want the legacy rule attributed to sg-aaa", resp.Rules)
	}
	stored, _ := corrosion.GetSGRule(bg, s.db, "legacy")
	if stored == nil || stored.SGID != "web" {
		t.Errorf("stored row was rewritten: %+v", stored)
	}
}

// With two live groups of the name it is not in the data which one the rule
// meant: it stays unapplied rather than landing on a guess.
func TestSecurityGroupLegacyNameRule_AmbiguousIsNotGuessed(t *testing.T) {
	s := testServer(t)
	ctx := adminCtxWithEngine(t, s)
	bg := context.Background()
	addSG(t, s, "sg-aaa", "web", "")
	addSG(t, s, "sg-bbb", "web", "shop")
	if err := corrosion.InsertSGRule(bg, s.db, corrosion.SGRule{ID: "legacy", SGID: "web", Direction: "ingress"}); err != nil {
		t.Fatal(err)
	}
	resp, err := s.ListSecurityGroups(ctx, &pb.ListSecurityGroupsRequest{IncludeRules: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range resp.Rules {
		if r.SgId != "web" { // reported unattributed, sg_id left as the bare name
			t.Errorf("an ambiguous legacy rule was attributed to %q", r.SgId)
		}
	}
}

// Deleting the group takes its legacy name-keyed rules with it; left behind they
// would attach to a later group of the same name.
func TestDeleteSecurityGroup_TakesLegacyNameRules(t *testing.T) {
	s := testServer(t)
	ctx := adminCtxWithEngine(t, s)
	bg := context.Background()
	addSG(t, s, "sg-aaa", "web", "")
	if err := corrosion.InsertSGRule(bg, s.db, corrosion.SGRule{ID: "legacy", SGID: "web", Direction: "ingress"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteSecurityGroup(ctx, &pb.DeleteSecurityGroupRequest{Id: "sg-aaa"}); err != nil {
		t.Fatal(err)
	}
	addSG(t, s, "sg-new", "web", "")
	resp, err := s.ListSecurityGroups(ctx, &pb.ListSecurityGroupsRequest{IncludeRules: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Rules) != 0 {
		t.Errorf("a deleted group's legacy rule attached to a new group: %v", resp.Rules)
	}
}

// Deleting one of two same-named groups must not hand a legacy name-keyed rule
// (unapplied while the name was shared) to the survivor.
func TestDeleteSecurityGroup_SharedNameLegacyRuleDoesNotFlipToSurvivor(t *testing.T) {
	s := testServer(t)
	ctx := adminCtxWithEngine(t, s)
	bg := context.Background()
	addSG(t, s, "sg-aaa", "web", "")
	addSG(t, s, "sg-bbb", "web", "shop")
	if err := corrosion.InsertSGRule(bg, s.db, corrosion.SGRule{ID: "legacy", SGID: "web", Direction: "ingress", Proto: "tcp", PortRange: "22"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteSecurityGroup(ctx, &pb.DeleteSecurityGroupRequest{Id: "sg-aaa"}); err != nil {
		t.Fatal(err)
	}
	resp, err := s.ListSecurityGroups(ctx, &pb.ListSecurityGroupsRequest{IncludeRules: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Rules) != 0 {
		t.Errorf("the survivor inherited an unattributed legacy rule: %v", resp.Rules)
	}
	// And the removal is in the audit record.
}

// While two groups share the name the legacy rule is reported, with sg_id left
// as the bare name, rather than silently unapplied.
func TestListSecurityGroups_ReportsAmbiguousLegacyRule(t *testing.T) {
	s := testServer(t)
	ctx := adminCtxWithEngine(t, s)
	bg := context.Background()
	addSG(t, s, "sg-aaa", "web", "")
	addSG(t, s, "sg-bbb", "web", "shop")
	if err := corrosion.InsertSGRule(bg, s.db, corrosion.SGRule{ID: "legacy", SGID: "web", Direction: "ingress"}); err != nil {
		t.Fatal(err)
	}
	resp, err := s.ListSecurityGroups(ctx, &pb.ListSecurityGroupsRequest{IncludeRules: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Rules) != 1 || resp.Rules[0].Id != "legacy" || resp.Rules[0].SgId != "web" {
		t.Errorf("rules = %v, want the legacy rule reported with sg_id=web", resp.Rules)
	}
}

// The delete's audit "before" includes the legacy rules it removes.
func TestDeleteSecurityGroup_AuditBeforeIncludesLegacyRules(t *testing.T) {
	s := testServer(t)
	bg := context.Background()
	addSG(t, s, "sg-aaa", "web", "")
	if err := corrosion.InsertSGRule(bg, s.db, corrosion.SGRule{ID: "legacy", SGID: "web", Direction: "ingress", Proto: "tcp", PortRange: "2222"}); err != nil {
		t.Fatal(err)
	}
	if got := corrosion.SecurityGroupAuditState(bg, s.db, "sg-aaa"); !strings.Contains(got, "2222") {
		t.Errorf("audit state omits the legacy rule: %s", got)
	}
}
