package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// sgProjectsFixture is a server with sg_projects_v1 latched, a global group
// "base", a group "a-web" of project acme and "b-web" of project other, each
// with one rule, and a real RBAC engine on which:
//
//   - alice holds NetworkAdmin on /projects/acme only;
//   - root holds Admin on /.
type sgProjectsFixture struct {
	s                *Server
	alice, root      context.Context
	base, aWeb, bWeb *pb.SecurityGroup
	baseRule, bRule  *pb.SecurityGroupRule
}

func newSGProjectsFixture(t *testing.T) *sgProjectsFixture {
	t.Helper()
	ctx := context.Background()
	s := testServer(t)
	s.db.SetSGProjectsGate(func() bool { return true })
	if err := auth.SeedBuiltinRoles(ctx, s.db); err != nil {
		t.Fatalf("SeedBuiltinRoles: %v", err)
	}
	for _, g := range []struct{ user, path, role string }{
		{"alice", "/projects/acme", "NetworkAdmin"},
		{"root", "/", "Admin"},
	} {
		if err := corrosion.InsertUser(ctx, s.db, g.user, "operator", "x"); err != nil {
			t.Fatalf("InsertUser %s: %v", g.user, err)
		}
		if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
			ID: g.user + "-binding", Path: g.path, Role: g.role,
			Principal: "user:" + g.user + "@local", Propagate: true,
		}); err != nil {
			t.Fatalf("InsertRoleBinding %s: %v", g.user, err)
		}
	}
	engine := auth.NewEngine(s.db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	s.SetAuthEngine(engine)

	f := &sgProjectsFixture{s: s, alice: userCtx("alice", "operator"), root: userCtx("root", "operator")}
	mk := func(name, project string) (*pb.SecurityGroup, *pb.SecurityGroupRule) {
		g, err := s.CreateSecurityGroup(f.root, &pb.CreateSecurityGroupRequest{Name: name, Project: project})
		if err != nil {
			t.Fatalf("root creates %s (project %q): %v", name, project, err)
		}
		r, err := s.AddSecurityGroupRule(f.root, &pb.AddSecurityGroupRuleRequest{Rule: &pb.SecurityGroupRule{
			SgId: g.Id, Direction: "ingress", Proto: "tcp", Port: "22", Cidr: "10.9.0.0/16", Action: "accept",
		}})
		if err != nil {
			t.Fatalf("root adds a rule to %s: %v", name, err)
		}
		return g, r
	}
	f.base, f.baseRule = mk("base", "")
	f.aWeb, _ = mk("a-web", "acme")
	f.bWeb, f.bRule = mk("b-web", "other")
	return f
}

func wantSGCode(t *testing.T, what string, err error, want codes.Code) {
	t.Helper()
	if status.Code(err) != want {
		t.Fatalf("%s: %v, want %v", what, err, want)
	}
}

func groupNames(resp *pb.ListSecurityGroupsResponse) []string {
	var out []string
	for _, g := range resp.GetGroups() {
		out = append(out, g.GetName()+"@"+g.GetProject())
	}
	return out
}

func ruleGroups(resp *pb.ListSecurityGroupsResponse) map[string]bool {
	out := map[string]bool{}
	for _, r := range resp.GetRules() {
		out[r.GetSgId()] = true
	}
	return out
}

// A group is created where the caller holds sg.write: a project-scoped
// NetworkAdmin creates in its own project and nowhere else, a global group
// included; the stored group carries its project.
func TestSGProjects_CreateIsAuthorizedOnTheGroupsProject(t *testing.T) {
	f := newSGProjectsFixture(t)
	g, err := f.s.CreateSecurityGroup(f.alice, &pb.CreateSecurityGroupRequest{Name: "a-db", Project: "acme"})
	if err != nil {
		t.Fatalf("alice creates in her own project: %v", err)
	}
	if g.GetProject() != "acme" {
		t.Errorf("created group's project = %q, want acme", g.GetProject())
	}
	_, err = f.s.CreateSecurityGroup(f.alice, &pb.CreateSecurityGroupRequest{Name: "b-db", Project: "other"})
	wantSGCode(t, "alice creates in another project", err, codes.PermissionDenied)
	_, err = f.s.CreateSecurityGroup(f.alice, &pb.CreateSecurityGroupRequest{Name: "glob"})
	wantSGCode(t, "alice creates a global group", err, codes.PermissionDenied)
	_, err = f.s.CreateSecurityGroup(f.root, &pb.CreateSecurityGroupRequest{Name: "bad", Project: "../x"})
	wantSGCode(t, "a malformed project", err, codes.InvalidArgument)
}

// A duplicate name is refused across projects (a NIC binds by name), and the
// refusal does not hand a caller the id of a group it may not read.
func TestSGProjects_ADuplicateNameDoesNotLeakAnotherProjectsGroup(t *testing.T) {
	f := newSGProjectsFixture(t)
	_, err := f.s.CreateSecurityGroup(f.alice, &pb.CreateSecurityGroupRequest{Name: "b-web", Project: "acme"})
	wantSGCode(t, "alice reuses another project's group name", err, codes.AlreadyExists)
	if strings.Contains(err.Error(), f.bWeb.GetId()) {
		t.Errorf("the refusal names another project's group id: %v", err)
	}
	_, err = f.s.CreateSecurityGroup(f.root, &pb.CreateSecurityGroupRequest{Name: "b-web"})
	wantSGCode(t, "root reuses the name", err, codes.AlreadyExists)
	if !strings.Contains(err.Error(), f.bWeb.GetId()) {
		t.Errorf("root's refusal should name the existing group: %v", err)
	}
}

// Until sg_projects_v1 latches a project group is refused as an upgrade still
// in progress, and a global group is created as before.
func TestSGProjects_AProjectGroupBeforeTheLatchIsFailedPrecondition(t *testing.T) {
	s := testServer(t)
	_, err := s.CreateSecurityGroup(adminCtx(), &pb.CreateSecurityGroupRequest{Name: "web", Project: "acme"})
	wantSGCode(t, "a project group before the latch", err, codes.FailedPrecondition)
	if !strings.Contains(err.Error(), "sg_projects_v1") {
		t.Errorf("the refusal does not name the token: %v", err)
	}
	if _, err := s.CreateSecurityGroup(adminCtx(), &pb.CreateSecurityGroupRequest{Name: "web"}); err != nil {
		t.Fatalf("a global group before the latch: %v", err)
	}
}

// The listing: root sees every group and rule; a project-scoped caller sees
// its project's groups, plus the global ones (names only) when it names the
// project, and never another project's.
func TestSGProjects_ListIsFilteredByProject(t *testing.T) {
	f := newSGProjectsFixture(t)

	resp, err := f.s.ListSecurityGroups(f.root, &pb.ListSecurityGroupsRequest{IncludeRules: true})
	if err != nil {
		t.Fatalf("root lists: %v", err)
	}
	if got := groupNames(resp); strings.Join(got, ",") != "a-web@acme,b-web@other,base@" {
		t.Errorf("root sees %v, want every group", got)
	}
	if rg := ruleGroups(resp); !rg[f.base.Id] || !rg[f.aWeb.Id] || !rg[f.bWeb.Id] {
		t.Errorf("root does not see every group's rules: %v", rg)
	}
	resp, err = f.s.ListSecurityGroups(f.root, &pb.ListSecurityGroupsRequest{Project: "acme"})
	if err != nil {
		t.Fatalf("root lists acme: %v", err)
	}
	if got := groupNames(resp); strings.Join(got, ",") != "a-web@acme,base@" {
		t.Errorf("root's acme view = %v, want acme's groups and the global ones", got)
	}

	resp, err = f.s.ListSecurityGroups(f.alice, &pb.ListSecurityGroupsRequest{IncludeRules: true})
	if err != nil {
		t.Fatalf("alice lists: %v", err)
	}
	if got := groupNames(resp); strings.Join(got, ",") != "a-web@acme" {
		t.Errorf("alice sees %v, want only her project's group", got)
	}
	if rg := ruleGroups(resp); rg[f.bWeb.Id] || rg[f.base.Id] || !rg[f.aWeb.Id] {
		t.Errorf("alice's rules come from %v, want only a-web's", rg)
	}

	resp, err = f.s.ListSecurityGroups(f.alice, &pb.ListSecurityGroupsRequest{Project: "acme", IncludeRules: true})
	if err != nil {
		t.Fatalf("alice lists acme: %v", err)
	}
	if got := groupNames(resp); strings.Join(got, ",") != "a-web@acme,base@" {
		t.Errorf("alice's acme view = %v, want a-web and the global base", got)
	}
	if rg := ruleGroups(resp); rg[f.base.Id] || rg[f.bWeb.Id] || !rg[f.aWeb.Id] {
		t.Errorf("alice's acme view has rules of %v: a global group's rules are read at / only", rg)
	}

	_, err = f.s.ListSecurityGroups(f.alice, &pb.ListSecurityGroupsRequest{Project: "other"})
	wantSGCode(t, "alice lists another project", err, codes.PermissionDenied)
}

// Every write on a group is authorized on that group's project: alice can
// change her own project's groups and neither another project's nor a global
// one.
func TestSGProjects_WritesAreAuthorizedOnTheGroupsProject(t *testing.T) {
	f := newSGProjectsFixture(t)
	rule := func(sg string) *pb.SecurityGroupRule {
		return &pb.SecurityGroupRule{SgId: sg, Direction: "ingress", Proto: "tcp", Port: "80", Action: "accept"}
	}

	for _, g := range []*pb.SecurityGroup{f.bWeb, f.base} {
		_, err := f.s.AddSecurityGroupRule(f.alice, &pb.AddSecurityGroupRuleRequest{Rule: rule(g.Id)})
		wantSGCode(t, "alice adds a rule to "+g.Name, err, codes.PermissionDenied)
		_, err = f.s.AddSecurityGroupRule(f.alice, &pb.AddSecurityGroupRuleRequest{Rule: rule(g.Name)})
		wantSGCode(t, "alice adds a rule to "+g.Name+" by name", err, codes.PermissionDenied)
		_, err = f.s.DeleteSecurityGroup(f.alice, &pb.DeleteSecurityGroupRequest{Id: g.Id})
		wantSGCode(t, "alice deletes "+g.Name, err, codes.PermissionDenied)
	}
	for _, r := range []*pb.SecurityGroupRule{f.bRule, f.baseRule} {
		_, err := f.s.RemoveSecurityGroupRule(f.alice, &pb.RemoveSecurityGroupRuleRequest{Id: r.Id})
		wantSGCode(t, "alice removes a rule of "+r.SgId, err, codes.PermissionDenied)
	}
	for _, id := range []string{f.bWeb.Id, f.base.Id} {
		if g, _ := corrosion.GetSecurityGroup(context.Background(), f.s.db, id); g == nil {
			t.Fatalf("a refused delete removed group %s", id)
		}
	}

	added, err := f.s.AddSecurityGroupRule(f.alice, &pb.AddSecurityGroupRuleRequest{Rule: rule(f.aWeb.Id)})
	if err != nil {
		t.Fatalf("alice adds a rule to her own group: %v", err)
	}
	if _, err := f.s.RemoveSecurityGroupRule(f.alice, &pb.RemoveSecurityGroupRuleRequest{Id: added.Id}); err != nil {
		t.Fatalf("alice removes her own rule: %v", err)
	}
	if _, err := f.s.DeleteSecurityGroup(f.alice, &pb.DeleteSecurityGroupRequest{Id: f.aWeb.Id}); err != nil {
		t.Fatalf("alice deletes her own group: %v", err)
	}
	// root reaches every project.
	if _, err := f.s.DeleteSecurityGroup(f.root, &pb.DeleteSecurityGroupRequest{Id: f.bWeb.Id}); err != nil {
		t.Fatalf("root deletes another project's group: %v", err)
	}
}

// A NIC of a workload in acme may bind acme's groups and the global ones,
// never other's — whoever asks, root included, because the rule is about the
// workload.
func TestSGProjects_BindRefusesAnotherProjectsGroup(t *testing.T) {
	f := newSGProjectsFixture(t)
	seedSGVM(t, f.s, "web", "acme")

	for _, who := range []context.Context{f.alice, f.root} {
		_, err := f.s.BindSecurityGroups(who, &pb.BindSecurityGroupsRequest{
			VmName: "web", NetworkName: "lan", SecurityGroups: []string{"a-web", "b-web"},
		})
		wantSGCode(t, "binding other's group to an acme VM", err, codes.PermissionDenied)
		if !strings.Contains(err.Error(), "b-web") {
			t.Errorf("the refusal does not name the group: %v", err)
		}
	}
	ifaces, _ := corrosion.GetVMInterfaces(context.Background(), f.s.db, "web")
	if len(ifaces) != 1 || len(ifaces[0].SecurityGroups) != 0 {
		t.Fatalf("a refused bind changed the NIC: %+v", ifaces)
	}
	if _, err := f.s.BindSecurityGroups(f.alice, &pb.BindSecurityGroupsRequest{
		VmName: "web", NetworkName: "lan", SecurityGroups: []string{"a-web", "base", "not-yet-created"},
	}); err != nil {
		t.Fatalf("alice binds her project's group and a global one: %v", err)
	}
}
