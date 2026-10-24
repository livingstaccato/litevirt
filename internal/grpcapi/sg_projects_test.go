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
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// sgProjectsFixture is a server with the sg_projects feature open, a global group
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
	s.SetReleaseFeatureGate(fakeFeatureGate{t: t, grant: true})
	for _, p := range []string{"acme", "other"} {
		if err := corrosion.InsertProject(ctx, s.db, corrosion.ProjectRecord{Name: p}); err != nil {
			t.Fatalf("InsertProject %s: %v", p, err)
		}
	}
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

// A project group names a project that exists, under the name its workloads
// carry: a project nobody created, or another spelling of one, is refused.
func TestSGProjects_CreateNeedsAnExistingProject(t *testing.T) {
	f := newSGProjectsFixture(t)
	for _, p := range []string{"ghost", "acme/", "/acme"} {
		_, err := f.s.CreateSecurityGroup(f.root, &pb.CreateSecurityGroupRequest{Name: "g-" + strings.Trim(p, "/"), Project: p})
		wantSGCode(t, "a group of project "+p, err, codes.NotFound)
	}
}

// A rule that needs a release feature records that feature's cluster-wide
// used bit, so on a project's group it needs sg.write at the root; a plain
// rule does not.
func TestSGProjects_AFeatureRuleOnAProjectGroupNeedsTheRoot(t *testing.T) {
	f := newSGProjectsFixture(t)
	v6 := &pb.SecurityGroupRule{SgId: f.aWeb.Id, Direction: "ingress", Proto: "tcp", Port: "443", Cidr: "2001:db8::/32", Action: "accept"}
	_, err := f.s.AddSecurityGroupRule(f.alice, &pb.AddSecurityGroupRuleRequest{Rule: v6})
	wantSGCode(t, "alice adds an IPv6 rule to her group", err, codes.PermissionDenied)
	if _, err := f.s.AddSecurityGroupRule(f.root, &pb.AddSecurityGroupRuleRequest{Rule: v6}); err != nil {
		t.Fatalf("root adds the IPv6 rule: %v", err)
	}
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

// Until the release feature sg_projects is available a project group is
// refused as an upgrade still in progress, and a global group is created as
// before.
func TestSGProjects_AProjectGroupBeforeTheLatchIsFailedPrecondition(t *testing.T) {
	s := testServer(t)
	if err := corrosion.InsertProject(context.Background(), s.db, corrosion.ProjectRecord{Name: "acme"}); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateSecurityGroup(adminCtx(), &pb.CreateSecurityGroupRequest{Name: "web", Project: "acme"})
	wantSGCode(t, "a project group before the latch", err, codes.FailedPrecondition)
	if !strings.Contains(err.Error(), "sg_projects") {
		t.Errorf("the refusal does not name the feature: %v", err)
	}
	if g, _ := corrosion.ListSecurityGroups(context.Background(), s.db, ""); len(g) != 0 {
		t.Fatalf("a refused project group was stored: %+v", g)
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

// A stack's firewall block writes global security groups and the cluster
// default policy, so a deploy carrying one needs sg.write at the cluster root:
// an Operator (sg.read only) is refused before anything is written; Admin is
// not refused on that ground.
func TestDeployStack_AFirewallBlockNeedsSGWriteAtTheRoot(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	if err := auth.SeedBuiltinRoles(ctx, s.db); err != nil {
		t.Fatal(err)
	}
	for _, g := range []struct{ user, role string }{{"opal", "Operator"}, {"ada", "Admin"}} {
		if err := corrosion.InsertUser(ctx, s.db, g.user, "operator", "x"); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
			ID: g.user, Path: "/", Role: g.role, Principal: "user:" + g.user + "@local", Propagate: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	engine := auth.NewEngine(s.db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	s.SetAuthEngine(engine)
	const yaml = `name: fwonly
security-groups:
  web:
    rules:
      - {direction: ingress, proto: tcp, port: "80", action: accept}
firewall:
  default-deny: true
`
	err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: yaml}, &mockDeployStreamR2{ctx: userCtx("opal", "operator")})
	wantSGCode(t, "an Operator deploys a stack with a firewall", err, codes.PermissionDenied)
	if !strings.Contains(err.Error(), "sg.write") {
		t.Errorf("the refusal does not name sg.write: %v", err)
	}
	if g, _ := corrosion.ListSecurityGroups(ctx, s.db, ""); len(g) != 0 {
		t.Fatalf("a refused deploy wrote security groups: %+v", g)
	}
	err = s.DeployStack(&pb.DeployStackRequest{ComposeYaml: yaml}, &mockDeployStreamR2{ctx: userCtx("ada", "operator")})
	if status.Code(err) == codes.PermissionDenied {
		t.Fatalf("Admin's deploy was refused: %v", err)
	}
}

const fwStackYAML = `name: fwonly
security-groups:
  web:
    rules:
      - {direction: ingress, proto: tcp, port: "80", action: accept}
firewall:
  default-deny: true
`

const fwStackNoBlockYAML = `name: fwonly
`

// stackFirewallFixture binds opal as Operator (sg.read only) and ada as Admin
// at the root, and has ada deploy a stack whose firewall block holds a group
// and the cluster default-deny.
func stackFirewallFixture(t *testing.T) (s *Server, opal, ada context.Context) {
	t.Helper()
	ctx := context.Background()
	s = testServer(t)
	if err := auth.SeedBuiltinRoles(ctx, s.db); err != nil {
		t.Fatal(err)
	}
	for _, g := range []struct{ user, role string }{{"opal", "Operator"}, {"ada", "Admin"}} {
		if err := corrosion.InsertUser(ctx, s.db, g.user, "operator", "x"); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
			ID: g.user, Path: "/", Role: g.role, Principal: "user:" + g.user + "@local", Propagate: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	engine := auth.NewEngine(s.db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	s.SetAuthEngine(engine)
	opal, ada = userCtx("opal", "operator"), userCtx("ada", "operator")
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: fwStackYAML}, &mockDeployStreamR2{ctx: ada}); err != nil {
		t.Fatalf("Admin deploys the firewall stack: %v", err)
	}
	assertStackFirewallIntact(t, s, "after the Admin's deploy")
	return s, opal, ada
}

// assertStackFirewallIntact fails unless the stack's group is live and the
// cluster default is deny.
func assertStackFirewallIntact(t *testing.T, s *Server, when string) {
	t.Helper()
	ctx := context.Background()
	if g, _ := corrosion.ListSecurityGroups(ctx, s.db, "fwonly"); len(g) != 1 || g[0].Name != "web" {
		t.Fatalf("%s: the stack's groups are %+v, want web", when, g)
	}
	if d, err := corrosion.GetFirewallDefault(ctx, s.db, "cluster"); err != nil || d == nil || !d.DefaultDeny {
		t.Fatalf("%s: the cluster default is %+v (%v), want deny", when, d, err)
	}
}

func wantGrantHint(t *testing.T, what string, err error) {
	t.Helper()
	wantSGCode(t, what, err, codes.PermissionDenied)
	if !strings.Contains(err.Error(), "lv role grant NetworkAdmin user:opal@local --path / --propagate") {
		t.Errorf("%s: the refusal does not name the grant that fixes it: %v", what, err)
	}
}

// Redeploying a stack without its firewall block tombstones its groups and
// its default-deny, a write to the same global rows deploying them is, so an
// Operator without sg.write at the root is refused before anything changes.
func TestDeployStack_DroppingAStacksFirewallNeedsSGWriteAtTheRoot(t *testing.T) {
	s, opal, ada := stackFirewallFixture(t)
	err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: fwStackNoBlockYAML}, &mockDeployStreamR2{ctx: opal})
	wantGrantHint(t, "an Operator redeploys the stack without its firewall", err)
	assertStackFirewallIntact(t, s, "after the refused redeploy")

	// A dry run is not refused, and says the real run would be.
	st := &mockDeployStreamR2{ctx: opal}
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: fwStackNoBlockYAML, DryRun: true}, st); err != nil {
		t.Fatalf("an Operator's dry run: %v", err)
	}
	warned := false
	for _, p := range st.sent {
		warned = warned || (p.GetPhase() == "warning" && strings.Contains(p.GetDetail(), "would be refused") &&
			strings.Contains(p.GetDetail(), "lv role grant NetworkAdmin"))
	}
	if !warned {
		t.Errorf("the dry run did not say the real run would be refused: %+v", st.sent)
	}

	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: fwStackNoBlockYAML}, &mockDeployStreamR2{ctx: ada}); err != nil {
		t.Fatalf("the Admin drops the firewall: %v", err)
	}
	if g, _ := corrosion.ListSecurityGroups(context.Background(), s.db, "fwonly"); len(g) != 0 {
		t.Fatalf("the Admin's redeploy left the stack's groups: %+v", g)
	}
}

// `lv compose down` of a stack that owns firewall rows removes them, so it
// needs sg.write at the root too, and a refused down leaves the whole stack.
func TestDeleteStack_AStackThatOwnsAFirewallNeedsSGWriteAtTheRoot(t *testing.T) {
	s, opal, ada := stackFirewallFixture(t)
	err := s.DeleteStack(&pb.DeleteStackRequest{Name: "fwonly"}, &mockDeleteStream{ctx: opal})
	wantGrantHint(t, "an Operator tears the stack down", err)
	assertStackFirewallIntact(t, s, "after the refused down")
	if st, _ := corrosion.GetStack(context.Background(), s.db, "fwonly"); st == nil || st.State == stackStateDeleting {
		t.Fatalf("the refused down changed the stack row: %+v", st)
	}
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "fwonly"}, &mockDeleteStream{ctx: ada}); err != nil {
		t.Fatalf("the Admin tears the stack down: %v", err)
	}
	if g, _ := corrosion.ListSecurityGroups(context.Background(), s.db, "fwonly"); len(g) != 0 {
		t.Fatalf("the Admin's down left the stack's groups: %+v", g)
	}
}

// A project's group is never a stack's: stack teardown would remove it.
func TestSGProjects_AProjectGroupHasNoStack(t *testing.T) {
	f := newSGProjectsFixture(t)
	_, err := f.s.CreateSecurityGroup(f.alice, &pb.CreateSecurityGroupRequest{Name: "a-db", Project: "acme", StackName: "prod"})
	wantSGCode(t, "a project group with a stack", err, codes.InvalidArgument)
}

// A malformed project is refused before any authorization, for root and for
// a project-scoped caller alike. The CLI relies on it to tell a daemon that
// implements project groups from one that drops the field: only this answer
// proves the field was read.
func TestSGProjects_ListRefusesAMalformedProjectFirst(t *testing.T) {
	f := newSGProjectsFixture(t)
	for who, c := range map[string]context.Context{"root": f.root, "alice": f.alice} {
		_, err := f.s.ListSecurityGroups(c, &pb.ListSecurityGroupsRequest{Project: ".."})
		wantSGCode(t, who+" lists project ..", err, codes.InvalidArgument)
		if !strings.Contains(err.Error(), "invalid project") {
			t.Errorf("%s: %v, want the invalid project refusal", who, err)
		}
	}
}

const denyOnlyYAML = `name: denyonly
firewall:
  default-deny: true
`

// A stack whose only firewall is the cluster default-deny: an Operator's
// redeploy without it, or its teardown, would turn the cluster default to
// allow, so both need sg.write at the root.
func TestStackFirewall_ADefaultDenyOnlyStackNeedsSGWriteAtTheRoot(t *testing.T) {
	s, opal, ada := stackFirewallFixture(t)
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: denyOnlyYAML}, &mockDeployStreamR2{ctx: ada}); err != nil {
		t.Fatalf("Admin deploys the deny-only stack: %v", err)
	}
	// fwonly set the deny first and owns the row; take it down so denyonly
	// owns it alone.
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "fwonly"}, &mockDeleteStream{ctx: ada}); err != nil {
		t.Fatalf("Admin tears fwonly down: %v", err)
	}
	if d, _ := corrosion.GetFirewallDefault(context.Background(), s.db, "cluster"); d == nil || !d.DefaultDeny || d.StackName != "denyonly" {
		t.Fatalf("the cluster default is %+v, want deny owned by denyonly", d)
	}
	err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: denyonly\n"}, &mockDeployStreamR2{ctx: opal})
	wantGrantHint(t, "an Operator drops a deny-only stack's firewall", err)
	err = s.DeleteStack(&pb.DeleteStackRequest{Name: "denyonly"}, &mockDeleteStream{ctx: opal})
	wantGrantHint(t, "an Operator tears a deny-only stack down", err)
	if d, _ := corrosion.GetFirewallDefault(context.Background(), s.db, "cluster"); d == nil || !d.DefaultDeny {
		t.Fatalf("a refused change turned the cluster default to %+v", d)
	}
	// The row alone counts: a stack that owns the deny row is held to it
	// even when the file this node stores no longer asks for it (a newer
	// file whose block was dropped by an Admin's deploy that has not
	// finished here, say).
	if err := corrosion.UpsertStack(context.Background(), s.db, corrosion.StackRecord{Name: "denyonly", ComposeYAML: "name: denyonly\n", State: "running"}); err != nil {
		t.Fatal(err)
	}
	err = s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: denyonly\n"}, &mockDeployStreamR2{ctx: opal})
	wantGrantHint(t, "an Operator redeploys a stack that owns the deny row but whose file does not ask", err)
}

// A stack whose file asks for default-deny while another stack owns the row
// owns no firewall row, but withdrawing its ask decides whether the deny is
// handed on: its file's firewall block counts.
func TestStackFirewall_AStacksStoredBlockCountsWithoutRows(t *testing.T) {
	s, opal, ada := stackFirewallFixture(t)
	if err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: denyOnlyYAML}, &mockDeployStreamR2{ctx: ada}); err != nil {
		t.Fatalf("Admin deploys the second deny stack: %v", err)
	}
	if owns, _ := corrosion.StackOwnsFirewall(context.Background(), s.db, "denyonly"); owns {
		t.Fatal("fixture: denyonly owns a firewall row; the test needs one that only asks")
	}
	err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: denyonly\n"}, &mockDeployStreamR2{ctx: opal})
	wantGrantHint(t, "an Operator withdraws a stack's deny ask", err)
	err = s.DeleteStack(&pb.DeleteStackRequest{Name: "denyonly"}, &mockDeleteStream{ctx: opal})
	wantGrantHint(t, "an Operator tears down a stack that asks for deny", err)
}

// A node whose replica lags: it holds the stack's record but none of its
// firewall rows, or its file cannot be read. Its own view must not authorize
// a teardown that the tombstone then carries to every node holding the rows.
func TestDeleteStack_ALaggingEntryNodeFailsClosed(t *testing.T) {
	ctx := context.Background()
	s, opal, _ := stackFirewallFixture(t)
	// Record and file present, rows not yet here.
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "lagging", ComposeYAML: fwStackYAML, State: "running"}); err != nil {
		t.Fatal(err)
	}
	err := s.DeleteStack(&pb.DeleteStackRequest{Name: "lagging"}, &mockDeleteStream{ctx: opal})
	wantGrantHint(t, "an Operator tears down a stack whose rows have not arrived", err)
	// A file this node cannot read.
	if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: "garbled", ComposeYAML: "{{{not yaml", State: "running"}); err != nil {
		t.Fatal(err)
	}
	err = s.DeleteStack(&pb.DeleteStackRequest{Name: "garbled"}, &mockDeleteStream{ctx: opal})
	wantGrantHint(t, "an Operator tears down a stack whose file cannot be read", err)
	for _, name := range []string{"lagging", "garbled"} {
		if st, _ := corrosion.GetStack(ctx, s.db, name); st == nil || st.State == stackStateDeleting {
			t.Fatalf("the refused down changed stack %s: %+v", name, st)
		}
	}
}

// A first `lv compose up` that failed in the workload phase leaves workloads
// that carry the stack's name and no stack record anywhere; `lv compose down`
// is how an Operator removes them. With no record here, the down removes only
// the workloads this node lists and writes nothing every peer applies by the
// stack's name (its state, its record) and no firewall row: on a node that
// merely lags, such a write would tear down a stack it cannot see.
func TestDeleteStack_AnOperatorCanTakeDownAFailedFirstDeploy(t *testing.T) {
	ctx := context.Background()
	s, opal, _ := stackFirewallFixture(t)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "ghost-web-1", StackName: "ghost",
		HostName: "other-host", State: "stopped", Spec: "{}"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	// A firewall row of the stack that reached this node ahead of its record.
	if err := corrosion.InsertSecurityGroup(ctx, s.db, corrosion.SecurityGroup{ID: "sg-ghost", Name: "ghost-web", StackName: "ghost"}); err != nil {
		t.Fatal(err)
	}
	before := stackStatements(t, s)
	st := &mockDeleteStream{ctx: opal}
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "ghost"}, st); err != nil {
		t.Fatalf("an Operator's compose down of a failed first deploy: %v", err)
	}
	tried, said := false, false
	for _, p := range st.sent {
		tried = tried || p.GetVmName() == "ghost-web-1"
		said = said || strings.Contains(p.GetError(), "holds no record of stack")
	}
	if !tried {
		t.Errorf("the down did not act on the stack's workload: %+v", st.sent)
	}
	if !said {
		t.Errorf("the down did not say it acted on this node's workloads only: %+v", st.sent)
	}
	for _, p := range st.sent {
		if p.GetStatus() != "local-only" {
			continue
		}
		// An Admin's plain down removes what is left from any node, record
		// or not: no redeploy is needed, so none is advised.
		if !strings.Contains(p.GetError(), "`lv compose down --name ghost`") || strings.Contains(p.GetError(), "lv compose up") {
			t.Errorf("the notice does not give an Admin's plain down as the exit: %s", p.GetError())
		}
	}
	if after := stackStatements(t, s); after != before {
		t.Fatalf("a record-less down wrote %d stack-wide statement(s) every peer applies", after-before)
	}
	if g, _ := corrosion.GetSecurityGroup(ctx, s.db, "sg-ghost"); g == nil {
		t.Fatal("a record-less down removed a firewall row")
	}
}

// stackStatements counts replicated statements that change a stack's state or
// record, or record a stack teardown.
func stackStatements(t *testing.T, s *Server) int {
	t.Helper()
	rows, err := s.db.Query(context.Background(), `SELECT stmts FROM mutation_log`)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range rows {
		st := r.String("stmts")
		if strings.Contains(st, "stacks") && (strings.Contains(st, "UPDATE stacks") || strings.Contains(st, "stack_teardown")) {
			n++
		}
	}
	return n
}

// The success path of a local-only down: the workload this node holds is
// deleted, and still nothing stack-wide is written and no firewall row
// removed — the record and firewall cleanup that a complete teardown ends
// with are not reached.
func TestDeleteStack_ALocalOnlyDownThatSucceedsWritesNothingStackWide(t *testing.T) {
	ctx := context.Background()
	s, opal, _ := stackFirewallFixture(t)
	s.virt = libvirtfake.New()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "ghost-web-1", StackName: "ghost",
		HostName: s.hostName, State: "stopped", Spec: "{}"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertSecurityGroup(ctx, s.db, corrosion.SecurityGroup{ID: "sg-ghost", Name: "ghost-web", StackName: "ghost"}); err != nil {
		t.Fatal(err)
	}
	before := stackStatements(t, s)
	st := &mockDeleteStream{ctx: opal}
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "ghost"}, st); err != nil {
		t.Fatalf("an Operator's local-only down: %v", err)
	}
	deleted := false
	for _, p := range st.sent {
		deleted = deleted || (p.GetVmName() == "ghost-web-1" && p.GetStatus() == "deleted")
		if p.GetStatus() == "error" {
			t.Fatalf("the local-only down failed: %+v", st.sent)
		}
	}
	if !deleted {
		t.Fatalf("the workload was not deleted: %+v", st.sent)
	}
	if after := stackStatements(t, s); after != before {
		t.Fatalf("a successful local-only down wrote %d stack-wide statement(s)", after-before)
	}
	if g, _ := corrosion.GetSecurityGroup(ctx, s.db, "sg-ghost"); g == nil {
		t.Fatal("a successful local-only down removed a firewall row")
	}
}
