package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ListSecurityGroups is the read twin of the security-group write RPCs, and
// the web UI's security-group pages read through it with the session's
// bearer. Before it existed they read the tables in-process, so any session —
// a scoped API token included — saw every group and rule in the cluster.

func seedSGs(t *testing.T, s *Server) {
	t.Helper()
	bg := context.Background()
	for _, g := range []corrosion.SecurityGroup{
		{ID: "sg-web", Name: "web"},
		{ID: "sg-db", Name: "db", StackName: "shop"},
	} {
		if err := corrosion.InsertSecurityGroup(bg, s.db, g); err != nil {
			t.Fatalf("InsertSecurityGroup(%s): %v", g.ID, err)
		}
	}
	for _, r := range []corrosion.SGRule{
		{ID: "r-web", SGID: "sg-web", Direction: "ingress", Proto: "tcp", PortRange: "443", CIDR: "0.0.0.0/0"},
		{ID: "r-db", SGID: "sg-db", Direction: "ingress", Proto: "tcp", PortRange: "5432", CIDR: "10.9.0.0/16"},
	} {
		if err := corrosion.InsertSGRule(bg, s.db, r); err != nil {
			t.Fatalf("InsertSGRule(%s): %v", r.ID, err)
		}
	}
}

func TestListSecurityGroups_AViewerListsGroupsAndRules(t *testing.T) {
	s := testServer(t)
	seedSGs(t, s)

	resp, err := s.ListSecurityGroups(viewerCtx(), &pb.ListSecurityGroupsRequest{IncludeRules: true})
	if err != nil {
		t.Fatalf("ListSecurityGroups as viewer: %v", err)
	}
	names := map[string]string{}
	for _, g := range resp.GetGroups() {
		names[g.GetId()] = g.GetName() + "/" + g.GetStackName()
	}
	if len(names) != 2 || names["sg-web"] != "web/" || names["sg-db"] != "db/shop" {
		t.Errorf("groups = %v, want sg-web=web/ and sg-db=db/shop", names)
	}
	rules := map[string]*pb.SecurityGroupRule{}
	for _, r := range resp.GetRules() {
		rules[r.GetId()] = r
	}
	if r := rules["r-db"]; len(rules) != 2 || r == nil || r.GetSgId() != "sg-db" || r.GetPort() != "5432" ||
		r.GetCidr() != "10.9.0.0/16" || r.GetProto() != "tcp" {
		t.Errorf("rules = %v, want r-web and r-db with their group, port and cidr", resp.GetRules())
	}

	// Without include_rules only the groups come back; the stack filter applies.
	resp, err = s.ListSecurityGroups(viewerCtx(), &pb.ListSecurityGroupsRequest{StackName: "shop"})
	if err != nil {
		t.Fatalf("ListSecurityGroups(stack=shop): %v", err)
	}
	if len(resp.GetGroups()) != 1 || resp.GetGroups()[0].GetId() != "sg-db" || len(resp.GetRules()) != 0 {
		t.Errorf("stack=shop without rules = %v, want only sg-db and no rules", resp)
	}
}

func TestListSecurityGroups_RefusesWhatTheWritesRefuse(t *testing.T) {
	cases := map[string]func(t *testing.T, s *Server) context.Context{
		// The cookie of a UI session can be a scoped API token. Security
		// groups are cluster-global, checked at "/", which a project scope
		// does not reach.
		"scoped token": func(t *testing.T, s *Server) context.Context {
			return context.WithValue(userCtx("ada", "admin"), ctxKeyScopePaths, []string{"/projects/teamA"})
		},
		// A binding that grants nothing at the cluster root: the RBAC engine
		// decides, and a project grant does not carry sg.read at "/".
		"project-bound Admin": func(t *testing.T, s *Server) context.Context {
			bg := context.Background()
			if err := auth.SeedBuiltinRoles(bg, s.db); err != nil {
				t.Fatalf("SeedBuiltinRoles: %v", err)
			}
			if err := corrosion.InsertRoleBinding(bg, s.db, corrosion.RoleBindingRecord{
				ID: "pat-a", Path: "/projects/teamA", Role: "Admin", Principal: "user:pat@local", Propagate: true,
			}); err != nil {
				t.Fatalf("InsertRoleBinding: %v", err)
			}
			engine := auth.NewEngine(s.db)
			if err := engine.Reload(bg); err != nil {
				t.Fatalf("Reload: %v", err)
			}
			s.SetAuthEngine(engine)
			return userCtx("pat", "admin")
		},
		"no principal": func(t *testing.T, s *Server) context.Context { return context.Background() },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			seedSGs(t, s)
			resp, err := s.ListSecurityGroups(mk(t, s), &pb.ListSecurityGroupsRequest{IncludeRules: true})
			if c := status.Code(err); c != codes.PermissionDenied && c != codes.Unauthenticated {
				t.Errorf("err = %v, want PermissionDenied or Unauthenticated", err)
			}
			if len(resp.GetGroups()) != 0 || len(resp.GetRules()) != 0 {
				t.Errorf("a refused caller got %v", resp)
			}
		})
	}
}

// A cluster Viewer binding carries *.read, so sg.read: the RBAC path admits the
// same reader the legacy fallback does.
func TestListSecurityGroups_ABoundViewerIsAdmitted(t *testing.T) {
	s := testServer(t)
	seedSGs(t, s)
	bg := context.Background()
	if err := auth.SeedBuiltinRoles(bg, s.db); err != nil {
		t.Fatalf("SeedBuiltinRoles: %v", err)
	}
	if err := corrosion.InsertRoleBinding(bg, s.db, corrosion.RoleBindingRecord{
		ID: "vic-root", Path: "/", Role: "Viewer", Principal: "user:vic@local", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	engine := auth.NewEngine(s.db)
	if err := engine.Reload(bg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	s.SetAuthEngine(engine)
	resp, err := s.ListSecurityGroups(userCtx("vic", "viewer"), &pb.ListSecurityGroupsRequest{})
	if err != nil || len(resp.GetGroups()) != 2 {
		t.Fatalf("ListSecurityGroups as a bound Viewer = %v, %v; want both groups", resp, err)
	}
}
