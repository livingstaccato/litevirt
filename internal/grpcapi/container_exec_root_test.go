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
	"github.com/litevirt/litevirt/internal/lxc"
)

// Exec in a privileged container is a root shell on the host (no user
// namespace), and in a legacy-confined one it runs with AppArmor nesting and
// the template's seccomp and capabilities. Both need the Admin role or the
// ContainerRoot role on that container (ctroot.exec); ct.exec, which
// Operator holds through ct.*, is enough only for an unprivileged container
// with default confinement.

// seedExecCT records a local container in project acme with spec.
func seedExecCT(t *testing.T, s *Server, name string, spec *corrosion.ContainerCreateSpec) {
	t.Helper()
	rec := corrosion.ContainerRecord{Name: name, HostName: s.hostName, State: "running", Project: "acme"}
	if spec != nil {
		rec.CreateSpec = corrosion.EncodeCreateSpec(*spec)
	}
	if err := corrosion.UpsertContainer(context.Background(), s.db, rec); err != nil {
		t.Fatal(err)
	}
}

var (
	unprivDefault = &corrosion.ContainerCreateSpec{Template: "download", IDMapBase: 1000000, Confinement: lxc.ConfinementDefault}
	unprivLegacy  = &corrosion.ContainerCreateSpec{Template: "download", IDMapBase: 1065536, Confinement: lxc.ConfinementLegacy}
	privDefault   = &corrosion.ContainerCreateSpec{Template: "download", Confinement: lxc.ConfinementDefault}
)

func execAs(ctx context.Context, s *Server, name string) error {
	_, err := s.ExecContainer(ctx, &pb.ExecContainerRequest{Name: name, Argv: []string{"id"}})
	return err
}

func TestExecContainer_PrivilegedOrLegacyNeedsAdminOnTheLegacyRoleModel(t *testing.T) {
	s := testServer(t)
	rt := &fakeCTRuntime{}
	s.containerRuntime = rt
	seedExecCT(t, s, "plain", unprivDefault)
	seedExecCT(t, s, "nested", unprivLegacy)
	seedExecCT(t, s, "priv", privDefault)
	seedExecCT(t, s, "mainera", nil) // no create spec: privileged and legacy

	if err := execAs(ctOperatorCtx(), s, "plain"); err != nil {
		t.Fatalf("an operator's exec in an unprivileged, confined container: %v", err)
	}
	for _, name := range []string{"nested", "priv", "mainera"} {
		err := execAs(ctOperatorCtx(), s, name)
		if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "ContainerRoot") {
			t.Errorf("an operator's exec in %s: %v, want PermissionDenied naming ContainerRoot", name, err)
		}
		if row := lastAuditRow(t, s, "ct.exec"); row.result != "denied" || row.target != name {
			t.Errorf("audit after the refused exec in %s: %+v, want it denied", name, row)
		}
		if err := execAs(adminCtx(), s, name); err != nil {
			t.Errorf("an admin's exec in %s: %v", name, err)
		}
	}
	if len(rt.execCalls) != 4 {
		t.Errorf("exec calls %+v, want the operator's one and the admin's three", rt.execCalls)
	}
}

// opRootCtx is pat bound Operator across the cluster (ct.* included), the way
// operators are bound on the binding model.
func opRootCtx(t *testing.T, s *Server, extra ...corrosion.RoleBindingRecord) context.Context {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "pat", "viewer", "x"); err != nil {
		t.Fatal(err)
	}
	if err := auth.SeedBuiltinRoles(ctx, s.db); err != nil {
		t.Fatal(err)
	}
	binds := append([]corrosion.RoleBindingRecord{{ID: "pat-op", Path: "/", Role: "Operator", Principal: "user:pat@local", Propagate: true}}, extra...)
	for _, b := range binds {
		if err := corrosion.InsertRoleBinding(ctx, s.db, b); err != nil {
			t.Fatal(err)
		}
	}
	engine := auth.NewEngine(s.db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	s.SetAuthEngine(engine)
	return context.WithValue(context.WithValue(context.Background(), ctxKeyUsername, "pat"), ctxKeyRole, "viewer")
}

func TestExecContainer_PrivilegedNeedsAContainerRootGrantOnTheBindingModel(t *testing.T) {
	s := testServer(t)
	s.containerRuntime = &fakeCTRuntime{}
	seedExecCT(t, s, "plain", unprivDefault)
	seedExecCT(t, s, "priv", privDefault)
	seedExecCT(t, s, "priv2", privDefault)

	pat := opRootCtx(t, s, corrosion.RoleBindingRecord{
		ID: "pat-root-priv", Path: "/projects/acme/containers/priv", Role: "ContainerRoot", Principal: "user:pat@local"})
	if err := execAs(pat, s, "plain"); err != nil {
		t.Fatalf("Operator's exec in an unprivileged, confined container: %v", err)
	}
	if err := execAs(pat, s, "priv"); err != nil {
		t.Fatalf("exec with ContainerRoot on the container: %v", err)
	}
	if err := execAs(pat, s, "priv2"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Operator's exec in a privileged container its grant does not name: %v, want PermissionDenied", err)
	}
}

// ContainerRoot alone is a working grant: it carries ct.exec too.
func TestContainerRootRoleCarriesExec(t *testing.T) {
	var verbs []string
	for _, r := range auth.BuiltinRoles {
		if r.Name == "ContainerRoot" {
			verbs = r.Verbs
		}
	}
	has := func(v string) bool {
		for _, g := range verbs {
			if g == v {
				return true
			}
		}
		return false
	}
	if !has("ct.exec") || !has(auth.VerbContainerRoot) {
		t.Fatalf("ContainerRoot verbs %v, want ct.exec and %s", verbs, auth.VerbContainerRoot)
	}
	for _, r := range auth.BuiltinRoles {
		if r.Name != "Admin" && r.Name != "ContainerRoot" {
			for _, g := range r.Verbs {
				if g == "*" || g == auth.VerbContainerRoot || strings.HasPrefix(auth.VerbContainerRoot, strings.TrimSuffix(g, "*")) && strings.HasSuffix(g, ".*") {
					t.Errorf("built-in role %s carries %s through %q", r.Name, auth.VerbContainerRoot, g)
				}
			}
		}
	}
}
