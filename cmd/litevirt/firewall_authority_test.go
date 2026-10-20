package main

import (
	"context"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// `lv firewall default-deny off` by an Operator bound at the cluster root,
// which holds sg.read only, is refused by a real daemon, and the error the
// CLI returns names the grant that lets the caller do it. The deny stays.
func TestFirewallCLI_AnOperatorIsToldWhichGrantDefaultDenyNeeds(t *testing.T) {
	ctx := context.Background()
	db := sgCLIRealDaemonRBAC(t, "opal", "Operator")
	if err := corrosion.SetFirewallDefault(ctx, db, "cluster", true, ""); err != nil {
		t.Fatal(err)
	}
	cmd := newFirewallCmd()
	cmd.SetArgs([]string{"default-deny", "off"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var err error
	out := captureStdout(t, func() { err = cmd.Execute() })
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("lv firewall default-deny off as an Operator: %v, want PermissionDenied", err)
	}
	for _, want := range []string{"sg.write at the cluster root", "`lv role grant NetworkAdmin user:opal@local --path / --propagate`"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not say %q: %v", want, err)
		}
	}
	if out != "" {
		t.Errorf("a refused change printed %q", out)
	}
	if d, _ := corrosion.GetFirewallDefault(ctx, db, "cluster"); d == nil || !d.DefaultDeny {
		t.Errorf("the cluster default = %+v, want deny", d)
	}
}

// sgCLIRealDaemonRBAC starts a real grpcapi server, as sgCLIRealDaemon does,
// with role bindings: its one user is bound to the built-in role at the
// cluster root.
func sgCLIRealDaemonRBAC(t *testing.T, user, role string) *corrosion.Client {
	t.Helper()
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(sgCLIToken), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser(ctx, db, user, "operator", string(hash)); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertToken(ctx, db, corrosion.TokenRecord{
		ID: "cli-token", Username: user, Name: "cli", TokenHash: string(hash),
	}); err != nil {
		t.Fatal(err)
	}
	if err := auth.SeedBuiltinRoles(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertRoleBinding(ctx, db, corrosion.RoleBindingRecord{
		ID: user, Path: "/", Role: role, Principal: "user:" + user + "@local", Propagate: true,
	}); err != nil {
		t.Fatal(err)
	}
	engine := auth.NewEngine(db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	service := grpcapi.NewServerForTests(grpcapi.TestServerOpts{HostName: "test-host", DataDir: t.TempDir(), DB: db})
	service.SetAuthEngine(engine)
	sgCLIDaemon(t, service, service.UnaryAuthInterceptor, sgCLIToken)
	return db
}
