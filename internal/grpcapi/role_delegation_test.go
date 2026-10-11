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

// delegationServer: pat administers /projects/acme — Operator and
// PermissionAdmin there, propagating — and is NOT a cluster admin (legacy
// role viewer). bob and carol already hold a binding each, so a delegated
// grant to them is not their first.
func delegationServer(t *testing.T) *Server {
	t.Helper()
	s := testServer(t)
	ctx := context.Background()
	if err := auth.SeedBuiltinRoles(ctx, s.db); err != nil {
		t.Fatalf("SeedBuiltinRoles: %v", err)
	}
	for _, u := range [][2]string{{"admin", "admin"}, {"pat", "viewer"}, {"bob", "viewer"}, {"carol", "operator"}, {"newbie", "operator"}} {
		if err := corrosion.InsertUser(ctx, s.db, u[0], u[1], "x"); err != nil {
			t.Fatalf("InsertUser %s: %v", u[0], err)
		}
	}
	for _, b := range []corrosion.RoleBindingRecord{
		{ID: "pat-op", Path: "/projects/acme", Role: "Operator", Principal: "user:pat@local", Propagate: true},
		{ID: "pat-perm", Path: "/projects/acme", Role: "PermissionAdmin", Principal: "user:pat@local", Propagate: true},
		{ID: "bob-view", Path: "/projects/acme", Role: "VMOperator", Principal: "user:bob@local", Propagate: true},
		{ID: "carol-view", Path: "/projects/acme/vms/web", Role: "VMOperator", Principal: "user:carol@local", Propagate: true},
		{ID: "bob-other", Path: "/projects/other", Role: "Viewer", Principal: "user:bob@local", Propagate: true},
	} {
		if err := corrosion.InsertRoleBinding(ctx, s.db, b); err != nil {
			t.Fatalf("InsertRoleBinding %s: %v", b.ID, err)
		}
	}
	engine := auth.NewEngine(s.db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	s.SetAuthEngine(engine)
	return s
}

func wantCode(t *testing.T, what string, err error, code codes.Code) {
	t.Helper()
	if status.Code(err) != code {
		t.Fatalf("%s: got %v, want %s", what, err, code)
	}
}

func patCtx() context.Context { return userCtx("pat", "viewer") }

func grant(s *Server, ctx context.Context, path, role, principal string, propagate bool) error {
	_, err := s.GrantRole(ctx, &pb.GrantRoleRequest{Path: path, Role: role, Principal: principal, Propagate: propagate})
	return err
}

func bindingCount(t *testing.T, s *Server) int {
	t.Helper()
	rows, err := corrosion.ListRoleBindings(context.Background(), s.db)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

// TestDelegatedGrant_WithinScopeAndHoldings: the case delegation exists for.
func TestDelegatedGrant_WithinScopeAndHoldings(t *testing.T) {
	s := delegationServer(t)
	resp, err := s.GrantRole(patCtx(), &pb.GrantRoleRequest{
		Path: "/projects/acme/", Role: "VMOperator", Principal: "user:bob@local", Propagate: true,
	})
	if err != nil {
		t.Fatalf("delegated grant of VMOperator in acme: %v", err)
	}
	if resp.Binding.Path != "/projects/acme" {
		t.Errorf("stored path %q, want the canonical /projects/acme", resp.Binding.Path)
	}
	if !s.authEngine.Allowed([]string{"user:bob@local"}, "vm.start", "/projects/acme/vms/x") {
		t.Error("the delegated grant did not take effect")
	}
	// Delegating delegation is within holdings too: pat holds perm.modify.
	if err := grant(s, patCtx(), "/projects/acme", "PermissionAdmin", "user:bob@local", true); err != nil {
		t.Fatalf("delegated grant of PermissionAdmin in acme: %v", err)
	}
}

// TestDelegatedGrant_NegativeCases: every way out of the delegated scope.
func TestDelegatedGrant_NegativeCases(t *testing.T) {
	for _, tc := range []struct {
		name, path, role, principal string
		propagate                   bool
		code                        codes.Code
		msg                         string
	}{
		{"escalate to global admin role", "/projects/acme", "Admin", "user:bob@local", true, codes.PermissionDenied, "do not hold"},
		{"escalate by role beyond holdings", "/projects/acme", "NetworkAdmin", "user:bob@local", true, codes.PermissionDenied, "do not hold"},
		// Viewer is *.read — every namespace's read, now and later. Operator
		// holds a list of specific reads, so it does not hold *.read.
		{"wildcard beyond a list of specifics", "/projects/acme", "Viewer", "user:bob@local", true, codes.PermissionDenied, "do not hold"},
		{"grant at the cluster root", "/", "VMOperator", "user:bob@local", true, codes.PermissionDenied, "lacks perm.modify"},
		{"grant in another project", "/projects/other", "VMOperator", "user:bob@local", true, codes.PermissionDenied, "lacks perm.modify"},
		{"sibling prefix", "/projects/acme2", "VMOperator", "user:bob@local", true, codes.PermissionDenied, "lacks perm.modify"},
		{"dot-dot escape", "/projects/acme/../other", "VMOperator", "user:bob@local", true, codes.InvalidArgument, ".."},
		{"dot segment", "/projects/acme/./x", "VMOperator", "user:bob@local", true, codes.InvalidArgument, ".."},
		{"double slash", "/projects/acme//x", "VMOperator", "user:bob@local", true, codes.InvalidArgument, "empty"},
		{"undefined role", "/projects/acme", "Ghost", "user:bob@local", true, codes.PermissionDenied, "not defined"},
		{"first binding of a principal", "/projects/acme", "VMOperator", "user:newbie@local", true, codes.PermissionDenied, "first"},
		{"unknown user", "/projects/acme", "VMOperator", "user:ghost@local", true, codes.PermissionDenied, "existing user"},
		{"bare principal", "/projects/acme", "VMOperator", "user:bob", true, codes.PermissionDenied, "existing user"},
		{"group with no binding", "/projects/acme", "VMOperator", "group:admin@local", true, codes.PermissionDenied, "first"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := delegationServer(t)
			before := bindingCount(t, s)
			err := grant(s, patCtx(), tc.path, tc.role, tc.principal, tc.propagate)
			wantCode(t, tc.name, err, tc.code)
			if !strings.Contains(err.Error(), tc.msg) {
				t.Errorf("%s: %v, want it to mention %q", tc.name, err, tc.msg)
			}
			if after := bindingCount(t, s); after != before {
				t.Errorf("%s: a refused grant was written (%d -> %d bindings)", tc.name, before, after)
			}
		})
	}
}

// TestDelegatedGrant_PropagationEscalation: a grantor whose own binding stops
// at a path holds nothing below it, so it may grant there only without
// propagation.
func TestDelegatedGrant_PropagationEscalation(t *testing.T) {
	s := delegationServer(t)
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "nora", "viewer", "x"); err != nil {
		t.Fatal(err)
	}
	for _, b := range []corrosion.RoleBindingRecord{
		{ID: "nora-op", Path: "/projects/acme/vms", Role: "Operator", Principal: "user:nora@local", Propagate: false},
		{ID: "nora-perm", Path: "/projects/acme/vms", Role: "PermissionAdmin", Principal: "user:nora@local", Propagate: false},
	} {
		if err := corrosion.InsertRoleBinding(ctx, s.db, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.authEngine.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	nora := userCtx("nora", "viewer")
	err := grant(s, nora, "/projects/acme/vms", "VMOperator", "user:bob@local", true)
	wantCode(t, "propagating grant from a non-propagating grantor", err, codes.PermissionDenied)
	if err := grant(s, nora, "/projects/acme/vms", "VMOperator", "user:bob@local", false); err != nil {
		t.Fatalf("the same grant without propagation: %v", err)
	}
}

// TestDelegatedGrant_ScopedTokenStaysInScope: a scoped token's holder may
// delegate only inside its scope, whatever its user holds.
func TestDelegatedGrant_ScopedTokenStaysInScope(t *testing.T) {
	s := delegationServer(t)
	ctx := context.WithValue(patCtx(), ctxKeyScopePaths, []string{"/projects/acme/vms"})
	err := grant(s, ctx, "/projects/acme", "VMOperator", "user:bob@local", true)
	wantCode(t, "grant outside the token scope", err, codes.PermissionDenied)
	if err := grant(s, ctx, "/projects/acme/vms", "VMOperator", "user:bob@local", true); err != nil {
		t.Fatalf("grant inside the token scope: %v", err)
	}
}

// TestDelegatedGrant_NoPermModifyKeepsTheAdminRefusal: an ordinary non-admin
// gets exactly the refusal it always got.
func TestDelegatedGrant_NoPermModifyKeepsTheAdminRefusal(t *testing.T) {
	s := delegationServer(t)
	err := grant(s, userCtx("bob", "viewer"), "/projects/acme", "Viewer", "user:carol@local", true)
	wantCode(t, "grant from a caller without perm.modify", err, codes.PermissionDenied)
	if !strings.Contains(err.Error(), `role "admin" required`) {
		t.Errorf("refusal %q changed for a caller who cannot delegate", err)
	}
	_, err = s.RevokeRole(userCtx("bob", "viewer"), &pb.RevokeRoleRequest{Id: "carol-view"})
	wantCode(t, "revoke from a caller without perm.modify", err, codes.PermissionDenied)
}

// TestDelegatedRevoke_Rules: in scope and within holdings is allowed;
// outside the scope is indistinguishable from a missing binding; beyond
// holdings and a principal's last binding are refused.
func TestDelegatedRevoke_Rules(t *testing.T) {
	s := delegationServer(t)
	ctx := context.Background()
	if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
		ID: "carol-admin-acme", Path: "/projects/acme", Role: "Admin", Principal: "user:carol@local", Propagate: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.authEngine.Reload(ctx); err != nil {
		t.Fatal(err)
	}

	_, err := s.RevokeRole(patCtx(), &pb.RevokeRoleRequest{Id: "bob-other"})
	wantCode(t, "revoke in another project", err, codes.PermissionDenied)
	_, err2 := s.RevokeRole(patCtx(), &pb.RevokeRoleRequest{Id: "no-such-binding"})
	if err.Error() != strings.Replace(err2.Error(), "no-such-binding", "bob-other", 1) {
		t.Errorf("an out-of-scope binding and a missing one answer differently: %q vs %q", err, err2)
	}

	_, err = s.RevokeRole(patCtx(), &pb.RevokeRoleRequest{Id: "carol-admin-acme"})
	wantCode(t, "revoke of a binding carrying more than the revoker holds", err, codes.PermissionDenied)

	if _, err := s.RevokeRole(patCtx(), &pb.RevokeRoleRequest{Id: "bob-view"}); err != nil {
		t.Fatalf("revoke of bob's acme binding: %v", err)
	}
	if s.authEngine.Allowed([]string{"user:bob@local"}, "vm.read", "/projects/acme") {
		t.Error("the revoke did not take effect")
	}
	// carol-view is her last binding once the admin removes the other: the
	// delegated revoke goes through and leaves a NoAccess sentinel, so she
	// never falls back to her legacy role (review I3).
	if _, err := s.RevokeRole(adminCtx(), &pb.RevokeRoleRequest{Id: "carol-admin-acme"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeRole(patCtx(), &pb.RevokeRoleRequest{Id: "carol-view"}); err != nil {
		t.Fatalf("delegated revoke of carol's last binding: %v", err)
	}
	if !s.authEngine.HasAnyBinding([]string{"user:carol@local"}) {
		t.Fatal("carol has no binding left in the live engine after a delegated revoke")
	}
}

// TestListRoleBindings_DelegateSeesItsPaths: a delegated admin sees its own
// bindings and the ones at paths it administers, not the rest.
func TestListRoleBindings_DelegateSeesItsPaths(t *testing.T) {
	s := delegationServer(t)
	resp, err := s.ListRoleBindings(patCtx(), &pb.ListRoleBindingsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, b := range resp.Bindings {
		got[b.Id] = true
	}
	for _, id := range []string{"pat-op", "pat-perm", "bob-view", "carol-view"} {
		if !got[id] {
			t.Errorf("delegate does not see %s", id)
		}
	}
	if got["bob-other"] {
		t.Error("delegate sees a binding in a project it does not administer")
	}
}
