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

// O11: no caller is matched as a bare user:<name>, so a bare binding grants
// nothing. A caller that asks for it (the CLI and the UI do) gets a refusal
// instead of an inert row.
func TestGrantRole_RefuseInertPrincipal(t *testing.T) {
	s := realmServer(t, false, false)
	for _, p := range []string{"user:bob", "user:bob@example.com"} {
		_, err := s.GrantRole(adminCtx(), &pb.GrantRoleRequest{
			Path: "/", Role: "Viewer", Principal: p, RefuseInertPrincipal: true,
		})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("%s with refuse_inert_principal: got %v, want FailedPrecondition", p, err)
		}
		if !strings.Contains(status.Convert(err).Message(), p+"@local") {
			t.Errorf("refusal %q does not show the qualified form", status.Convert(err).Message())
		}
	}
	rows, err := corrosion.ListRoleBindings(context.Background(), s.db)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if strings.HasPrefix(r.Principal, "user:bob") {
			t.Fatalf("a refused grant stored %q", r.Principal)
		}
	}
	// A qualified principal and a group pass.
	for _, p := range []string{"user:bob@local", "user:bob@oidc:corp", "group:admin@local"} {
		if _, err := s.GrantRole(adminCtx(), &pb.GrantRoleRequest{
			Path: "/", Role: "Viewer", Principal: p, RefuseInertPrincipal: true,
		}); err != nil {
			t.Errorf("%s with refuse_inert_principal: %v", p, err)
		}
	}
}

// With auth.rbac_realm latched the server resolves a bare grant to a real
// principal, which is not inert, so the request flag does not refuse it.
func TestGrantRole_RefuseInertPrincipal_RealmResolvedPasses(t *testing.T) {
	s := realmServer(t, true, true)
	seedUser(t, s, "bob", "viewer", "hunter2")
	resp, err := s.GrantRole(adminCtx(), &pb.GrantRoleRequest{
		Path: "/", Role: "Viewer", Principal: "user:bob", RefuseInertPrincipal: true,
	})
	if err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	if resp.Binding.Principal != "user:bob@local" {
		t.Fatalf("principal %q, want user:bob@local", resp.Binding.Principal)
	}
}
