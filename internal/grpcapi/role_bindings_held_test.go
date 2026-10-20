package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Review PR-3: a binding granted for an earlier project of the name is listed
// "(held)", grants nothing in the engine, keeps its principal bound, and lv
// role revoke (RevokeRole) removes it.
//
// Mutation: no "(held)" suffix in the API — red.
func TestRoleBindings_AHeldBindingIsListedAndRevocable(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	s.db.SetProjectIncarnationGate(func() bool { return true })
	if err := auth.SeedBuiltinRoles(ctx, s.db); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertProject(ctx, s.db, corrosion.ProjectRecord{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	// As a lagging node's grant for an earlier p arrives: raw row, another tag.
	id := "deadbeef~p:r00000000000000000000000000000000"
	if err := s.db.Execute(ctx, `INSERT INTO role_bindings (id, path, role, principal, propagate, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, "/projects/p", "Operator", "user:bob@local", 1, s.db.NowTS()); err != nil {
		t.Fatal(err)
	}
	resp, err := s.ListRoleBindings(adminCtx(), &pb.ListRoleBindingsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Bindings) != 1 || resp.Bindings[0].Role != "Operator (held)" {
		t.Fatalf("listing = %+v, want one Operator (held)", resp.Bindings)
	}
	e := auth.NewEngine(s.db)
	if err := e.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	ids := []string{"user:bob@local", "group:operator@local"}
	if e.Allowed(ids, "vm.start", "/projects/p/vms/x") || e.HoldsVerbAnywhere(ids, "vm.start") ||
		len(e.GrantsAt(ids, "/projects/p", false)) != 0 || e.AllowedExplicit(ids, "vm.start", "/projects/p/vms/x") {
		t.Fatal("a held binding grants through the engine")
	}
	if !e.HasAnyBinding(ids) {
		t.Fatal("a held binding does not keep its principal bound")
	}
	for _, b := range e.BindingsOf(ids) {
		if !strings.EqualFold(b.Role, corrosion.SentinelRole) {
			t.Fatalf("engine holds %+v, want NoAccess", b)
		}
	}
	if _, err := s.RevokeRole(adminCtx(), &pb.RevokeRoleRequest{Id: id}); err != nil {
		t.Fatalf("revoke a held binding: %v", err)
	}
	rows, err := corrosion.ListRoleBindings(ctx, s.db)
	if err != nil || len(rows) != 0 {
		t.Fatalf("after revoke: %+v (err %v), want none", rows, err)
	}
}
