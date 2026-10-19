// Two projects deleted at once on two replicas, each a user's only bindings.
// Each delete sees the other's binding as the one that survives, so a sentinel
// decided from that snapshot is skipped on both; the bindings then converge to
// zero and RequirePerm reads "no bindings" as "use the legacy role", cluster-wide.
package fleet

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Mutation: skip the sentinel for a principal with a binding outside the
// project (the snapshot rule) — red.
func TestFleet_ConcurrentProjectDeletesNeverUnbindAUser(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	a, b := c.Nodes[0], c.Nodes[1]
	for _, p := range []string{"/p", "/q"} {
		if _, err := c.SelfClient(a).CreateProject(ctx, &pb.CreateProjectRequest{Name: p}); err != nil {
			t.Fatal(err)
		}
	}
	for _, bd := range []corrosion.RoleBindingRecord{
		{ID: "u-p", Path: "/projects/p", Role: "Operator", Principal: "user:u@local", Propagate: true},
		{ID: "u-q", Path: "/projects/q", Role: "Operator", Principal: "user:u@local", Propagate: true},
	} {
		if err := corrosion.InsertRoleBinding(ctx, a.DB, bd); err != nil {
			t.Fatal(err)
		}
	}
	pumpMutations(t, c, a, b)

	// Both deletes before either node hears of the other's.
	if _, err := c.SelfClient(a).DeleteProject(ctx, &pb.DeleteProjectRequest{Name: "/p"}); err != nil {
		t.Fatalf("delete /p on A: %v", err)
	}
	if _, err := c.SelfClient(b).DeleteProject(ctx, &pb.DeleteProjectRequest{Name: "/q"}); err != nil {
		t.Fatalf("delete /q on B: %v", err)
	}
	for i := 0; i < 2; i++ {
		pumpMutations(t, c, a, b)
		pumpMutations(t, c, b, a)
	}

	for _, n := range []*Node{a, b} {
		e := auth.NewEngine(n.DB)
		if err := e.Reload(ctx); err != nil {
			t.Fatal(err)
		}
		if !e.HasAnyBinding([]string{"user:u@local"}) {
			t.Fatalf("%s: user u has no binding left; RequirePerm now falls back to its legacy role cluster-wide", n.Name)
		}
		bs, _ := corrosion.ListRoleBindings(ctx, n.DB)
		for _, bd := range bs {
			if bd.Principal == "user:u@local" && bd.Role != corrosion.SentinelRole {
				t.Fatalf("%s: a granting binding survived: %+v", n.Name, bd)
			}
		}
	}
}
