// A deleted project's name must be creatable again, on any node, and the
// replicas must agree on the new incarnation without resurrecting the old one.
// Lab 3 2026-10-18: `lv project create` of a deleted name failed on a UNIQUE
// collision with the tombstone.
package fleet

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Mutations: revert InsertProject to a plain INSERT — red (the create on B
// collides). Drop retireProjectGrants — red on the grants assertions. Bind the
// revive's updated_at to an old clock — red (the late tombstone resurrects the
// delete).
func TestFleet_ProjectNameReusedAcrossNodesConverges(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	ctx := context.Background()
	a, b, o := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	all := []*Node{a, b, o}

	if _, err := c.SelfClient(a).CreateProject(ctx, &pb.CreateProjectRequest{Name: "/reuse", Display: "old"}); err != nil {
		t.Fatalf("create on A: %v", err)
	}
	if err := corrosion.InsertRoleBinding(ctx, a.DB, corrosion.RoleBindingRecord{
		ID: "old-grant", Path: "/projects/reuse", Role: "Admin", Principal: "user:mallory", Propagate: true}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertProjectQuota(ctx, a.DB, corrosion.ProjectQuotaRecord{ProjectName: "/reuse", VCPULimit: 900}); err != nil {
		t.Fatal(err)
	}
	for _, to := range []*Node{b, o} {
		pumpMutations(t, c, a, to)
	}

	// A deletes; only B hears of it. O still holds the old live project.
	if _, err := c.SelfClient(a).DeleteProject(ctx, &pb.DeleteProjectRequest{Name: "/reuse"}); err != nil {
		t.Fatalf("delete on A: %v", err)
	}
	pumpMutations(t, c, a, b)

	// B re-creates the name.
	if _, err := c.SelfClient(b).CreateProject(ctx, &pb.CreateProjectRequest{Name: "/reuse"}); err != nil {
		t.Fatalf("re-create on B: %v", err)
	}

	// B's incarnation reaches O BEFORE A's tombstone does (late tombstone), then
	// everything is exchanged both ways, twice.
	pumpMutations(t, c, b, o)
	for i := 0; i < 2; i++ {
		for _, from := range all {
			for _, to := range all {
				if from != to {
					pumpMutations(t, c, from, to)
				}
			}
		}
	}

	for _, n := range all {
		p, err := corrosion.GetProject(ctx, n.DB, "/reuse")
		if err != nil || p == nil || p.Display != "old" {
			t.Fatalf("%s: project = %+v err=%v, want the revived project live with its old display", n.Name, p, err)
		}
		bs, _ := corrosion.ListRoleBindings(ctx, n.DB)
		for _, bd := range bs {
			if bd.ID == "old-grant" {
				t.Fatalf("%s: the old incarnation's role binding is live on the re-created project", n.Name)
			}
		}
		if q, _ := corrosion.GetProjectQuota(ctx, n.DB, "/reuse"); q != nil && q.VCPULimit != 0 {
			t.Fatalf("%s: re-created project inherited quota %+v", n.Name, q)
		}
	}
}
