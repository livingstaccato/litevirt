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
	if ok, err := corrosion.ClaimInitialProjectAuthority(ctx, a.DB, "/reuse", a.Name); err != nil || !ok {
		t.Fatalf("claim authority on A: ok=%v err=%v", ok, err)
	}
	for _, to := range []*Node{b, o} {
		pumpMutations(t, c, a, to)
	}

	// A deletes; only B hears of it. O still holds the old live project.
	if _, err := c.SelfClient(a).DeleteProject(ctx, &pb.DeleteProjectRequest{Name: "/reuse"}); err != nil {
		t.Fatalf("delete on A: %v", err)
	}
	pumpMutations(t, c, a, b)

	// Retirement happens at the delete, before any re-create: on A, no live
	// authority, no live binding but the sentinel, and no quota.
	if _, ok, _ := corrosion.CurrentProjectAuthority(ctx, a.DB, "/reuse"); ok {
		t.Fatal("A: the deleted project still holds live authority")
	}
	abs, _ := corrosion.ListRoleBindings(ctx, a.DB)
	for _, bd := range abs {
		if bd.Role != corrosion.SentinelRole {
			t.Fatalf("A: a binding survived the delete: %+v", bd)
		}
	}
	if q, _ := corrosion.GetProjectQuota(ctx, a.DB, "/reuse"); q != nil && q.VCPULimit != 0 {
		t.Fatalf("A: quota survived the delete: %+v", q)
	}

	// B re-creates the name and its coordinator mints the new incarnation's
	// first authority epoch.
	if _, err := c.SelfClient(b).CreateProject(ctx, &pb.CreateProjectRequest{Name: "/reuse"}); err != nil {
		t.Fatalf("re-create on B: %v", err)
	}
	if ok, err := corrosion.ClaimInitialProjectAuthority(ctx, b.DB, "/reuse", b.Name); err != nil || !ok {
		t.Fatalf("claim authority on B: ok=%v err=%v", ok, err)
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
		// The new incarnation's authority survives the old delete's retirement
		// arriving late, on every replica, with the same holder.
		auth, ok, err := corrosion.CurrentProjectAuthority(ctx, n.DB, "/reuse")
		if err != nil || !ok || auth.Holder != b.Name || auth.Epoch != 2 {
			t.Fatalf("%s: authority = %+v ok=%v err=%v, want epoch 2 held by %s", n.Name, auth, ok, err, b.Name)
		}
		if q, _ := corrosion.GetProjectQuota(ctx, n.DB, "/reuse"); q != nil && q.VCPULimit != 0 {
			t.Fatalf("%s: re-created project inherited quota %+v", n.Name, q)
		}
	}
}
