package fleet

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// grantOn grants role to principal at path through node n's GrantRole RPC.
func grantOn(t *testing.T, c *Cluster, n *Node, path, role, principal string) string {
	t.Helper()
	resp, err := c.SelfClient(n).GrantRole(context.Background(), &pb.GrantRoleRequest{
		Path: path, Role: role, Principal: principal, Propagate: true})
	if err != nil {
		t.Fatalf("grant %s %s at %s on %s: %v", role, principal, path, n.Name, err)
	}
	return resp.Binding.Id
}

// seedRoles installs the built-in roles on every node, which the fleet
// daemons do not, so an engine can resolve a role's verbs.
func seedRoles(t *testing.T, c *Cluster) {
	t.Helper()
	for _, n := range c.Nodes {
		if err := auth.SeedBuiltinRoles(context.Background(), n.DB); err != nil {
			t.Fatalf("%s: seed roles: %v", n.Name, err)
		}
	}
}

// engineOf is a freshly loaded auth engine over node n's database.
func engineOf(t *testing.T, n *Node) *auth.Engine {
	t.Helper()
	e := auth.NewEngine(n.DB)
	if err := e.Reload(context.Background()); err != nil {
		t.Fatalf("%s: reload: %v", n.Name, err)
	}
	return e
}

// TestFleet_ALaggingNodesGrantDoesNotReachARecreatedProject is Codex's
// projects I2 schedule. A and B know live p. B grants bob Operator on it, and
// the grant is withheld from A. A deletes p and creates it again, and grants
// carol on the new p. A's stream then reaches B, and B's grant reaches A,
// over the WAL or by anti-entropy (before or after B hears of the re-create).
// On no node may bob be granted anything on the new p, and he must stay
// bound (a principal with no binding falls back to its legacy role). Grants
// made for the new p, and an unrelated grant B made meanwhile, are kept.
//
// Red on 1f052cf68 in every variant: bob may start VMs in the new p on both
// nodes. Mutations, each red: the auth engine reading a held binding's role;
// a receiver skipping a grant for another incarnation (bob left unbound on
// A); settleProjectName a no-op; the WAL or the anti-entropy retirement hook
// removed; the revive written without a new incarnation.
func TestFleet_ALaggingNodesGrantDoesNotReachARecreatedProject(t *testing.T) {
	for _, delivery := range []string{"the WAL", "anti-entropy after the re-create", "anti-entropy before the re-create",
		"the lagging node learns of the re-create by anti-entropy"} {
		t.Run(delivery, func(t *testing.T) {
			ctx := context.Background()
			c := New(t, Options{Nodes: 2})
			latchProjectIncarnation(t, c, nil, nil)
			seedRoles(t, c)
			a, b := c.Nodes[0], c.Nodes[1]
			for _, p := range []string{"/p", "/q"} {
				if _, err := c.SelfClient(a).CreateProject(ctx, &pb.CreateProjectRequest{Name: p}); err != nil {
					t.Fatal(err)
				}
			}
			pumpMutations(t, c, a, b)

			// B, lagging from here on, grants on the p it knows, and on q.
			grantOn(t, c, b, "/projects/p", "Operator", "user:bob@local")
			grantOn(t, c, b, "/projects/q", "Operator", "user:dave@local")

			// A re-creates p and grants carol on the new one.
			if _, err := c.SelfClient(a).DeleteProject(ctx, &pb.DeleteProjectRequest{Name: "/p"}); err != nil {
				t.Fatal(err)
			}
			if _, err := c.SelfClient(a).CreateProject(ctx, &pb.CreateProjectRequest{Name: "/p"}); err != nil {
				t.Fatalf("re-create /p: %v", err)
			}
			grantOn(t, c, a, "/projects/p", "Operator", "user:carol@local")

			switch delivery {
			case "the WAL":
				pumpMutations(t, c, a, b)
				pumpMutations(t, c, b, a)
			case "anti-entropy after the re-create":
				pumpMutations(t, c, a, b)
				if err := a.DB.MergeStateBytesLWW(pullDump(t, c, b)); err != nil {
					t.Fatal(err)
				}
			case "anti-entropy before the re-create":
				if err := a.DB.MergeStateBytesLWW(pullDump(t, c, b)); err != nil {
					t.Fatal(err)
				}
				pumpMutations(t, c, a, b)
			case "the lagging node learns of the re-create by anti-entropy":
				if err := b.DB.MergeStateBytesLWW(pullDump(t, c, a)); err != nil {
					t.Fatal(err)
				}
				pumpMutations(t, c, b, a)
			}
			check := func(when string) {
				t.Helper()
				for _, n := range []*Node{a, b} {
					e := engineOf(t, n)
					if e.Allowed([]string{"user:bob@local"}, "vm.start", "/projects/p/vms/x") {
						t.Errorf("%s, %s: bob may start VMs in the re-created p with the old p's grant", when, n.Name)
					}
					if !e.HasAnyBinding([]string{"user:bob@local"}) {
						t.Errorf("%s, %s: bob has no binding left and falls back to his legacy role", when, n.Name)
					}
					if !e.Allowed([]string{"user:carol@local"}, "vm.start", "/projects/p/vms/x") {
						t.Errorf("%s, %s: the new p's own grant to carol is lost", when, n.Name)
					}
					if !e.Allowed([]string{"user:dave@local"}, "vm.start", "/projects/q/vms/x") {
						t.Errorf("%s, %s: B's unrelated grant on q is lost", when, n.Name)
					}
				}
			}
			check("after delivery")
			for i := 0; i < 2; i++ {
				pumpMutations(t, c, a, b)
				pumpMutations(t, c, b, a)
				antiEntropyRound(t, c)
			}
			check("after the WAL and anti-entropy both ways")
			// The lagging node retired bob's grant when it learned of the
			// re-create, and that retirement reached every node.
			for _, n := range []*Node{a, b} {
				bs, err := corrosion.ListBindingsForPrincipal(ctx, n.DB, "user:bob@local")
				if err != nil {
					t.Fatal(err)
				}
				for _, bd := range bs {
					if bd.Role != corrosion.SentinelRole {
						t.Errorf("%s: bob's old grant is still stored as %s (held=%v), want it retired to NoAccess", n.Name, bd.Role, bd.Held)
					}
				}
			}
		})
	}
}

// TestFleet_GrantsSurviveTheProjectIncarnationUpgrade: a cluster with grants
// made before the upgrade rolls through the project_incarnation_v1 latch
// (node-2 on the previous build until it is upgraded), then sees ordinary
// writes: a grant on the node that latched last, a quota, another project,
// and anti-entropy. Every grant keeps granting on every node. Re-creating
// one project afterwards ends its own pre-latch grant and nothing else.
//
// Mutation: an untagged binding held whatever the incarnation (the pre-latch
// rule off in projectBindingHeld) — red at "after ordinary writes".
func TestFleet_GrantsSurviveTheProjectIncarnationUpgrade(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 7781})
	var held atomic.Bool
	held.Store(true)
	latchProjectIncarnation(t, c, c.Nodes[2], &held) // node-2 on the previous build
	seedRoles(t, c)
	for _, p := range []string{"/a", "/b"} {
		if _, err := c.SelfClient(c.Nodes[0]).CreateProject(ctx, &pb.CreateProjectRequest{Name: p}); err != nil {
			t.Fatal(err)
		}
	}
	c.WaitConverged(t, convergeTimeout)
	grantOn(t, c, c.Nodes[1], "/projects/a", "Operator", "user:bob@local")
	grantOn(t, c, c.Nodes[1], "/projects/b", "Operator", "user:erin@local")
	drainAndExchange(t, c)
	allowed := func(when, who, project string, want bool) {
		t.Helper()
		for _, n := range c.Nodes {
			if got := engineOf(t, n).Allowed([]string{who}, "vm.start", "/projects"+project+"/vms/x"); got != want {
				t.Errorf("%s, %s: %s may start VMs in %s = %v, want %v", when, n.Name, who, project, got, want)
			}
		}
	}
	allowed("before the latch", "user:bob@local", "/a", true)
	allowed("before the latch", "user:erin@local", "/b", true)

	held.Store(false) // node-2 is upgraded
	latchProjectIncarnation(t, c, nil, nil)
	grantOn(t, c, c.Nodes[2], "/projects/a", "Operator", "user:frank@local")
	if _, err := c.SelfClient(c.Nodes[0]).SetProjectQuota(ctx, &pb.SetProjectQuotaRequest{
		Quota: &pb.ProjectQuota{ProjectName: "/a", VcpuLimit: 64}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelfClient(c.Nodes[1]).CreateProject(ctx, &pb.CreateProjectRequest{Name: "/c"}); err != nil {
		t.Fatal(err)
	}
	drainAndExchange(t, c)
	for _, n := range c.Nodes {
		corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
	}
	allowed("after ordinary writes", "user:bob@local", "/a", true)
	allowed("after ordinary writes", "user:frank@local", "/a", true)
	allowed("after ordinary writes", "user:erin@local", "/b", true)
	for _, n := range c.Nodes {
		if q, err := corrosion.GetProjectQuota(ctx, n.DB, "/a"); err != nil || q == nil || q.VCPULimit != 64 {
			t.Errorf("%s: /a's quota = %+v (err %v), want vcpu 64", n.Name, q, err)
		}
	}

	if _, err := c.SelfClient(c.Nodes[0]).DeleteProject(ctx, &pb.DeleteProjectRequest{Name: "/b"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelfClient(c.Nodes[0]).CreateProject(ctx, &pb.CreateProjectRequest{Name: "/b"}); err != nil {
		t.Fatal(err)
	}
	drainAndExchange(t, c)
	allowed("after /b is re-created", "user:erin@local", "/b", false)
	allowed("after /b is re-created", "user:bob@local", "/a", true)
	allowed("after /b is re-created", "user:frank@local", "/a", true)
}

// TestFleet_AnOrphanReaperDoesNotRetireARecreatedProjectsAuthority is the
// projects re-review's R4. Both nodes hold p, deleted by an older build that
// left its authority (epoch 1) live: an orphan. B re-creates p and mints
// epoch 2. Before B's stream reaches A, A's orphan reaper retires p's
// authority, stamped with A's later clock. That retirement must not reach
// B's epoch 2: B never held the tombstone it names.
//
// Red on 1f052cf68: B's p has no authority after A's stream. Mutation: the
// reaper's retirement unguarded — red.
func TestFleet_AnOrphanReaperDoesNotRetireARecreatedProjectsAuthority(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	latchProjectIncarnation(t, c, nil, nil)
	a, b := c.Nodes[0], c.Nodes[1]
	if err := corrosion.InsertProject(ctx, b.DB, corrosion.ProjectRecord{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := corrosion.ClaimInitialProjectAuthority(ctx, b.DB, "/p", a.Name); err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	// An older build's delete: the tombstone only.
	if err := b.DB.Execute(ctx, `UPDATE projects SET deleted_at = ?, updated_at = ? WHERE name = ?`,
		time.Now().UTC().Format(time.RFC3339), b.DB.NowTS(), "/p"); err != nil {
		t.Fatal(err)
	}
	pumpMutations(t, c, b, a)

	// B re-creates p and mints its authority; A does not hear of it yet.
	if err := corrosion.InsertProject(ctx, b.DB, corrosion.ProjectRecord{Name: "/p"}); err != nil {
		t.Fatalf("re-create: %v", err)
	}
	if ok, err := corrosion.ClaimInitialProjectAuthority(ctx, b.DB, "/p", b.Name); err != nil || !ok {
		t.Fatalf("claim after re-create: ok=%v err=%v", ok, err)
	}
	if n, err := corrosion.ReconcileOrphanedProjectAuthority(ctx, a.DB); err != nil || n != 1 {
		t.Fatalf("A's reaper retired %d (err %v), want its orphan", n, err)
	}
	pumpMutations(t, c, a, b)
	pumpMutations(t, c, b, a)
	for _, n := range []*Node{a, b} {
		if got, ok, err := corrosion.CurrentProjectAuthority(ctx, n.DB, "/p"); err != nil || !ok || got.Holder != b.Name || got.Epoch != 2 {
			t.Errorf("%s: the re-created p's authority = %+v ok=%v (err %v), want epoch 2 held by %s", n.Name, got, ok, err, b.Name)
		}
	}
}
