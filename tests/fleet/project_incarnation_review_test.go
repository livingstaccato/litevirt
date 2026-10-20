package fleet

// The projinc review's probes PR-1 and PR-2 (projinc-review.md).

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Review PR-1: a grant to a local account, heard before the account's create.
// node-0 (cut off) creates bob; node-1 takes it by anti-entropy and grants bob
// Operator on /projects/p; node-2 hears node-1's grant before node-0's create.
// With user_incarnation_v1 alone (1f052cf68) node-2 holds the grant
// (userVerdictAhead) and replays it once bob arrives. Expectation: after the
// WAL drains (no anti-entropy) bob is bound on every node, so he does not fall
// back to his legacy role (operator, cluster-wide).
//
// Green on 1f052cf68, red on 6bf531113 (the grant dropped as Ahead).
// Mutation: the user part of a project grant skipped again — red.
func TestFleet_AProjectGrantHeardBeforeItsAccountIsKept(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 7301})
	latchUserIncarnation(t, c, nil, nil)
	latchProjectIncarnation(t, c, nil, nil)
	seedRoles(t, c)
	for _, n := range c.Nodes {
		n.DB.SetCredentialsSplitGate(func() bool { return true })
	}
	a, b, lag := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if _, err := c.SelfClient(a).CreateProject(ctx, &pb.CreateProjectRequest{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	c.Isolate(a)
	if err := corrosion.InsertUser(ctx, a.DB, "bob", "operator", "hash-1"); err != nil {
		t.Fatal(err)
	}
	learnByAE(t, a, b)
	if u, _ := corrosion.GetUser(ctx, b.DB, "bob"); u == nil {
		t.Fatal("fixture: node-1 did not take the create")
	}
	if _, err := c.SelfClient(b).GrantRole(ctx, &pb.GrantRoleRequest{
		Path: "/projects/p", Role: "Operator", Principal: "user:bob@local", Propagate: true}); err != nil {
		t.Fatal(err)
	}
	seenAll(t, b, lag)
	if u, _ := corrosion.GetUser(ctx, lag.DB, "bob"); u != nil {
		t.Fatalf("fixture: node-2 already holds bob %+v", u)
	}
	c.ClearLinkFaults()
	eventually(t, convergeTimeout, "the WAL to drain", func() bool {
		n, err := undelivered(c.Nodes)
		return err == nil && n == 0
	})
	for _, n := range c.Nodes {
		if u, _ := corrosion.GetUser(ctx, n.DB, "bob"); u == nil {
			t.Fatalf("%s: no bob after the WAL drained", n.Name)
		}
		e := engineOf(t, n)
		if !e.HasAnyBinding([]string{"user:bob@local"}) {
			t.Errorf("%s: bob holds no binding after the WAL drained: he falls back to his legacy role (operator) cluster-wide", n.Name)
		}
	}
	antiEntropyRound(t, c)
	for _, n := range c.Nodes {
		if !engineOf(t, n).HasAnyBinding([]string{"user:bob@local"}) {
			t.Errorf("%s: bob holds no binding even after anti-entropy", n.Name)
		}
	}
}

// Review PR-2: a quota a lagging node sets on the OLD p, later in
// HLC than the new p's own quota, reaches the new p by anti-entropy and wins.
// The new p keeps its own vcpu 10 on both nodes.
//
// Red on 1f052cf68 and 6bf531113. Mutations: projectQuotaDecision normal —
// red; dropOtherIncarnationQuotas a no-op — red.
func TestFleet_AStaleLargerQuotaDoesNotReachTheNewProject(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	latchProjectIncarnation(t, c, nil, nil)
	a, b := c.Nodes[0], c.Nodes[1]
	if _, err := c.SelfClient(a).CreateProject(ctx, &pb.CreateProjectRequest{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	pumpMutations(t, c, a, b)
	if _, err := c.SelfClient(a).DeleteProject(ctx, &pb.DeleteProjectRequest{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelfClient(a).CreateProject(ctx, &pb.CreateProjectRequest{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelfClient(a).SetProjectQuota(ctx, &pb.SetProjectQuotaRequest{
		Quota: &pb.ProjectQuota{ProjectName: "/p", VcpuLimit: 10}}); err != nil {
		t.Fatal(err)
	}
	// B, lagging, still holds the old p and caps it at 100, after A's 10.
	if _, err := c.SelfClient(b).SetProjectQuota(ctx, &pb.SetProjectQuotaRequest{
		Quota: &pb.ProjectQuota{ProjectName: "/p", VcpuLimit: 100}}); err != nil {
		t.Fatal(err)
	}
	pumpMutations(t, c, a, b)
	pumpMutations(t, c, b, a)
	if q, _ := corrosion.GetProjectQuota(ctx, a.DB, "/p"); q == nil || q.VCPULimit != 10 {
		t.Logf("over the WAL, A: the new p's quota = %+v", q)
	}
	for i := 0; i < 2; i++ {
		antiEntropyRound(t, c)
	}
	for _, n := range []*Node{a, b} {
		if q, err := corrosion.GetProjectQuota(ctx, n.DB, "/p"); err != nil || q == nil || q.VCPULimit != 10 {
			t.Errorf("after anti-entropy, %s: the new p's quota = %+v (err %v), want the new p's own vcpu 10", n.Name, q, err)
		}
	}
}
