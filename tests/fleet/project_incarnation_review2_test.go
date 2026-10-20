package fleet

// The projinc round-2 review's probes R2-A and R2-B (projinc-r2-review.md).

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Review R2-A: the new incarnation's OWN quota, heard before the re-create,
// is kept, and enforced once the re-create arrives, with no anti-entropy.
//
// Green on 1f052cf68, red on 6bf531113 and b27949454 (the quota skipped by
// its guard). Mutation: a quota keyed by the bare name again — red.
func TestFleet_ANewProjectsOwnQuotaHeardBeforeItsRecreateIsKept(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 7401})
	latchProjectIncarnation(t, c, nil, nil)
	a, b, lag := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if _, err := c.SelfClient(a).CreateProject(ctx, &pb.CreateProjectRequest{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	c.Isolate(a)
	if _, err := c.SelfClient(a).DeleteProject(ctx, &pb.DeleteProjectRequest{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelfClient(a).CreateProject(ctx, &pb.CreateProjectRequest{Name: "/p"}); err != nil {
		t.Fatal(err)
	}
	learnByAE(t, a, b)
	if _, err := c.SelfClient(b).SetProjectQuota(ctx, &pb.SetProjectQuotaRequest{
		Quota: &pb.ProjectQuota{ProjectName: "/p", VcpuLimit: 10}}); err != nil {
		t.Fatal(err)
	}
	seenAll(t, b, lag)
	c.ClearLinkFaults()
	eventually(t, convergeTimeout, "the WAL to drain", func() bool {
		n, err := undelivered(c.Nodes)
		return err == nil && n == 0
	})
	for _, n := range c.Nodes {
		if q, err := corrosion.GetProjectQuota(ctx, n.DB, "/p"); err != nil || q == nil || q.VCPULimit != 10 {
			t.Errorf("after the WAL drained, %s: the new p's own quota = %+v (err %v), want vcpu 10", n.Name, q, err)
		}
	}
}

// Review R2-B: a quota set on a node that holds p deleted never overrides the
// new p's own quota, over the WAL or anti-entropy: it is refused there, and
// any other incarnation's quota is keyed apart from the new p's.
//
// Red on 1f052cf68, 6bf531113 and b27949454 in both variants. Mutation:
// GetProjectQuota reading the bare name — red.
func TestFleet_AQuotaSetOnADeletedProjectDoesNotOverrideTheNewOnes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		bSeesDelete bool // B holds p deleted; otherwise B still holds the old p live
		ae          bool
	}{
		{"deleted on B, the WAL", true, false},
		{"deleted on B, anti-entropy", true, true},
		{"the old p on B, the WAL", false, false},
		{"the old p on B, anti-entropy", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := New(t, Options{Nodes: 2})
			latchProjectIncarnation(t, c, nil, nil)
			a, b := c.Nodes[0], c.Nodes[1]
			if _, err := c.SelfClient(a).CreateProject(ctx, &pb.CreateProjectRequest{Name: "/p"}); err != nil {
				t.Fatal(err)
			}
			if !tc.bSeesDelete {
				pumpMutations(t, c, a, b) // B holds the old p live
			}
			if _, err := c.SelfClient(a).DeleteProject(ctx, &pb.DeleteProjectRequest{Name: "/p"}); err != nil {
				t.Fatal(err)
			}
			if tc.bSeesDelete {
				pumpMutations(t, c, a, b) // B holds p deleted
			}
			if _, err := c.SelfClient(a).CreateProject(ctx, &pb.CreateProjectRequest{Name: "/p"}); err != nil {
				t.Fatal(err)
			}
			if _, err := c.SelfClient(a).SetProjectQuota(ctx, &pb.SetProjectQuotaRequest{
				Quota: &pb.ProjectQuota{ProjectName: "/p", VcpuLimit: 10}}); err != nil {
				t.Fatal(err)
			}
			_, err := c.SelfClient(b).SetProjectQuota(ctx, &pb.SetProjectQuotaRequest{
				Quota: &pb.ProjectQuota{ProjectName: "/p", VcpuLimit: 100}})
			if tc.bSeesDelete && err == nil {
				t.Error("a quota for a project deleted on B was accepted there")
			}
			if !tc.bSeesDelete && err != nil {
				t.Fatalf("a quota for the old p on B: %v", err)
			}
			if tc.ae {
				if err := a.DB.MergeStateBytesLWW(pullDump(t, c, b)); err != nil {
					t.Fatal(err)
				}
			} else {
				pumpMutations(t, c, b, a)
			}
			if q, err := corrosion.GetProjectQuota(ctx, a.DB, "/p"); err != nil || q == nil || q.VCPULimit != 10 {
				t.Errorf("the new p's quota on A = %+v (err %v), want its own vcpu 10", q, err)
			}
			// B takes the re-create: it reads the new p's own quota, not its 100.
			pumpMutations(t, c, a, b)
			antiEntropyRound(t, c)
			for _, n := range []*Node{a, b} {
				if q, err := corrosion.GetProjectQuota(ctx, n.DB, "/p"); err != nil || q == nil || q.VCPULimit != 10 {
					t.Errorf("after both ways, %s: the new p's quota = %+v (err %v), want vcpu 10", n.Name, q, err)
				}
			}
		})
	}
}
