package fleet

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Review R3-A: the default project has no projects row, by design, so after
// the project_incarnation_v1 latch its quota is still set and changed under
// its bare key, not refused as a project that does not exist.
//
// Red on bcb94ec73: NotFound, project "_default" does not exist. Mutation:
// the default project taken through the live check again — red.
func TestFleet_TheDefaultProjectsQuotaCanBeSetAfterTheLatch(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	latchProjectIncarnation(t, c, nil, nil)
	a := c.Nodes[0]
	for _, v := range []int32{4, 8} {
		if _, err := c.SelfClient(a).SetProjectQuota(ctx, &pb.SetProjectQuotaRequest{
			Quota: &pb.ProjectQuota{ProjectName: "_default", VcpuLimit: v}}); err != nil {
			t.Fatalf("set _default quota to %d after the latch: %v", v, err)
		}
		if q, err := corrosion.GetProjectQuota(ctx, a.DB, "_default"); err != nil || q == nil || q.VCPULimit != int(v) {
			t.Fatalf("_default quota = %+v (err %v), want %d", q, err, v)
		}
	}
}
