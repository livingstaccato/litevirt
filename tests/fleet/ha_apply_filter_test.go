package fleet

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestHADisarm_ApplyFilterHoldsOneKey pins the harness's per-node, per-key
// apply filter (Node.HoldPolicyKey): with x holding cluster_policies key `ha`,
// a policy written elsewhere reaches every node but x, while another policy
// row and x's Ready answers still flow. Released, the row reaches x through
// anti-entropy.
func TestHADisarm_ApplyFilterHoldsOneKey(t *testing.T) {
	ctx := context.Background()
	c, _ := latchedFleet(t, 3, 1015)
	a, b, x := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	release := x.HoldPolicyKey(t, "ha")

	ts, err := corrosion.SetHAPolicy(ctx, a.DB, capabilities.GrantForTest(t, capabilities.FeatureHADisarm),
		corrosion.HADisarmed, "filter test", "alice", "")
	if err != nil {
		t.Fatalf("disarm on %s: %v", a.Name, err)
	}
	if err := corrosion.SetFailbackPolicy(ctx, a.DB, capabilities.GrantForTest(t, capabilities.FeatureDrainFailback), true, "alice"); err != nil {
		t.Fatalf("failback policy on %s: %v", a.Name, err)
	}
	eventually(t, convergeTimeout, "the ha row on "+b.Name, func() bool {
		p, _ := corrosion.GetHAPolicy(ctx, b.DB)
		return p.UpdatedAt == ts
	})
	eventually(t, convergeTimeout, "the failback row on "+x.Name, func() bool {
		p, _ := corrosion.GetFailbackPolicy(ctx, x.DB)
		return p.Enabled
	})
	// Give the held row every chance to arrive: a push that would carry it has
	// already delivered the later failback row.
	time.Sleep(500 * time.Millisecond)
	if p, _ := corrosion.GetHAPolicy(ctx, x.DB); p.UpdatedAt != "" {
		t.Fatalf("%s holds the ha row through its filter: %+v", x.Name, p)
	}
	if r, err := c.PeerClient(a, x).Ready(ctx, &pb.ReadyRequest{}); err != nil || !r.GetReady() {
		t.Fatalf("Ready %s→%s while the filter holds: %+v %v", a.Name, x.Name, r, err)
	}

	release()
	antiEntropyEverywhere(t, c)
	eventually(t, convergeTimeout, "the ha row on "+x.Name+" after release", func() bool {
		p, _ := corrosion.GetHAPolicy(ctx, x.DB)
		return p.UpdatedAt == ts && p.State == corrosion.HADisarmed
	})
}
