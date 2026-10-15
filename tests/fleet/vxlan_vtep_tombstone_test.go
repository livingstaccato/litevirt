package fleet

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestFleet_VXLAN_DeleteTombstonesTheVTEPs: deleting a vxlan network
// tombstones every host's network_vteps row on every replica, once the release
// token has latched. Left live, a network created again under the name read
// them as its peers.
func TestFleet_VXLAN_DeleteTombstonesTheVTEPs(t *testing.T) {
	c, gates := latchedFleet(t, 3, 1515)
	latchReleaseToken(t, c, gates)
	setHostAddresses(c)
	createVXLAN(t, c, "vxd_vxdnet")
	for _, n := range c.Nodes {
		n := n
		eventually(t, 15*time.Second, "every VTEP row to reach "+n.Name, func() bool {
			return len(vtepsOn(t, n, "vxd_vxdnet")) == len(c.Nodes)
		})
	}

	if _, err := c.SelfClient(c.Nodes[0]).DeleteNetwork(context.Background(), &pb.DeleteNetworkRequest{Name: "vxd_vxdnet"}); err != nil {
		t.Fatalf("DeleteNetwork: %v", err)
	}
	for _, n := range c.Nodes {
		n := n
		eventually(t, 15*time.Second, "the VTEP rows to be tombstoned on "+n.Name, func() bool {
			return len(vtepsOn(t, n, "vxd_vxdnet")) == 0
		})
	}
}

// TestFleet_VXLAN_DeleteBeforeTheLatchLeavesTheVTEPs: before the release
// token latches a host may still run the previous build, which does not know
// the tombstone's statement shape, so the delete writes none.
func TestFleet_VXLAN_DeleteBeforeTheLatchLeavesTheVTEPs(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 1516})
	setHostAddresses(c)
	createVXLAN(t, c, "vxd_vxdnet")
	n0 := c.Nodes[0]
	eventually(t, 15*time.Second, "every VTEP row to reach "+n0.Name, func() bool {
		return len(vtepsOn(t, n0, "vxd_vxdnet")) == len(c.Nodes)
	})
	if _, err := c.SelfClient(n0).DeleteNetwork(context.Background(), &pb.DeleteNetworkRequest{Name: "vxd_vxdnet"}); err != nil {
		t.Fatalf("DeleteNetwork: %v", err)
	}
	if got := len(vtepsOn(t, n0, "vxd_vxdnet")); got != len(c.Nodes) {
		t.Fatalf("live VTEP rows on %s after a pre-latch delete = %d, want %d", n0.Name, got, len(c.Nodes))
	}
}
