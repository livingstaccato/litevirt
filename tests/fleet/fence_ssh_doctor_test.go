package fleet

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/fencessh"
)

// TestFleet_FenceSSH_DoctorMatrix: `lv doctor fence`'s matrix is every
// host's own view, collected over real RPCs by the host it asked: node-0 and
// node-1 have published, node-2 has not, so every fence toward node-2 is the
// unpinned legacy path (the warning doctor prints), and node-0 and node-1
// reach each other over the managed path.
//
// Mutation: answer fan_out with this node's view only — node-1's and
// node-2's rows of the matrix are missing, red.
func TestFleet_FenceSSH_DoctorMatrix(t *testing.T) {
	ctx := context.Background()
	c, fs := fenceSSHFleet(t, 3, 2619)
	for _, n := range c.Nodes {
		n.Server.SetFenceSSH(fs[n.Name].agent)
	}
	syncAll(t, fs["node-0"], fs["node-1"])
	c.WaitConverged(t, convergeTimeout)
	syncAll(t, fs["node-0"], fs["node-1"])

	st, err := c.SelfClient(c.Nodes[0]).GetFenceSSHStatus(ctx, &pb.FenceSSHStatusRequest{FanOut: true})
	if err != nil {
		t.Fatalf("GetFenceSSHStatus: %v", err)
	}
	path := map[string]string{}
	for _, n := range st.GetNodes() {
		if !n.GetReachable() || n.GetError() != "" {
			t.Fatalf("%s did not answer: %+v", n.GetHost(), n)
		}
		for _, p := range n.GetPeers() {
			path[n.GetHost()+">"+p.GetHost()] = p.GetPath() + "/" + p.GetRow()
		}
	}
	for pair, want := range map[string]string{
		"node-0>node-1": "managed/verified",
		"node-1>node-0": "managed/verified",
		"node-0>node-2": "legacy-unpinned/missing",
		"node-1>node-2": "legacy-unpinned/missing",
		"node-2>node-2": fencessh.PathSelf + "/missing",
	} {
		if path[pair] != want {
			t.Errorf("%s = %q, want %q (all %v)", pair, path[pair], want, path)
		}
	}
	// node-2 has no fence key of its own yet, so it cannot use node-0's
	// managed path; in auto it fences node-0 pinned meanwhile.
	if p := path["node-2>node-0"]; p != "legacy-pinned/verified" {
		t.Errorf("node-2>node-0 = %q, want legacy-pinned/verified", p)
	}
}
