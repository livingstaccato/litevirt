package fleet

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_ClearIPMIReachesEveryNode: `lv host config --clear-ipmi` through
// one node removes the IPMI settings on every node, both copies of the
// password included. A clear that reached only the old column would leave
// every latched node serving the password from its credential row.
func TestFleet_ClearIPMIReachesEveryNode(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	for _, n := range c.Nodes {
		n.DB.SetCredentialsSplitGate(func() bool { return true })
	}
	a, b, target := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	configureIPMI(t, c, a, target.Name, "bmc-pass-1")
	c.WaitConverged(t, convergeTimeout)

	if _, err := c.SelfClient(b).ConfigureHost(ctx, &pb.ConfigureHostRequest{
		Name: target.Name, FenceStrategy: "ssh", ClearIpmi: true,
	}); err != nil {
		t.Fatalf("clear IPMI via %s: %v", b.Name, err)
	}
	c.WaitConverged(t, convergeTimeout)

	for _, n := range c.Nodes {
		h, err := corrosion.GetHost(ctx, n.DB, target.Name)
		if err != nil || h == nil {
			t.Fatalf("%s: GetHost: %v", n.Name, err)
		}
		if h.IPMIAddress != "" || h.IPMIUser != "" || h.IPMIPass != "" || h.FenceStrategy != "ssh" {
			t.Errorf("%s still holds IPMI settings after the clear: %s %q / %q @ %q", n.Name,
				h.FenceStrategy, h.IPMIUser, h.IPMIPass, h.IPMIAddress)
		}
		assertBothCopies(t, n, "hosts.ipmi_pass", "",
			`SELECT ipmi_pass FROM hosts WHERE name = ?`,
			`SELECT ipmi_pass FROM host_fence_credentials WHERE host_name = ?`, target.Name)
	}
}
