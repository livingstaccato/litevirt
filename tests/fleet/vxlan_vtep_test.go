package fleet

import (
	"context"
	"fmt"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// vtepsOn returns network's live VTEP rows on n, host → address.
func vtepsOn(t *testing.T, n *Node, name string) map[string]string {
	t.Helper()
	vs, err := network.GetVTEPs(context.Background(), n.DB, name)
	if err != nil {
		t.Fatalf("GetVTEPs on %s: %v", n.Name, err)
	}
	out := map[string]string{}
	for _, v := range vs {
		out[v.HostName] = v.VTEPAddr
	}
	return out
}

// setHostAddresses gives each node an advertise address of its own. The nodes
// share one machine, so their default-route source address is the same — the
// lab's shape (lab1-vxlan-dhcp.md: 10.0.2.15 on every node), where only the
// advertise address tells them apart.
func setHostAddresses(c *Cluster) map[string]string {
	addr := map[string]string{}
	for i, n := range c.Nodes {
		a := fmt.Sprintf("10.77.0.%d", 11+i)
		n.Server.SetHostAddress(a)
		addr[n.Name] = a
	}
	return addr
}

// createVXLAN creates a vxlan network on the first node and has every other
// node's network reconciler provision it once the row reaches it.
func createVXLAN(t *testing.T, c *Cluster, name string) {
	t.Helper()
	ctx := context.Background()
	if _, err := c.SelfClient(c.Nodes[0]).CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: name, Type: "vxlan", Vni: 5177,
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	for _, n := range c.Nodes[1:] {
		n := n
		eventually(t, 15*time.Second, "the network row to reach "+n.Name, func() bool {
			nr, err := corrosion.GetNetwork(ctx, n.DB, name)
			return err == nil && nr != nil
		})
		reconcileNetworks(t, n)
	}
}

// TestFleet_VXLAN_VTEPIsTheHostAddress: every node provisions a vxlan network
// with its own host address as the VTEP, registers that address in
// network_vteps, and every node's replica of the rows says so — so no node's
// flood list holds a peer row that is really itself.
func TestFleet_VXLAN_VTEPIsTheHostAddress(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 1514})
	addr := setHostAddresses(c)
	createVXLAN(t, c, "vxd_vxdnet")

	for _, n := range c.Nodes {
		if got := n.Net.VTEP("vxd_vxdnet"); got != addr[n.Name] {
			t.Errorf("%s provisioned the network with VTEP %q, want its host address %s", n.Name, got, addr[n.Name])
		}
	}
	for _, n := range c.Nodes {
		n := n
		eventually(t, 15*time.Second, "every VTEP row to reach "+n.Name, func() bool {
			return len(vtepsOn(t, n, "vxd_vxdnet")) == len(c.Nodes)
		})
		for host, got := range vtepsOn(t, n, "vxd_vxdnet") {
			if got != addr[host] {
				t.Errorf("on %s, %s's VTEP row says %q, want %s", n.Name, host, got, addr[host])
			}
		}
	}
}
