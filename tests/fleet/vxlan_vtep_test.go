package fleet

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
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

// vtepRowsAre waits until every node's replica of network's VTEP rows names
// each node at want(node).
func vtepRowsAre(t *testing.T, c *Cluster, name, what string, want func(host string) string) {
	t.Helper()
	for _, n := range c.Nodes {
		n := n
		eventually(t, 15*time.Second, what+" on "+n.Name, func() bool {
			rows := vtepsOn(t, n, name)
			if len(rows) != len(c.Nodes) {
				return false
			}
			for host, got := range rows {
				if got != want(host) {
					return false
				}
			}
			return true
		})
	}
}

// TestFleet_VXLAN_VTEPMovesToTheHostAddressAtTheLatch: until the release
// token latches every node keeps the tunnel endpoint every earlier build
// used (the default-route address, shared by the fleet's nodes as by the
// lab's), so a host on this build still reaches its peers on the previous
// one. Once it latches, each node's next network pass provisions the network
// again on its own host address, registers that, and every replica's rows say
// so; after that, passes only sync the forwarding entries.
func TestFleet_VXLAN_VTEPMovesToTheHostAddressAtTheLatch(t *testing.T) {
	c, gates := latchedFleet(t, 3, 1514)
	addr := setHostAddresses(c)
	for _, n := range c.Nodes {
		if gates[n.Name].DurablyLatched(capabilities.ReleaseToken) {
			t.Fatalf("precondition: %s has already latched the release token", n.Name)
		}
	}
	createVXLAN(t, c, "vxd_vxdnet")
	for _, n := range c.Nodes {
		if got := n.Net.VTEP("vxd_vxdnet"); got != LegacyVTEP {
			t.Errorf("%s before the latch: VTEP %q, want the previous build's %s", n.Name, got, LegacyVTEP)
		}
	}
	vtepRowsAre(t, c, "vxd_vxdnet", "the pre-latch VTEP rows", func(string) string { return LegacyVTEP })

	latchReleaseToken(t, c, gates)
	for _, n := range c.Nodes {
		before := n.Net.Provisions("vxd_vxdnet")
		reconcileNetworks(t, n)
		if got := n.Net.VTEP("vxd_vxdnet"); got != addr[n.Name] {
			t.Errorf("%s after the latch: VTEP %q, want its host address %s", n.Name, got, addr[n.Name])
		}
		if got := n.Net.Provisions("vxd_vxdnet"); got != before+1 {
			t.Errorf("%s: %d provisions at the latch, want exactly one more than %d", n.Name, got, before)
		}
	}
	vtepRowsAre(t, c, "vxd_vxdnet", "the host-address VTEP rows", func(h string) string { return addr[h] })

	// Settled: a further pass does not provision again; it syncs the entries.
	n := c.Nodes[1]
	p, s := n.Net.Provisions("vxd_vxdnet"), n.Net.FDBSyncs("vxd_vxdnet")
	reconcileNetworks(t, n)
	if got := n.Net.Provisions("vxd_vxdnet"); got != p {
		t.Errorf("%s provisioned the network again on a settled pass (%d → %d)", n.Name, p, got)
	}
	if got := n.Net.FDBSyncs("vxd_vxdnet"); got != s+1 {
		t.Errorf("%s: forwarding-entry syncs %d → %d on a settled pass, want one", n.Name, s, got)
	}
}

// TestFleet_VXLAN_AMovedVTEPReachesEveryPeersFloodList: when one host's VTEP
// moves and only that host provisions again — the lab's partial heal, where a
// compose update re-provisioned three of six nodes and node-1 never learned
// node-4's new address — every other node's next network pass floods to the
// new address, from the replicated row, with no provisioning of its own.
func TestFleet_VXLAN_AMovedVTEPReachesEveryPeersFloodList(t *testing.T) {
	c, gates := latchedFleet(t, 3, 1517)
	latchReleaseToken(t, c, gates)
	addr := setHostAddresses(c)
	createVXLAN(t, c, "vxd_vxdnet")
	reconcileNetworks(t, c.Nodes[0]) // settled: every node's reconciler has it applied
	vtepRowsAre(t, c, "vxd_vxdnet", "the VTEP rows", func(h string) string { return addr[h] })

	moved := c.Nodes[2]
	addr[moved.Name] = "10.77.1.13"
	moved.Server.SetHostAddress(addr[moved.Name])
	moved.Server.ForgetNetworkReconcileForTests()
	reconcileNetworks(t, moved)
	vtepRowsAre(t, c, "vxd_vxdnet", "the moved VTEP row", func(h string) string { return addr[h] })

	for _, n := range c.Nodes[:2] {
		p := n.Net.Provisions("vxd_vxdnet")
		reconcileNetworks(t, n)
		var want []string
		for _, o := range c.Nodes {
			if o != n {
				want = append(want, addr[o.Name])
			}
		}
		sort.Strings(want)
		if got := n.Net.Flood("vxd_vxdnet"); !slices.Equal(got, want) {
			t.Errorf("%s floods to %v after %s's VTEP moved, want %v", n.Name, got, moved.Name, want)
		}
		if got := n.Net.Provisions("vxd_vxdnet"); got != p {
			t.Errorf("%s provisioned the network again (%d → %d); the sync alone should carry the move", n.Name, p, got)
		}
	}
}
