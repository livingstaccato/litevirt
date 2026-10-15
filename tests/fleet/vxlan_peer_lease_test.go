package fleet

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// TestFleet_VXLANGuestAddressFromThePeersLease: a VM on a vxlan network whose
// dnsmasq runs on ANOTHER host (lab 1 B2: vtpb on node-5, leased by node-4)
// has no lease on its own host, so its address was reported only once its
// host's ARP table learned it — over 60 s, once still unknown after 9 min. The
// IP scanner on the VM's host now asks the network's other hosts for their
// dnsmasq lease over real gRPC and records it on its first pass; the
// single-VM read reports it too.
//
// Mutation: drop the peer lookup from discoverNICAddressWithPeers — red.
func TestFleet_VXLANGuestAddressFromThePeersLease(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	ctx := context.Background()
	dhcpHost, vmHost := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		n.Server.SetBridgeEnsure(n.Net.EnsureBridge)
	}

	if _, err := c.SelfClient(dhcpHost).CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "vtp", Type: "vxlan", Vni: 5178, Subnet: "10.218.0.0/24", Dhcp: true,
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	eventually(t, 15*time.Second, "the network row to reach "+vmHost.Name, func() bool {
		nr, err := corrosion.GetNetwork(ctx, vmHost.DB, "vtp")
		return err == nil && nr != nil
	})
	reconcileNetworks(t, vmHost)
	eventually(t, 15*time.Second, "both VTEP rows on "+vmHost.Name, func() bool {
		return len(vtepsOn(t, vmHost, "vtp")) == 2
	})

	mustCreateVMOnNetwork(t, c, vmHost, "vtpb", "vtp")
	mac := vmNICMAC(t, vmHost, "vtpb")
	if got := vmNICIP(t, vmHost, "vtpb"); got != "" {
		t.Fatalf("precondition: a VM on a DHCP network has no recorded address at create, got %q", got)
	}

	// Nothing on the VM's own host: no lease file of its own, nothing in ARP.
	vmHost.Server.SetNICIPDiscovery(func(string) string { return "" })
	const leased = "10.218.0.173"
	var held atomic.Bool
	dhcpHost.Server.SetDHCPLeaseLookup(func(m, bridge string) (string, int64) {
		if held.Load() && strings.EqualFold(m, mac) && bridge == "br-vni5178" {
			return leased, time.Now().Add(time.Hour).Unix()
		}
		return "", 0
	})

	// Control: with no lease anywhere, nothing is recorded.
	grpcapi.NewIPScanner(vmHost.Server).ScanOnce(ctx)
	if got := vmNICIP(t, vmHost, "vtpb"); got != "" {
		t.Fatalf("address %q recorded with no lease anywhere", got)
	}

	held.Store(true)
	grpcapi.NewIPScanner(vmHost.Server).ScanOnce(ctx)
	if got := vmNICIP(t, vmHost, "vtpb"); got != leased {
		t.Errorf("vtpb's recorded address = %q after one scan, want %s from %s's lease", got, leased, dhcpHost.Name)
	}
	vm, err := c.SelfClient(vmHost).InspectVM(ctx, &pb.InspectVMRequest{Name: "vtpb"})
	if err != nil {
		t.Fatalf("InspectVM: %v", err)
	}
	if ifs := vm.GetInterfaces(); len(ifs) != 1 || ifs[0].GetIp() != leased {
		t.Errorf("InspectVM reports interfaces %+v, want one at %s", ifs, leased)
	}
}
