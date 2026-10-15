package fleet

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"google.golang.org/grpc"
)

// TestFleet_VXLANGuestAddressFromThePeersLease: a VM on a vxlan network whose
// dnsmasq runs on ANOTHER host (lab 1 B2: vtpb on node-5, leased by node-4)
// has no lease on its own host, so its address was reported only once its
// host's ARP table learned it — over 60 s, once still unknown after 9 min.
// The IP scanner on the VM's host now asks the network's other hosts for
// their dnsmasq lease over real gRPC and records it on its first pass; the
// single-VM read reports it too.
//
// The VM's host runs the production lookup (no discovery seam): its own lease
// files and ARP table hold nothing for these fresh MACs, so the address can
// only come from the peer. A third host of the network is powered off without
// a reset — every call to it hangs — yet a pass over four NICs stays inside
// its budget, and a single-VM read over three NICs waits once, not per NIC.
// Once that host leaves this node's membership it is not asked at all.
//
// Mutation: drop the peer lookup from discoverNICAddressesWithPeers, or pass
// it nil on the production branch — red; look NICs up one at a time — the
// timing assertions go red; ask hosts outside membership — red.
func TestFleet_VXLANGuestAddressFromThePeersLease(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	ctx := context.Background()
	dhcpHost, vmHost, downHost := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	for _, n := range c.Nodes {
		n.Server.SetBridgeEnsure(n.Net.EnsureBridge)
	}

	// vtp carries the scenario; vtq and vtr give one VM three NICs (one per
	// network: a VM has one NIC per network).
	for i, name := range []string{"vtp", "vtq", "vtr"} {
		if _, err := c.SelfClient(dhcpHost).CreateNetwork(ctx, &pb.CreateNetworkRequest{
			Name: name, Type: "vxlan", Vni: int32(5178 + i), Subnet: fmt.Sprintf("10.%d.0.0/24", 218+i), Dhcp: true,
		}); err != nil {
			t.Fatalf("CreateNetwork %s: %v", name, err)
		}
	}
	for _, n := range []*Node{vmHost, downHost} {
		n := n
		eventually(t, 15*time.Second, "the network rows to reach "+n.Name, func() bool {
			for _, name := range []string{"vtp", "vtq", "vtr"} {
				if nr, err := corrosion.GetNetwork(ctx, n.DB, name); err != nil || nr == nil {
					return false
				}
			}
			return true
		})
		reconcileNetworks(t, n)
	}
	eventually(t, 15*time.Second, "every VTEP row on "+vmHost.Name, func() bool {
		for _, name := range []string{"vtp", "vtq", "vtr"} {
			if len(vtepsOn(t, vmHost, name)) != 3 {
				return false
			}
		}
		return true
	})

	leases := map[string]string{} // MAC → address dhcpHost leases
	var vms []string
	for i := 0; i < 4; i++ {
		name := fmt.Sprintf("vtpb%d", i)
		mustCreateVMOnNetwork(t, c, vmHost, name, "vtp")
		if got := vmNICIP(t, vmHost, name); got != "" {
			t.Fatalf("precondition: a VM on a DHCP network has no recorded address at create, got %q", got)
		}
		leases[strings.ToLower(vmNICMAC(t, vmHost, name))] = fmt.Sprintf("10.218.0.%d", 170+i)
		vms = append(vms, name)
	}
	var held atomic.Bool
	var lmu sync.Mutex
	dhcpHost.Server.SetDHCPLeaseLookup(func(m, bridge string) (string, int64) {
		lmu.Lock()
		defer lmu.Unlock()
		if ip := leases[strings.ToLower(m)]; held.Load() && ip != "" && bridge == "br-vni5178" {
			return ip, time.Now().Add(time.Hour).Unix()
		}
		return "", 0
	})
	// downHost answers nothing: each call hangs until the caller gives up.
	var asked atomic.Int32
	for i := 0; i < 200; i++ {
		downHost.HookUnary("GetVMIPRemote", func(ctx context.Context, _ any, _ grpc.UnaryHandler) (any, error) {
			asked.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		})
	}

	// Control: with no lease anywhere, nothing is recorded.
	grpcapi.NewIPScanner(vmHost.Server).ScanOnce(ctx)
	for _, name := range vms {
		if got := vmNICIP(t, vmHost, name); got != "" {
			t.Fatalf("%s: address %q recorded with no lease anywhere", name, got)
		}
	}

	held.Store(true)
	start := time.Now()
	grpcapi.NewIPScanner(vmHost.Server).ScanOnce(ctx)
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("a scan pass over %d NICs with one host down took %s; the pass budget is 5s, the interval 30s", len(vms), d)
	}
	for _, name := range vms {
		mac := strings.ToLower(vmNICMAC(t, vmHost, name))
		if got := vmNICIP(t, vmHost, name); got != leases[mac] {
			t.Errorf("%s's recorded address = %q after one scan, want %s from %s's lease", name, got, leases[mac], dhcpHost.Name)
		}
	}
	if asked.Load() == 0 {
		t.Errorf("%s, in membership, was never asked", downHost.Name)
	}
	vm, err := c.SelfClient(vmHost).InspectVM(ctx, &pb.InspectVMRequest{Name: vms[0]})
	if err != nil {
		t.Fatalf("InspectVM: %v", err)
	}
	if ifs := vm.GetInterfaces(); len(ifs) != 1 || ifs[0].GetIp() != leases[strings.ToLower(ifs[0].GetMac())] {
		t.Errorf("InspectVM reports interfaces %+v, want its lease", ifs)
	}

	// A VM with three NICs and no lease anywhere: the single-VM read waits
	// on the down host once, not once per NIC.
	if _, err := c.SelfClient(vmHost).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "vtpc", Cpu: 1, MemoryMib: 512, Placement: &pb.PlacementSpec{Host: vmHost.Name},
		Network: []*pb.NetworkAttachment{{Name: "vtp"}, {Name: "vtq"}, {Name: "vtr"}},
	}}); err != nil {
		t.Fatalf("CreateVM vtpc: %v", err)
	}
	start = time.Now()
	if _, err := c.SelfClient(vmHost).InspectVM(ctx, &pb.InspectVMRequest{Name: "vtpc"}); err != nil {
		t.Fatalf("InspectVM vtpc: %v", err)
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Errorf("InspectVM of a three-NIC VM with one host down took %s; its budget is 2s once", d)
	}

	// The down host leaves this node's gossip membership: it is not asked.
	vmHost.DB.SetMembersForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{{Name: dhcpHost.Name, Addr: dhcpHost.Address + ":7946"}}
	})
	before := asked.Load()
	start = time.Now()
	grpcapi.NewIPScanner(vmHost.Server).ScanOnce(ctx)
	if got := asked.Load(); got != before {
		t.Errorf("%s, out of membership, was asked %d more times", downHost.Name, got-before)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("a scan pass with the down host out of membership took %s", d)
	}
}
