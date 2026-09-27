package grpcapi

import (
	"context"
	"encoding/json"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Every MAC-to-address lookup that knows the NIC's network restricts itself to
// the bridge that network leases on — the rule the IP scanner and the VM
// probe already follow. A MAC with leases on two bridges (a deprovisioned
// network's leftover file, a network the guest has left) otherwise resolves
// to whichever lease is newest, which need not be its own network's.

const (
	bridgeTestMAC     = "52:54:00:11:22:55"
	bridgeTestOwnIP   = "10.0.60.5" // br-lan's lease: the NIC's own network
	bridgeTestOtherIP = "10.0.99.5" // another bridge's lease for the same MAC
)

// bridgeDiscoveryFixture is a running VM "web" in stack "app" on test-host,
// one NIC on network "lan" (bridge br-lan) with no recorded address, and a
// discovery seam in which the unrestricted lookup finds the other bridge's
// lease.
func bridgeDiscoveryFixture(t *testing.T) *Server {
	t.Helper()
	s := testServerCov(t)
	ctx := context.Background()
	cfg, _ := json.Marshal(compose.NetworkDef{Interface: "br-lan"})
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "lan", Type: "bridge", Config: string(cfg)}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "web", StackName: "app", HostName: "test-host", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "web", NetworkName: "lan", MAC: bridgeTestMAC},
	}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// A known peer, for the peer-only GetVMIPRemote.
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "peer-1", Address: "127.0.0.1", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	s.setNICIPDiscoveryOnBridge(func(mac, bridge string) string {
		if mac != bridgeTestMAC {
			return ""
		}
		if bridge == "br-lan" {
			return bridgeTestOwnIP
		}
		return bridgeTestOtherIP
	})
	return s
}

func TestResolveStackBackends_DiscoversOnTheNICsBridge(t *testing.T) {
	s := bridgeDiscoveryFixture(t)
	var got string
	for _, rb := range s.resolveStackBackends(context.Background(), "app", false, false) {
		if rb.Name == "web" {
			got = rb.IP
		}
	}
	if got != bridgeTestOwnIP {
		t.Fatalf("LB backend web = %q, want %s from its NIC's bridge br-lan", got, bridgeTestOwnIP)
	}
}

func TestCreateLoadBalancer_VMBackendDiscoversOnTheNICsBridge(t *testing.T) {
	s := bridgeDiscoveryFixture(t)
	ctx := adminCtx()
	createLBTable(t, ctx, s.db)
	if _, err := s.CreateLoadBalancer(ctx, &pb.CreateLBRequest{
		Name:       "web-lb",
		Vip:        "10.0.100.61/24",
		Ports:      []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
		VmBackends: []string{"web"},
		Hosts:      []string{"other-host"},
	}); err != nil {
		t.Fatalf("CreateLoadBalancer: %v", err)
	}
	backends, err := corrosion.ListLBBackends(ctx, s.db, "web-lb")
	if err != nil || len(backends) != 1 {
		t.Fatalf("backends = %+v, %v; want web's one", backends, err)
	}
	if backends[0].Address != bridgeTestOwnIP {
		t.Fatalf("VM backend address = %q, want %s from its NIC's bridge br-lan", backends[0].Address, bridgeTestOwnIP)
	}
}

func TestInspectVM_DiscoversOnTheNICsBridge(t *testing.T) {
	s := bridgeDiscoveryFixture(t)
	vm, err := s.InspectVM(adminCtx(), &pb.InspectVMRequest{Name: "web"})
	if err != nil {
		t.Fatalf("InspectVM: %v", err)
	}
	if len(vm.Interfaces) != 1 || vm.Interfaces[0].Ip != bridgeTestOwnIP {
		t.Fatalf("interfaces = %+v, want web's NIC at %s from br-lan", vm.Interfaces, bridgeTestOwnIP)
	}
}

func TestListVMs_DiscoversOnTheNICsBridge(t *testing.T) {
	s := bridgeDiscoveryFixture(t)
	resp, err := s.ListVMs(adminCtx(), &pb.ListVMsRequest{})
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	for _, vm := range resp.Vms {
		if vm.Name != "web" {
			continue
		}
		if len(vm.Interfaces) != 1 || vm.Interfaces[0].Ip != bridgeTestOwnIP {
			t.Fatalf("interfaces = %+v, want web's NIC at %s from br-lan", vm.Interfaces, bridgeTestOwnIP)
		}
		return
	}
	t.Fatal("ListVMs did not list web")
}

// The peer lookup is told the NIC's network, so it restricts itself too.
func TestGetVMIPRemote_DiscoversOnTheNICsBridge(t *testing.T) {
	s := bridgeDiscoveryFixture(t)
	resp, err := s.GetVMIPRemote(mtlsCtx("peer-1"), &pb.GetVMIPRequest{Mac: bridgeTestMAC, NetworkName: "lan"})
	if err != nil {
		t.Fatalf("GetVMIPRemote: %v", err)
	}
	if resp.Ip != bridgeTestOwnIP {
		t.Fatalf("GetVMIPRemote = %q, want %s from the NIC's bridge br-lan", resp.Ip, bridgeTestOwnIP)
	}
}

// With the network unknown there is no bridge to restrict to, and the lookup
// falls back to every bridge's leases rather than finding nothing.
func TestGetVMIPRemote_UnknownNetworkFallsBackToAnyBridge(t *testing.T) {
	s := bridgeDiscoveryFixture(t)
	resp, err := s.GetVMIPRemote(mtlsCtx("peer-1"), &pb.GetVMIPRequest{Mac: bridgeTestMAC})
	if err != nil {
		t.Fatalf("GetVMIPRemote: %v", err)
	}
	if resp.Ip != bridgeTestOtherIP {
		t.Fatalf("GetVMIPRemote with no network = %q, want the unrestricted lookup's %s", resp.Ip, bridgeTestOtherIP)
	}
}
