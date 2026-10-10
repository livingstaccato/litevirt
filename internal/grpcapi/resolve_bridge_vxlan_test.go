package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// A vxlan network's host bridge is br-vni<VNI>: that is the device Provision
// creates and returns. `lv network create` stores interface=<name> on every
// network, so resolveBridge used to hand the NIC paths that trust it (hot
// attach, restart, containers) a bridge named after the network, which
// provisioning never creates.
func TestResolveBridge_VXLANNamesTheProvisionedBridge(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name:   "ov",
		Type:   "vxlan",
		Config: `{"interface":"ov","vni":500}`,
	}); err != nil {
		t.Fatalf("seed network: %v", err)
	}

	if got := resolveBridge(ctx, s.db, "ov"); got != "br-vni500" {
		t.Errorf("resolveBridge = %q, want br-vni500 (the bridge Provision creates)", got)
	}
}

// The create sites put a NIC on a record-less network on network.FlatBridgeName.
// Reconcile, restart and hot attach resolve the device through resolveBridge, so
// it must name the same one — a long name resolved raw points the domain at a
// bridge that does not exist and cannot be created.
func TestResolveBridge_RecordlessNameMatchesCreateSites(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	for _, name := range []string{"web", "mystack_frontend_net", "123456789012345"} {
		if got, want := resolveBridge(ctx, s.db, name), network.FlatBridgeName(name); got != want {
			t.Errorf("resolveBridge(%q) = %q, want %q", name, got, want)
		}
	}
	if got := resolveBridge(ctx, s.db, "mystack_frontend_net"); len(got) > 15 {
		t.Errorf("resolved device %q exceeds IFNAMSIZ", got)
	}
	// A bridge that exists today keeps its name.
	if got := resolveBridge(ctx, s.db, "hc_a"); got != "hc_a" {
		t.Errorf("short name changed: %q", got)
	}
}

// A bridge-type network whose bridge name cannot be a Linux interface is refused
// at create, not left to fail every VM placed on it.
func TestCreateNetwork_RefusesBridgeNameOver15Bytes(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	_, err := s.CreateNetwork(ctx, &pb.CreateNetworkRequest{Name: "a-very-long-network-name", Type: "bridge"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument naming the 15-byte limit", err)
	}
	if !strings.Contains(err.Error(), "15") {
		t.Errorf("message does not name the limit: %v", err)
	}
	_, err = s.CreateNetwork(ctx, &pb.CreateNetworkRequest{Name: "x", Type: "bridge", Iface: "a-very-long-bridge-name"})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("long --iface: err = %v, want InvalidArgument", err)
	}
	// A type that names its device itself is not constrained by the network name.
	if _, err := s.CreateNetwork(ctx, &pb.CreateNetworkRequest{Name: "a-very-long-network-name", Type: "sriov", Pf: "ens1f0"}); err != nil {
		t.Errorf("sriov with a long name: %v", err)
	}
}
