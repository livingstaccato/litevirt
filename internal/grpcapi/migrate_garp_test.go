package grpcapi

import (
	"context"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// After a live migration lands here, the target announces the gateway of each
// network the guest has a NIC on: the network's first IPv4 address, out of
// the network's bridge on this host (its interface, br-vni<N> for vxlan). A
// network with no subnet, a macvtap network and a NIC on no network row
// announce nothing, and two networks on one bridge and subnet announce once.
//
// Mutations: announce the NIC's own IP instead of the gateway — red; use the
// network NAME as the device (the old garp.go bug) — red; drop the
// direct: skip — red.
func TestAnnounceMigratedGuest_AnnouncesEachNetworksGatewayFromItsBridge(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	put := func(name string, def compose.NetworkDef) {
		t.Helper()
		cfg, _ := json.Marshal(def)
		if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: name, Type: def.Type, Config: string(cfg)}); err != nil {
			t.Fatal(err)
		}
	}
	put("st_lan", compose.NetworkDef{Type: "bridge", Interface: "lan", Subnet: "172.46.0.0/24"})
	put("st_lan2", compose.NetworkDef{Type: "bridge", Interface: "lan", Subnet: "172.46.0.0/24"})
	put("ovl", compose.NetworkDef{Type: "vxlan", VNI: 100, Subnet: "10.71.0.0/24"})
	put("bare", compose.NetworkDef{Type: "bridge", Interface: "bare"})
	put("mvt", compose.NetworkDef{Type: "direct", Interface: "eth0", Subnet: "10.72.0.0/24"})
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "g", HostName: s.hostName, State: "running", Spec: "{}"},
		[]corrosion.InterfaceRecord{
			{VMName: "g", NetworkName: "st_lan", Ordinal: 0, MAC: "52:54:00:00:00:01", IP: "172.46.0.7"},
			{VMName: "g", NetworkName: "st_lan2", Ordinal: 1, MAC: "52:54:00:00:00:02", IP: "172.46.0.8"},
			{VMName: "g", NetworkName: "ovl", Ordinal: 2, MAC: "52:54:00:00:00:03"},
			{VMName: "g", NetworkName: "bare", Ordinal: 3, MAC: "52:54:00:00:00:04"},
			{VMName: "g", NetworkName: "mvt", Ordinal: 4, MAC: "52:54:00:00:00:05"},
			{VMName: "g", NetworkName: "flat0", Ordinal: 5, MAC: "52:54:00:00:00:06"},
		}, nil); err != nil {
		t.Fatal(err)
	}
	var got []string
	s.SetGatewayAnnouncer(func(bridge string, gw netip.Addr) (bool, error) {
		got = append(got, bridge+" "+gw.String())
		return true, nil
	})

	if _, err := s.AnnounceMigratedGuest(peerCtxFor(t, s, "node-src"), &pb.AnnounceMigratedGuestRequest{VmName: "g"}); err != nil {
		t.Fatalf("AnnounceMigratedGuest: %v", err)
	}
	sort.Strings(got)
	if want := "br-vni100 10.71.0.1,lan 172.46.0.1"; strings.Join(got, ",") != want {
		t.Errorf("announced %q, want %q", strings.Join(got, ","), want)
	}
}
