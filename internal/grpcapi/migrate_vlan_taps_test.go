package grpcapi

import (
	"context"
	"net/netip"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/network"
)

// A NIC's VLANs live on its host tap, not in the domain XML, so a live
// migration does not carry them: the target's AnnounceMigratedGuest puts them
// on the taps libvirt made there — a trunk's converged to exactly its VLANs
// (NegotiateTrunkVLANs), an access port's as its pvid — and a NIC with no
// trunk gets none.
//
// Mutation: drop applyTapVLANs from AnnounceMigratedGuest — red (no tap
// is configured on the target).
func TestAnnounceMigratedGuest_PutsTheNICsVLANsOnTheTargetTaps(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "g", HostName: s.hostName, State: "running",
		Spec: seedSpecJSON(t, &pb.VMSpec{Name: "g", Cpu: 1, MemoryMib: 512, Network: []*pb.NetworkAttachment{
			{Name: "plain", Mac: "52:54:00:47:00:01"},
			{Name: "trk", Mac: "52:54:00:47:00:02", Trunk: []int32{100, 101}},
			{Name: "acc", Mac: "52:54:00:47:00:03", Trunk: []int32{30}},
		}})}, nil, nil); err != nil {
		t.Fatal(err)
	}
	s.SetGatewayAnnouncer(func(string, netip.Addr) (bool, error) { return false, nil })
	virt := libvirtfake.New()
	s.virt = virt
	virt.SetState("g", "running")

	if _, err := s.AnnounceMigratedGuest(peerCtxFor(t, s, "node-src"), &pb.AnnounceMigratedGuestRequest{VmName: "g"}); err != nil {
		t.Fatalf("AnnounceMigratedGuest: %v", err)
	}
	got := map[string]string{}
	for _, e := range virt.EventLog() {
		if e.Domain == "g" && (e.Op == "trunk-tap" || e.Op == "vlan-tap") {
			got[e.Op] += e.Note + ";"
		}
	}
	want := map[string]string{
		"trunk-tap": "bridge=" + network.FlatBridgeName("trk") + " mac=52:54:00:47:00:02 vlans=[100 101];",
		"vlan-tap":  "bridge=" + network.FlatBridgeName("acc") + " mac=52:54:00:47:00:03 vlan=30;",
	}
	for op, w := range want {
		if got[op] != w {
			t.Errorf("%s on the target = %q, want %q", op, got[op], w)
		}
	}
}
