package grpcapi

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
)

// TestGetVMIPRemote_LeaseOnly: a lease_only lookup answers from this host's
// dnsmasq lease on the network's bridge and says so, with the expiry; with no
// lease it answers nothing — not the ARP entry the plain lookup would give,
// which is not authoritative for a guest on another host.
//
// Mutation: answer lease_only through discoverNICAddress — red (the ARP
// answer comes back, and lease is never set).
func TestGetVMIPRemote_LeaseOnly(t *testing.T) {
	s := testServer(t)
	putNetwork(t, s, "ovl", "vxlan", compose.NetworkDef{VNI: 5000, Subnet: "10.200.0.0/24", DHCP: true})
	const mac = "52:54:00:aa:bb:01"
	s.SetNICIPDiscovery(func(string) string { return "10.200.0.99" }) // what ARP would say
	var asked []string
	lease := map[string]string{}
	s.SetDHCPLeaseLookup(func(m, bridge string) (string, int64) {
		asked = append(asked, bridge)
		if strings.EqualFold(m, mac) && bridge == "br-vni5000" && lease[bridge] != "" {
			return lease[bridge], 2000003600
		}
		return "", 0
	})
	ctx := peerCtxFor(t, s, "node-2")
	req := &pb.GetVMIPRequest{Mac: mac, NetworkName: "ovl", LeaseOnly: true}

	resp, err := s.GetVMIPRemote(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetIp() != "" || resp.GetLease() {
		t.Errorf("no lease here: got ip=%q lease=%v, want nothing", resp.GetIp(), resp.GetLease())
	}

	lease["br-vni5000"] = "10.200.0.173"
	resp, err = s.GetVMIPRemote(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetIp() != "10.200.0.173" || !resp.GetLease() || resp.GetLeaseExpiry() != 2000003600 {
		t.Errorf("got ip=%q lease=%v expiry=%d, want 10.200.0.173 from the lease, expiry 2000003600",
			resp.GetIp(), resp.GetLease(), resp.GetLeaseExpiry())
	}
	if len(asked) == 0 || asked[len(asked)-1] != "br-vni5000" {
		t.Errorf("lease files read: %v, want the network's bridge br-vni5000", asked)
	}

	// No record of the network: no bridge, so no lease file to read.
	resp, err = s.GetVMIPRemote(ctx, &pb.GetVMIPRequest{Mac: mac, NetworkName: "nope", LeaseOnly: true})
	if err != nil || resp.GetIp() != "" {
		t.Errorf("unknown network: ip=%q err=%v, want nothing", resp.GetIp(), err)
	}
	if _, err := s.GetVMIPRemote(ctx, &pb.GetVMIPRequest{Mac: "x;y", NetworkName: "ovl", LeaseOnly: true}); err == nil {
		t.Error("a malformed MAC was accepted")
	}
	if _, err := s.GetVMIPRemote(adminCtx(), req); err == nil {
		t.Error("a non-peer caller was answered")
	}
}

// TestBestPeerLease: of the leases the network's hosts hold for a MAC, the
// one granted most recently wins (latest expiry, 0 = infinite); an answer
// outside the subnet is not one.
//
// Mutation: take the first answer — red.
func TestBestPeerLease(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answers []peerLease
		want    string
	}{
		{"none", nil, ""},
		{"one", []peerLease{{"a", "10.200.0.5", 100}}, "10.200.0.5"},
		{"latest expiry", []peerLease{{"a", "10.200.0.5", 100}, {"b", "10.200.0.6", 200}}, "10.200.0.6"},
		{"latest expiry, other order", []peerLease{{"b", "10.200.0.6", 200}, {"a", "10.200.0.5", 100}}, "10.200.0.6"},
		{"infinite wins", []peerLease{{"a", "10.200.0.5", 0}, {"b", "10.200.0.6", 200}}, "10.200.0.5"},
		{"outside the subnet", []peerLease{{"a", "192.0.2.5", 900}, {"b", "10.200.0.6", 200}}, "10.200.0.6"},
		{"not an address", []peerLease{{"a", "nope", 900}}, ""},
	} {
		if got := bestPeerLease("10.200.0.0/24", tc.answers).ip; got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}
