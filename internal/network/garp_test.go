package network

import (
	"bytes"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The frame is a broadcast ARP request from the bridge's MAC in which the
// gateway announces itself: sender and target protocol address both the
// gateway, sender hardware address the bridge's MAC.
//
// Mutations: put the guest-facing target MAC in the Ethernet source, or
// swap the opcode to 2 — each breaks the exact bytes.
func TestGatewayARPFrame(t *testing.T) {
	mac, _ := net.ParseMAC("0a:11:22:33:44:55")
	f, err := GatewayARPFrame(mac, netip.MustParseAddr("172.46.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString(
		"ffffffffffff" + "0a1122334455" + "0806" + // Ethernet: broadcast, from the bridge, ARP
			"0001" + "0800" + "06" + "04" + "0001" + // Ethernet/IPv4, request
			"0a1122334455" + "ac2e0001" + // sender: bridge MAC, gateway
			"000000000000" + "ac2e0001") // target: gateway
	want = append(want, make([]byte, 60-len(want))...)
	if !bytes.Equal(f, want) {
		t.Errorf("frame\n got %x\nwant %x", f, want)
	}
	if _, err := GatewayARPFrame(mac, netip.MustParseAddr("fd00::1")); err == nil {
		t.Error("an IPv6 gateway produced an ARP frame")
	}
}

// AnnounceGateway sends the frame out of the bridge, from the bridge's own
// MAC, only when the bridge holds the gateway address and has no uplink; a
// bridge without the address (another router's gateway) or with an uplink
// sends nothing.
//
// Mutations: drop the holds-the-address check — the second case sends; drop
// the uplink check — the third does.
func TestAnnounceGateway_FromTheBridgeThatHoldsTheGateway(t *testing.T) {
	sys := t.TempDir()
	origSysfs := sysfsNet
	sysfsNet = sys
	t.Cleanup(func() { sysfsNet = origSysfs })

	origAddrs, origLink, origSend := interfaceAddrs, linkByName, sendLinkFrames
	t.Cleanup(func() { interfaceAddrs, linkByName, sendLinkFrames = origAddrs, origLink, origSend })
	mac, _ := net.ParseMAC("0a:de:ad:be:ef:01")
	held := "172.46.0.1"
	interfaceAddrs = func(name string) ([]net.Addr, error) {
		if name != "brx" {
			t.Errorf("addresses read from %s, want brx", name)
		}
		return []net.Addr{&net.IPNet{IP: net.ParseIP(held), Mask: net.CIDRMask(24, 32)}}, nil
	}
	linkByName = func(name string) (int, net.HardwareAddr, error) { return 42, mac, nil }
	type sent struct {
		idx   int
		frame []byte
		count int
	}
	var got []sent
	sendLinkFrames = func(idx int, frame []byte, count int, _ time.Duration) error {
		got = append(got, sent{idx, append([]byte(nil), frame...), count})
		return nil
	}

	gw := netip.MustParseAddr("172.46.0.1")
	ok, err := AnnounceGateway("brx", gw)
	if err != nil || !ok {
		t.Fatalf("AnnounceGateway = %v, %v; want sent", ok, err)
	}
	want, _ := GatewayARPFrame(mac, gw)
	if len(got) != 1 || got[0].idx != 42 || got[0].count != gatewayARPCount || !bytes.Equal(got[0].frame, want) {
		t.Fatalf("sent %+v, want the gateway frame from %s out of ifindex 42, %d times", got, mac, gatewayARPCount)
	}

	got, held = nil, "172.46.0.254"
	ok, err = AnnounceGateway("brx", gw)
	if err != nil || ok || len(got) != 0 {
		t.Errorf("a bridge without the gateway address announced it: ok=%v err=%v sent=%d", ok, err, len(got))
	}

	// A bridge with an uplink shares its L2 with other hosts: no announcement.
	if err := os.MkdirAll(filepath.Join(sys, "brx", "brif", "eth9"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sys, "eth9", "device"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, held = nil, "172.46.0.1"
	ok, err = AnnounceGateway("brx", gw)
	if err != nil || ok || len(got) != 0 {
		t.Errorf("a bridge with an uplink announced the gateway: ok=%v err=%v sent=%d", ok, err, len(got))
	}
}

func TestSubnetGatewayV4(t *testing.T) {
	if gw, ok := SubnetGatewayV4("172.46.0.0/24"); !ok || gw.String() != "172.46.0.1" {
		t.Errorf("SubnetGatewayV4 = %v, %v; want 172.46.0.1", gw, ok)
	}
	if _, ok := SubnetGatewayV4("fd00::/64"); ok {
		t.Error("an IPv6 subnet has an ARP gateway")
	}
	if _, ok := SubnetGatewayV4(""); ok {
		t.Error("no subnet has a gateway")
	}
}
