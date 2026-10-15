package network

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"
)

// gatewayARPCount and gatewayARPGap are how many gratuitous ARPs
// AnnounceGateway sends and how far apart.
const (
	gatewayARPCount = 3
	gatewayARPGap   = 200 * time.Millisecond
)

// GatewayARPFrame is a gratuitous ARP announcing that ip is at mac: an
// Ethernet broadcast from mac carrying an ARP request whose sender and target
// protocol addresses are both ip, padded to the Ethernet minimum. A guest
// that holds ip in its ARP cache under another MAC updates it on receipt.
func GatewayARPFrame(mac net.HardwareAddr, ip netip.Addr) ([]byte, error) {
	if len(mac) != 6 {
		return nil, fmt.Errorf("gratuitous ARP: MAC %q is not 6 bytes", mac)
	}
	if !ip.Is4() {
		return nil, fmt.Errorf("gratuitous ARP: %s is not an IPv4 address", ip)
	}
	f := make([]byte, 60)
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(f[6:12], mac)
	binary.BigEndian.PutUint16(f[12:14], 0x0806) // ARP
	a := f[14:]
	binary.BigEndian.PutUint16(a[0:2], 1)      // hardware: Ethernet
	binary.BigEndian.PutUint16(a[2:4], 0x0800) // protocol: IPv4
	a[4], a[5] = 6, 4
	binary.BigEndian.PutUint16(a[6:8], 1) // request
	copy(a[8:14], mac)
	ip4 := ip.As4()
	copy(a[14:18], ip4[:])
	// a[18:24], the target hardware address, stays zero.
	copy(a[24:28], ip4[:])
	return f, nil
}

// SubnetGatewayV4 is litevirt's gateway address on an IPv4 subnet (its first
// host, as SubnetRange gives it), or false for no subnet or an IPv6 one.
func SubnetGatewayV4(subnet string) (netip.Addr, bool) {
	if subnet == "" {
		return netip.Addr{}, false
	}
	gw, _, _, _, err := SubnetRange(subnet)
	if err != nil {
		return netip.Addr{}, false
	}
	p, err := netip.ParsePrefix(gw)
	if err != nil || !p.Addr().Is4() {
		return netip.Addr{}, false
	}
	return p.Addr(), true
}

// linkByName reads an interface's index and MAC; a seam for tests.
var linkByName = func(name string) (int, net.HardwareAddr, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return 0, nil, err
	}
	return ifc.Index, ifc.HardwareAddr, nil
}

// sendLinkFrames sends frame out of the interface with index ifindex count
// times, gap apart; a seam for tests (sendRawFrames on Linux).
var sendLinkFrames = sendRawFrames

// AnnounceGateway sends gratuitous ARPs for gateway out of bridge, from the
// bridge's own MAC, when this host holds gateway on bridge. It reports
// whether it sent them; a host that does not hold the address there sends
// nothing, since announcing another router's address would take its traffic.
func AnnounceGateway(bridge string, gateway netip.Addr) (bool, error) {
	if validLinkName(bridge) != nil || !gateway.Is4() {
		return false, nil
	}
	held, err := bridgeHoldsAddr(bridge, gateway)
	if err != nil || !held {
		return false, err
	}
	idx, mac, err := linkByName(bridge)
	if err != nil {
		return false, err
	}
	frame, err := GatewayARPFrame(mac, gateway)
	if err != nil {
		return false, err
	}
	if err := sendLinkFrames(idx, frame, gatewayARPCount, gatewayARPGap); err != nil {
		return false, fmt.Errorf("gratuitous ARP for %s on %s: %w", gateway, bridge, err)
	}
	slog.Debug("announced the gateway", "bridge", bridge, "gateway", gateway.String(), "mac", mac.String())
	return true, nil
}

// AnnounceGatewayBestEffort is AnnounceGateway that only logs a failure.
func AnnounceGatewayBestEffort(bridge string, gateway netip.Addr) {
	if _, err := AnnounceGateway(bridge, gateway); err != nil {
		slog.Warn("gratuitous ARP for the gateway failed (non-fatal)", "bridge", bridge, "gateway", gateway.String(), "error", err)
	}
}

// bridgeHoldsAddr reports whether interface name carries ip.
func bridgeHoldsAddr(name string, ip netip.Addr) (bool, error) {
	addrs, err := interfaceAddrs(name)
	if err != nil {
		return false, err
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if got, ok := netip.AddrFromSlice(ipn.IP); ok && got.Unmap() == ip {
			return true, nil
		}
	}
	return false, nil
}
