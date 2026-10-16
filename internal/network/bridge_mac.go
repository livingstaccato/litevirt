package network

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// bridgeMACPrefix is the first octet of every bridge MAC BridgeMAC derives: locally administered (bit 1 set), unicast (bit 0 clear).
const bridgeMACPrefix = 0x0a

// BridgeMAC is the MAC address of bridge device, a bridge litevirt created for
// a network: derived from the device's name alone. A network names the same
// device on every host (BridgeName), so its bridge has the same MAC on every
// host, and networks that share a bridge agree on it. A guest that moves to
// another host keeps reaching its gateway at the MAC its ARP cache holds.
func BridgeMAC(device string) net.HardwareAddr {
	sum := sha256.Sum256([]byte("litevirt-bridge-mac\x00" + device))
	mac := make(net.HardwareAddr, 6)
	mac[0] = bridgeMACPrefix
	copy(mac[1:], sum[:5])
	return mac
}

// ensureBridgeMAC sets bridge's MAC to mac when it has another one, and
// reports whether it changed it. It acts only on a bridge whose current
// address it can read from sysfs.
func ensureBridgeMAC(bridge string, mac net.HardwareAddr) (bool, error) {
	if validLinkName(bridge) != nil {
		return false, nil
	}
	cur, err := os.ReadFile(filepath.Join(sysClassNet, bridge, "address"))
	if err != nil {
		return false, fmt.Errorf("read the MAC of %s: %w", bridge, err)
	}
	if strings.EqualFold(strings.TrimSpace(string(cur)), mac.String()) {
		return false, nil
	}
	if out, err := execCommand("ip", "link", "set", "dev", bridge, "address", mac.String()); err != nil {
		return false, fmt.Errorf("set the MAC of %s to %s: %w: %s", bridge, mac, err, out)
	}
	return true, nil
}

// ensureNetworkBridgeMAC gives bridge, which litevirt created for network
// networkName, its MAC (BridgeMAC). When that changes the address of a bridge
// that already carries the network's gateway, the gateway is announced at the
// new MAC, so guests already on the bridge do not wait out their ARP cache.
// Best effort: a bridge whose MAC cannot be set keeps working as it did.
func ensureNetworkBridgeMAC(networkName, bridge, subnet string) {
	changed, err := ensureBridgeMAC(bridge, BridgeMAC(bridge))
	if err != nil {
		slog.Warn("network bridge MAC not set; a guest moved to another host waits out its ARP cache for the gateway",
			"network", networkName, "bridge", bridge, "error", err)
		return
	}
	if changed {
		slog.Info("set the network bridge MAC", "network", networkName, "bridge", bridge, "mac", BridgeMAC(bridge).String())
		if gw, ok := SubnetGatewayV4(subnet); ok {
			AnnounceGatewayBestEffort(bridge, gw)
		}
	}
}

// warnSharedMACOnUplink warns when bridge, which litevirt gave its derived
// MAC, has since gained an uplink: every host's bridge of that name then
// carries the same MAC on one L2. litevirt does not change it back; an
// operator who bridges an uplink into it must set its address.
func warnSharedMACOnUplink(networkName, bridge string) {
	cur, err := os.ReadFile(filepath.Join(sysClassNet, bridge, "address"))
	if err != nil || !strings.EqualFold(strings.TrimSpace(string(cur)), BridgeMAC(bridge).String()) {
		return
	}
	slog.Warn("a bridge litevirt gave the same MAC on every host now has an uplink; hosts sharing that L2 carry one MAC — set the bridge's address",
		"network", networkName, "bridge", bridge, "mac", BridgeMAC(bridge).String())
}
