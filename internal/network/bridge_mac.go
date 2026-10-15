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

// bridgeMACPrefix is the first octet of every bridge MAC NetworkBridgeMAC
// derives: locally administered (bit 1 set), unicast (bit 0 clear).
const bridgeMACPrefix = 0x0a

// NetworkBridgeMAC is the MAC address of the bridge litevirt creates for
// network networkName: derived from the network's name alone, so it is the
// same on every host. A guest that moves to another host keeps reaching its
// gateway at the MAC its ARP cache already holds.
func NetworkBridgeMAC(networkName string) net.HardwareAddr {
	sum := sha256.Sum256([]byte("litevirt-bridge-mac\x00" + networkName))
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
// networkName, the network's MAC (NetworkBridgeMAC). When that changes the
// address of a bridge that already carries the network's gateway, the
// gateway is announced at the new MAC, so guests already on the bridge do not
// wait out their ARP cache. Best effort: a bridge whose MAC cannot be set
// keeps working as it did.
func ensureNetworkBridgeMAC(networkName, bridge, subnet string) {
	changed, err := ensureBridgeMAC(bridge, NetworkBridgeMAC(networkName))
	if err != nil {
		slog.Warn("network bridge MAC not set; a guest moved to another host waits out its ARP cache for the gateway",
			"network", networkName, "bridge", bridge, "error", err)
		return
	}
	if changed {
		slog.Info("set the network bridge MAC", "network", networkName, "bridge", bridge, "mac", NetworkBridgeMAC(networkName).String())
		if gw, ok := SubnetGatewayV4(subnet); ok {
			AnnounceGatewayBestEffort(bridge, gw)
		}
	}
}
