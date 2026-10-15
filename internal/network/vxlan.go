package network

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
)

// vxlanMu serializes concurrent EnsureVXLAN calls per VNI.
var vxlanMu sync.Map

func vniMutex(vni int) *sync.Mutex {
	v, _ := vxlanMu.LoadOrStore(vni, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// vxlanBridgeName returns the bridge name for a given VNI.
func vxlanBridgeName(vni int) string {
	return fmt.Sprintf("br-vni%d", vni)
}

// vtepName returns the VXLAN interface name for a given VNI.
func vtepName(vni int) string {
	return fmt.Sprintf("vxlan%d", vni)
}

// isFileExists returns true if the command output contains "File exists".
func isFileExists(out []byte) bool {
	return strings.Contains(string(out), "File exists")
}

// EnsureVXLAN idempotently creates a VXLAN interface and bridge for the given VNI.
// Returns the bridge name "br-vni<VNI>".
func EnsureVXLAN(vni int, underlay, localIP string) (string, error) {
	mu := vniMutex(vni)
	mu.Lock()
	defer mu.Unlock()

	vxlan := vtepName(vni)
	bridge := vxlanBridgeName(vni)

	// 1. Create VXLAN interface
	add := func() ([]byte, error) {
		return execCommand("ip", "link", "add", vxlan, "type", "vxlan",
			"id", fmt.Sprintf("%d", vni), "dstport", "4789",
			"local", localIP, "dev", underlay, "nolearning")
	}
	out, err := add()
	if err != nil && !isFileExists(out) {
		return "", fmt.Errorf("ip link add %s: %w: %s", vxlan, err, out)
	}
	if err != nil {
		// It exists. A device made with another local address or underlay —
		// by a build that took both from the default route — is recreated, or
		// the host keeps tunnelling from the wrong address after an upgrade.
		// Only the vxlan port goes: the bridge and the guests' taps on it stay,
		// and steps 3-4 put the new port back on the bridge.
		if gotLocal, gotDev, ok := vxlanEndpoint(vxlan); ok && (gotLocal != localIP || gotDev != underlay) {
			// Never trade a device for one whose local address this host
			// does not hold: the kernel cannot send from it.
			if !isLocalAddress(localIP) {
				return "", fmt.Errorf("not recreating %s (local %s dev %s) with local address %s, which no interface of this host holds",
					vxlan, gotLocal, gotDev, localIP)
			}
			slog.Warn("vxlan: recreating a tunnel device whose local address or underlay is not this host's",
				"device", vxlan, "local", gotLocal, "dev", gotDev, "want_local", localIP, "want_dev", underlay)
			if out, err := execCommand("ip", "link", "del", vxlan); err != nil && !isNoSuchDevice(out) {
				return "", fmt.Errorf("ip link del %s: %w: %s", vxlan, err, out)
			}
			if out, err := add(); err != nil {
				return "", fmt.Errorf("ip link add %s: %w: %s", vxlan, err, out)
			}
		}
	}

	// 2. Create bridge
	out, err = execCommand("ip", "link", "add", bridge, "type", "bridge")
	if err != nil && !isFileExists(out) {
		return "", fmt.Errorf("ip link add %s: %w: %s", bridge, err, out)
	}

	// 3. Attach VXLAN to bridge
	out, err = execCommand("ip", "link", "set", vxlan, "master", bridge)
	if err != nil && !isFileExists(out) {
		return "", fmt.Errorf("ip link set %s master %s: %w: %s", vxlan, bridge, err, out)
	}

	// 4. Bring VXLAN up
	out, err = execCommand("ip", "link", "set", vxlan, "up")
	if err != nil && !isFileExists(out) {
		return "", fmt.Errorf("ip link set %s up: %w: %s", vxlan, err, out)
	}

	// 5. Bring bridge up
	out, err = execCommand("ip", "link", "set", bridge, "up")
	if err != nil && !isFileExists(out) {
		return "", fmt.Errorf("ip link set %s up: %w: %s", bridge, err, out)
	}

	// 6. Set MTU: underlay MTU minus 50 bytes VXLAN overhead.
	if iface, err := net.InterfaceByName(underlay); err == nil && iface.MTU > 0 {
		vxlanMTU := fmt.Sprintf("%d", iface.MTU-50)
		execCommand("ip", "link", "set", vxlan, "mtu", vxlanMTU)  //nolint:errcheck
		execCommand("ip", "link", "set", bridge, "mtu", vxlanMTU) //nolint:errcheck
	}

	return bridge, nil
}

// DeprovisionVXLAN removes the bridge and VXLAN interface for the given VNI.
func DeprovisionVXLAN(vni int) error {
	bridge := vxlanBridgeName(vni)
	vxlan := vtepName(vni)

	if out, err := execCommand("ip", "link", "del", bridge); err != nil {
		if !isNoSuchDevice(out) {
			return fmt.Errorf("ip link del %s: %w: %s", bridge, err, out)
		}
	}

	if out, err := execCommand("ip", "link", "del", vxlan); err != nil {
		if !isNoSuchDevice(out) {
			return fmt.Errorf("ip link del %s: %w: %s", vxlan, err, out)
		}
	}

	return nil
}

// vxlanEndpoint reads an existing vxlan device's local address and underlay
// device from `ip -d -o link show`, which prints them as
// "vxlan id <VNI> local <addr> dev <underlay> ...". ok is false when the
// device cannot be read, so the caller leaves it alone.
func vxlanEndpoint(dev string) (local, underlay string, ok bool) {
	out, err := execCommand("ip", "-d", "-o", "link", "show", dev)
	if err != nil {
		return "", "", false
	}
	f := strings.Fields(string(out))
	for i := range f {
		if f[i] != "vxlan" || i+1 >= len(f) || f[i+1] != "id" {
			continue
		}
		// The endpoint fields come before the port ones; stop there, so a
		// later section's tokens cannot be read as them.
	scan:
		for j := i + 2; j+1 < len(f); j++ {
			switch f[j] {
			case "local":
				local = f[j+1]
			case "dev":
				underlay = f[j+1]
			case "srcport", "dstport":
				break scan
			}
		}
		return local, underlay, true
	}
	return "", "", false
}
