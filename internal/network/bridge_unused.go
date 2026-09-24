package network

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
)

// sysClassNet is the sysfs root RemoveBridgeIfUnused reads; a test points it
// at a temp tree.
var sysClassNet = "/sys/class/net"

// bridgeIPv4 reports whether an interface carries an IPv4 address; a seam for
// the same reason.
var bridgeIPv4 = func(name string) bool {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return true // unknown: treat as in use
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			return true
		}
	}
	return false
}

// RemoveBridgeIfUnused deletes bridge name from this host when it exists, is
// a bridge, has no ports and carries no IPv4 address — the shape of a flat
// bridge litevirt auto-created for a NIC and nothing uses any more. It
// reports whether it deleted it; an absent bridge is (false, nil).
//
// It reads sysfs and the interface table; the only command it runs is the
// `ip link del` itself.
func RemoveBridgeIfUnused(name string) (bool, error) {
	if _, err := os.Stat(filepath.Join(sysClassNet, name, "bridge")); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil // absent, or not a bridge
		}
		return false, err
	}
	ports, err := os.ReadDir(filepath.Join(sysClassNet, name, "brif"))
	if err != nil {
		return false, err
	}
	if len(ports) > 0 || bridgeIPv4(name) {
		return false, nil
	}
	if out, err := execCommand("ip", "link", "del", name); err != nil && !isNoSuchDevice(out) {
		return false, fmt.Errorf("ip link del %s: %w: %s", name, err, out)
	}
	return true, nil
}
