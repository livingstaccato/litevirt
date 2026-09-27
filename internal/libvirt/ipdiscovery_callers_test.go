package libvirt

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMACDiscoveryHasOneEntryPoint keeps every MAC-to-address lookup on
// DiscoverIPForMACOnBridge. A caller that reads ARP or the dnsmasq leases on
// its own picks its own order, and an ARP-first order returns a stale address
// after a VM is re-leased.
//
// Outside this package the unrestricted DiscoverIPForMAC is banned too: a
// caller passes the NIC's network.LeaseBridge ("" only when it is unknown), or
// a MAC with leases on two bridges resolves to whichever is newest. In
// internal/grpcapi every lookup goes through Server.discoverNICAddress, the
// one place that derives the bridge from the NIC's network and the seam tests
// drive discovery through.
func TestMACDiscoveryHasOneEntryPoint(t *testing.T) {
	root := filepath.Join("..", "..")
	banned := []string{"GetIPFromARP(", "GetIPFromDHCPLeases(", "/proc/net/arp", "DiscoverIPForMAC("}
	grpcapiDir := filepath.Join(root, "internal", "grpcapi")
	grpcapiEntry := filepath.Join(grpcapiDir, "netbox_discovery.go")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n != "." && n != ".." && (strings.HasPrefix(n, ".") || n == "vendor" || n == "node_modules") {
				return filepath.SkipDir
			}
			if filepath.Clean(path) == filepath.Join(root, "internal", "libvirt") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, b := range banned {
			if strings.Contains(string(src), b) {
				t.Errorf("%s uses %s; look addresses up with libvirt.DiscoverIPForMACOnBridge and the NIC's network.LeaseBridge", path, b)
			}
		}
		if filepath.Dir(filepath.Clean(path)) == grpcapiDir && filepath.Clean(path) != grpcapiEntry &&
			strings.Contains(string(src), "DiscoverIPForMACOnBridge(") {
			t.Errorf("%s calls DiscoverIPForMACOnBridge directly; use Server.discoverNICAddress(ctx, mac, networkName)", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
