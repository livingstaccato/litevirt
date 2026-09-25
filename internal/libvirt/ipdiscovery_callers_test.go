package libvirt

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMACDiscoveryHasOneEntryPoint keeps every MAC-to-address lookup on
// DiscoverIPForMAC. A caller that reads ARP or the dnsmasq leases on its own
// picks its own order, and an ARP-first order returns a stale address after a
// VM is re-leased.
func TestMACDiscoveryHasOneEntryPoint(t *testing.T) {
	root := filepath.Join("..", "..")
	banned := []string{"GetIPFromARP(", "GetIPFromDHCPLeases(", "/proc/net/arp"}
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
				t.Errorf("%s uses %s; look addresses up with libvirt.DiscoverIPForMAC", path, b)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
