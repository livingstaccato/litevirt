package lxc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A managed NIC's gateway reaches both the LXC config and the guest's ifupdown
// stanza, beside the prefixed address.
func TestNetworkConfig_GatewayRendered(t *testing.T) {
	cfg, err := NetworkConfig([]NetworkAttach{{Name: "eth0", Bridge: "br0", IP: "172.16.77.2/24", Gateway: "172.16.77.1"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"lxc.net.0.ipv4.address = 172.16.77.2/24\n", "lxc.net.0.ipv4.gateway = 172.16.77.1\n"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q:\n%s", want, cfg)
		}
	}
	if _, err := NetworkConfig([]NetworkAttach{{Bridge: "br0", IP: "10.0.0.2/24", Gateway: "10.0.0.1\nlxc.apparmor.profile = unconfined"}}); err == nil {
		t.Error("a gateway carrying a newline forged a config line")
	}
	root := t.TempDir()
	if err := configureGuestStaticIP(root, []NetworkAttach{{Name: "eth0", IP: "172.16.77.2/24", Gateway: "172.16.77.1"}}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, "etc/network/interfaces"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"address 172.16.77.2\n", "netmask 255.255.255.0\n", "gateway 172.16.77.1\n"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("interfaces missing %q:\n%s", want, b)
		}
	}
}
