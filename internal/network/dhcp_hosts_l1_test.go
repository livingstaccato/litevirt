package network

import (
	"context"
	"os"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
)

// TestDeprovision_RemovesTheDHCPHostsFile (re-review 5, L1): deprovisioning a
// network's dnsmasq removes its reservations file with its leases file. A
// file left behind is kept by the next StartDHCP on that bridge, and a
// re-created network's reservation of the same address beside the old MAC's
// makes dnsmasq refuse it and hand out a dynamic address the NIC's exact
// guard drops.
func TestDeprovision_RemovesTheDHCPHostsFile(t *testing.T) {
	execCommand = func(string, ...string) ([]byte, error) { return nil, nil }
	defer func() { execCommand = defaultExec }()
	old := dnsmasqLeaseDir
	dnsmasqLeaseDir = t.TempDir()
	defer func() { dnsmasqLeaseDir = old }()

	def := compose.NetworkDef{Type: "bridge", Interface: "br-app", Subnet: "10.0.1.0/24"}
	mine, other := DHCPHostsFile("br-app"), DHCPHostsFile("br-other")
	for _, f := range []string{mine, other} {
		if err := os.WriteFile(f, []byte("52:54:00:aa:bb:01,10.0.1.2\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := Deprovision(context.Background(), nil, "app", def, "host-a"); err != nil {
		t.Fatalf("Deprovision: %v", err)
	}
	if _, err := os.Stat(mine); !os.IsNotExist(err) {
		t.Errorf("hosts file %s survived deprovisioning its network (stat err %v)", mine, err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("another network's hosts file was touched: %v", err)
	}
}

// TestAddDHCPHost_TakesTheAddressFromAStaleReservation (re-review 5, L1): a
// reservation of an address another MAC still holds in the file — one a host
// that was down when the network was deleted kept — replaces it, so dnsmasq
// never sees two lines for one address.
func TestAddDHCPHost_TakesTheAddressFromAStaleReservation(t *testing.T) {
	old := dnsmasqLeaseDir
	dnsmasqLeaseDir = t.TempDir()
	defer func() { dnsmasqLeaseDir = old }()
	path := DHCPHostsFile("lvbr-l1")
	if err := os.WriteFile(path, []byte("52:54:00:00:00:01,10.9.0.2\n52:54:00:00:00:03,10.9.0.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := AddDHCPHost("lvbr-l1", "52:54:00:00:00:02", "10.9.0.2"); err != nil {
		t.Fatalf("AddDHCPHost: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "52:54:00:00:00:02,10.9.0.2\n52:54:00:00:00:03,10.9.0.3\n"; string(got) != want {
		t.Errorf("hosts file =\n%s\nwant\n%s", got, want)
	}
}
