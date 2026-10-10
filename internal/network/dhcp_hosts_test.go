package network

import (
	"errors"
	"testing"
)

// TestAddDHCPHost_NoServerIsAnError (re-review I-8): a reservation made where
// no litevirt dnsmasq serves the bridge reserves nothing, so it must not
// report success: the guest would take a dynamic address its exact guard then
// drops.
func TestAddDHCPHost_NoServerIsAnError(t *testing.T) {
	old := dnsmasqLeaseDir
	dnsmasqLeaseDir = t.TempDir()
	defer func() { dnsmasqLeaseDir = old }()
	err := AddDHCPHost("lvbr-none", "52:54:00:00:00:01", "10.9.0.5")
	if !errors.Is(err, ErrNoLocalDHCPServer) {
		t.Fatalf("AddDHCPHost with no hosts file = %v, want ErrNoLocalDHCPServer", err)
	}
}
