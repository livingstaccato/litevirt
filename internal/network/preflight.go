package network

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// PreFlightCheck is the host wiring of one NIC, checked on the host that is
// about to define or start the NIC's VM.
type PreFlightCheck struct {
	Bridge string // the Linux bridge the NIC's tap joins
	// AccessVLAN is the VLAN of a NIC on the `trunk:` feature with exactly one
	// VLAN (an access port: pvid + untagged on its tap); 0 for any other NIC.
	AccessVLAN int
}

// RunPreFlight checks each NIC's host wiring and returns the first problem,
// or nil.
//
// The one check: an access-port NIC needs a bridge that filters VLANs. Its
// VLAN is the tap's pvid, and a bridge with vlan_filtering off ignores the
// pvid, so the NIC would join the bridge's untagged segment instead of its
// VLAN. A bridge that does not exist here, or a device that is not a Linux
// bridge, is not judged: creating the bridge is ensureBridge's, and a bridge
// litevirt cannot find fails the define on its own.
func RunPreFlight(checks []PreFlightCheck) error {
	for _, c := range checks {
		if c.AccessVLAN == 0 || c.Bridge == "" {
			continue
		}
		if err := checkVLANFiltering(c.Bridge, c.AccessVLAN); err != nil {
			return err
		}
	}
	return nil
}

// checkVLANFiltering refuses a Linux bridge whose vlan_filtering is off.
func checkVLANFiltering(bridge string, vlan int) error {
	dir := filepath.Join(sysClassNet, bridge, "bridge")
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil // no such device here, or not a Linux bridge
	}
	path := filepath.Join(dir, "vlan_filtering")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("bridge %q: cannot read whether it filters VLANs, needed for a NIC on VLAN %d: %w", bridge, vlan, err)
	}
	if strings.TrimSpace(string(data)) != "1" {
		return fmt.Errorf("bridge %q does not filter VLANs, so a NIC on VLAN %d (trunk: [%d]) would join its untagged "+
			"segment instead of the VLAN; turn VLAN filtering on (ip link set dev %s type bridge vlan_filtering 1) "+
			"and give its uplink the VLAN, or move the NIC to a network on the VLAN", bridge, vlan, vlan, bridge)
	}
	return nil
}
