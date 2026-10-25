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
	return RunPreFlightWith(checks, BridgeVLANFiltering)
}

// RunPreFlightWith is RunPreFlight with the read of a bridge's VLAN filtering
// given (BridgeVLANFiltering's contract).
func RunPreFlightWith(checks []PreFlightCheck, filtering func(bridge string) (isBridge, on bool, err error)) error {
	for _, c := range checks {
		if c.AccessVLAN == 0 || c.Bridge == "" {
			continue
		}
		if err := AccessVLANBridgeProblem(c.Bridge, c.AccessVLAN, filtering); err != nil {
			return err
		}
	}
	return nil
}

// AccessVLANBridgeProblem is why bridge on this host cannot carry a NIC on
// access VLAN vlan (it is a Linux bridge, and its VLAN filtering is off or
// cannot be read), or nil.
func AccessVLANBridgeProblem(bridge string, vlan int, filtering func(bridge string) (isBridge, on bool, err error)) error {
	isBridge, on, err := filtering(bridge)
	switch {
	case err != nil:
		return fmt.Errorf("bridge %q: cannot read whether it filters VLANs, needed for a NIC on VLAN %d: %w", bridge, vlan, err)
	case !isBridge || on:
		return nil
	}
	return fmt.Errorf("bridge %q does not filter VLANs, so a NIC on VLAN %d (trunk: [%d]) would join its untagged "+
		"segment instead of the VLAN; turn VLAN filtering on (ip link set dev %s type bridge vlan_filtering 1) "+
		"and give its uplink the VLAN, or move the NIC to a network on the VLAN", bridge, vlan, vlan, bridge)
}

// BridgeVLANFiltering reads whether bridge, on this host, is a Linux bridge
// (isBridge; false for a missing device or one that is not a bridge, with no
// error) and whether its vlan_filtering is 1 (on). err: it is a bridge, and
// its vlan_filtering could not be read.
func BridgeVLANFiltering(bridge string) (isBridge, on bool, err error) {
	dir := filepath.Join(sysClassNet, bridge, "bridge")
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return false, false, nil
	}
	data, err := os.ReadFile(filepath.Join(dir, "vlan_filtering"))
	if err != nil {
		return true, false, err
	}
	return true, strings.TrimSpace(string(data)) == "1", nil
}
