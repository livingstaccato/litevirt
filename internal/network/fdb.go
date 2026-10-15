package network

import (
	"fmt"
	"log/slog"
	"strings"
)

// refuseLocalDst reports, loudly, a forwarding entry whose destination is this
// host's own address (isLocalAddress). It is never installed: the kernel hands
// such a frame straight back to the vxlan device, so a flood entry like that
// black-holes the whole VNI and a unicast one black-holes that MAC.
func refuseLocalDst(vni int, mac, dst string) bool {
	if !isLocalAddress(dst) {
		return false
	}
	slog.Error("vxlan: refusing a forwarding entry that points at this host's own address; it would loop the frames back into the overlay",
		"vni", vni, "mac", mac, "dst", dst)
	return true
}

// isAlreadyExists returns true if the command output contains "File exists" or "already exists".
func isAlreadyExists(out []byte) bool {
	s := string(out)
	return strings.Contains(s, "File exists") || strings.Contains(s, "already exists") || strings.Contains(s, "already assigned")
}

// AddFDBEntry adds a unicast FDB entry: bridge fdb add <mac> dev vxlan<VNI> dst <remoteVTEP>
// An entry whose remoteVTEP is this host's own address is refused (nil, and
// nothing installed): see refuseLocalDst.
func AddFDBEntry(vni int, mac, remoteVTEP string) error {
	if refuseLocalDst(vni, mac, remoteVTEP) {
		return nil
	}
	out, err := execCommand("bridge", "fdb", "add", mac,
		"dev", vtepName(vni), "dst", remoteVTEP)
	if err != nil && !isAlreadyExists(out) {
		return fmt.Errorf("bridge fdb add %s: %w: %s", mac, err, out)
	}
	return nil
}

// DeleteFDBEntry removes a unicast FDB entry: bridge fdb del <mac> dev vxlan<VNI> dst <remoteVTEP>
func DeleteFDBEntry(vni int, mac, remoteVTEP string) error {
	out, err := execCommand("bridge", "fdb", "del", mac,
		"dev", vtepName(vni), "dst", remoteVTEP)
	if err != nil && !isAlreadyExists(out) {
		return fmt.Errorf("bridge fdb del %s: %w: %s", mac, err, out)
	}
	return nil
}

// FloodEntry adds a BUM flood entry: bridge fdb add 00:00:00:00:00:00 dev vxlan<VNI> dst <remoteVTEP>
// As with AddFDBEntry, a remoteVTEP of this host's own is refused.
func FloodEntry(vni int, remoteVTEP string) error {
	if refuseLocalDst(vni, floodMAC, remoteVTEP) {
		return nil
	}
	out, err := execCommand("bridge", "fdb", "add", floodMAC,
		"dev", vtepName(vni), "dst", remoteVTEP)
	if err != nil && !isAlreadyExists(out) {
		return fmt.Errorf("bridge fdb add flood %s: %w: %s", remoteVTEP, err, out)
	}
	return nil
}

// DeleteFloodEntry removes a BUM flood entry: bridge fdb del 00:00:00:00:00:00 dev vxlan<VNI> dst <remoteVTEP>
func DeleteFloodEntry(vni int, remoteVTEP string) error {
	out, err := execCommand("bridge", "fdb", "del", floodMAC,
		"dev", vtepName(vni), "dst", remoteVTEP)
	if err != nil && !isAlreadyExists(out) {
		return fmt.Errorf("bridge fdb del flood %s: %w: %s", remoteVTEP, err, out)
	}
	return nil
}

// floodMAC is the all-zeros MAC of a BUM flood entry.
const floodMAC = "00:00:00:00:00:00"

// fdbEntry is one forwarding entry on a vxlan device that has a destination.
type fdbEntry struct {
	MAC string
	Dst string
}

// vxlanFDB lists the forwarding entries with a destination on vxlan<VNI>
// (`bridge fdb show dev vxlan<VNI>`). Entries without one — those the bridge
// learned on its port — are not listed. A missing device has none.
func vxlanFDB(vni int) ([]fdbEntry, error) {
	out, err := execCommand("bridge", "fdb", "show", "dev", vtepName(vni))
	if err != nil {
		if isNoSuchDevice(out) {
			return nil, nil
		}
		return nil, fmt.Errorf("bridge fdb show dev %s: %w: %s", vtepName(vni), err, out)
	}
	var entries []fdbEntry
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		for i := 1; i+1 < len(f); i++ {
			if f[i] == "dst" {
				entries = append(entries, fdbEntry{MAC: f[0], Dst: f[i+1]})
				break
			}
		}
	}
	return entries, nil
}
