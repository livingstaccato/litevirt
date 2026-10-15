package network

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

// refuseLocalDst reports, loudly, a forwarding entry whose destination is one
// of this host's addresses (local). It is never installed: the kernel hands
// such a frame straight back to the vxlan device, so a flood entry like that
// black-holes the whole VNI and a unicast one black-holes that MAC.
func refuseLocalDst(local localAddrs, vni int, mac, dst string) bool {
	if !local.has(dst) {
		return false
	}
	if logOnce(fmt.Sprintf("refuse|%d|%s|%s", vni, mac, dst)) {
		slog.Warn("vxlan: refusing a forwarding entry that points at this host's own address; it would loop the frames back into the overlay",
			"vni", vni, "mac", mac, "dst", dst)
	}
	return true
}

// logged holds the keys logOnce has seen.
var logged sync.Map

// logOnce reports whether key is new, so a condition that every sync meets
// again — a peer still registering an address of this host's — is logged
// once per peer and address, not once per pass.
func logOnce(key string) bool {
	_, seen := logged.LoadOrStore(key, true)
	return !seen
}

// isAlreadyExists returns true if the command output contains "File exists" or "already exists".
func isAlreadyExists(out []byte) bool {
	s := string(out)
	return strings.Contains(s, "File exists") || strings.Contains(s, "already exists") || strings.Contains(s, "already assigned")
}

// fdbOps runs the `bridge fdb` commands of one pass through exec, against
// one read of this host's addresses.
type fdbOps struct {
	exec  ExecFunc
	local localAddrs
}

// hostFDB is fdbOps on this host: the package's exec seam and a fresh read of
// its addresses.
func hostFDB() fdbOps { return fdbOps{exec: execCommand, local: loadLocalAddrs()} }

// AddFDBEntry adds a unicast FDB entry: bridge fdb add <mac> dev vxlan<VNI> dst <remoteVTEP>
// An entry whose remoteVTEP is this host's own address is refused (nil, and
// nothing installed): see refuseLocalDst.
func AddFDBEntry(vni int, mac, remoteVTEP string) error {
	return hostFDB().addUnicast(vni, mac, remoteVTEP)
}

// addUnicast creates a MAC's entry (`bridge fdb add`): one destination per
// MAC. An entry the MAC already has is left as it is ("File exists").
func (o fdbOps) addUnicast(vni int, mac, remoteVTEP string) error {
	if refuseLocalDst(o.local, vni, mac, remoteVTEP) {
		return nil
	}
	out, err := o.exec("bridge", "fdb", "add", mac,
		"dev", vtepName(vni), "dst", remoteVTEP)
	if err != nil && !isAlreadyExists(out) {
		return fmt.Errorf("bridge fdb add %s: %w: %s", mac, err, out)
	}
	return nil
}

// appendFlood adds remoteVTEP to the all-zeros flood entry (`bridge fdb
// append`). The kernel keeps ONE entry per MAC with a list of destinations:
// `add` creates that entry and answers "File exists" for every later
// destination, so a flood list built with it holds only its first peer.
func (o fdbOps) appendFlood(vni int, remoteVTEP string) error {
	if refuseLocalDst(o.local, vni, floodMAC, remoteVTEP) {
		return nil
	}
	out, err := o.exec("bridge", "fdb", "append", floodMAC,
		"dev", vtepName(vni), "dst", remoteVTEP)
	if err != nil && !isAlreadyExists(out) {
		return fmt.Errorf("bridge fdb append flood %s: %w: %s", remoteVTEP, err, out)
	}
	return nil
}

// del removes one destination of mac's entry (`bridge fdb del ... dst`); the
// MAC's other destinations stay.
func (o fdbOps) del(vni int, mac, remoteVTEP string) error {
	out, err := o.exec("bridge", "fdb", "del", mac,
		"dev", vtepName(vni), "dst", remoteVTEP)
	if err != nil && !isAlreadyExists(out) {
		return fmt.Errorf("bridge fdb del %s dst %s: %w: %s", mac, remoteVTEP, err, out)
	}
	return nil
}

// DeleteFDBEntry removes a unicast FDB entry: bridge fdb del <mac> dev vxlan<VNI> dst <remoteVTEP>
func DeleteFDBEntry(vni int, mac, remoteVTEP string) error {
	return fdbOps{exec: execCommand}.del(vni, mac, remoteVTEP)
}

// FloodEntry adds a BUM flood destination: bridge fdb append 00:00:00:00:00:00 dev vxlan<VNI> dst <remoteVTEP>
// As with AddFDBEntry, a remoteVTEP of this host's own is refused.
func FloodEntry(vni int, remoteVTEP string) error {
	return hostFDB().appendFlood(vni, remoteVTEP)
}

// DeleteFloodEntry removes one BUM flood destination: bridge fdb del 00:00:00:00:00:00 dev vxlan<VNI> dst <remoteVTEP>
func DeleteFloodEntry(vni int, remoteVTEP string) error {
	return fdbOps{exec: execCommand}.del(vni, floodMAC, remoteVTEP)
}

// floodMAC is the all-zeros MAC of a BUM flood entry.
const floodMAC = "00:00:00:00:00:00"

// fdbEntry is one forwarding entry on a vxlan device that has a destination.
type fdbEntry struct {
	MAC string
	Dst string
}

// list lists the forwarding entries with a destination on vxlan<VNI>
// (`bridge fdb show dev vxlan<VNI>`). Entries without one — those the bridge
// learned on its port — are not listed. A missing device has none.
func (o fdbOps) list(vni int) ([]fdbEntry, error) {
	out, err := o.exec("bridge", "fdb", "show", "dev", vtepName(vni))
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
