package grpcapi

import "github.com/litevirt/litevirt/internal/corrosion"

// copyNICGuards is the guard record of each NIC a renamed promotion or a
// restore under a new name creates. Those NICs are new — fresh MACs on a
// second VM beside the original — so each gets the default guard, as a
// create's and a clone's do (the source's relaxations are not copied: relaxing
// a guard needs network authority the caller may not hold). They are written
// through writeNewNICGuards, the nic_guards gate (merge checklist M8), which
// never fails or slows the operation for a default guard.
func copyNICGuards(vm, uuid string, ifaces []corrosion.InterfaceRecord) []corrosion.NICGuardRecord {
	out := make([]corrosion.NICGuardRecord, 0, len(ifaces))
	for _, f := range ifaces {
		out = append(out, corrosion.NICGuardRecord{VMName: vm, MAC: f.MAC, Mode: corrosion.NICGuardOn,
			VMUUID: uuid, Network: f.NetworkName, Ordinal: f.Ordinal})
	}
	return out
}
