package grpcapi

import (
	"github.com/litevirt/litevirt/internal/corrosion"
)

// nicInterfaceRecords is nics as interface records, for a caller written
// against vm_interfaces rows. Their security groups are not carried.
func nicInterfaceRecords(nics []corrosion.NICRecord) []corrosion.InterfaceRecord {
	out := make([]corrosion.InterfaceRecord, 0, len(nics))
	for _, n := range nics {
		out = append(out, corrosion.InterfaceRecord{
			VMName: n.VMName, NetworkName: n.NetworkName, Ordinal: n.Ordinal,
			MAC: n.MAC, IP: n.IP, TapDevice: n.TapDevice,
		})
	}
	return out
}
