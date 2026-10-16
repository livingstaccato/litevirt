package grpcapi

import (
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// recordedNICModel is the model CreateVM gave nic: the spec's NIC it was
// created as, else (a NIC hot-plugged later) its row's. A vm_interfaces row
// has no model column and reads as virtio, so the spec comes first; a NIC's
// model is never changed after it is created.
func recordedNICModel(spec *pb.VMSpec, nic corrosion.NICRecord) string {
	stored := spec.GetNetwork()
	if i := matchStoredNIC(stored, make([]bool, len(stored)), nic); i >= 0 {
		if m := stored[i].GetModel(); m != "" {
			return m
		}
	}
	if nic.Model != "" {
		return nic.Model
	}
	return "virtio"
}

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
