package placement

import (
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pci"
)

// DeviceRequestFor converts one protobuf device request into the exact selector
// semantics the allocator will use (corrosion.ClassifyPCISelector: mapping →
// SR-IOV → type/vendor → exact address). A caller that places a VM spec
// against its PCI devices builds each request here: a hand-copied subset of the
// fields drops a selector, and a request left with no selector is rejected by
// every host.
//
// Address can be a frozen resolution artifact on a portable mapping/SR-IOV/type
// selector; it must not outrank that selector during placement.
func DeviceRequestFor(dev *pb.DeviceSpec) DeviceRequest {
	if dev == nil {
		return DeviceRequest{}
	}
	count := int(dev.Count)
	kind, _ := corrosion.ClassifyPCISelector(dev)
	switch kind {
	case "mapping":
		return DeviceRequest{
			Mapping: dev.Mapping,
			Count:   count,
		}
	case "sriov":
		return DeviceRequest{
			Type:   dev.Type,
			Count:  count,
			Vendor: dev.Vendor,
			Model:  dev.Model,
			Sriov:  true,
			Parent: dev.Parent,
		}
	case "type":
		return DeviceRequest{
			Type:   dev.Type,
			Count:  count,
			Vendor: dev.Vendor,
			Model:  dev.Model,
		}
	default:
		address := dev.Address
		if canonical, ok := pci.CanonicalBDF(address); ok {
			address = canonical
		}
		return DeviceRequest{
			Count:   count,
			Address: address,
		}
	}
}
