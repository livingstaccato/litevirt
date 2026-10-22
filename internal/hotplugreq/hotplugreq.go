// Package hotplugreq builds the PCI attach request `lv attach-pci` sends, so
// the CLI and the tests that prove the advice given in migration refusals
// share one request shape.
package hotplugreq

import (
	"errors"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// AttachPCIOptions are the attach-pci flags.
type AttachPCIOptions struct {
	// Address attaches that concrete device. It is the only selector the
	// journaled path handles, which is also the one that works on a stopped VM.
	Address string
	Type    string
	Vendor  string
	Count   int32
	Sriov   bool
	Parent  string
}

// AttachPCI is the AttachDeviceRequest for vm. With an Address no other
// selector may be set, as they would turn it into a type selector, which is
// attached to a running VM only.
func AttachPCI(vm string, o AttachPCIOptions) (*pb.AttachDeviceRequest, error) {
	if o.Address != "" {
		if o.Vendor != "" || o.Sriov || o.Parent != "" {
			return nil, errors.New("--address names one device; it cannot be combined with --vendor, --sriov or --parent")
		}
		return &pb.AttachDeviceRequest{VmName: vm, PciDevice: &pb.DeviceSpec{Address: o.Address}}, nil
	}
	return &pb.AttachDeviceRequest{VmName: vm, PciDevice: &pb.DeviceSpec{
		Type: o.Type, Vendor: o.Vendor, Count: o.Count, Sriov: o.Sriov, Parent: o.Parent,
	}}, nil
}
