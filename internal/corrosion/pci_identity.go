package corrosion

import (
	"context"
	"errors"
	"fmt"

	"github.com/litevirt/litevirt/internal/pci"
)

// A PCI address (BDF) names a slot on one host. The device in the same slot
// on another host is whatever that host has there: another GPU model, a NIC,
// an NVMe drive. A VM whose device is named by address, recovered onto
// another host, needs a device of the same KIND there, and the kind is the
// vendor and device id its old host's inventory records for that address.

// PCIIdentity is the kind of a PCI device: vendor and device id. Name is the
// inventory's device name, for messages only.
type PCIIdentity struct {
	VendorID string
	DeviceID string
	Name     string
}

// String is "vendor:device", with the name when the inventory has one.
func (i PCIIdentity) String() string {
	s := i.VendorID + ":" + i.DeviceID
	if i.Name != "" {
		s += " (" + i.Name + ")"
	}
	return s
}

// Matches reports whether d is a device of this kind.
func (i PCIIdentity) Matches(d PCIDeviceRecord) bool {
	return i.VendorID != "" && i.DeviceID != "" && d.VendorID == i.VendorID && d.DeviceID == i.DeviceID
}

// ErrPCIIdentityUnknown is returned when no inventory row says what device a
// concrete PCI address named.
var ErrPCIIdentityUnknown = errors.New("the identity of the PCI device is not known")

// PCIAddressIdentity returns the kind of the device vmName's concrete-address
// selector bdf names: the device the inventory of origin, the host the
// selector was recorded on, has at bdf; failing that (origin unknown, or its
// row gone), the device at bdf a live host records vmName as owning. host is
// the host it was read on.
func PCIAddressIdentity(ctx context.Context, c *Client, vmName, origin, bdf string) (ident PCIIdentity, host string, err error) {
	// Where to look: origin's inventory at bdf, then each live host that
	// records vmName as owning a device, at bdf and owned by it.
	type look struct {
		host    string
		mustOwn bool
	}
	var looks []look
	if origin != "" {
		looks = append(looks, look{host: origin})
	}
	owners, err := PCIOwnerHostsForVM(ctx, c, vmName)
	if err != nil {
		return PCIIdentity{}, "", err
	}
	for _, h := range owners {
		looks = append(looks, look{host: h, mustOwn: true})
	}
	want, wantOK := pci.CanonicalBDF(bdf)
	for _, l := range looks {
		devs, err := ListPCIDevices(ctx, c, l.host, "")
		if err != nil {
			return PCIIdentity{}, "", err
		}
		for _, d := range devs {
			got, gotOK := pci.CanonicalBDF(d.Address)
			if !((wantOK && gotOK && got == want) || (!wantOK && d.Address == bdf)) || (l.mustOwn && d.VMName != vmName) {
				continue
			}
			if d.VendorID == "" || d.DeviceID == "" {
				return PCIIdentity{}, "", fmt.Errorf("%w: %s on %s has no vendor/device id in the inventory", ErrPCIIdentityUnknown, bdf, l.host)
			}
			return PCIIdentity{VendorID: d.VendorID, DeviceID: d.DeviceID, Name: d.DeviceName}, l.host, nil
		}
	}
	if origin != "" {
		return PCIIdentity{}, "", fmt.Errorf("%w: %s is not in the inventory of %s, and no host records %s as owning it", ErrPCIIdentityUnknown, bdf, origin, vmName)
	}
	return PCIIdentity{}, "", fmt.Errorf("%w: no host records %s as owning %s", ErrPCIIdentityUnknown, vmName, bdf)
}
