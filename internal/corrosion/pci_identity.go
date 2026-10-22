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
	// Host and Address are the inventory row it was read from.
	Host    string
	Address string
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
// selector names, and the host it was read on. deviceID is the selector's
// intent ("" for a spec device with no intent); origin is the host the
// address was recorded on ("" when not known). In this order:
//
//  1. the device that realizes the intent (its primary member's
//     vm_pci_realizations row), read where it was realized, when vmName owns
//     it there, or it is free there and that is the host the VM lives on: a
//     VM recovered onto another host keeps the kind of device it has there,
//     whatever becomes of the row it was first recorded on;
//  2. unless the intent was realized on a host other than origin (the hosts
//     a VM left keep their rows, and a rescan rewrites them: another card
//     may sit there since), origin's device at bdf, when vmName owns it or
//     it is free;
//  3. likewise, the device at bdf a live host records vmName as owning.
//
// Anything else is ErrPCIIdentityUnknown: the caller fails closed.
func PCIAddressIdentity(ctx context.Context, c *Client, vmName, deviceID, origin, bdf string) (ident PCIIdentity, host string, err error) {
	type found struct {
		PCIIdentity
		owner string
	}
	at := func(host, addr string, owned bool) (found, bool, error) {
		devs, err := ListPCIDevices(ctx, c, host, "")
		if err != nil {
			return found{}, false, err
		}
		want, wantOK := pci.CanonicalBDF(addr)
		for _, d := range devs {
			got, gotOK := pci.CanonicalBDF(d.Address)
			if !((wantOK && gotOK && got == want) || (!wantOK && d.Address == addr)) {
				continue
			}
			if owned && d.VMName != vmName {
				return found{}, false, nil
			}
			if d.VendorID == "" || d.DeviceID == "" {
				return found{}, false, fmt.Errorf("%w: %s on %s has no vendor/device id in the inventory", ErrPCIIdentityUnknown, addr, host)
			}
			return found{PCIIdentity{VendorID: d.VendorID, DeviceID: d.DeviceID, Name: d.DeviceName, Host: host, Address: d.Address}, d.VMName}, true, nil
		}
		return found{}, false, nil
	}

	realizedElsewhere := false
	if deviceID != "" {
		reals, err := ListVMPCIRealizations(ctx, c, vmName)
		if err != nil {
			return PCIIdentity{}, "", err
		}
		// The host the VM lives on now: there a realized device may be free,
		// released by a stop before the latch (a start then does not claim
		// it again), and is still the VM's. Only another VM's is not.
		current := ""
		if vm, err := GetVM(ctx, c, vmName); err != nil {
			return PCIIdentity{}, "", err
		} else if vm != nil {
			current = vm.HostName
		}
		for _, r := range reals {
			if r.DeviceID != deviceID || r.Ordinal != 0 || r.ResolvedAddress == "" {
				continue
			}
			if r.HostName != origin {
				realizedElsewhere = true
			}
			id, ok, err := at(r.HostName, r.ResolvedAddress, false)
			if err != nil {
				return PCIIdentity{}, "", err
			}
			if ok && (id.owner == vmName || (id.owner == "" && r.HostName == current)) {
				return id.PCIIdentity, r.HostName, nil
			}
		}
	}
	if realizedElsewhere {
		// The VM has had its device on another host since; what the hosts
		// it left still record (ownership is not released there, and a
		// rescan rewrites the row) says nothing about it.
		return PCIIdentity{}, "", fmt.Errorf("%w: %s's device %s was realized on another host, which no longer records it as the VM's",
			ErrPCIIdentityUnknown, vmName, bdf)
	}
	if origin != "" {
		// The VM's own device there, or a free one.
		id, ok, err := at(origin, bdf, false)
		if err != nil {
			return PCIIdentity{}, "", err
		}
		if ok && (id.owner == "" || id.owner == vmName) {
			return id.PCIIdentity, origin, nil
		}
	}
	owners, err := PCIOwnerHostsForVM(ctx, c, vmName)
	if err != nil {
		return PCIIdentity{}, "", err
	}
	for _, h := range owners {
		id, ok, err := at(h, bdf, true)
		if err != nil {
			return PCIIdentity{}, "", err
		}
		if ok {
			return id.PCIIdentity, h, nil
		}
	}
	if origin != "" {
		return PCIIdentity{}, "", fmt.Errorf("%w: %s on %s is not the VM's (gone from the inventory, or not owned by %s on a host it has left), "+
			"and no host records %s as owning a device that realizes it", ErrPCIIdentityUnknown, bdf, origin, vmName, vmName)
	}
	return PCIIdentity{}, "", fmt.Errorf("%w: no host records %s as owning %s", ErrPCIIdentityUnknown, vmName, bdf)
}
