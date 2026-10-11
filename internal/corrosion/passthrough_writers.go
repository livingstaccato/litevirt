package corrosion

import (
	"context"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// The writers of the usb_mounts_memory feature's data: a VM spec that carries
// USB devices or a memory hot-add band, and a container create spec that
// carries host mounts or devices. An older host decodes a spec into a struct
// without those fields and drops them from any spec it rewrites, so a write
// that ADDS them waits for the release token and its used record
// (capabilities.FeatureUSBMountsMemory).
//
// Only a write that adds them goes through these. A rewrite that keeps what the
// row already holds (a label, a resize, a relocation, a clone of a VM or
// container that has them) stays on the plain writer: the feature is already
// recorded as used, and a refusal there would stop a workflow main allows.

// InsertVMWithPassthrough is InsertVMWithHardware for a VM row whose spec
// carries USB devices or memory hot-add (a create, a live restore).
func InsertVMWithPassthrough(ctx context.Context, c *Client, g capabilities.FeatureGrant, vm VMRecord,
	ifaces []InterfaceRecord, disks []DiskRecord, nics []NICRecord, pciIntents []PCIIntentRecord, adopt bool) error {
	if err := g.Check(capabilities.FeatureUSBMountsMemory); err != nil {
		return err
	}
	return InsertVMWithHardware(ctx, c, vm, ifaces, disks, nics, pciIntents, adopt)
}

// MutateDesiredSpecPassthrough is MutateDesiredSpec for an UpdateVM that sets
// USB devices or turns memory hot-add on.
func MutateDesiredSpecPassthrough(ctx context.Context, c *Client, g capabilities.FeatureGrant, name string,
	fn func(oldSpec string) (string, error)) (applied bool, newGen int64, err error) {
	if err := g.Check(capabilities.FeatureUSBMountsMemory); err != nil {
		return false, 0, err
	}
	return MutateDesiredSpec(ctx, c, name, fn)
}

// CreateContainerAtomicWithHostAccess is CreateContainerAtomic for a container
// row whose create spec carries host mounts or devices (a create, an admin's
// operator restore).
func CreateContainerAtomicWithHostAccess(ctx context.Context, c *Client, g capabilities.FeatureGrant,
	rec ContainerRecord, ifaces []ContainerInterfaceRecord) error {
	if err := g.Check(capabilities.FeatureUSBMountsMemory); err != nil {
		return err
	}
	return CreateContainerAtomic(ctx, c, rec, ifaces)
}

// UpsertContainerWithHostAccess is UpsertContainer for lv ct convert setting a
// container's host mounts or devices.
func UpsertContainerWithHostAccess(ctx context.Context, c *Client, g capabilities.FeatureGrant, rec ContainerRecord) error {
	if err := g.Check(capabilities.FeatureUSBMountsMemory); err != nil {
		return err
	}
	return UpsertContainer(ctx, c, rec)
}
