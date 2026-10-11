package corrosion

import (
	"context"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// VMSpecFeatures says which release features' data one write of a VM's spec
// carries: disk/NIC tuning (vm_disk_nic_io), USB devices or memory hot-add
// (usb_mounts_memory), CPU or NIC limits (vm_limits). One spec can carry any
// of them together — a create, a restore, a clone or an update that sets
// several — and each must have passed its own release gate before the spec is
// written (integration checklist M9).
type VMSpecFeatures struct {
	Tuning      bool
	Passthrough bool
	Limits      bool
}

// InsertVMWithReleaseFeatures is InsertVMWithHardware for a VM spec that may
// carry the data of several release features at once. It takes one grant per
// feature and checks every one the spec's data needs (needs), so a spec that
// carries three features cannot be written on the strength of one grant. A
// grant the data does not need is not checked (the zero grant is fine there).
func InsertVMWithReleaseFeatures(ctx context.Context, c *Client, tuning, passthrough, limits capabilities.FeatureGrant,
	needs VMSpecFeatures, vm VMRecord, ifaces []InterfaceRecord, disks []DiskRecord, nics []NICRecord,
	pciIntents []PCIIntentRecord, adopt bool) error {
	if needs.Tuning {
		if err := tuning.Check(capabilities.FeatureVMDiskNICIO); err != nil {
			return err
		}
	}
	if needs.Passthrough {
		if err := passthrough.Check(capabilities.FeatureUSBMountsMemory); err != nil {
			return err
		}
	}
	if needs.Limits {
		if err := limits.Check(capabilities.FeatureVMLimits); err != nil {
			return err
		}
	}
	return InsertVMWithHardware(ctx, c, vm, ifaces, disks, nics, pciIntents, adopt)
}

// MutateDesiredSpecWithReleaseFeatures is MutateDesiredSpec for an update
// whose new spec may carry the data of several release features: every grant
// needs names is checked before anything is written.
func MutateDesiredSpecWithReleaseFeatures(ctx context.Context, c *Client, tuning, passthrough, limits capabilities.FeatureGrant,
	needs VMSpecFeatures, name string, fn func(oldSpec string) (string, error)) (applied bool, newGen int64, err error) {
	if needs.Tuning {
		if err := tuning.Check(capabilities.FeatureVMDiskNICIO); err != nil {
			return false, 0, err
		}
	}
	if needs.Passthrough {
		if err := passthrough.Check(capabilities.FeatureUSBMountsMemory); err != nil {
			return false, 0, err
		}
	}
	if needs.Limits {
		if err := limits.Check(capabilities.FeatureVMLimits); err != nil {
			return false, 0, err
		}
	}
	return MutateDesiredSpec(ctx, c, name, fn)
}
