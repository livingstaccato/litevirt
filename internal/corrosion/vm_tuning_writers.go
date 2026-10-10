package corrosion

import (
	"context"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// The writers of the vm_disk_nic_io feature's data: a VM spec that carries disk
// discard, detect_zeroes, an I/O throttle or NIC queues. An older host drops
// those fields from any spec it rewrites, so a write that adds them waits for
// the release token and its used record (capabilities.FeatureVMDiskNICIO).
//
// Only a write that ADDS tuning goes through these. A rewrite that keeps what
// the spec already holds (a label, a resize, a clone of a tuned VM) stays on
// MutateDesiredSpec / InsertVMWithHardware: the tuning is already recorded as
// used, and a refusal there would stop a workflow main allows.

// InsertVMWithTuning is InsertVMWithHardware for a VM row whose spec carries
// disk or NIC tuning (a create, a restore, a renamed promotion).
func InsertVMWithTuning(ctx context.Context, c *Client, g capabilities.FeatureGrant, vm VMRecord,
	ifaces []InterfaceRecord, disks []DiskRecord, nics []NICRecord, pciIntents []PCIIntentRecord, adopt bool) error {
	if err := g.Check(capabilities.FeatureVMDiskNICIO); err != nil {
		return err
	}
	return InsertVMWithHardware(ctx, c, vm, ifaces, disks, nics, pciIntents, adopt)
}

// MutateDesiredSpecTuning is MutateDesiredSpec for a change that adds disk or
// NIC tuning to a VM's stored spec (SetDiskIO, an UpdateVM carrying tuning).
func MutateDesiredSpecTuning(ctx context.Context, c *Client, g capabilities.FeatureGrant, name string,
	fn func(oldSpec string) (string, error)) (applied bool, newGen int64, err error) {
	if err := g.Check(capabilities.FeatureVMDiskNICIO); err != nil {
		return false, 0, err
	}
	return MutateDesiredSpec(ctx, c, name, fn)
}
