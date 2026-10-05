package grpcapi

import (
	"fmt"

	"google.golang.org/grpc/codes"

	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// pciAttachErrorCode classifies a failed live device attach (disk, NIC, or PCI
// hostdev): FailedPrecondition when the domain has no free PCI slot to put the
// device on — a q35 guest with no spare pcie-root-port left, an operator fix
// (see pciAttachError) — Internal for everything else, exactly as every attach
// failure was mapped before this case was special-cased.
func pciAttachErrorCode(err error) codes.Code {
	if lv.IsPCISlotsExhausted(err) {
		return codes.FailedPrecondition
	}
	return codes.Internal
}

// pciAttachError wraps a failed attach's cause under op (e.g. "attach disk"),
// adding an actionable message ONLY when the failure is a PCI-slot exhaustion —
// every other failure keeps exactly the %w-wrapped message it had before this
// existed, so an unrelated libvirt fault is never misdescribed as a slots
// problem.
func pciAttachError(op string, err error) error {
	if lv.IsPCISlotsExhausted(err) {
		return fmt.Errorf("%s: no free PCI slot on this q35 guest "+
			"(detach another device first; raising pci.spare_pcie_root_ports gives more spare ports only to a "+
			"newly defined domain, such as one made with `lv clone` — see docs/pci-passthrough.md, "+
			"\"Spare PCIe root ports\"): %w", op, err)
	}
	return fmt.Errorf("%s: %w", op, err)
}
