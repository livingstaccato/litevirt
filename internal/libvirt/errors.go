package libvirt

import (
	"strings"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// IsNotFound classifies a libvirt error as "the object does not exist", so callers
// can treat a delete/lookup of an already-gone domain, snapshot, or checkpoint as
// success instead of conflating it with a real fault.
//
// Typed go-libvirt error codes are authoritative and checked first. The substring
// fallback exists because litevirt wraps several libvirt calls with its own text
// (e.g. snapshot.go's `snapshot %q not found: %w`), and because some paths surface
// a message-only error with no code attached — a typed-only check would regress
// those callers.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(golibvirt.Error); ok {
		switch e.Code {
		case uint32(golibvirt.ErrNoDomainCheckpoint),
			uint32(golibvirt.ErrNoDomain),
			uint32(golibvirt.ErrNoDomainSnapshot):
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "no domain checkpoint") ||
		strings.Contains(msg, "no domain snapshot") ||
		strings.Contains(msg, "cannot find")
}

// IsPCISlotsExhausted classifies a libvirt attach error as "the domain has no free
// PCI slot to put this device on" — the failure a q35 guest with no spare
// pcie-root-port hits on a hot-plug (disk/NIC/PCI) once every root port already
// holds a device. Callers map this to FailedPrecondition (an operator fix —
// detach something first, or raise pci.spare_pcie_root_ports for newly
// defined domains) instead of Internal (a fault this host cannot explain).
//
// Substring-only: libvirt raises this as a generic VIR_ERR_INTERNAL_ERROR with no
// dedicated typed code (unlike IsNotFound's ErrNoDomain family), so there is no
// typed check to add. The exact wording has drifted across libvirt/qemu
// versions ("No more available PCI slots" vs "No more available PCI addresses"
// vs "no more free PCI slots"); all three are matched so a version bump cannot
// silently turn this back into a generic Internal error.
func IsPCISlotsExhausted(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no more available pci slots") ||
		strings.Contains(msg, "no more available pci addresses") ||
		strings.Contains(msg, "no more free pci slots")
}
