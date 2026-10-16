package grpcapi

import (
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// baseDomainConfig assembles the libvirt VMConfig fields that MUST be identical
// between CreateVM, a full-regeneration redefine and the reconciler's failover
// start — every field derived from the VMSpec (compose.DomainConfig). The old
// inline redefine builder dropped MinMemoryMiB/MaxMemoryMiB (collapsing the
// balloon ceiling to the current memory) and Hostdevs (silently detaching PCI
// passthrough on any `lv update` of a stopped VM).
//
// Disks, networks, and hostdevs are passed in because their SOURCING differs:
// CreateVM allocates brand-new devices, while a redefine rebuilds them from the
// authoritative stored spec + PCI ownership. Firmware/nvram/TPM and the create-time
// cloud-init ISO are applied by the caller (create host-resolves firmware paths and
// refuses to adopt orphaned state; redefine reuses the existing state).
func baseDomainConfig(spec *pb.VMSpec, disks []lv.DiskConfig, nets []lv.NetworkConfig, hostdevs []lv.HostdevConfig) lv.VMConfig {
	return compose.DomainConfig(spec, disks, nets, hostdevs)
}
