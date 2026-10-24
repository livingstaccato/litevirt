package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// refuseMIGHostdevsAtStart refuses to start name's domain when its definition
// passes through an NVIDIA GPU that MIG holds (refuseMIGRebind). Its PCI
// hostdevs are managed='yes': libvirt binds each one to vfio-pci itself at
// start, taking a GPU from the nvidia driver it went back to when the domain
// last stopped. Not every start reaches acquireDeviceLeases first (a start
// before the hardware_v2 latch of a domain that already has its hostdevs, a
// cutover's handoff), so the definition about to start is judged here, in
// both regimes. A hostdev already on vfio-pci is not rebound and passes. A
// domain with no definition has nothing for libvirt to bind; the start
// fails on its own. It changes nothing.
func (s *Server) refuseMIGHostdevsAtStart(ctx context.Context, name string) error {
	if s.virt == nil {
		return nil
	}
	def, err := s.virt.DumpXMLInactive(name)
	if err != nil {
		return nil
	}
	addrs, err := lv.ParseHostdevSourcePCIAddresses(def)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition,
			"start %q: its definition's PCI passthrough devices cannot be read: %v", name, err)
	}
	if len(addrs) == 0 {
		return nil
	}
	return s.refuseMIGRebind(ctx, addrs)
}
