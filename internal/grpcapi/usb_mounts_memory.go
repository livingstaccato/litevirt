package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// usbMountsMemoryActive reports whether this node may originate a VM's
// usb_devices / memory hot-add or a container's host mounts / devices: the
// config flag AND the cluster-wide UsbMountsMemoryV1 latch, so no older peer
// can drop the fields from a spec it rewrites or place the workload without
// them. Same `flag && Enforced` shape as liveResizeActive.
func (s *Server) usbMountsMemoryActive(ctx context.Context) bool {
	return s.enfUsbMountsMemory && s.gate != nil && s.gate.Enforced(ctx, capabilities.UsbMountsMemoryV1)
}

// usbMountsMemoryRefusalText is the fixed part of the refusal, matched by tests.
const usbMountsMemoryRefusalText = "needs enforcement.usb_mounts_memory on this node and the usb_mounts_memory_v1 capability latched cluster-wide"

// usbMountsMemoryRefusal is the refusal for a request that sets one of the
// gated fields while usbMountsMemoryActive is false.
func usbMountsMemoryRefusal(what string) error {
	return status.Errorf(codes.FailedPrecondition,
		"%s %s (an older peer would drop the setting)", what, usbMountsMemoryRefusalText)
}
