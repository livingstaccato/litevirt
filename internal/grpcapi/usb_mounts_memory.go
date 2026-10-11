package grpcapi

import (
	"context"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// USB passthrough, memory hot-add and container host mounts/devices are one
// release feature, capabilities.FeatureUSBMountsMemory, opened by the shared
// release token.
//
// An older peer decodes a spec into a struct without these fields and drops
// them from any spec it rewrites, and an older coordinator would place, fail
// over or recreate the workload without them. So in a mixed-version cluster
// they must not be set, and once they are, a rollback below the release must
// quarantine (the feature's used record). Clearing a field is never gated, and
// a spec without them is unaffected.

// passthroughFeatureGate is the entry-node check: nil when the release token
// has latched, else the release gate's own refusal (FailedPrecondition, "the
// cluster upgrade must finish first (usb_mounts_memory needs
// release_2026_11_v1)", the hosts still to upgrade, and the pointer to `lv
// cluster upgrade-status`). It drives the latch but records and grants nothing
// (Server.ReleaseFeatureRefusal), so a request that later fails leaves no used
// record. The node that WRITES takes the grant itself (passthroughGrant), so a
// forwarded request is gated there.
func (s *Server) passthroughFeatureGate(ctx context.Context) error {
	return s.ReleaseFeatureRefusal(ctx, capabilities.FeatureUSBMountsMemory)
}

// passthroughGrant runs the feature's gate on THIS node, the one that writes
// the feature's data, and returns the grant its writers take
// (corrosion.InsertVMWithPassthrough and the rest). A refusal is the release
// gate's error, unchanged.
func (s *Server) passthroughGrant(ctx context.Context) (capabilities.FeatureGrant, error) {
	var g capabilities.FeatureGrant
	err := s.WithReleaseFeature(ctx, capabilities.FeatureUSBMountsMemory,
		func(_ context.Context, got capabilities.FeatureGrant) error { g = got; return nil })
	return g, err
}

// passthroughGrantIfLatched is passthroughGrant for a caller that falls back
// before the release token latches (an admin's restore strips the backup's
// host access then, as main does): ok is false, with no error, when the token
// has not latched here, and nothing is asked of any peer. Once it has latched
// the gate decides, and its refusal (a first use not yet acknowledged, a host
// rolled back after the latch) is returned unchanged: what the caller asked to
// keep is never silently dropped after the latch.
func (s *Server) passthroughGrantIfLatched(ctx context.Context) (g capabilities.FeatureGrant, ok bool, err error) {
	if !s.ReleaseFeatureAvailable(capabilities.FeatureUSBMountsMemory) {
		return g, false, nil
	}
	g, err = s.passthroughGrant(ctx)
	if err != nil {
		return g, false, err
	}
	return g, true, nil
}

// containerSpecSetsHostAccess reports whether a container create spec carries
// the feature's data.
func containerSpecSetsHostAccess(cs corrosion.ContainerCreateSpec) bool {
	return len(cs.Mounts) > 0 || len(cs.Devices) > 0
}

// passthroughGranted reports whether g is the feature's grant.
func passthroughGranted(g capabilities.FeatureGrant) bool {
	return g.Check(capabilities.FeatureUSBMountsMemory) == nil
}

// vmSpecSetsPassthrough reports whether a VM spec carries the feature's data.
func vmSpecSetsPassthrough(spec *pb.VMSpec) bool {
	return len(spec.GetUsbDevices()) > 0 || spec.GetMemoryHotplugMaxMib() != 0
}

// updateSetsPassthrough reports whether an UpdateVM ADDS the feature's data:
// a non-empty USB list or a non-zero hot-add ceiling. A clear adds nothing.
func updateSetsPassthrough(req *pb.UpdateVMRequest) bool {
	return (req.GetSetUsbDevices() && len(req.GetUsbDevices()) > 0) ||
		(req.MemoryHotplugMaxMib != nil && *req.MemoryHotplugMaxMib != 0)
}
