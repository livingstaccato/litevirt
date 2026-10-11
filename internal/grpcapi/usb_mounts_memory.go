package grpcapi

import (
	"context"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
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
// has durably latched here, else the release gate's own refusal
// (FailedPrecondition, "the cluster upgrade must finish first
// (usb_mounts_memory needs release_2026_11_v1)", naming the hosts still to
// upgrade). It lets a request fail before anything is created or forwarded; it
// grants nothing. The node that WRITES takes the grant itself
// (passthroughGrant), so a forwarded request is gated there.
func (s *Server) passthroughFeatureGate(ctx context.Context) error {
	if s.ReleaseFeatureAvailable(capabilities.FeatureUSBMountsMemory) {
		return nil
	}
	return s.WithReleaseFeature(ctx, capabilities.FeatureUSBMountsMemory,
		func(context.Context, capabilities.FeatureGrant) error { return nil })
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

// passthroughGrantIfAvailable is passthroughGrant for a caller that falls back
// rather than fails (an admin's restore keeps the backup's host access only
// when it can be written, and otherwise strips it as main does): ok is false,
// with no error, when the token has not latched here or the gate refuses. It
// asks no peer unless the token has latched.
func (s *Server) passthroughGrantIfAvailable(ctx context.Context) (g capabilities.FeatureGrant, ok bool) {
	if !s.ReleaseFeatureAvailable(capabilities.FeatureUSBMountsMemory) {
		return g, false
	}
	g, err := s.passthroughGrant(ctx)
	return g, err == nil
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
