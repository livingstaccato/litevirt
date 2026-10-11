package grpcapi

import (
	"context"
	"log/slog"
	"strings"

	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
)

// promotedRelease is what restrictPromotedReleaseFeatures decided for a
// promoted spec's CPU/NIC limits (vm_limits), memory hot-add and USB devices
// (usb_mounts_memory).
type promotedRelease struct {
	// limits and passthrough are the grants taken for what the spec keeps; the
	// zero grant when it keeps none. The renamed copy's row is written through
	// insertVMWithGrants with them.
	limits, passthrough capabilities.FeatureGrant
	// dropped names each part of the spec that was dropped, and why.
	dropped []string
}

// restrictPromotedReleaseFeatures is the release gate for the limits, hot-add
// band and USB devices of a promoted record. A promotion is a recovery path, so
// it is never refused for them — main, which knows none of these fields, drops
// them, and so does this:
//
//   - before the feature's release token has latched here, the data is
//     dropped (main's behaviour);
//   - once it has latched, values a create would refuse are dropped (a record
//     from before a rollback must not define what the cluster refuses), and
//     otherwise the feature's grant is taken on this node, the one that writes;
//     a gate that still refuses (a first use that cannot be acknowledged, a
//     host rolled back after the latch) drops the data rather than the
//     promotion.
//
// A renamed promotion is a second VM: it never carries the source's USB
// devices (a clone does not either, a raw device needs an admin, and the
// source still holds them). A takeover writes no spec — it re-homes the row —
// and its domain is defined without USB devices, so they are left in place.
//
// Each drop is logged here; the caller audits it once the promotion commits.
func (s *Server) restrictPromotedReleaseFeatures(ctx context.Context, spec *pb.VMSpec, renamed bool) promotedRelease {
	var r promotedRelease
	drop := func(what, why string) {
		r.dropped = append(r.dropped, what+" ("+why+")")
		slog.Warn("promote: dropped from the promoted spec", "vm", spec.GetName(), "what", what, "why", why)
	}
	// gate runs feature's gate: "" with the grant, or why it did not open.
	gate := func(feature capabilities.Feature, valid error, take func(context.Context) (capabilities.FeatureGrant, error)) (capabilities.FeatureGrant, string) {
		var none capabilities.FeatureGrant
		if !s.ReleaseFeatureAvailable(feature) {
			return none, "the cluster upgrade has not finished"
		}
		if valid != nil {
			return none, "invalid in the stored spec: " + status.Convert(valid).Message()
		}
		g, err := take(ctx)
		if err != nil {
			return none, "the " + string(feature) + " gate refused after the latch: " + status.Convert(err).Message()
		}
		return g, ""
	}

	if specSetsLimits(spec) && s.ReleaseFeatureAvailable(capabilities.FeatureVMLimits) {
		// Past the latch, a value a create would refuse is dropped by itself
		// and the valid rest kept (as restore does: dropInvalidLimits).
		for _, d := range dropInvalidLimits(spec) {
			drop(d, "invalid in the stored spec")
		}
	}
	if specSetsLimits(spec) {
		g, why := gate(capabilities.FeatureVMLimits, nil, func(ctx context.Context) (capabilities.FeatureGrant, error) {
			return s.recordLimitedSpec(ctx, spec)
		})
		if why != "" {
			for _, k := range stripLimits(spec) {
				drop(k, why)
			}
		}
		r.limits = g
	}
	if renamed && len(spec.UsbDevices) > 0 {
		what := usbSummary(spec.UsbDevices)
		spec.UsbDevices = nil
		drop("USB devices "+what, "a renamed promotion is a new VM and does not take the source's devices")
	}
	if spec.MemoryHotplugMaxMib != 0 {
		g, why := gate(capabilities.FeatureUSBMountsMemory, validateMemoryHotplugSpec(spec), s.passthroughGrant)
		if why != "" {
			spec.MemoryHotplugMaxMib, spec.MemoryHotplugBaseMib = 0, 0
			drop("memory hot-add", why)
		}
		r.passthrough = g
	}
	return r
}

// audit records what restrictPromotedReleaseFeatures dropped. Called only once
// the promotion can no longer be refused, with the VM's actual name.
func (r promotedRelease) audit(ctx context.Context, s *Server, vm, op string) {
	if len(r.dropped) == 0 {
		return
	}
	s.audit(ctx, "vm.release_features_dropped", vm, op+": not carried: "+strings.Join(r.dropped, "; "), "degraded")
}
