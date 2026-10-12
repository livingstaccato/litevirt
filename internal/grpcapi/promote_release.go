package grpcapi

import (
	"context"
	"log/slog"
	"strings"

	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
)

// promotedRelease is what restrictPromotedReleaseFeatures and grant decided
// for a promoted spec's CPU/NIC limits (vm_limits), memory hot-add and USB
// devices (usb_mounts_memory).
type promotedRelease struct {
	// limits and passthrough are the grants taken for what the spec keeps; the
	// zero grant when it keeps none. The renamed copy's row is written through
	// insertVMWithGrants with them.
	limits, passthrough capabilities.FeatureGrant
	// dropped names each part of the spec that was dropped, and why.
	dropped []string
	// renamed: the promotion writes a new row from the spec. A takeover keeps
	// its row's spec, so what was dropped is only not applied to its domain.
	renamed bool
}

func (r *promotedRelease) drop(spec *pb.VMSpec, what, why string) {
	r.dropped = append(r.dropped, what+" ("+why+")")
	slog.Warn("promote: dropped from the promoted spec", "vm", spec.GetName(), "what", what, "why", why)
}

// restrictPromotedReleaseFeatures is the first half of the release gate for
// the limits, hot-add band and USB devices of a promoted record; grant is the
// second. A promotion is a recovery path, so it is never refused for them —
// main, which knows none of these fields, drops them, and so does this:
//
//   - before the feature's release token has latched here, the data is
//     dropped (main's behaviour);
//   - once it has latched, each value a create would refuse is dropped (a
//     record from before a rollback must not define what the cluster
//     refuses), the valid rest kept.
//
// A renamed promotion is a second VM: it never carries the source's USB
// devices (a clone does not either, a raw device needs an admin, and the
// source still holds them). A takeover writes no spec — it re-homes the row —
// and its domain is defined without USB devices, so they are left in place.
//
// Nothing here records a use: it runs before the promotion's own refusals.
// Each drop is logged here; the caller audits it once the promotion commits.
func (s *Server) restrictPromotedReleaseFeatures(spec *pb.VMSpec, renamed bool) promotedRelease {
	r := promotedRelease{renamed: renamed}
	const unlatched = "the cluster upgrade has not finished"
	if specSetsLimits(spec) {
		if !s.ReleaseFeatureAvailable(capabilities.FeatureVMLimits) {
			for _, k := range stripLimits(spec) {
				r.drop(spec, k, unlatched)
			}
		} else {
			for _, d := range dropInvalidLimits(spec) {
				r.drop(spec, d, "invalid in the stored spec")
			}
		}
	}
	if renamed && len(spec.UsbDevices) > 0 {
		what := usbSummary(spec.UsbDevices)
		spec.UsbDevices = nil
		r.drop(spec, "USB devices "+what, "a renamed promotion is a new VM and does not take the source's devices")
	}
	if spec.MemoryHotplugMaxMib != 0 {
		why := ""
		if !s.ReleaseFeatureAvailable(capabilities.FeatureUSBMountsMemory) {
			why = unlatched
		} else if err := validateMemoryHotplugSpec(spec); err != nil {
			why = "invalid in the stored spec: " + status.Convert(err).Message()
		}
		if why != "" {
			spec.MemoryHotplugMaxMib, spec.MemoryHotplugBaseMib = 0, 0
			r.drop(spec, "memory hot-add", why)
		}
	}
	return r
}

// grant takes, on this node, the grant of each feature whose data spec still
// carries, recording its use. It runs once every refusal of the promotion has
// passed, immediately before the NICs and the domain are built, so a refused
// promotion records no use. A gate that refuses (a first use that cannot be
// acknowledged, a host rolled back after the latch) drops that data, not the
// promotion.
func (r *promotedRelease) grant(ctx context.Context, s *Server, spec *pb.VMSpec) {
	refused := func(f capabilities.Feature, err error) string {
		return "the " + string(f) + " gate refused after the latch: " + status.Convert(err).Message()
	}
	if specSetsLimits(spec) {
		g, err := s.recordLimitedSpec(ctx, spec)
		if err != nil {
			for _, k := range stripLimits(spec) {
				r.drop(spec, k, refused(capabilities.FeatureVMLimits, err))
			}
		}
		r.limits = g
	}
	if spec.MemoryHotplugMaxMib != 0 {
		g, err := s.passthroughGrant(ctx)
		if err != nil {
			spec.MemoryHotplugMaxMib, spec.MemoryHotplugBaseMib = 0, 0
			r.drop(spec, "memory hot-add", refused(capabilities.FeatureUSBMountsMemory, err))
		}
		r.passthrough = g
	}
}

// audit records what was dropped. Called only once the promotion can no
// longer be refused, with the VM's actual name. A takeover keeps its row's
// spec, so for it the data is not applied to the defined domain, and stays in
// the row for the next redefine.
func (r promotedRelease) audit(ctx context.Context, s *Server, vm, op string) {
	if len(r.dropped) == 0 {
		return
	}
	what := "not carried: "
	if !r.renamed {
		what = "not applied to the defined domain (kept in the row): "
	}
	s.audit(ctx, "vm.release_features_dropped", vm, op+": "+what+strings.Join(r.dropped, "; "), "degraded")
}
