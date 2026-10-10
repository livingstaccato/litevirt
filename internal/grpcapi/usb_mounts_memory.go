package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// passthroughFeaturesActive is the ONE gate for SETTING a VM's USB devices
// or memory hot-add, or a container's host mounts and devices.
//
// An older peer decodes a spec into a struct without these fields and drops
// them from any spec it rewrites, and an older coordinator would place, fail
// over or recreate the workload without them. So in a mixed-version cluster
// they must not be set. That is a fact about the release, and it is decided
// by the cluster's shared release token (branch feat/release-token), which
// wires passthroughGate. Unwired, the gate FAILS CLOSED: nothing proves every
// host runs this release, so the fields cannot be set. Clearing a field is
// never gated, and a spec without them is unaffected.
func (s *Server) passthroughFeaturesActive(ctx context.Context) bool {
	if s.passthroughGate == nil {
		return false
	}
	return s.passthroughGate(ctx)
}

// SetPassthroughGate wires the release gate for the passthrough features.
func (s *Server) SetPassthroughGate(fn func(ctx context.Context) bool) { s.passthroughGate = fn }

// passthroughRefusalText is the fixed part of the refusal, matched by tests.
const passthroughRefusalText = "the cluster upgrade must finish first"

// passthroughRefusal is the refusal for a request that sets one of the gated
// fields while passthroughFeaturesActive is false.
func passthroughRefusal(what string) error {
	return status.Errorf(codes.FailedPrecondition,
		"%s: %s (until every host runs this release, an older host would drop the setting)", what, passthroughRefusalText)
}
