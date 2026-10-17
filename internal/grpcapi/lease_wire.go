package grpcapi

import (
	"context"
	"fmt"
	"slices"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// leaseWireSupport is a fresh authenticated Ping observation, never a replicated
// capability row or a historical latch. preKind allows only an actual unknown-kind
// Prepare refusal to reach the existing fallback classifier; it permits no payload.
func (s *Server) leaseWireSupport(ctx context.Context, peer string) (preKind bool, err error) {
	caps, _, err := s.PeerCapabilities(ctx, peer)
	if err != nil {
		return false, fmt.Errorf("observe lease wire support of %s: %w", peer, err)
	}
	if slices.Contains(caps, capabilities.LeaseTermClaimV1) {
		return false, nil
	}
	// RecoveryClaimV1 is conditional enforcement, not a build-version marker.
	// A recognized fresh observation permits only a probe; the exact payload-free
	// unknown-kind Prepare response must still prove the historical fallback.
	for _, known := range capabilities.Supported() {
		if slices.Contains(caps, known) {
			return true, nil
		}
	}
	return false, status.Errorf(codes.FailedPrecondition, "%s has no authenticated known lease wire support", peer)
}
func (s *Server) requireLeaseWire(ctx context.Context, peer string) error {
	preKind, err := s.leaseWireSupport(ctx, peer)
	if err != nil {
		return err
	}
	if preKind {
		return status.Errorf(codes.FailedPrecondition, "%s predates lease-term wire support", peer)
	}
	return nil
}
func (s *Server) requireInboundLeaseWire(ctx context.Context) error {
	peer := callerMTLSCommonName(ctx)
	if peer == "" {
		return status.Error(codes.FailedPrecondition, "lease-term state requires a wire-compatible authenticated peer")
	}
	return s.requireLeaseWire(ctx, peer)
}
func leaseBearingValue(v *corrosion.ClaimValue) bool { return v != nil && v.LeaseTerm != nil }
