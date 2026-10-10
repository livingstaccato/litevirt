package grpcapi

// Release features and `lv cluster upgrade-status` (capabilities.ReleaseToken,
// docs/upgrades.md "Rolling back after a release token latched").

import (
	"context"
	"sort"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// releaseFeatureGate opens a release feature: *health.Checker in production.
type releaseFeatureGate interface {
	RequireFeature(ctx context.Context, feature capabilities.Feature) error
}

// SetReleaseFeatureGate injects the release-feature gate.
func (s *Server) SetReleaseFeatureGate(g releaseFeatureGate) { s.releaseFeatures = g }

// RequireReleaseFeature is the release-feature gate for a handler: call it
// immediately before the write a capabilities.Feature's data needs, and return
// its error unchanged. It refuses with FailedPrecondition until the feature's
// release token has latched, and records the feature's first use, replicated,
// before it returns nil (health.Checker.RequireFeature). With no gate wired it
// refuses everything: fail closed.
func (s *Server) RequireReleaseFeature(ctx context.Context, feature capabilities.Feature) error {
	if s.releaseFeatures == nil {
		return status.Errorf(codes.FailedPrecondition,
			"the cluster upgrade must finish first (%s needs %s): this host has no release-feature gate",
			feature, featureToken(feature))
	}
	return s.releaseFeatures.RequireFeature(ctx, feature)
}

func featureToken(feature capabilities.Feature) string {
	if info, ok := capabilities.LookupFeature(feature); ok {
		return info.Token
	}
	return capabilities.ReleaseToken
}

// GetUpgradeStatus reports, as this host sees them, every capability token
// latched here, whether each would block a rollback, and every release
// feature with its used bit. Viewer.
func (s *Server) GetUpgradeStatus(ctx context.Context, _ *emptypb.Empty) (*pb.UpgradeStatus, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	uses, err := corrosion.ListReleaseFeatureUses(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read release feature uses: %v", err)
	}
	usedBy := map[string]corrosion.ReleaseFeatureUse{}
	usedTokens := map[string]bool{}
	for _, u := range uses {
		usedBy[u.Token+"/"+u.Feature] = u
		usedTokens[u.Token] = true
	}

	out := &pb.UpgradeStatus{ReleaseToken: capabilities.ReleaseToken}
	if s.gate != nil {
		for _, tok := range capabilities.All() {
			if !s.gate.Latched(tok) {
				continue
			}
			rule := capabilities.RollbackRule(tok)
			out.Tokens = append(out.Tokens, &pb.UpgradeToken{
				Name:           tok,
				Durable:        s.gate.DurablyLatched(tok),
				Mandatory:      capabilities.Mandatory(tok),
				RollbackRule:   rule,
				BlocksRollback: rule != capabilities.RollbackSafeIfUnused || usedTokens[tok],
			})
		}
	}
	sort.Slice(out.Tokens, func(i, j int) bool { return out.Tokens[i].GetName() < out.Tokens[j].GetName() })

	seen := map[string]bool{}
	for _, f := range capabilities.Features() {
		info, _ := capabilities.LookupFeature(f)
		key := info.Token + "/" + string(f)
		seen[key] = true
		row := &pb.ReleaseFeatureStatus{Token: info.Token, Name: string(f),
			Description: info.Description, Declared: true}
		if u, ok := usedBy[key]; ok {
			row.Used, row.FirstUsedBy, row.RecordedAt = true, u.FirstUsedBy, u.UpdatedAt
		}
		out.Features = append(out.Features, row)
	}
	// A use under a token or feature this build does not declare: a later
	// release's, which is what would quarantine this build.
	for _, u := range uses {
		if seen[u.Token+"/"+u.Feature] {
			continue
		}
		out.Features = append(out.Features, &pb.ReleaseFeatureStatus{Token: u.Token, Name: u.Feature,
			Used: true, FirstUsedBy: u.FirstUsedBy, RecordedAt: u.UpdatedAt})
	}
	sort.Slice(out.Features, func(i, j int) bool {
		a, b := out.Features[i], out.Features[j]
		if a.GetToken() != b.GetToken() {
			return a.GetToken() < b.GetToken()
		}
		return a.GetName() < b.GetName()
	})

	if s.walQuarantinedNow() {
		out.WalQuarantined = true
		if reason := s.db.QuarantineReason(); reason != "" {
			out.QuarantineReason = reason
		}
	}
	return out, nil
}
