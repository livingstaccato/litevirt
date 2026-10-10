package grpcapi

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func upgradeStatusServer(t *testing.T) *Server {
	t.Helper()
	t.Cleanup(capabilities.OverrideFeaturesForTest(map[capabilities.Feature]capabilities.FeatureInfo{
		"widgets": {Token: capabilities.ReleaseToken, Description: "Widgets on every VM"},
		"gadgets": {Token: capabilities.ReleaseToken, Description: "Gadgets on every host"},
	}))
	s := testServer(t)
	s.gate = fakeServerGate{enforcedTok: map[string]bool{
		capabilities.SplitBrainGateV1: true,
		capabilities.ReleaseToken:     true,
	}}
	s.db.SetClusterPolicyGate(func() bool { return true })
	return s
}

func tokenRow(st *pb.UpgradeStatus, name string) *pb.UpgradeToken {
	for _, tk := range st.GetTokens() {
		if tk.GetName() == name {
			return tk
		}
	}
	return nil
}

func featureRow(st *pb.UpgradeStatus, token, name string) *pb.ReleaseFeatureStatus {
	for _, f := range st.GetFeatures() {
		if f.GetToken() == token && f.GetName() == name {
			return f
		}
	}
	return nil
}

// TestGetUpgradeStatus_NeedsARole: it is a status read, open to a viewer.
func TestGetUpgradeStatus_NeedsARole(t *testing.T) {
	s := upgradeStatusServer(t)
	if _, err := s.GetUpgradeStatus(context.Background(), &emptypb.Empty{}); status.Code(err) == codes.OK {
		t.Fatal("GetUpgradeStatus answered a caller with no role")
	}
	if _, err := s.GetUpgradeStatus(viewerCtx(), &emptypb.Empty{}); err != nil {
		t.Fatalf("GetUpgradeStatus as viewer: %v", err)
	}
}

// TestGetUpgradeStatus_ReleaseTokenBlocksRollbackOnlyOnceUsed: the latched
// tokens, each with whether it blocks a rollback, and the release token's
// features with their used bit.
func TestGetUpgradeStatus_ReleaseTokenBlocksRollbackOnlyOnceUsed(t *testing.T) {
	ctx := context.Background()
	s := upgradeStatusServer(t)
	st, err := s.GetUpgradeStatus(viewerCtx(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetUpgradeStatus: %v", err)
	}
	if st.GetReleaseToken() != capabilities.ReleaseToken {
		t.Errorf("release_token = %q, want %q", st.GetReleaseToken(), capabilities.ReleaseToken)
	}
	sb := tokenRow(st, capabilities.SplitBrainGateV1)
	if sb == nil || !sb.GetBlocksRollback() || sb.GetRollbackRule() != "" || !sb.GetMandatory() {
		t.Errorf("split_brain_gate_v1 row = %+v, want latched, mandatory, no rule, blocking", sb)
	}
	if tokenRow(st, capabilities.OperationProtocolV1) != nil {
		t.Errorf("an unlatched token is listed")
	}
	rel := tokenRow(st, capabilities.ReleaseToken)
	if rel == nil || rel.GetBlocksRollback() || rel.GetRollbackRule() != capabilities.RollbackSafeIfUnused {
		t.Fatalf("release token row with nothing used = %+v, want safe_if_unused and not blocking", rel)
	}
	w := featureRow(st, capabilities.ReleaseToken, "widgets")
	if w == nil || w.GetUsed() || !w.GetDeclared() || w.GetDescription() != "Widgets on every VM" {
		t.Fatalf("widgets row = %+v, want declared and unused", w)
	}

	if err := corrosion.RecordReleaseFeatureUse(ctx, s.db, capabilities.ReleaseToken, "widgets", "host-b"); err != nil {
		t.Fatalf("RecordReleaseFeatureUse: %v", err)
	}
	st, err = s.GetUpgradeStatus(viewerCtx(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetUpgradeStatus: %v", err)
	}
	if rel := tokenRow(st, capabilities.ReleaseToken); rel == nil || !rel.GetBlocksRollback() {
		t.Fatalf("release token row with widgets used = %+v, want blocking", rel)
	}
	if w := featureRow(st, capabilities.ReleaseToken, "widgets"); w == nil || !w.GetUsed() || w.GetFirstUsedBy() != "host-b" {
		t.Fatalf("widgets row after use = %+v, want used by host-b", w)
	}
	if g := featureRow(st, capabilities.ReleaseToken, "gadgets"); g == nil || g.GetUsed() {
		t.Fatalf("gadgets row = %+v, want unused", g)
	}
}

// TestGetUpgradeStatus_ShowsUsesOfUnknownTokens: a use recorded under a token
// this build does not know is what quarantines it, so it is shown.
func TestGetUpgradeStatus_ShowsUsesOfUnknownTokens(t *testing.T) {
	s := upgradeStatusServer(t)
	if err := corrosion.RecordReleaseFeatureUse(context.Background(), s.db, "release_2099_01_v1", "sprockets", "host-c"); err != nil {
		t.Fatalf("RecordReleaseFeatureUse: %v", err)
	}
	st, err := s.GetUpgradeStatus(viewerCtx(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetUpgradeStatus: %v", err)
	}
	f := featureRow(st, "release_2099_01_v1", "sprockets")
	if f == nil || !f.GetUsed() || f.GetDeclared() || f.GetFirstUsedBy() != "host-c" {
		t.Fatalf("unknown-token use row = %+v, want used, undeclared, by host-c", f)
	}
}

type refusingFeatureGate struct{ err error }

func (g refusingFeatureGate) RequireFeature(context.Context, capabilities.Feature) error {
	return g.err
}

// TestRequireReleaseFeature_FailsClosed: with no gate wired every feature is
// refused, and a wired gate's refusal is passed through unchanged.
func TestRequireReleaseFeature_FailsClosed(t *testing.T) {
	s := testServer(t)
	if err := s.RequireReleaseFeature(context.Background(), "widgets"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("RequireReleaseFeature with no gate: %v, want FailedPrecondition", err)
	}
	want := status.Error(codes.FailedPrecondition, "the cluster upgrade must finish first")
	s.SetReleaseFeatureGate(refusingFeatureGate{err: want})
	if err := s.RequireReleaseFeature(context.Background(), "widgets"); !errors.Is(err, want) {
		t.Fatalf("RequireReleaseFeature = %v, want the gate's refusal", err)
	}
	s.SetReleaseFeatureGate(refusingFeatureGate{})
	if err := s.RequireReleaseFeature(context.Background(), "widgets"); err != nil {
		t.Fatalf("RequireReleaseFeature with a passing gate: %v", err)
	}
}
