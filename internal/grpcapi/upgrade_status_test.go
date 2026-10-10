package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
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

// TestGetUpgradeStatus_ReleaseTokenBlocksRollback (I4): every build below the
// first release token predates rollback rules, so a rollback below it
// quarantines whether or not anything was used. BLOCKS ROLLBACK says so; the
// rule-aware column says what a rule-aware target would do.
func TestGetUpgradeStatus_ReleaseTokenBlocksRollback(t *testing.T) {
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
	if sb == nil || !sb.GetBlocksRollback() || !sb.GetBlocksRollbackRuleAware() || sb.GetRollbackRule() != "" || !sb.GetMandatory() {
		t.Errorf("split_brain_gate_v1 row = %+v, want latched, mandatory, no rule, blocking everywhere", sb)
	}
	if tokenRow(st, capabilities.OperationProtocolV1) != nil {
		t.Errorf("an unlatched token is listed")
	}
	rel := tokenRow(st, capabilities.ReleaseToken)
	if rel == nil || !rel.GetBlocksRollback() || rel.GetBlocksRollbackRuleAware() ||
		rel.GetRollbackRule() != capabilities.RollbackSafeIfUnused {
		t.Fatalf("release token row with nothing used = %+v, want blocking (the build below reads no rule), "+
			"not blocking on a rule-aware build, rule safe_if_unused", rel)
	}
	w := featureRow(st, capabilities.ReleaseToken, "widgets")
	if w == nil || w.GetUsed() || !w.GetDeclared() || w.GetDescription() != "Widgets on every VM" {
		t.Fatalf("widgets row = %+v, want declared and unused", w)
	}

	if err := corrosion.RecordReleaseFeatureUse(ctx, s.db, capabilities.ReleaseToken, "widgets", "host-b", false); err != nil {
		t.Fatalf("RecordReleaseFeatureUse: %v", err)
	}
	st, err = s.GetUpgradeStatus(viewerCtx(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetUpgradeStatus: %v", err)
	}
	if rel := tokenRow(st, capabilities.ReleaseToken); rel == nil || !rel.GetBlocksRollback() || !rel.GetBlocksRollbackRuleAware() {
		t.Fatalf("release token row with widgets used = %+v, want blocking everywhere", rel)
	}
	if w := featureRow(st, capabilities.ReleaseToken, "widgets"); w == nil || !w.GetUsed() || w.GetRecordedBy() != "host-b" {
		t.Fatalf("widgets row after use = %+v, want used, recorded by host-b", w)
	}
	if g := featureRow(st, capabilities.ReleaseToken, "gadgets"); g == nil || g.GetUsed() {
		t.Fatalf("gadgets row = %+v, want unused", g)
	}
}

// TestGetUpgradeStatus_ShowsUsesOfUnknownTokens: a use recorded under a token
// this build does not know is what quarantines it, so it is shown.
func TestGetUpgradeStatus_ShowsUsesOfUnknownTokens(t *testing.T) {
	s := upgradeStatusServer(t)
	if err := corrosion.RecordReleaseFeatureUse(context.Background(), s.db, "release_2099_01_v1", "sprockets", "host-c", false); err != nil {
		t.Fatalf("RecordReleaseFeatureUse: %v", err)
	}
	st, err := s.GetUpgradeStatus(viewerCtx(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetUpgradeStatus: %v", err)
	}
	f := featureRow(st, "release_2099_01_v1", "sprockets")
	if f == nil || !f.GetUsed() || f.GetDeclared() || f.GetRecordedBy() != "host-c" {
		t.Fatalf("unknown-token use row = %+v, want used, undeclared, by host-c", f)
	}
}

type fakeFeatureGate struct {
	err   error
	grant bool
}

func (g fakeFeatureGate) WithFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	if g.err != nil {
		return g.err
	}
	var grant capabilities.FeatureGrant
	if g.grant {
		grant = capabilities.MintFeatureGrant(f)
	}
	return write(ctx, grant)
}

// TestWithReleaseFeature_FailsClosed: with no gate wired every feature is
// refused and the write never runs; a wired gate's refusal passes through; a
// passing gate runs the write with its grant.
func TestWithReleaseFeature_FailsClosed(t *testing.T) {
	s := testServer(t)
	ran := false
	write := func(_ context.Context, g capabilities.FeatureGrant) error {
		ran = true
		return g.Check("widgets")
	}
	if err := s.WithReleaseFeature(context.Background(), "widgets", write); status.Code(err) != codes.FailedPrecondition || ran {
		t.Fatalf("WithReleaseFeature with no gate: ran=%v err=%v, want FailedPrecondition", ran, err)
	}
	want := status.Error(codes.FailedPrecondition, "the cluster upgrade must finish first")
	s.SetReleaseFeatureGate(fakeFeatureGate{err: want})
	if err := s.WithReleaseFeature(context.Background(), "widgets", write); !errors.Is(err, want) || ran {
		t.Fatalf("WithReleaseFeature = %v ran=%v, want the gate's refusal", err, ran)
	}
	s.SetReleaseFeatureGate(fakeFeatureGate{grant: true})
	if err := s.WithReleaseFeature(context.Background(), "widgets", write); err != nil || !ran {
		t.Fatalf("WithReleaseFeature with a passing gate: ran=%v err=%v", ran, err)
	}
}

// TestHoldsReleaseFeatureUse: the acknowledgement RPC a first use waits on.
// Peer-only; answers whether this replica holds the record.
func TestHoldsReleaseFeatureUse(t *testing.T) {
	s := upgradeStatusServer(t)
	q := &pb.ReleaseFeatureUseQuery{Token: capabilities.ReleaseToken, Feature: "widgets"}
	if _, err := s.HoldsReleaseFeatureUse(adminCtx(), q); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("HoldsReleaseFeatureUse from a non-peer: %v, want PermissionDenied", err)
	}
	peer := peerCtxFor(t, s, "host-b")
	if r, err := s.HoldsReleaseFeatureUse(peer, q); err != nil || r.GetHeld() {
		t.Fatalf("before the record: held=%v err=%v", r.GetHeld(), err)
	}
	if err := corrosion.RecordReleaseFeatureUse(context.Background(), s.db, capabilities.ReleaseToken, "widgets", "host-a", false); err != nil {
		t.Fatal(err)
	}
	if r, err := s.HoldsReleaseFeatureUse(peer, q); err != nil || !r.GetHeld() {
		t.Fatalf("after the record: held=%v err=%v", r.GetHeld(), err)
	}
}

// TestPushMutations_RefusesAPeerThatCannotKeepAUsedFeature (I6): once a
// feature of a latched release token is in use, a peer that does not advertise
// the token — rolled back, or back from a long absence on an older build — has
// its replication back-pressured, not applied, and the refusal is an HA
// condition naming it.
func TestPushMutations_RefusesAPeerThatCannotKeepAUsedFeature(t *testing.T) {
	ctx := context.Background()
	s := upgradeStatusServer(t)
	s.replicator = corrosion.NewReplicator(s.db, "", corrosion.RelayConfig{})
	s.gate = fakeServerGate{
		enforcedTok: map[string]bool{capabilities.ReleaseToken: true},
		supportsTok: map[string]map[string]bool{
			"old-peer": {capabilities.SplitBrainGateV1: true},
			"new-peer": {capabilities.ReleaseToken: true},
		},
	}
	const hlc = "2000000000002-0000-n9"
	entry := func(host string) []*pb.MutationEntry {
		b, _ := json.Marshal([]corrosion.Statement{{
			SQL:    "INSERT OR REPLACE INTO crl_versions (host, version, updated_at)\n\t\t\t\t VALUES (?, ?, ?)",
			Params: []interface{}{host, float64(3), hlc},
		}})
		return []*pb.MutationEntry{{Seq: 1, Hlc: hlc, Origin: host, Stmts: string(b)}}
	}
	// Nothing used yet: the old peer is accepted, as on main.
	if _, err := s.PushMutations(replicationPeerCtx("old-peer"), &pb.ReplicateRequest{Sender: "old-peer", Entries: entry("old-peer")}); err != nil {
		t.Fatalf("PushMutations from an old peer with nothing used: %v", err)
	}
	if err := corrosion.RecordReleaseFeatureUse(ctx, s.db, capabilities.ReleaseToken, "widgets", "test-host", true); err != nil {
		t.Fatal(err)
	}
	s.resetReleasePeerCache()
	_, err := s.PushMutations(replicationPeerCtx("old-peer"), &pb.ReplicateRequest{Sender: "old-peer", Entries: entry("old-peer-2")})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), capabilities.ReleaseToken) {
		t.Fatalf("PushMutations from an old peer after a use: %v, want FailedPrecondition naming %s", err, capabilities.ReleaseToken)
	}
	if rows, _ := s.db.Query(ctx, `SELECT 1 AS one FROM crl_versions WHERE host = 'old-peer-2'`); len(rows) != 0 {
		t.Fatal("the refused push was applied")
	}
	if _, err := s.PushMutations(replicationPeerCtx("new-peer"), &pb.ReplicateRequest{Sender: "new-peer", Entries: entry("new-peer")}); err != nil {
		t.Fatalf("PushMutations from an upgraded peer: %v", err)
	}
	cur, _ := s.evaluateHADegraded(ctx)
	if !cur[haReleasePeerRefused] {
		t.Fatalf("HA reasons = %v, want %s", cur, haReleasePeerRefused)
	}
	if d := s.releasePeerRefusedDetail(); !strings.Contains(d, "old-peer") {
		t.Fatalf("detail %q does not name the refused peer", d)
	}
}
