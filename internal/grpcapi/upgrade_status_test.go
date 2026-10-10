package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
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
	t     testing.TB
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
		grant = capabilities.GrantForTest(g.t, f)
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
	s.SetReleaseFeatureGate(fakeFeatureGate{t: t, grant: true})
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

func crlEntry(origin, hlc string) []*pb.MutationEntry {
	b, _ := json.Marshal([]corrosion.Statement{{
		SQL:    "INSERT OR REPLACE INTO crl_versions (host, version, updated_at)\n\t\t\t\t VALUES (?, ?, ?)",
		Params: []interface{}{origin + "-" + hlc, float64(3), hlc},
	}})
	return []*pb.MutationEntry{{Seq: 1, Hlc: hlc, Origin: origin, Stmts: string(b)}}
}

func crlApplied(t *testing.T, s *Server, origin, hlc string) bool {
	t.Helper()
	rows, _ := s.db.Query(context.Background(), `SELECT 1 AS one FROM crl_versions WHERE host = ?`, origin+"-"+hlc)
	return len(rows) > 0
}

// releasePeerServer has a feature of the release token in use, and a gate
// that has NOT latched the token here (N5: a recorded use proves the latch
// formed somewhere, which is enough) and cannot dial any peer back (N4).
func releasePeerServer(t *testing.T) *Server {
	t.Helper()
	s := upgradeStatusServer(t)
	s.replicator = corrosion.NewReplicator(s.db, "", corrosion.RelayConfig{})
	s.gate = fakeServerGate{}
	if err := corrosion.RecordReleaseFeatureUse(context.Background(), s.db, capabilities.ReleaseToken, "widgets", "test-host", true); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestPushMutations_JudgesTheSenderByItsDeclaration (I6, N4, N5): once a feature
// is used, a sender whose declared capabilities lack the release token is
// back-pressured; one that declares it is accepted though this node cannot dial
// it back (asymmetric links); an older build declares nothing and is refused.
// This node need not have latched the token itself.
func TestPushMutations_JudgesTheSenderByItsDeclaration(t *testing.T) {
	ctx := context.Background()
	s := releasePeerServer(t)
	withTok := capabilities.Supported()
	if _, err := s.PushMutations(replicationPeerCtx("new-peer"), &pb.ReplicateRequest{
		Sender: "new-peer", Entries: crlEntry("new-peer", "2000000000001-0000-n1"), SenderCapabilities: withTok,
	}); err != nil || !crlApplied(t, s, "new-peer", "2000000000001-0000-n1") {
		t.Fatalf("a sender declaring the token, not dialable back: err=%v", err)
	}
	for name, caps := range map[string][]string{
		"declares nothing (an older build)": nil,
		"declares without the token":        {capabilities.SplitBrainGateV1},
	} {
		_, err := s.PushMutations(replicationPeerCtx("old-peer"), &pb.ReplicateRequest{
			Sender: "old-peer", Entries: crlEntry("old-peer", "2000000000002-0000-n2"), SenderCapabilities: caps,
		})
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), capabilities.ReleaseToken) {
			t.Fatalf("%s: %v, want FailedPrecondition naming %s", name, err, capabilities.ReleaseToken)
		}
		if crlApplied(t, s, "old-peer", "2000000000002-0000-n2") {
			t.Fatalf("%s: the refused push was applied", name)
		}
	}
	cur, _ := s.evaluateHADegraded(ctx)
	if !cur[haReleasePeerRefused] {
		t.Fatalf("HA reasons = %v, want %s", cur, haReleasePeerRefused)
	}
	if d := s.releasePeerRefusedDetail(); !strings.Contains(d, "old-peer") || strings.Contains(d, "new-peer") {
		t.Fatalf("detail %q does not name exactly the refused peer", d)
	}
}

// TestPushMutations_NothingUsedAcceptsEveryone: with no release feature in
// use, a sender that declares nothing is accepted, as on main.
func TestPushMutations_NothingUsedAcceptsEveryone(t *testing.T) {
	s := upgradeStatusServer(t)
	s.replicator = corrosion.NewReplicator(s.db, "", corrosion.RelayConfig{})
	if _, err := s.PushMutations(replicationPeerCtx("old-peer"), &pb.ReplicateRequest{
		Sender: "old-peer", Entries: crlEntry("old-peer", "2000000000003-0000-n2"),
	}); err != nil {
		t.Fatalf("PushMutations with nothing used: %v", err)
	}
}

// TestPushMutations_RelayedOriginJudgedByItsLastAnswer (residual a): an origin
// this node cannot reach is judged by the last thing it declared; one never
// heard from is not judged.
func TestPushMutations_RelayedOriginJudgedByItsLastAnswer(t *testing.T) {
	s := releasePeerServer(t)
	withTok := capabilities.Supported()
	// old-peer once pushed directly, declaring no release token, and was refused.
	_, _ = s.PushMutations(replicationPeerCtx("old-peer"), &pb.ReplicateRequest{
		Sender: "old-peer", Entries: crlEntry("old-peer", "2000000000004-0000-n2"), SenderCapabilities: []string{capabilities.SplitBrainGateV1},
	})
	// Its entries relayed by an upgraded peer: refused by origin.
	_, err := s.PushMutations(replicationPeerCtx("relay"), &pb.ReplicateRequest{
		Sender: "relay", Entries: crlEntry("old-peer", "2000000000005-0000-n2"), SenderCapabilities: withTok,
	})
	if status.Code(err) != codes.FailedPrecondition || crlApplied(t, s, "old-peer", "2000000000005-0000-n2") {
		t.Fatalf("relayed entries of an origin last seen without the token: %v", err)
	}
	// An origin never heard from, and unreachable, is not judged.
	if _, err := s.PushMutations(replicationPeerCtx("relay"), &pb.ReplicateRequest{
		Sender: "relay", Entries: crlEntry("stranger", "2000000000006-0000-n3"), SenderCapabilities: withTok,
	}); err != nil {
		t.Fatalf("relayed entries of an unknown, unreachable origin: %v", err)
	}
	// old-peer upgraded: its declaration replaces the old answer.
	if _, err := s.PushMutations(replicationPeerCtx("old-peer"), &pb.ReplicateRequest{
		Sender: "old-peer", Entries: crlEntry("old-peer", "2000000000007-0000-n2"), SenderCapabilities: withTok,
	}); err != nil {
		t.Fatalf("old-peer after upgrading: %v", err)
	}
	if _, err := s.PushMutations(replicationPeerCtx("relay"), &pb.ReplicateRequest{
		Sender: "relay", Entries: crlEntry("old-peer", "2000000000008-0000-n2"), SenderCapabilities: withTok,
	}); err != nil {
		t.Fatalf("relayed entries of old-peer after it upgraded: %v", err)
	}
}

// TestReleasePeerRefusedGrew (N12): a peer newly refused while the reason is
// already raised is news.
func TestReleasePeerRefusedGrew(t *testing.T) {
	if !releasePeerRefusedGrew([]string{"a"}, []string{"a", "b"}) {
		t.Error("a second refused peer is not reported")
	}
	if releasePeerRefusedGrew([]string{"a", "b"}, []string{"a"}) || releasePeerRefusedGrew([]string{"a"}, []string{"a"}) {
		t.Error("no new peer, but reported")
	}
}

// TestPing_ProbationIsNotWALQuarantine (N1): a node in release probation keeps
// advertising, never reports wal_quarantined, and says release_probation.
func TestPing_ProbationIsNotWALQuarantine(t *testing.T) {
	s := testServer(t)
	s.SetWALQuarantined(s.db.WALQuarantined)
	s.db.EnterReleaseProbation([]string{"release_2099_01_v1"})
	resp, err := s.Ping(context.Background(), &pb.PingRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetWalQuarantined() || !resp.GetReleaseProbation() || !slices.Contains(resp.GetCapabilities(), capabilities.ReleaseToken) {
		t.Fatalf("Ping in probation: wal_quarantined=%v release_probation=%v caps=%v, want false/true/advertising",
			resp.GetWalQuarantined(), resp.GetReleaseProbation(), resp.GetCapabilities())
	}
}

// TestPushMutations_OriginJudgedWithoutDialling (I-R2-1): the push path never
// dials. A relayed origin is judged from what it last declared; an origin never
// heard from is not judged now and is refreshed in the background, with at
// most one dial in flight per origin.
func TestPushMutations_OriginJudgedWithoutDialling(t *testing.T) {
	s := releasePeerServer(t)
	var mu sync.Mutex
	dials := map[string]int{}
	release := make(chan struct{})
	s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		mu.Lock()
		dials[host]++
		mu.Unlock()
		<-release
		return nil, nil, errors.New("unreachable")
	}
	withTok := capabilities.Supported()
	// good-peer declared the token in its own push.
	if _, err := s.PushMutations(replicationPeerCtx("good-peer"), &pb.ReplicateRequest{
		Sender: "good-peer", Entries: crlEntry("good-peer", "2000000000010-0000-n1"), SenderCapabilities: withTok,
	}); err != nil {
		t.Fatal(err)
	}
	for i, hlc := range []string{"2000000000011-0000-n4", "2000000000012-0000-n4", "2000000000013-0000-n4"} {
		entries := append(crlEntry("good-peer", hlc), crlEntry("stranger", hlc)...)
		entries[1].Seq = 2
		if _, err := s.PushMutations(replicationPeerCtx("relay"), &pb.ReplicateRequest{
			Sender: "relay", Entries: entries, SenderCapabilities: withTok,
		}); err != nil {
			t.Fatalf("relayed push %d: %v", i, err)
		}
	}
	mu.Lock()
	if dials["good-peer"] != 0 {
		t.Errorf("a recently declared origin was dialled %d time(s) on the push path", dials["good-peer"])
	}
	if dials["stranger"] > 1 {
		t.Errorf("an unknown origin was dialled %d times: more than one in flight", dials["stranger"])
	}
	mu.Unlock()
	close(release)
}

// TestDeclaredCapabilities_SelfFencedStillDeclares (I-R2-2, m-R2-1): a push
// declares this build's release tokens whatever the live advertisement says —
// a self-fenced node's pending writes are not refused for it. A WAL-quarantined
// node declares nothing (and emits nothing).
func TestDeclaredCapabilities_SelfFencedStillDeclares(t *testing.T) {
	s := testServer(t)
	s.SetWatchdogFenced(func() bool { return true })
	if got := s.DeclaredCapabilities(); !slices.Contains(got, capabilities.ReleaseToken) {
		t.Fatalf("a self-fenced node declares %v, want %s", got, capabilities.ReleaseToken)
	}
	s2 := testServer(t)
	s2.SetWALQuarantined(func() bool { return true })
	if got := s2.DeclaredCapabilities(); len(got) != 0 {
		t.Fatalf("a WAL-quarantined node declares %v, want nothing", got)
	}
}

func rolloutServer(t *testing.T, latched bool) *Server {
	t.Helper()
	s := upgradeStatusServer(t)
	ctx := context.Background()
	for _, h := range []struct{ name, version string }{{"test-host", "1.10.0"}, {"peer-new", "1.10.0"}, {"peer-old", "1.9.0"}} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: h.name, Address: "10.0.0.9", State: "active", Role: "worker"}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.UpdateHostVersion(ctx, s.db, h.name, h.version); err != nil {
			t.Fatal(err)
		}
	}
	s.gate = fakeServerGate{
		enforcedTok: map[string]bool{capabilities.SplitBrainGateV1: true, capabilities.ReleaseToken: latched},
		supportsTok: map[string]map[string]bool{
			"peer-new": {capabilities.ReleaseToken: true},
			"peer-old": {capabilities.SplitBrainGateV1: true},
		},
	}
	return s
}

// TestGetUpgradeStatus_RolloutSummaryAndProbation (UX 2, m-R2-3): the status
// opens with how far the rollout is and which features wait on it, and shows a
// release probation.
func TestGetUpgradeStatus_RolloutSummaryAndProbation(t *testing.T) {
	s := rolloutServer(t, false)
	s.db.EnterReleaseProbation([]string{"release_2099_01_v1"})
	st, err := s.GetUpgradeStatus(viewerCtx(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetHostsTotal() != 3 || st.GetHostsOnRelease() != 2 || st.GetFeaturesWaiting() != 2 {
		t.Fatalf("summary: %d of %d hosts, %d features waiting; want 2 of 3, 2 waiting",
			st.GetHostsOnRelease(), st.GetHostsTotal(), st.GetFeaturesWaiting())
	}
	if len(st.GetLagging()) != 1 || st.GetLagging()[0].GetName() != "peer-old" || st.GetLagging()[0].GetVersion() != "1.9.0" {
		t.Fatalf("lagging = %v, want peer-old (1.9.0)", st.GetLagging())
	}
	if !st.GetReleaseProbation() || !strings.Contains(st.GetProbationReason(), "release probation") {
		t.Fatalf("probation not shown: %v %q", st.GetReleaseProbation(), st.GetProbationReason())
	}
	st, _ = rolloutServer(t, true).GetUpgradeStatus(viewerCtx(), &emptypb.Empty{})
	if st.GetFeaturesWaiting() != 0 {
		t.Fatalf("features waiting with the token latched = %d, want 0", st.GetFeaturesWaiting())
	}
}

// TestReleaseRolloutCondition (UX 3): an informational health condition stands
// while hosts lag the release, names them, and resolves once the token latches.
func TestReleaseRolloutCondition(t *testing.T) {
	ctx := context.Background()
	s := rolloutServer(t, false)
	s.evaluateReleaseRollout(ctx)
	h, ok, err := corrosion.GetHealthCondition(ctx, s.db, releaseRolloutEvaluator, condReleaseRolloutPending, "cluster", capabilities.ReleaseToken)
	if err != nil || !ok || h.Lifecycle == corrosion.ConditionResolved || h.Severity != corrosion.SeverityInfo ||
		!slices.Contains(h.Hosts, "peer-old") {
		t.Fatalf("condition while peer-old lags = %+v ok=%v err=%v, want an open info condition naming peer-old", h, ok, err)
	}
	s.gate = fakeServerGate{enforcedTok: map[string]bool{capabilities.ReleaseToken: true}}
	s.evaluateReleaseRollout(ctx)
	h, _, _ = corrosion.GetHealthCondition(ctx, s.db, releaseRolloutEvaluator, condReleaseRolloutPending, "cluster", capabilities.ReleaseToken)
	if h.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("condition after the latch = %+v, want resolved", h)
	}
}
