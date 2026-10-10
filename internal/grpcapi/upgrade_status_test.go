package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc"
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

func (g fakeFeatureGate) FeatureAvailable(capabilities.Feature) bool { return g.err == nil }

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
	for i := 0; i < 3; i++ { // one peer asked per cycle (m2)
		s.evaluateReleaseRollout(ctx)
	}
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

// pingOnlyClient answers Ping with a fixed response: what a peer says of itself.
type pingOnlyClient struct {
	pb.LiteVirtClient
	resp *pb.PingResponse
}

func (f pingOnlyClient) Ping(context.Context, *pb.PingRequest, ...grpc.CallOption) (*pb.PingResponse, error) {
	return f.resp, nil
}

// TestReleasePeerAllowed_SelfFencedOriginKeepsItsLastList (I-R3-2): a
// self-fenced peer advertises nothing, but it is not WAL-quarantined, and its
// pushes still declare this build's release tokens. Its empty Ping is no news:
// it keeps its last list, is never refused for it, raises no alarm, and leaves
// no negative entry behind; one never heard from stays unjudged. A relay stream
// carrying its entries with another origin's flows. A WAL-quarantined peer's
// empty answer is still a refusal.
func TestReleasePeerAllowed_SelfFencedOriginKeepsItsLastList(t *testing.T) {
	ctx := context.Background()
	s := releasePeerServer(t)
	withTok := capabilities.Supported()
	answers := map[string]*pb.PingResponse{
		"fenced":          {Capabilities: []string{}},
		"stranger-fenced": {Capabilities: []string{}},
		"rolled-back":     {Capabilities: []string{}, WalQuarantined: true},
	}
	s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		return pingOnlyClient{resp: answers[host]}, func() {}, nil
	}
	s.notePeerCaps("fenced", withTok)
	s.notePeerCaps("rolled-back", withTok)
	for peer := range answers { // the background refresh, run to completion
		s.refreshPeerCaps(peer)
	}
	if err := s.ReleasePeerAllowed(ctx, "fenced"); err != nil {
		t.Fatalf("a self-fenced origin last known to carry the token: %v", err)
	}
	if err := s.ReleasePeerAllowed(ctx, "stranger-fenced"); err != nil {
		t.Fatalf("a self-fenced origin never heard from: %v", err)
	}
	if err := s.ReleasePeerAllowed(ctx, "rolled-back"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a WAL-quarantined origin advertising nothing: %v, want FailedPrecondition", err)
	}
	if got := s.RefusedReleasePeers(); !slices.Equal(got, []string{"rolled-back"}) {
		t.Fatalf("refused peers = %v, want only rolled-back", got)
	}
	s.releasePeerMu.Lock()
	if e := s.releasePeerLast["fenced"]; e == nil || e.backoff != 0 {
		t.Errorf("the fenced origin's entry = %+v, want its positive list kept with no backoff", e)
	}
	if e := s.releasePeerLast["stranger-fenced"]; e != nil && e.known {
		t.Errorf("a fenced stranger was recorded as known: %+v", e)
	}
	s.releasePeerMu.Unlock()
	entries := append(crlEntry("fenced", "2000000000021-0000-n5"), crlEntry("other", "2000000000022-0000-n6")...)
	if _, err := s.PushMutations(replicationPeerCtx("relay"), &pb.ReplicateRequest{
		Sender: "relay", Entries: entries, SenderCapabilities: withTok,
	}); err != nil || !crlApplied(t, s, "other", "2000000000022-0000-n6") {
		t.Fatalf("a relay stream carrying a self-fenced origin's entries: %v", err)
	}
}

// TestPushMutations_RefusedInReleaseProbation (I-R3-1): a node in release
// probation applies nothing a peer pushes — the data of a first use can reach
// it with its record pruned away — until a voter majority has been asked. The
// refusal is back-pressure: retried, nothing dropped.
func TestPushMutations_RefusedInReleaseProbation(t *testing.T) {
	s := upgradeStatusServer(t)
	s.replicator = corrosion.NewReplicator(s.db, "", corrosion.RelayConfig{})
	s.db.EnterReleaseProbation([]string{"release_2099_01_v1"})
	_, err := s.PushMutations(replicationPeerCtx("peer-a"), &pb.ReplicateRequest{
		Sender: "peer-a", Entries: crlEntry("peer-a", "2000000000031-0000-n1"), SenderCapabilities: capabilities.Supported(),
	})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "probation") ||
		crlApplied(t, s, "peer-a", "2000000000031-0000-n1") {
		t.Fatalf("a push in release probation: %v, want FailedPrecondition naming the probation, nothing applied", err)
	}
}

// TestGetUpgradeStatus_RolloutCountsTheLatchHostSet (m2): the rollout summary
// counts the hosts the release token's latch waits on — every voting-eligible
// host and every admitted member — and no other: a powered-off host parked in
// maintenance is not "not yet", while a member in maintenance that is still
// replicated to is.
func TestGetUpgradeStatus_RolloutCountsTheLatchHostSet(t *testing.T) {
	ctx := context.Background()
	s := rolloutServer(t, false)
	for _, h := range []struct{ name, version string }{{"peer-parked", "1.8.0"}, {"peer-member", "1.9.5"}} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: h.name, Address: "10.0.0.9", State: "maintenance", Role: "worker"}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.UpdateHostVersion(ctx, s.db, h.name, h.version); err != nil {
			t.Fatal(err)
		}
	}
	s.db.SetMembersForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{{Name: "peer-new"}, {Name: "peer-old"}, {Name: "peer-member"}}
	})
	st, err := s.GetUpgradeStatus(viewerCtx(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, l := range st.GetLagging() {
		names = append(names, l.GetName()+" ("+l.GetVersion()+")")
	}
	if st.GetHostsTotal() != 4 || st.GetHostsOnRelease() != 2 ||
		!slices.Equal(names, []string{"peer-member (1.9.5)", "peer-old (1.9.0)"}) {
		t.Fatalf("summary: %d of %d hosts, lagging %v; want 2 of 4, lagging [peer-member (1.9.5) peer-old (1.9.0)]",
			st.GetHostsOnRelease(), st.GetHostsTotal(), names)
	}
}

// countingGate counts the peer answers the rollout asks for.
type countingGate struct {
	fakeServerGate
	calls *atomic.Int32
	per   *sync.Map
	down  map[string]bool
}

func (g countingGate) PeerSupportsFresh(ctx context.Context, peer, token string) bool {
	g.calls.Add(1)
	n, _ := g.per.LoadOrStore(peer, new(atomic.Int32))
	n.(*atomic.Int32).Add(1)
	if g.down[peer] {
		return false
	}
	return g.fakeServerGate.PeerSupportsFresh(ctx, peer, token)
}

func (g countingGate) PeerSupports(ctx context.Context, peer, token string) bool {
	return g.PeerSupportsFresh(ctx, peer, token)
}

// TestReleaseRolloutCondition_AsksOnePeerPerCycle (m2): before the latch, the
// HA monitor keeps the rollout condition from cached answers and asks at most
// one peer per cycle; an unreachable peer is re-asked only after a backoff, so
// it cannot hold every cycle up.
func TestReleaseRolloutCondition_AsksOnePeerPerCycle(t *testing.T) {
	ctx := context.Background()
	s := rolloutServer(t, false)
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "peer-down", Address: "10.0.0.9", State: "active", Role: "worker"}); err != nil {
		t.Fatal(err)
	}
	g := countingGate{fakeServerGate: s.gate.(fakeServerGate), calls: new(atomic.Int32), per: new(sync.Map),
		down: map[string]bool{"peer-down": true}}
	s.gate = g
	const cycles = 6
	for i := 0; i < cycles; i++ {
		before := g.calls.Load()
		s.evaluateReleaseRollout(ctx)
		if n := g.calls.Load() - before; n > 1 {
			t.Fatalf("cycle %d asked %d peers, want at most one", i, n)
		}
	}
	if n, _ := g.per.Load("peer-down"); n != nil && n.(*atomic.Int32).Load() > 1 {
		t.Fatalf("an unreachable peer was asked %d times in %d quick cycles; want once, then a backoff",
			n.(*atomic.Int32).Load(), cycles)
	}
	h, ok, err := corrosion.GetHealthCondition(ctx, s.db, releaseRolloutEvaluator, condReleaseRolloutPending, "cluster", capabilities.ReleaseToken)
	if err != nil || !ok || !slices.Equal(h.Hosts, []string{"peer-down", "peer-old"}) {
		t.Fatalf("condition = %+v ok=%v err=%v, want it naming peer-down and peer-old", h, ok, err)
	}
}

// TestReleaseRolloutCondition_ReopenKeepsFirstSeen (m5): while the token has
// not latched, a condition that resolved and opens again keeps the time the
// rollout was first seen pending, so a flapping row still shows how long the
// roll has taken.
func TestReleaseRolloutCondition_ReopenKeepsFirstSeen(t *testing.T) {
	ctx := context.Background()
	s := rolloutServer(t, false)
	const first = "2026-01-01T00:00:00Z"
	if err := corrosion.UpsertHealthCondition(ctx, s.db, corrosion.HealthCondition{
		Evaluator: releaseRolloutEvaluator, Code: condReleaseRolloutPending, SubjectKind: "cluster",
		SubjectID: capabilities.ReleaseToken, Severity: corrosion.SeverityInfo, Reporter: "test-host",
		Lifecycle: corrosion.ConditionResolved, FirstSeen: first, ConfirmedAt: first, LastSeen: first, ResolvedAt: first,
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		s.evaluateReleaseRollout(ctx)
	}
	h, ok, err := corrosion.GetHealthCondition(ctx, s.db, releaseRolloutEvaluator, condReleaseRolloutPending, "cluster", capabilities.ReleaseToken)
	if err != nil || !ok || h.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("condition = %+v ok=%v err=%v, want it open again", h, ok, err)
	}
	if h.FirstSeen != first {
		t.Fatalf("reopened condition FirstSeen = %q, want %q kept from the resolved row", h.FirstSeen, first)
	}
}

// TestReleaseFeatureAvailable_AsksNoPeer (m7): a caller that falls back rather
// than fails (backup_zstd's default) asks whether a feature can be used without
// a peer being asked: the release token's durable latch, read locally.
func TestReleaseFeatureAvailable_AsksNoPeer(t *testing.T) {
	s := upgradeStatusServer(t)
	if s.ReleaseFeatureAvailable("widgets") {
		t.Fatal("available with no gate wired")
	}
	g := &availGate{latched: false}
	s.SetReleaseFeatureGate(g)
	if s.ReleaseFeatureAvailable("widgets") {
		t.Fatal("available before the latch")
	}
	g.latched = true
	if !s.ReleaseFeatureAvailable("widgets") {
		t.Fatal("not available once latched")
	}
	if g.withFeature != 0 {
		t.Fatalf("the availability read ran the gate %d time(s)", g.withFeature)
	}
}

type availGate struct {
	latched     bool
	withFeature int
}

func (g *availGate) WithFeature(context.Context, capabilities.Feature, func(context.Context, capabilities.FeatureGrant) error) error {
	g.withFeature++
	return nil
}

func (g *availGate) FeatureAvailable(capabilities.Feature) bool { return g.latched }
