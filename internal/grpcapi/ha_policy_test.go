package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// haClock is the handler's fake clock: every sleep advances it and then runs
// onSleep, which is how a test plays the peers' answers arriving.
type haClock struct {
	now     time.Time
	slept   time.Duration
	onSleep func()
}

func useHAClock(t *testing.T) *haClock {
	t.Helper()
	c := &haClock{now: time.Unix(1_900_000_000, 0)}
	oldNow, oldSleep := haNow, haSleep
	haNow = func() time.Time { return c.now }
	haSleep = func(ctx context.Context, d time.Duration) error {
		c.now = c.now.Add(d)
		c.slept += d
		if c.onSleep != nil {
			c.onSleep()
		}
		return ctx.Err()
	}
	t.Cleanup(func() { haNow, haSleep = oldNow, oldSleep })
	return c
}

// haServer is scopeServer (test-host, e2, e3 in east; w1, w2 in west; five
// voters) with the latches, a quorum, a release gate and an empty
// fence-candidate list.
func haServer(t *testing.T) *Server {
	t.Helper()
	s := scopeServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	s.SetReleaseFeatureGate(fakeFeatureGate{t: t, grant: true})
	g := latchedGate(allPeers)
	g.quorum, g.live, g.needed = health.QuorumYes, 5, 3
	s.SetGate(g)
	s.SetFenceCandidates(func(context.Context) ([]string, error) { return nil, nil })
	if err := s.RefreshHAPolicyCache(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

// answer records host's Ready answer carrying the row the replica holds now.
func answer(t *testing.T, s *Server, clk *haClock, hosts ...string) {
	t.Helper()
	p, err := corrosion.GetHAPolicy(context.Background(), s.db)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hosts {
		s.peerHA.record(h, peerHAAnswer{asked: clk.now, known: true, disarmed: p.Disarmed(), policyAt: p.UpdatedAt})
	}
}

func setHAReq(state string) *pb.SetHAPolicyRequest {
	return &pb.SetHAPolicyRequest{State: state, Reason: "core switch, CHG-1234"}
}

func TestHAPolicyRPC_Roles(t *testing.T) {
	s := haServer(t)
	if _, err := s.GetHAPolicy(viewerCtx(), &emptypb.Empty{}); err != nil {
		t.Fatalf("viewer get: %v", err)
	}
	if _, err := s.SetHAPolicy(viewerCtx(), setHAReq(corrosion.HADisarmed)); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("viewer set: %v, want PermissionDenied", err)
	}
	if _, err := s.SetHAPolicy(operatorCtx(), setHAReq(corrosion.HADisarmed)); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator set: %v, want PermissionDenied", err)
	}
}

// The release gate's refusal comes first, before any other precondition.
func TestHAPolicyRPC_FeatureRefusalFirst(t *testing.T) {
	s := haServer(t)
	s.SetGate(nil)
	refusal := status.Error(codes.FailedPrecondition, "the cluster upgrade must finish first (ha_disarm needs "+capabilities.ReleaseToken+")")
	s.SetReleaseFeatureGate(fakeFeatureGate{err: refusal})
	if _, err := s.SetHAPolicy(adminCtx(), setHAReq(corrosion.HADisarmed)); err == nil || err.Error() != refusal.Error() {
		t.Fatalf("SetHAPolicy before the release latched: %v, want %v", err, refusal)
	}
}

// Both directions need this node to hold the voter majority.
func TestHAPolicyRPC_BothDirectionsNeedTheMajority(t *testing.T) {
	for _, st := range []string{corrosion.HADisarmed, corrosion.HAArmed} {
		s := haServer(t)
		g := latchedGate(allPeers)
		g.quorum, g.live, g.needed = health.QuorumNo, 2, 3
		s.SetGate(g)
		if _, err := s.SetHAPolicy(adminCtx(), setHAReq(st)); status.Code(err) != codes.FailedPrecondition ||
			!strings.Contains(err.Error(), "majority") {
			t.Fatalf("%s without the majority: %v", st, err)
		}
		if p, _ := corrosion.GetHAPolicy(context.Background(), s.db); p.UpdatedAt != "" {
			t.Fatalf("%s without the majority wrote %+v", st, p)
		}
	}
}

// Arm refuses while a host that is not in maintenance would be fenced,
// listing it and naming lv host rm --dead, unless fence_down_hosts is set. An
// unreachable voter that is not a fence candidate does not block it.
func TestHAPolicyRPC_ArmGate(t *testing.T) {
	ctx := context.Background()
	s := haServer(t)
	clk := useHAClock(t)
	clk.onSleep = func() { answer(t, s, clk, "e2", "e3") }
	if err := corrosion.UpdateHostState(ctx, s.db, "w2", "maintenance"); err != nil {
		t.Fatal(err)
	}
	// w1 unreachable but not down long enough to be a candidate; w2 is a
	// candidate in maintenance: neither blocks.
	g := latchedGate([]string{"e2", "e3"})
	g.quorum, g.live, g.needed = health.QuorumYes, 3, 3
	s.SetGate(g)
	s.SetFenceCandidates(func(context.Context) ([]string, error) { return []string{"w2"}, nil })
	if _, err := s.SetHAPolicy(adminCtx(), setHAReq(corrosion.HAArmed)); err != nil {
		t.Fatalf("arm with only a maintenance candidate: %v", err)
	}

	s.SetFenceCandidates(func(context.Context) ([]string, error) { return []string{"w1", "w2"}, nil })
	_, err := s.SetHAPolicy(adminCtx(), setHAReq(corrosion.HAArmed))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "w1") || strings.Contains(err.Error(), "w2") ||
		!strings.Contains(err.Error(), "lv host rm --dead") || !strings.Contains(err.Error(), "--fence-down-hosts") {
		t.Fatalf("arm with a down host: %v", err)
	}
	req := setHAReq(corrosion.HAArmed)
	req.FenceDownHosts = true
	if _, err := s.SetHAPolicy(adminCtx(), req); err != nil {
		t.Fatalf("arm --fence-down-hosts: %v", err)
	}
	// A candidate list that cannot be read is no list at all.
	s.SetFenceCandidates(func(context.Context) ([]string, error) { return nil, errors.New("store down") })
	if _, err := s.SetHAPolicy(adminCtx(), setHAReq(corrosion.HAArmed)); status.Code(err) != codes.Unavailable {
		t.Fatalf("arm with an unreadable candidate list: %v", err)
	}
}

// Cluster scope: a majority must answer with the written state AND
// timestamp, and the handler then waits W_L2 before it returns.
//
// Mutations: match on the timestamp only — the wrong-state answers confirm and
// the first call returns OK; drop the W_L2 wait — the wait check goes red.
func TestHAPolicyRPC_ConfirmsOnStateAndTimestampThenWaits(t *testing.T) {
	ctx := context.Background()
	s := haServer(t)
	clk := useHAClock(t)
	// e2 and e3 answer the right timestamp with the WRONG state: no majority.
	clk.onSleep = func() {
		p, _ := corrosion.GetHAPolicy(ctx, s.db)
		for _, h := range []string{"e2", "e3"} {
			s.peerHA.record(h, peerHAAnswer{asked: clk.now, known: true, disarmed: false, policyAt: p.UpdatedAt})
		}
	}
	_, err := s.SetHAPolicy(adminCtx(), setHAReq(corrosion.HADisarmed))
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "may still take effect") ||
		!strings.Contains(err.Error(), "e2") || !strings.Contains(err.Error(), "w1") {
		t.Fatalf("answers with the wrong state: %v, want Unavailable naming the unconfirmed", err)
	}
	if p, _ := corrosion.GetHAPolicy(ctx, s.db); p.State != corrosion.HADisarmed {
		t.Fatalf("the row did not stay after a timeout: %+v", p)
	}

	s2 := haServer(t)
	clk2 := useHAClock(t)
	var confirmedAt time.Time
	clk2.onSleep = func() {
		answer(t, s2, clk2, "e2", "e3")
		if confirmedAt.IsZero() {
			confirmedAt = clk2.now
		}
	}
	st, err := s2.SetHAPolicy(adminCtx(), setHAReq(corrosion.HADisarmed))
	if err != nil || !strings.HasPrefix(st.GetState(), corrosion.HADisarmed) {
		t.Fatalf("confirmed disarm: %+v %v", st, err)
	}
	if waited := clk2.now.Sub(confirmedAt); waited < health.PeerAnswerWindow {
		t.Fatalf("returned %s after the confirmation, want at least W_L2 (%s)", waited, health.PeerAnswerWindow)
	}
	rows, _ := s2.db.Query(ctx, `SELECT action FROM audit_log WHERE action = 'cluster.ha'`)
	if len(rows) != 1 {
		t.Fatalf("audit rows for cluster.ha: %d, want 1", len(rows))
	}
}

// Region scope: a majority of EVERY region holding a voter, a one-voter
// region included, and a timeout names the region.
//
// Mutation: exempt regions with fewer than three voters — south never
// confirms and the call succeeds; this goes red.
func TestHAPolicyRPC_RegionScopeNeedsEveryRegion(t *testing.T) {
	ctx := context.Background()
	s := haServer(t)
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "s1", Address: "10.0.0.9", SSHUser: "root",
		State: "active", CertSerial: "s-s1"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostRegion(ctx, s.db, "s1", "south"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.SetFailoverScope(ctx, s.db, corrosion.FailoverScopeRegion, "test"); err != nil {
		t.Fatal(err)
	}
	g := latchedGate(append(allPeers, "s1"))
	g.quorum, g.live, g.needed = health.QuorumYes, 6, 4
	s.SetGate(g)
	clk := useHAClock(t)
	clk.onSleep = func() { answer(t, s, clk, "e2", "w1", "w2") }
	_, err := s.SetHAPolicy(adminCtx(), setHAReq(corrosion.HADisarmed))
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "south") {
		t.Fatalf("south unconfirmed: %v, want Unavailable naming south", err)
	}
	st, err := s.GetHAPolicy(adminCtx(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range st.GetRegions() {
		got[r.GetRegion()] = r.GetConfirmed()
	}
	if !got["east"] || !got["west"] || got["south"] || len(got) != 3 {
		t.Fatalf("region confirmation %v", got)
	}

	clk.onSleep = func() { answer(t, s, clk, "e2", "w1", "w2", "s1") }
	if _, err := s.SetHAPolicy(adminCtx(), setHAReq(corrosion.HADisarmed)); err != nil {
		t.Fatalf("every region confirmed: %v", err)
	}
}

// A newer row in a voter's answer aborts the handler, during the
// confirmation and during the W_L2 wait.
func TestHAPolicyRPC_SupersededAborts(t *testing.T) {
	for _, during := range []string{"confirmation", "wait"} {
		s := haServer(t)
		clk := useHAClock(t)
		calls := 0
		clk.onSleep = func() {
			calls++
			p, _ := corrosion.GetHAPolicy(context.Background(), s.db)
			inst, _ := corrosion.ParseUpdatedAt(p.UpdatedAt)
			newer := inst.Add(time.Second).UTC().Format(time.RFC3339Nano)
			if during == "confirmation" {
				s.peerHA.record("e2", peerHAAnswer{asked: clk.now, known: true, disarmed: false, policyAt: newer})
				return
			}
			answer(t, s, clk, "e2", "e3")
			if calls == 3 {
				s.peerHA.record("w1", peerHAAnswer{asked: clk.now, known: true, disarmed: false, policyAt: newer})
			}
		}
		_, err := s.SetHAPolicy(adminCtx(), setHAReq(corrosion.HADisarmed))
		if status.Code(err) != codes.Aborted || !strings.Contains(err.Error(), "superseded") || !strings.Contains(err.Error(), "armed") {
			t.Fatalf("superseded during the %s: %v, want Aborted", during, err)
		}
	}
}

// The written updated_at is newer than this node's own row and than every
// recorded peer answer, one stamped ahead of this node's clock included; a
// peer answer stamped implausibly far ahead is refused, naming the host.
func TestHAPolicyRPC_StampsAfterEverythingSeen(t *testing.T) {
	ctx := context.Background()
	s := haServer(t)
	clk := useHAClock(t)
	clk.onSleep = func() { answer(t, s, clk, "e2", "e3") }
	ahead := time.Now().Add(3 * time.Second).UTC().Format(time.RFC3339Nano)
	s.peerHA.record("w2", peerHAAnswer{asked: clk.now, known: true, disarmed: true, policyAt: ahead})
	if _, err := s.SetHAPolicy(adminCtx(), setHAReq(corrosion.HAArmed)); err != nil {
		t.Fatalf("arm after a peer answer ahead of this clock: %v", err)
	}
	p, _ := corrosion.GetHAPolicy(ctx, s.db)
	if !corrosion.LWWNewer(p.UpdatedAt, ahead) {
		t.Fatalf("stamped %s, not newer than the peer's %s", p.UpdatedAt, ahead)
	}

	skewed := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	s.peerHA.record("w1", peerHAAnswer{asked: clk.now, known: true, policyAt: skewed})
	_, err := s.SetHAPolicy(adminCtx(), setHAReq(corrosion.HADisarmed))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "w1") || !strings.Contains(err.Error(), skewed) {
		t.Fatalf("after a future-skewed peer row: %v, want FailedPrecondition naming w1", err)
	}
}

// The status speaks the peer veto's vocabulary, says whether the first use is
// paid, and lists the hosts an arm would fence.
func TestHAPolicyRPC_Status(t *testing.T) {
	ctx := context.Background()
	s := haServer(t)
	clk := useHAClock(t)
	clk.onSleep = func() { answer(t, s, clk, "e2", "e3") }
	if _, err := s.SetHAPolicy(adminCtx(), setHAReq(corrosion.HADisarmed)); err != nil {
		t.Fatal(err)
	}
	p, _ := corrosion.GetHAPolicy(ctx, s.db)
	delete(s.peerHA.m, "e3") // its last answer is an old one
	s.peerHA.record("e3", peerHAAnswer{asked: clk.now.Add(-health.PeerAnswerWindow - time.Second), known: true, disarmed: true, policyAt: p.UpdatedAt})
	s.peerHA.record("w1", peerHAAnswer{asked: clk.now, known: false})
	s.peerHA.record("w2", peerHAAnswer{asked: clk.now, known: true, policyAt: "2001-01-01T00:00:00Z"})
	g := latchedGate([]string{"e2", "e3", "w1", "w2"})
	g.quorum = health.QuorumYes
	s.SetGate(g)
	s.SetFenceCandidates(func(context.Context) ([]string, error) { return []string{"w9"}, nil })
	st, err := s.GetHAPolicy(viewerCtx(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, v := range st.GetVoters() {
		got[v.GetHost()] = v.GetStatus()
	}
	want := map[string]string{"test-host": haStatusConfirmed, "e2": haStatusConfirmed, "e3": haStatusStale,
		"w1": haStatusUnknown, "w2": haStatusOlder}
	for h, w := range want {
		if got[h] != w {
			t.Errorf("voter %s status %q, want %q", h, got[h], w)
		}
	}
	if st.GetSetBy() == "" || st.GetReason() != "core switch, CHG-1234" || len(st.GetWouldBeFenced()) != 1 || st.GetFirstUsePaid() {
		t.Fatalf("status %+v", st)
	}
	s.SetGate(latchedGate([]string{"e2"}))
	st, _ = s.GetHAPolicy(viewerCtx(), &emptypb.Empty{})
	for _, v := range st.GetVoters() {
		if v.GetHost() == "w1" && v.GetStatus() != haStatusNotLive {
			t.Fatalf("w1 not probed healthy: %q, want %q", v.GetStatus(), haStatusNotLive)
		}
	}
}
