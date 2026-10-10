package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func relayRestoreServer(t *testing.T, latched bool) *Server {
	t.Helper()
	s := testServer(t)
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
		Name: "n1", Address: "10.0.0.1", SSHUser: "root", State: "active", CertSerial: "s-n1",
	}); err != nil {
		t.Fatal(err)
	}
	if latched {
		s.db.SetClusterPolicyGate(func() bool { return true })
		s.db.SetRelayHealthGate(func() bool { return true })
	}
	return s
}

// The stand-down for relay_health_v1 (colonelpanik/litevirt#175): an admin
// clears a demotion at once, replicated through the demotion row, audited, and
// with a hold the lease holder may not demote the host again until it runs
// out.
//
// Mutation: drop the hold from the written row — the hold is missing, red.
func TestRestoreRelay_ClearsTheDemotionAndHolds(t *testing.T) {
	s := relayRestoreServer(t, true)
	ctx := context.Background()
	if err := corrosion.SetRelayDemotion(ctx, s.db, "n1",
		corrosion.RelayDemotion{Demoted: true, Since: "2026-10-10T00:00:00Z", Reason: "probes"}, "lease"); err != nil {
		t.Fatal(err)
	}
	resp, err := s.RestoreRelay(adminCtx(), &pb.RestoreRelayRequest{Host: "n1", HoldSeconds: 3600})
	if err != nil {
		t.Fatalf("RestoreRelay: %v", err)
	}
	if !resp.GetWasDemoted() || resp.GetHoldUntil() == "" {
		t.Fatalf("response = %+v, want was_demoted and a hold", resp)
	}
	if !corrosion.RelayEligibleHosts(ctx, s.db)["n1"] {
		t.Fatal("n1 still ineligible after the restore")
	}
	holds, err := corrosion.ListRelayHolds(ctx, s.db)
	if err != nil {
		t.Fatal(err)
	}
	if h := holds["n1"]; !h.Active(time.Now()) || h.Active(time.Now().Add(2*time.Hour)) || h.By != "admin" {
		t.Fatalf("hold = %+v, want held by admin for about an hour", h)
	}
	got := lastAuditRow(t, s, "cluster.relay_restore")
	if !got.found || got.user != "admin" || got.target != "n1" || !strings.Contains(got.detail, "was demoted: true") {
		t.Fatalf("audit row = %+v", got)
	}
}

// Admin only: a demotion is a cluster-wide topology decision.
//
// Mutation: drop the role check — the operator's call succeeds, red.
func TestRestoreRelay_AdminOnly(t *testing.T) {
	s := relayRestoreServer(t, true)
	for _, ctx := range []context.Context{viewerCtx(), operatorCtx()} {
		if _, err := s.RestoreRelay(ctx, &pb.RestoreRelayRequest{Host: "n1"}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("RestoreRelay as non-admin: %v, want PermissionDenied", err)
		}
	}
}

// Before relay_health_v1 latches nothing is ever demoted, and nothing may be
// written: a previous-release peer ignores the key.
func TestRestoreRelay_RefusedBeforeTheLatch(t *testing.T) {
	s := relayRestoreServer(t, false)
	if _, err := s.RestoreRelay(adminCtx(), &pb.RestoreRelayRequest{Host: "n1"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("RestoreRelay before the latch: %v, want FailedPrecondition", err)
	}
}

// An unknown host with no row is a typo, not a restore; a bad hold is refused.
func TestRestoreRelay_ValidatesItsArguments(t *testing.T) {
	s := relayRestoreServer(t, true)
	for _, tc := range []struct {
		req  *pb.RestoreRelayRequest
		code codes.Code
	}{
		{&pb.RestoreRelayRequest{Host: ""}, codes.InvalidArgument},
		{&pb.RestoreRelayRequest{Host: "nope"}, codes.NotFound},
		{&pb.RestoreRelayRequest{Host: "n1", HoldSeconds: -1}, codes.InvalidArgument},
		{&pb.RestoreRelayRequest{Host: "n1", HoldSeconds: int64(maxRelayHold/time.Second) + 1}, codes.InvalidArgument},
	} {
		if _, err := s.RestoreRelay(adminCtx(), tc.req); status.Code(err) != tc.code {
			t.Errorf("RestoreRelay(%+v) = %v, want %s", tc.req, err, tc.code)
		}
	}
}

// A restore without a hold ends an earlier hold: the operator's latest word
// stands.
//
// Mutation: leave an earlier hold alone on a zero hold — it stays in force,
// red.
func TestRestoreRelay_ZeroHoldEndsAnEarlierHold(t *testing.T) {
	s := relayRestoreServer(t, true)
	ctx := context.Background()
	if _, err := s.RestoreRelay(adminCtx(), &pb.RestoreRelayRequest{Host: "n1", HoldSeconds: 3600}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RestoreRelay(adminCtx(), &pb.RestoreRelayRequest{Host: "n1"}); err != nil {
		t.Fatal(err)
	}
	holds, _ := corrosion.ListRelayHolds(ctx, s.db)
	if holds["n1"].Active(time.Now().Add(time.Second)) {
		t.Fatalf("hold %+v still in force after a restore without one", holds["n1"])
	}
}

// GetRelayHealth makes demotions and holds visible to any viewer: which host
// is demoted, since when and why, and which is held until when, by whom.
//
// Mutation: leave holds out of the listing — the held host is missing, red.
func TestGetRelayHealth_ListsDemotionsAndHolds(t *testing.T) {
	s := relayRestoreServer(t, true)
	ctx := context.Background()
	if err := corrosion.SetRelayDemotion(ctx, s.db, "n2",
		corrosion.RelayDemotion{Demoted: true, Since: "2026-10-10T00:00:00Z", Reason: "2 of 4 voter observers"}, "lease"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RestoreRelay(adminCtx(), &pb.RestoreRelayRequest{Host: "n1", HoldSeconds: 600}); err != nil {
		t.Fatal(err)
	}
	st, err := s.GetRelayHealth(viewerCtx(), nil)
	if err != nil {
		t.Fatalf("GetRelayHealth as viewer: %v", err)
	}
	if !st.GetLatched() || len(st.GetHosts()) != 2 {
		t.Fatalf("status = %+v, want latched with n1 and n2", st)
	}
	n1, n2 := st.GetHosts()[0], st.GetHosts()[1]
	if n1.GetHost() != "n1" || n1.GetDemoted() || n1.GetHoldUntil() == "" || n1.GetHoldBy() != "an operator" {
		t.Errorf("n1 = %+v, want restored and held, the author withheld from a viewer", n1)
	}
	if n2.GetHost() != "n2" || !n2.GetDemoted() || n2.GetSince() == "" || n2.GetReason() == "" {
		t.Errorf("n2 = %+v, want demoted with since and reason", n2)
	}
}

// The hold's author is a username: an admin sees it, a viewer sees only that
// an operator set it, and when.
//
// Mutation: show the username to every role — the viewer sees "admin", red.
func TestGetRelayHealth_HoldAuthorOnlyForAdmins(t *testing.T) {
	s := relayRestoreServer(t, true)
	if _, err := s.RestoreRelay(adminCtx(), &pb.RestoreRelayRequest{Host: "n1", HoldSeconds: 600}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ctx  context.Context
		want string
	}{{adminCtx(), "admin"}, {viewerCtx(), "an operator"}, {operatorCtx(), "an operator"}} {
		st, err := s.GetRelayHealth(tc.ctx, nil)
		if err != nil || len(st.GetHosts()) != 1 {
			t.Fatalf("GetRelayHealth: %v %+v", err, st)
		}
		if e := st.GetHosts()[0]; e.GetHoldBy() != tc.want || e.GetHoldUntil() == "" {
			t.Errorf("hold by = %q until %q, want %q with the time", e.GetHoldBy(), e.GetHoldUntil(), tc.want)
		}
	}
}
