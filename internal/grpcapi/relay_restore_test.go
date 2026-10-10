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
	rows, err := corrosion.ListRelayRows(ctx, s.db)
	if err != nil {
		t.Fatal(err)
	}
	if !rows["n1"].Held(time.Now()) || rows["n1"].Held(time.Now().Add(2*time.Hour)) {
		t.Fatalf("row = %+v, want held for about an hour", rows["n1"])
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
