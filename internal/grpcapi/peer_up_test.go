package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// peerUpGate is a gate whose probe plan does not include every peer, as a
// non-voter's does (health/probe_plan.go): HealthyPeers is empty because this
// node watches nobody, and PeerUp answers by probing.
type peerUpGate struct {
	fakeServerGate
	up map[string]bool
}

func (g peerUpGate) PeerUp(_ context.Context, host string) bool { return g.up[host] }

// Both readers that act on "this host is down" must ask PeerUp, not infer down
// from absence in HealthyPeers. A non-voter samples the other non-voters, so a
// live host it does not watch is absent from its HealthyPeers — and a stale
// manual fence confirmation would then free that live host's VIP, or let the
// sweeper treat it as powered off.
func TestPowerOffReaders_AskPeerUpNotHealthyPeers(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertFenceLog(ctx, db, corrosion.FenceLogRecord{ID: "mc", HostName: "h", Method: "manual", Result: "manual-confirmed"}); err != nil {
		t.Fatal(err)
	}
	s := &Server{hostName: "self", db: db, gate: peerUpGate{up: map[string]bool{"h": true}}}

	if s.manualFenceConfirmedVIP(ctx, "h") {
		t.Error("manualFenceConfirmedVIP honoured a stale confirmation for a host PeerUp reports live")
	}
	if !s.hostIsReachable(ctx, "h") {
		t.Error("hostIsReachable = false for a host PeerUp reports live")
	}

	// And a host PeerUp reports down is still down, with the confirmation honoured.
	s.gate = peerUpGate{up: map[string]bool{}}
	if !s.manualFenceConfirmedVIP(ctx, "h") {
		t.Error("manualFenceConfirmedVIP refused a fresh confirmation for a host PeerUp reports down")
	}
	if s.hostIsReachable(ctx, "h") {
		t.Error("hostIsReachable = true for a host PeerUp reports down")
	}
}
