package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// clearanceNow is the instant the takeover cases classify at.
const clearanceNow = "2026-09-08T12:10:00Z"

func mintReq(key string, term int64, takeover bool) corrosion.LeaseMintRequest {
	return corrosion.LeaseMintRequest{Key: key, Term: term, Holder: "node-a", Takeover: takeover, Now: clearanceNow}
}

// A cluster of one mints without asking, even while the health checker is
// still in its startup warm-up (QuorumUnknown): there is no peer that could
// hold a higher term, and waiting would only delay a lone node's first lease.
func TestLeaseMintClearance_AClusterOfOneIsClearedWithoutAsking(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	insertTestHost(t, ctx, s.db, s.hostName, "active")
	s.SetGate(fakeServerGate{quorum: health.QuorumUnknown, needed: 1})
	s.peerClientOverride = unreachablePeers()

	if ok, why := s.LeaseMintClearance(ctx, mintReq(corrosion.LeaseKeyFailover, 1, false)); !ok {
		t.Fatalf("a cluster of one was refused (%q); nobody else can hold a term", why)
	}
}

// Knowing of ANY peer means asking — whichever source knows of it. The hosts
// table can lag gossip on a joining node, and gossip can lag the table on a
// node whose memberlist has not formed.
func TestLeaseMintClearance_AKnownPeerMeansAsking(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		setup  func(t *testing.T, s *Server)
		reason string
	}{
		{"peer in the hosts table only", func(t *testing.T, s *Server) {
			insertTestHost(t, ctx, s.db, "peer-1", "active")
		}, "hosts table"},
		{"peer in gossip only", func(t *testing.T, s *Server) {
			s.db.SetMembersForTests(func() []corrosion.PeerInfo {
				return []corrosion.PeerInfo{{Name: "peer-1", Addr: "10.0.0.2:7946"}}
			})
		}, "gossip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			insertTestHost(t, ctx, s.db, s.hostName, "active")
			tc.setup(t, s)
			s.SetGate(fakeServerGate{quorum: health.QuorumUnknown, needed: 2})
			s.peerClientOverride = unreachablePeers()
			if ok, _ := s.LeaseMintClearance(ctx, mintReq(corrosion.LeaseKeyFailover, 1, false)); ok {
				t.Fatalf("cleared with a peer known only through the %s and no quorum; a node "+
					"that knows of a peer must confirm the high water before minting", tc.reason)
			}
		})
	}
}

// The threshold rule: withheld when a peer has already seen `next`, cleared
// when every answer is below it.
func TestLeaseMintClearance_WithheldAtOrBelowThePeerHighWater(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		peerTerm, next int64
		want           bool
	}{
		{peerTerm: 5, next: 5, want: false}, // the lab: a peer already took the term
		{peerTerm: 7, next: 5, want: false}, // several tenures behind
		{peerTerm: 4, next: 5, want: true},  // current: next is genuinely free
	} {
		s := barrierNode(t, 4, 2, "node-c")
		insertTestHost(t, ctx, s.db, "node-c", "active") // not a cluster of one
		s.db.MarkReplicaCaughtUpForTests("node-c")
		s.peerClientOverride = fakePeers(map[string]int64{"node-c": tc.peerTerm})
		if ok, why := s.LeaseMintClearance(ctx, mintReq(corrosion.LeaseKeyFailover, tc.next, false)); ok != tc.want {
			t.Errorf("peer at %d, minting %d: cleared=%v (%q), want %v", tc.peerTerm, tc.next, ok, why, tc.want)
		}
	}
}

// A replica that has not caught up is withheld whatever its quorum read says.
// On a fresh database the read is over a voter set and a peer list taken from
// that same replica, so a low answer proves nothing (drill 6 on main-b3368d7c:
// a reinstalled node minted terms the cluster had minted weeks before). The
// same node clears once an exchange has completed.
func TestLeaseMintClearance_WithheldUntilTheReplicaHasCaughtUp(t *testing.T) {
	ctx := context.Background()
	s := barrierNode(t, 0, 2, "node-c")
	insertTestHost(t, ctx, s.db, "node-c", "active")
	s.peerClientOverride = fakePeers(map[string]int64{"node-c": 0})
	if ok, why := s.LeaseMintClearance(ctx, mintReq(corrosion.LeaseKeyFailover, 1, true)); ok || !strings.Contains(why, "caught up") {
		t.Fatalf("not caught up: cleared=%v (%q), want withheld naming the catch-up", ok, why)
	}
	s.db.MarkReplicaCaughtUpForTests("node-c")
	if ok, why := s.LeaseMintClearance(ctx, mintReq(corrosion.LeaseKeyFailover, 1, true)); !ok {
		t.Fatalf("caught up, every answer below the term: cleared=false (%q), want true", why)
	}
}

// The takeover rule: with the term cleared, a takeover is still withheld while
// a peer reports the lease live for another holder at the caller's instant —
// that peer has seen a renewal this node's leader_election row has not.
func TestLeaseMintClearance_ATakeoverWaitsForAPeerThatSeesTheLeaseLive(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name            string
		holder, expires string
		takeover        bool
		want            bool
		reason          string
	}{
		{name: "live for another holder", holder: "node-x", expires: "2026-09-08T12:10:30Z", takeover: true, reason: "node-x"},
		{name: "expiring this very second is still live", holder: "node-x", expires: clearanceNow, takeover: true, reason: "node-x"},
		{name: "not a takeover", holder: "node-x", expires: "2026-09-08T12:10:30Z", takeover: false, want: true},
		{name: "expired everywhere", holder: "node-x", expires: "2026-09-08T12:09:59Z", takeover: true, want: true},
		{name: "live for us", holder: "node-a", expires: "2026-09-08T12:10:30Z", takeover: true, want: true},
		{name: "an older peer reports no row", takeover: true, want: true},
		{name: "an unparseable expiry is no evidence", holder: "node-x", expires: "soon", takeover: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := barrierNode(t, 4, 2, "node-c")
			insertTestHost(t, ctx, s.db, "node-c", "active")
			s.db.MarkReplicaCaughtUpForTests("node-c")
			s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
				if host != "node-c" {
					return nil, nil, context.DeadlineExceeded
				}
				return &fakeHighWaterPeer{term: 4, leaseHolder: tc.holder, leaseExpires: tc.expires}, func() {}, nil
			}
			ok, why := s.LeaseMintClearance(ctx, mintReq(corrosion.LeaseKeyFailover, 5, tc.takeover))
			if ok != tc.want || (tc.reason != "" && !strings.Contains(why, tc.reason)) {
				t.Fatalf("cleared=%v (%q), want %v (reason naming %q)", ok, why, tc.want, tc.reason)
			}
		})
	}
}
