package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// A cluster of one mints without asking, even while the health checker is
// still in its startup warm-up (QuorumUnknown): there is no peer that could
// hold a higher term, and waiting would only delay a lone node's first lease.
func TestLeaseMintClearance_AClusterOfOneIsClearedWithoutAsking(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	insertTestHost(t, ctx, s.db, s.hostName, "active")
	s.SetGate(fakeServerGate{quorum: health.QuorumUnknown, needed: 1})
	s.peerClientOverride = unreachablePeers()

	if ok, why := s.LeaseMintClearance(ctx, corrosion.LeaseKeyFailover, 1); !ok {
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
			if ok, _ := s.LeaseMintClearance(ctx, corrosion.LeaseKeyFailover, 1); ok {
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
		s.peerClientOverride = fakePeers(map[string]int64{"node-c": tc.peerTerm})
		if ok, why := s.LeaseMintClearance(ctx, corrosion.LeaseKeyFailover, tc.next); ok != tc.want {
			t.Errorf("peer at %d, minting %d: cleared=%v (%q), want %v", tc.peerTerm, tc.next, ok, why, tc.want)
		}
	}
}
