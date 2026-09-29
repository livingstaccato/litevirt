package grpcapi

import (
	"context"
	"fmt"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// LeaseMintClearance decides whether this node may record lease term `next`
// for key: whether it can confirm that no peer has already seen that term. It
// is the corrosion.LeaseMintClearanceFunc the daemon wires into its Client; see
// internal/corrosion/leader_lease_clearance.go for why a mint needs one.
//
// The answer is the same quorum high-water read the executor-side barrier
// uses (sweepLeaseTermHighWater): every healthy peer is asked for its newest
// term, a quorum of answers is required, and the highest answer is the
// threshold. One read, one quorum rule, one notion of "the cluster's newest
// term" for both the node minting a term and the node judging it.
//
//   - threshold >= next: some peer has already seen term `next` or later, so
//     this replica is behind. Withheld; replication delivers the row, and the
//     next poll classifies from it.
//   - no quorum: the node cannot tell, so it does not claim. Everything a
//     lease authorises — a fence, a reschedule — already needs quorum, so this
//     withholds a number, not an action. It ends the moment a quorum answers.
//   - a cluster of one: nobody else can hold a term. Cleared without asking,
//     which matters because a lone node's quorum read would otherwise wait out
//     the health checker's startup warm-up for nothing.
//
// A refusal may be served from the barrier's cached threshold, and an accept
// may not, for the barrier's own reason: the high water only rises, so a cached
// value is a lower bound — enough to refuse on, never enough to accept on.
func (s *Server) LeaseMintClearance(ctx context.Context, key string, next int64) (bool, string) {
	alone, err := s.clusterOfOne(ctx)
	if err != nil {
		return false, "hosts table unreadable: " + err.Error()
	}
	if alone {
		return true, ""
	}
	if cached, ok := s.cachedLeaseThreshold(key); ok && cached >= next {
		return false, fmt.Sprintf("a peer has already recorded term %d; waiting for replication to deliver it", cached)
	}
	threshold, ok := s.sweepLeaseTermHighWater(ctx, key)
	if !ok {
		return false, "quorum high-water mark unconfirmed: a quorum of peers did not answer"
	}
	s.storeLeaseThreshold(key, threshold)
	if threshold >= next {
		return false, fmt.Sprintf("a peer has already recorded term %d; waiting for replication to deliver it", threshold)
	}
	return true, ""
}

// clusterOfOne reports whether this node has no peer at all: no other host in
// its hosts table AND no gossip member. Both, because each alone can be empty
// on a node that does have peers — the hosts table on a node that has joined
// gossip but not yet received the table, gossip on a node whose memberlist has
// not formed. A node that knows of any peer, reachable or not, asks.
func (s *Server) clusterOfOne(ctx context.Context) (bool, error) {
	if len(s.db.Members()) > 0 {
		return false, nil
	}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return false, err
	}
	for _, h := range hosts {
		if h.Name != s.hostName {
			return false, nil
		}
	}
	return true, nil
}
