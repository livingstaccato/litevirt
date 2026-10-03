package grpcapi

import (
	"context"
	"fmt"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// LeaseMintClearance decides whether this node may record lease term req.Term
// for req.Key: whether it can confirm that no peer has already seen that term,
// and, for a takeover, that no peer sees the lease live. It is the
// corrosion.LeaseMintClearanceFunc the daemon wires into its Client; see
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
//   - a takeover, with a peer reporting the lease live for another holder at
//     req.Now: this node's leader_election row is behind that peer's. Withheld
//     until the renewal reaches this node (it then defers to the live holder)
//     or every expiry a peer reports has passed (the holder is gone). The
//     answers come from the same sweep as the threshold, so this costs no
//     extra round trip. A peer on an older build reports no row, which is no
//     evidence: against such a peer the takeover is judged on the term alone,
//     as before.
//
// A refusal may be served from the barrier's cached threshold, and an accept
// may not, for the barrier's own reason: the high water only rises, so a cached
// value is a lower bound — enough to refuse on, never enough to accept on.
func (s *Server) LeaseMintClearance(ctx context.Context, req corrosion.LeaseMintRequest) (bool, string) {
	key, next := req.Key, req.Term
	alone, err := s.clusterOfOne(ctx)
	if err != nil {
		return false, "hosts table unreadable: " + err.Error()
	}
	if alone {
		return true, ""
	}
	// A replica that has not caught up cannot vouch for its own quorum read.
	// The read counts over the voter set and asks the healthy peers in this
	// replica, and on a fresh database both come from a hosts table that may
	// name only this node: the quorum is itself, nobody is asked, and the high
	// water is its own empty ledger. That is how a reinstalled node-5 recorded
	// failover and dual_run_detector term 1 a minute after `lv host add`, both
	// already minted in 2026-09 (drill 6 on main-b3368d7c). An anti-entropy
	// exchange carries leader_lease_terms, so once it completes the ledger
	// holds the cluster's history and the read below is over the real fleet.
	if ok, why := s.db.ReplicaCaughtUp(); !ok {
		return false, "this node's replica has not caught up with the cluster yet (" + why +
			"), so its lease ledger and voter set may be missing the cluster's history"
	}
	if cached, ok := s.cachedLeaseThreshold(key); ok && cached >= next {
		return false, fmt.Sprintf("a peer has already recorded term %d; waiting for replication to deliver it", cached)
	}
	sweep := s.sweepLeaseTerm(ctx, key)
	if !sweep.ok {
		return false, "quorum high-water mark unconfirmed: a quorum of peers did not answer"
	}
	threshold := sweep.threshold
	s.storeLeaseThreshold(key, threshold)
	if threshold >= next {
		return false, fmt.Sprintf("a peer has already recorded term %d; waiting for replication to deliver it", threshold)
	}
	if req.Takeover {
		self := req.Holder
		if self == "" {
			self = s.hostName
		}
		if row, live := liveLeaseElsewhere(sweep.rows, self, req.Now); live {
			return false, fmt.Sprintf("peer %s reports the lease live for %s; this node's leader_election "+
				"row is behind (renewals are not carried by anti-entropy), waiting for the renewal or "+
				"for the reported expiry to pass", row.peer, row.holder)
		}
	}
	return true, ""
}

// liveLeaseElsewhere returns a row some peer reported that shows the lease live
// for a holder other than self at now (both RFC3339). An unparseable instant on
// either side is no evidence. Of several such rows it returns the one from the
// lowest-sorting peer, so the reason — and the once-per-reason log line — does
// not flap with the order the answers arrived in.
func liveLeaseElsewhere(rows []peerLeaseRow, self, now string) (peerLeaseRow, bool) {
	at, err := time.Parse(time.RFC3339, now)
	if err != nil {
		return peerLeaseRow{}, false
	}
	var found peerLeaseRow
	ok := false
	for _, r := range rows {
		if r.holder == "" || r.holder == self {
			continue
		}
		exp, err := time.Parse(time.RFC3339, r.expiresAt)
		if err != nil || exp.Before(at) {
			continue
		}
		if !ok || r.peer < found.peer {
			found, ok = r, true
		}
	}
	return found, ok
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
