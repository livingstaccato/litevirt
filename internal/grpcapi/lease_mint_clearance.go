package grpcapi

import (
	"context"
	"fmt"
	"sort"
	"strings"
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
//   - once this node has adopted a voter generation with members: cleared
//     only when a majority of that generation decides the term for this node
//     (lease_term_claim.go). The read above shows that nobody has recorded
//     the term; only the decision shows that nobody else is about to.
//
// A refusal may be served from the barrier's cached threshold, and an accept
// may not, for the barrier's own reason: the high water only rises, so a cached
// value is a lower bound — enough to refuse on, never enough to accept on.
func (s *Server) LeaseMintClearance(ctx context.Context, req corrosion.LeaseMintRequest) (bool, string) {
	key, next := req.Key, req.Term
	started := time.Now()
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
		if joining := s.onlyJoiningPeers(ctx); len(joining) > 0 {
			return false, fmt.Sprintf("this node's replica has not caught up, and its only peers are %s, "+
				"admitted by `lv host add` and still joining. A joining host is a voter, so this node alone is "+
				"no majority: it claims no new term until it has caught up with that host once its daemon "+
				"starts. If the add failed, `lv host rm %s` ends the wait",
				strings.Join(joining, ", "), joining[0])
		}
		return false, "this node's replica has not caught up with the cluster yet (" + why +
			"), so its lease ledger and voter set may be missing the cluster's history"
	}
	mode, cfg, why := s.leaseTermClaimMode(ctx)
	if mode == leaseClaimClosed {
		return false, why
	}
	if cached, ok := s.cachedLeaseThreshold(key); ok && cached >= next {
		return false, fmt.Sprintf("a peer has already recorded term %d; waiting for replication to deliver it", cached)
	}
	sweep := s.sweepLeaseTerm(ctx, key)
	if !sweep.ok {
		// No quorum to read from is no voter majority to take the lease over
		// with: a stalled takeover, counted and raised like a claim's. A sweep
		// that did not run, because the gate is not wired yet at start-up, asked
		// nobody and is not counted.
		why := "quorum high-water mark unconfirmed: a quorum of peers did not answer"
		if sweep.unwired {
			return false, "quorum high-water mark unconfirmed: the health gate is not wired yet"
		}
		s.noteLeaseNoMajority(ctx, key, req.TTL, clearanceInstant(req, started), why)
		return false, why
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
	if mode == leaseClaimOn {
		return s.claimLeaseTerm(ctx, cfg, req, started)
	}
	return true, ""
}

// clearanceInstant is req.Now advanced by the time the clearance has taken
// since started: the caller's clock, now. An unparseable req.Now falls back
// to this node's clock.
func clearanceInstant(req corrosion.LeaseMintRequest, started time.Time) time.Time {
	at := started
	if t, err := time.Parse(time.RFC3339, req.Now); err == nil {
		at = t
	}
	return at.Add(time.Since(started))
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

// clusterOfOneBut is clusterOfOne for a decision about subject, a host whose
// admission this node may itself have just written: subject's row does not
// make this node "not alone" while it is still 'joining' and, when serial is
// set, while it holds that certificate (the admission being asked about
// again). See corrosion.ClusterOfOneBut for why a joining host is no peer.
// Without this, a founder that has never had a peer wedged on its first `lv
// host add`: the add's first AdmitHost wrote the joining row, and its re-ask
// before the install, and `lv host rm` of the half-admitted host, both found
// it no longer alone. Any gossip member, any other host, or another admission
// of subject still means it is not.
func (s *Server) clusterOfOneBut(ctx context.Context, subject, serial string) (bool, error) {
	return corrosion.ClusterOfOneBut(ctx, s.db, s.hostName, func(h corrosion.HostRecord) bool {
		return h.Name == subject && (serial == "" || sameSerial(h.CertSerial, serial))
	})
}

// onlyJoiningPeers names the hosts still joining when they are this node's
// only peers (corrosion.ClusterOfOneBut with any admission, and at least one
// joining host), sorted; otherwise, or on a read error, nil. It only words a
// refusal: nothing is decided from it.
func (s *Server) onlyJoiningPeers(ctx context.Context) []string {
	alone, err := corrosion.ClusterOfOneBut(ctx, s.db, s.hostName, corrosion.AnyAdmission)
	if err != nil || !alone {
		return nil
	}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return nil
	}
	var names []string
	for _, h := range hosts {
		if h.Name != s.hostName {
			names = append(names, h.Name)
		}
	}
	sort.Strings(names)
	return names
}

// clusterOfOne reports whether this node has no peer at all: no other host in
// its hosts table AND no gossip member (corrosion.ClusterOfOneBut, with no
// joining host let through). A node that knows of any peer, reachable or not,
// asks.
//
// LeaseMintClearance asks this, and not the joining-host exception: a joining
// host is a voter (corrosion.HostStateJoining), so a node alone with one is
// not a voter majority, and once that host boots it may mint from the same
// ledger before this node sees it in gossip.
func (s *Server) clusterOfOne(ctx context.Context) (bool, error) {
	return corrosion.ClusterOfOneBut(ctx, s.db, s.hostName, corrosion.NoAdmission)
}
