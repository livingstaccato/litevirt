package corrosion

import (
	"context"
	"log/slog"
)

// Mint clearance: a node must not record lease term N+1 from a ledger that has
// not seen the cluster's N+1.
//
// The term a new tenure claims is MAX(term)+1 over THIS node's replica
// (nextLeaseTerm). That is only a cluster-unique number if this replica already
// holds every term the cluster has minted, and a node that was away does not: a
// restarted daemon, or a node reconnecting after a partition, comes back with
// the ledger as it was when it left. Its own expired lease row then classifies
// as a lapse-and-retake, it allocates the term a peer took while it was gone,
// and it commits a second claimant for that term. leader_lease_terms keeps both
// rows by design (immutableMergeKeepLocalRow), so that is a PERMANENT
// immutable-ledger conflict, which only `lv cluster acknowledge-lease-term`
// clears. Observed on the lab: a daemon started at 08:34:40 minted its own
// dual_run_detector term 5 at 08:34:45, eight minutes after a peer had.
//
// The clearance is the quorum high-water read the lease-term barrier already
// runs for executors (GetLeaseTermHighWater, fanned out to every healthy peer
// and required from a quorum): before committing N+1, the node confirms that no
// reachable peer has seen N+1 or higher. It is asked about the TERM, not about
// how long ago the process started, which is why it also covers the no-restart
// case — a long partition healing presents exactly the same stale ledger, with
// no restart for a "wait after start" rule to key on.
//
// It is asked only for a mint. A renewal of a tenure this node already holds
// mints nothing and asks nothing, so a holder keeps its lease through any
// partition exactly as before; and a poll that finds a peer's live lease never
// reaches the mint either (see AcquireLeaseWithTerm). Mints are rare — one per
// change of tenure — so the read costs one RPC per healthy peer per takeover.
//
// A withheld mint is reported as "not held", the same shape as losing the
// race: the caller retries on its next poll, by which time replication has
// usually delivered the row the node was missing, and it then classifies from
// the real ledger.

// LeaseMintClearanceFunc reports whether this node may record term `next` for
// key now. ok=false withholds the mint; reason says why, for the log.
type LeaseMintClearanceFunc func(ctx context.Context, key string, next int64) (ok bool, reason string)

// SetLeaseMintClearance injects the check run before every new lease term is
// recorded. Wired at daemon start to the gRPC server's quorum high-water read
// (grpcapi.Server.LeaseMintClearance).
//
// Nil means no check, which is what a single-package test Client has: it has
// no peers to ask. The daemon always wires it.
func (c *Client) SetLeaseMintClearance(fn LeaseMintClearanceFunc) { c.leaseMintClearance = fn }

// clearLeaseMint runs the clearance for (key, next) and logs a withholding
// once per key per reason.
func (c *Client) clearLeaseMint(ctx context.Context, key string, next int64) bool {
	if c.leaseMintClearance == nil {
		return true
	}
	ok, reason := c.leaseMintClearance(ctx, key, next)
	c.mintWithheldMu.Lock()
	prev := c.mintWithheld[key]
	if ok {
		delete(c.mintWithheld, key)
	} else {
		if c.mintWithheld == nil {
			c.mintWithheld = make(map[string]string, 1)
		}
		c.mintWithheld[key] = reason
	}
	c.mintWithheldMu.Unlock()
	switch {
	case !ok && prev != reason:
		slog.Warn("leader lease: not claiming a new term yet — this node cannot confirm its ledger "+
			"is current for the key, and a term minted from a stale ledger is a permanent "+
			"immutable-ledger conflict (retries each poll)",
			"key", key, "term", next, "reason", reason)
	case ok && prev != "":
		slog.Info("leader lease: new-term claim cleared", "key", key, "term", next)
	}
	return ok
}
