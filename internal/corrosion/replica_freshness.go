package corrosion

import (
	"log/slog"
	"sync"
	"time"
)

// Replica freshness: has this node's local replica been reconciled against the
// cluster since it last had reason to believe it is stale?
//
// A node that was away — powered off by a fence, or cut off by a partition —
// comes back holding the cluster as it was when it left. Until something
// delivers what happened meanwhile, every "this VM is mine" its replica reports
// may be false: the VM can have been rescheduled and be running elsewhere.
// Decisions a node takes purely from its own replica and PUBLISHES to the
// cluster (the reconciler's out-of-band stop sync is the one observed live on
// 2026-09-24) must wait for that delivery, or a stale belief replicates over
// the real owner's row.
//
// WHAT MARKS IT CAUGHT UP: one anti-entropy exchange with a peer that
// COMPLETED — the digests compared equal, or the peer's full state dump was
// merged without error. After either, the local replica holds everything that
// peer held when the exchange began (LWW keeps whichever side is newer), so
// anything the cluster decided while this node was away and that peer knew is
// now here. The replicator's push path may deliver the same rows sooner; it
// cannot say when it is DONE, which is why it is not the signal.
//
// There is no durable form, deliberately. The question is about the gap
// between this process's view and the cluster's, and a restart is exactly the
// event that opens one: the zero value — not caught up — is what every process
// starts with.
//
// WHAT MAKES IT STALE AGAIN: losing sight of every gossip peer. A node that
// can see no one cannot be receiving replication, and anything decided while
// it was alone is missing — the rejoin after a partition is the same hazard as
// the boot after a fence. It is reset from memberlist's leave events (the
// moment the last peer goes) and, as a backstop, by an anti-entropy pass or a
// re-join tick that finds no peers at all.
//
// An exchange that STARTED before a reset and finished after it proves nothing
// about the gap the reset opened, so each reset bumps a generation and a pass
// may only mark the generation it began under.
type replicaFreshness struct {
	mu       sync.Mutex
	gen      uint64
	caughtUp bool
	peer     string    // the peer the catch-up was against
	at       time.Time // when it completed
	// staleReason is why the replica is not (or no longer) trusted, for the
	// deferral log line. Empty means "since process start".
	staleReason string
}

// ReplicaCaughtUp reports whether this node's replica has completed an
// anti-entropy reconciliation with a peer since process start and since it
// last lost every gossip peer. When it has not, the string says why, in a form
// fit for a log line.
func (c *Client) ReplicaCaughtUp() (bool, string) {
	f := &c.freshness
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.caughtUp {
		return true, ""
	}
	if f.staleReason != "" {
		return false, f.staleReason
	}
	return false, "no anti-entropy exchange with a peer has completed since this process started"
}

// replicaFreshnessGen returns the current staleness generation, captured by an
// anti-entropy pass before it reads anything so it can later mark only the gap
// it actually covered.
func (c *Client) replicaFreshnessGen() uint64 {
	c.freshness.mu.Lock()
	defer c.freshness.mu.Unlock()
	return c.freshness.gen
}

// markReplicaCaughtUp records a completed exchange with peer, begun under
// generation gen. A pass that straddled a reset (gen moved on) marks nothing.
func (c *Client) markReplicaCaughtUp(gen uint64, peer string) {
	f := &c.freshness
	f.mu.Lock()
	defer f.mu.Unlock()
	if gen != f.gen || f.caughtUp {
		return
	}
	f.caughtUp, f.peer, f.at, f.staleReason = true, peer, time.Now(), ""
	slog.Info("replica caught up: anti-entropy exchange with a peer completed; decisions published from the local replica may proceed",
		"peer", peer)
}

// MarkReplicaStale withdraws trust in the local replica until the next
// completed anti-entropy exchange. Idempotent: a reset while already stale only
// bumps the generation (so an in-flight pass cannot mark it) and logs nothing.
func (c *Client) MarkReplicaStale(reason string) {
	f := &c.freshness
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gen++
	if !f.caughtUp {
		if f.staleReason == "" {
			f.staleReason = reason
		}
		return
	}
	f.caughtUp, f.staleReason = false, reason
	slog.Warn("replica no longer trusted as caught up — waiting for the next anti-entropy exchange",
		"reason", reason, "last_caught_up_peer", f.peer, "last_caught_up_at", f.at.UTC().Format(time.RFC3339))
}
