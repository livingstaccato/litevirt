package corrosion

import (
	"context"
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
// COMPLETED — the digests compared equal, or the peer's dump of every table
// whose digest differed was merged without error. After either, the local
// replica holds everything that
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
	// staleSince is when the replica last stopped being trusted; zero means
	// since process start (processStart).
	staleSince time.Time
	// wake is signalled when a caught-up replica goes stale, so the
	// anti-entropy loop runs a catch-up pass now instead of at the end of
	// the interval it is sleeping in (ReplicaStaleWake).
	wake chan struct{}
}

// processStart stands in for "when this process started" in ReplicaStaleFor:
// a fresh process is the first reason a replica is not caught up.
var processStart = time.Now()

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
	f.caughtUp, f.staleReason, f.staleSince = false, reason, time.Now()
	if f.wake != nil {
		select {
		case f.wake <- struct{}{}:
		default:
		}
	}
	slog.Warn("replica no longer trusted as caught up — waiting for the next anti-entropy exchange",
		"reason", reason, "last_caught_up_peer", f.peer, "last_caught_up_at", f.at.UTC().Format(time.RFC3339))
}

// ReplicaStaleFor reports how long the replica has gone without being caught
// up — since process start, or since it last went stale — and zero while it is
// caught up. For the refusal text: an operator told "not caught up for 4s" can
// tell a node that is catching up from one that cannot reach a peer.
func (c *Client) ReplicaStaleFor() time.Duration {
	f := &c.freshness
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.caughtUp {
		return 0
	}
	since := f.staleSince
	if since.IsZero() {
		since = processStart
	}
	return time.Since(since)
}

// ReplicaStaleWake returns a channel that receives when a caught-up replica
// goes stale (MarkReplicaStale's transition, not its repeats). One per Client;
// the anti-entropy loop selects on it.
func (c *Client) ReplicaStaleWake() <-chan struct{} {
	f := &c.freshness
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.wake == nil {
		f.wake = make(chan struct{}, 1)
	}
	return f.wake
}

// MarkReplicaCaughtUpForTests records a completed catch-up without running an
// exchange. Test seam only: an in-process harness whose nodes are bootstrapped
// together (tests/fleet) starts them as a cluster that has already converged,
// which a real daemon only reaches through an anti-entropy pass. A scenario
// modelling a rejoin calls MarkReplicaStale afterwards.
func (c *Client) MarkReplicaCaughtUpForTests(peer string) {
	c.markReplicaCaughtUp(c.replicaFreshnessGen(), peer)
}

// ReplicaTrusted reports whether decisions read from c may be acted on and
// published by host self: caughtUp (normally c.ReplicaCaughtUp) says so, or
// the cluster is a cluster of one. A single node is trusted without a catch-up
// — there is no peer to catch up with and no other host that could own the
// workload. "Of one" is read from the local hosts table: any other admitted
// host, reachable or not, means another owner is possible and the gate holds —
// except a host still joining, while this node has no gossip member
// (ClusterOfOneBut): its daemon has never booted on this admission, so it has
// written nothing this node lacks (see ClusterOfOneBut for a re-admitted
// name's recorded workloads), and a
// founder holding its own half-added second host stays a cluster of one.
// An unreadable hosts table fails closed. A nil caughtUp is unwired and
// trusted, for tests that do not exercise the gate.
//
// It is the one policy behind both consumers: the reconciler's out-of-band
// stop sync and the client-facing workload mutations (grpcapi's
// staleReplicaGated).
func ReplicaTrusted(ctx context.Context, c *Client, self string, caughtUp func() (bool, string)) (bool, string) {
	if caughtUp == nil {
		return true, ""
	}
	ok, why := caughtUp()
	if ok {
		return true, ""
	}
	alone, err := soleOrOnlyJoiners(ctx, c, self)
	if err != nil {
		return false, why + " (and the hosts table could not be read to rule out a single-node cluster: " + err.Error() + ")"
	}
	if !alone {
		return false, why
	}
	return true, ""
}
