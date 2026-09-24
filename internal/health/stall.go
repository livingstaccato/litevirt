package health

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Local stall detection.
//
// A failed probe is evidence against the PEER only if this observer was running
// while it waited for the answer. When the observer itself stops — the
// hypervisor suspends the guest, swaps it out, or starves it of CPU — every
// probe it had in flight runs out its deadline without it ever having waited,
// because the guest's clocks keep moving while it is descheduled (kvmclock
// follows the host). Those probes report "unreachable" about peers that were
// answering the whole time, and a cluster whose observers all stall together
// (one overloaded or suspended host under every node) can reach fencing quorum
// against a live peer.
//
// So each checker runs a heartbeat that only measures its own scheduling: it
// beats every stallBeat, and a gap between beats longer than stallThreshold
// means this process was not running for that long. After one, failed probes
// are not counted for StallGrace, and the failure count every peer had built up
// before the stall is discarded, so a verdict against a peer is always made of
// probes attempted after the observer resumed.
//
// The gap is measured on BOTH clocks. Go's monotonic reading is CLOCK_MONOTONIC,
// which on bare metal does not advance across a system suspend, so a suspended
// host sees only its wall clock jump. Inside a guest the monotonic clock jumps
// too. Taking the larger of the two catches both. The price is that a forward
// NTP step larger than stallThreshold also reads as a stall, which costs one
// grace window of withheld failure counting: the direction that delays a fence
// by a bounded amount, never the direction that causes one.
//
// What this does not do: it cannot tell a peer that stopped from a peer that
// answered slowly. A PEER that stalls for longer than the failure threshold is
// indistinguishable from a dead one — to every observer that kept running, it
// was — and is fenced exactly as before.

const (
	// stallBeat is the heartbeat period. It only has to be well below
	// stallThreshold; the heartbeat does no I/O.
	stallBeat = 250 * time.Millisecond
	// stallThreshold is the heartbeat gap that counts as this process having
	// stopped. It equals checkInterval: an observer that missed a whole probe
	// tick was not observing.
	stallThreshold = checkInterval
	// StallGrace is how long after a local stall this node refuses to count a
	// failed probe, and (via InStallGrace) its coordinator refuses to fence. It
	// is long enough for every peer resumed by the same event to answer fresh
	// probes — five probe ticks — and it bounds the delay a stall adds to
	// fencing a peer that really is dead: after it, offlineThreshold fresh
	// failures are needed as usual.
	StallGrace = 10 * time.Second
)

// stallState is the heartbeat's record. Its own lock, not Checker.mu, because
// beat runs on every probe result and the probe path already holds c.mu.
type stallState struct {
	mu       sync.Mutex
	lastBeat time.Time // local clock at the previous beat; zero before the first
	stallAt  time.Time // local clock when the most recent stall was noticed
	epoch    uint64    // incremented once per stall
}

// stallGap is how long the process was away between two beats, taking the
// larger of the monotonic and wall-clock readings (see the file comment).
func stallGap(prev, now time.Time) time.Duration {
	gap := now.Sub(prev)                                     // monotonic when both carry it
	if wall := now.Round(0).Sub(prev.Round(0)); wall > gap { // Round(0) strips monotonic
		gap = wall
	}
	return gap
}

// beat records one heartbeat at now and reports the most recent stall. It is
// called by the heartbeat loop and on every probe result, so a probe that
// completes the instant the process resumes sees the stall even if it runs
// before the heartbeat goroutine does.
func (c *Checker) beat(now time.Time) (stallAt time.Time, epoch uint64) {
	s := &c.stall
	s.mu.Lock()
	var gap time.Duration
	if !s.lastBeat.IsZero() {
		if g := stallGap(s.lastBeat, now); g > stallThreshold {
			gap = g
			s.stallAt = now
			s.epoch++
		}
	}
	if s.lastBeat.IsZero() || now.Sub(s.lastBeat) > 0 {
		s.lastBeat = now
	}
	stallAt, epoch = s.stallAt, s.epoch
	s.mu.Unlock()
	if gap > 0 {
		slog.Warn("health checker: this node was not running — peer failures observed across the gap are discarded, and none are counted for the grace window",
			"gap", gap.Round(time.Millisecond), "grace", StallGrace)
	}
	return stallAt, epoch
}

// inGrace reports whether now falls inside the grace window of stallAt.
func inGrace(stallAt, now time.Time) bool {
	return !stallAt.IsZero() && now.Sub(stallAt) < StallGrace
}

// InStallGrace reports whether this node stopped running within the last
// StallGrace. The failover coordinator refuses to decide a fence while it is
// true: a node that was not running moments ago has not been watching.
func (c *Checker) InStallGrace() bool {
	now := c.now()
	stallAt, _ := c.beat(now)
	return inGrace(stallAt, now)
}

// runStallHeartbeat beats until ctx ends. Started by Start, before probing.
func (c *Checker) runStallHeartbeat(ctx context.Context) {
	t := time.NewTicker(stallBeat)
	defer t.Stop()
	c.beat(c.now())
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.beat(c.now())
		}
	}
}
