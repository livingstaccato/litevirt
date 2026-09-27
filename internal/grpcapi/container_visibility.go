package grpcapi

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A container operation asked of one node and carried out on the container's
// owner is written on the owner, and reaches the asking node only when
// replication brings it. Reads — `lv ct ls`, the compose depends-on gates, the
// UI — are served from the asking node's own replica. So an operation that
// returned on the owner's answer alone reported success while the node the
// caller talks to still listed the old state: `lv compose up` printed
// "Stack deployed." and the `lv ct ls` after it showed the container stopped
// until the start arrived.
//
// awaitForwardedContainer closes that gap: after a forwarded operation
// succeeds, the asking node waits — bounded — until its own replica shows the
// result. It never turns a success into a failure: the owner did the work, and
// a replica that is slow to catch up is a replication problem to log, not an
// error in the operation.

// forwardedVisibleTimeout bounds the wait. It covers the replicator's idle
// push tick (10s ± 20%), which is the longest a healthy peer waits for an
// entry it missed the wake for.
const forwardedVisibleTimeout = 15 * time.Second

// forwardedVisiblePoll is how often the local replica is re-read.
const forwardedVisiblePoll = 25 * time.Millisecond

// awaitForwardedContainer waits until this node's replica holds the (host,
// name) container row in the state done accepts, or forwardedVisibleTimeout
// passes, or ctx ends. what names the awaited state for the log.
func (s *Server) awaitForwardedContainer(ctx context.Context, host, name, what string, done func(*corrosion.ContainerRecord) bool) {
	if s.db == nil {
		return
	}
	deadline := time.Now().Add(forwardedVisibleTimeout)
	for {
		rec, err := corrosion.GetContainer(ctx, s.db, host, name)
		if err == nil && done(rec) {
			return
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			slog.Warn("container operation succeeded on its owner, but this node's replica has not caught up",
				"container", name, "owner", host, "awaiting", what, "waited", forwardedVisibleTimeout)
			return
		}
		t := time.NewTimer(min(forwardedVisiblePoll, remaining))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// containerRowPresent accepts any live row: a create is visible once the row is.
func containerRowPresent(rec *corrosion.ContainerRecord) bool { return rec != nil }

// containerRunning accepts a row recorded running: a start is visible once
// the owner's running write is.
func containerRunning(rec *corrosion.ContainerRecord) bool {
	return rec != nil && rec.State == "running"
}

// containerNotRunning accepts a row not recorded running, or no row: a stop is
// visible once the owner's stopped write is.
func containerNotRunning(rec *corrosion.ContainerRecord) bool {
	return rec == nil || rec.State != "running"
}

// containerRowGone accepts no live row: a delete is visible once the owner's
// tombstone is.
func containerRowGone(rec *corrosion.ContainerRecord) bool { return rec == nil }
