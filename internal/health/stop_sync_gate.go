package health

import (
	"context"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// stopSyncAllowed decides whether the reconciler's out-of-band stop sync may
// PUBLISH its write for this VM now. It refuses — and the caller retries next
// tick — when:
//
//   - this node's replica has not caught up with a peer since the process
//     started or since it last lost every gossip peer (see
//     corrosion.Client.ReplicaCaughtUp). A rejoined host's replica can still
//     name it the owner of a VM that was rescheduled while it was away; the
//     sync would then replicate "stopped" over the real owner's running row.
//     This is the default-on guard: it does not depend on owner_epoch
//     enforcement, which only closes the same hole when enabled and latched.
//   - the VM has an active ownership condition (dual-run, runtime owner
//     mismatch, owner-epoch mismatch). Which host's view is true is exactly
//     what is in dispute, so neither side publishes a state for it; the same
//     rule the self-heal restart follows.
//   - the conditions cannot be read (fail closed).
//
// Deferral is logged once per VM per cause, not every tick.
func (r *Reconciler) stopSyncAllowed(ctx context.Context, name string) bool {
	if ok, why := r.replicaTrusted(ctx); !ok {
		r.noteStopSyncDeferred(name, "replica not caught up", why)
		return false
	}
	disputed, code, err := corrosion.WorkloadHasActiveOwnershipCondition(ctx, r.db, "vm", name)
	if err != nil {
		r.noteStopSyncDeferred(name, "health conditions unreadable", err.Error())
		return false
	}
	if disputed {
		r.noteStopSyncDeferred(name, "active ownership condition", code)
		return false
	}
	r.staleDeferMu.Lock()
	delete(r.staleDeferLogged, name)
	r.staleDeferMu.Unlock()
	return true
}

// replicaTrusted reports whether decisions read from this node's replica may be
// published. Unwired (nil) means trusted, for tests that do not exercise it; the
// daemon always wires it. The policy, including the cluster-of-one exemption,
// is corrosion.ReplicaTrusted — shared with grpcapi's gate on client-facing
// workload mutations.
func (r *Reconciler) replicaTrusted(ctx context.Context) (bool, string) {
	return corrosion.ReplicaTrusted(ctx, r.db, r.hostName, r.replicaCaughtUp)
}

// noteStopSyncDeferred logs a deferral the first time it happens for this VM
// with this cause; repeats while the same cause holds are debug-level only.
func (r *Reconciler) noteStopSyncDeferred(name, cause, detail string) {
	r.staleDeferMu.Lock()
	if r.staleDeferLogged == nil {
		r.staleDeferLogged = make(map[string]string)
	}
	first := r.staleDeferLogged[name] != cause
	r.staleDeferLogged[name] = cause
	r.staleDeferMu.Unlock()
	if first {
		slog.Warn("reconciler: VM looks stopped out-of-band, but deferring the cluster state sync (retries each pass)",
			"vm", name, "cause", cause, "detail", detail)
		return
	}
	slog.Debug("reconciler: out-of-band stop sync still deferred", "vm", name, "cause", cause)
}
