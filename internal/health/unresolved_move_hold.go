package health

import (
	"context"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A paused copy a live move left on this host, its target, while the move is
// unresolved.
//
// A move whose source failed before the ownership commit can leave the guest
// paused here, mid-migration or after the cutover, and that copy may hold the
// only state written since the cutover. The move's source, or failover's hold
// of its row, records it as vm.migration_unresolved toward this host. While
// that is open, the start of the VM here does not destroy and redefine a
// paused domain of it: a lease holder on an older build can reschedule the
// migrating row onto this host, and the start would boot the VM afresh from
// its disks over the paused guest. The domain is left as it is, and the
// condition stays open while it is (grpcapi.resolveMigrationUnresolvedIfSettled):
// resumed, it is the running copy the start then records; destroyed, the VM
// is started from its disks.
//
// Only a paused domain: a shut-off one holds no guest state its replacement
// loses (its definition, NVRAM and disks are kept), and a running one is the
// start's to record. What cannot be read holds the start (fail closed): the
// condition, its evidence, or the domain's state while the condition names
// this host. A condition naming no target is taken to name this host. The start is retried on the
// next pass.

// unresolvedMoveHolds reports whether name's start here waits for its
// unresolved move, and why. It fails closed: a condition, evidence or domain
// state that cannot be read holds the start, so the domain is kept.
func (r *Reconciler) unresolvedMoveHolds(ctx context.Context, name string) (bool, string) {
	if r.virt == nil || !r.virt.DomainExists(name) {
		return false, ""
	}
	ev, open, err := corrosion.OpenMigrationUnresolved(ctx, r.db, name)
	if err != nil {
		return true, "whether its move is unresolved cannot be read: " + err.Error()
	}
	if !open {
		return false, ""
	}
	// A condition naming no target may be about this host's copy.
	if ev.Target != "" && ev.Target != r.hostName {
		return false, ""
	}
	move := "its move from " + ev.Source + " to this host is unresolved (" + corrosion.CondMigrationUnresolved + ")"
	if ev.Target == "" {
		move = "its move from " + ev.Source + " is unresolved (" + corrosion.CondMigrationUnresolved + ") and names no target"
	}
	st, err := r.virt.DomainStateReason(name)
	if err != nil {
		return true, move + ", and its domain's state here cannot be read: " + err.Error()
	}
	if st.Reason != "paused" {
		return false, ""
	}
	return true, move + ", and its domain here is paused: it may be the only copy of the guest"
}

// holdForUnresolvedMove is unresolvedMoveHolds for a start, logging a hold
// once per VM and cause.
func (r *Reconciler) holdForUnresolvedMove(ctx context.Context, name string) bool {
	held, why := r.unresolvedMoveHolds(ctx, name)
	r.moveHoldMu.Lock()
	defer r.moveHoldMu.Unlock()
	if !held {
		delete(r.moveHoldLogged, name)
		return false
	}
	if r.moveHoldLogged == nil {
		r.moveHoldLogged = map[string]string{}
	}
	if r.moveHoldLogged[name] != why {
		r.moveHoldLogged[name] = why
		slog.Warn("reconciler: not starting the VM — its paused domain here is kept while its move is unresolved; "+
			"resume it to run it here, or destroy it to start the VM from its disks",
			"vm", name, "why", why)
	}
	return true
}
