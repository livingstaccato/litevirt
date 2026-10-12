package health

import (
	"context"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A start whose row went while it was being prepared (lab 2 run c713, N-2).
//
// startPendingVM decides from the row it re-reads under the start lease, then
// spends a while preparing — disks, images, the hardware pre-start, the
// define — before it boots the domain. A DeleteVM on this host holds the same
// lease (grpcapi deleteLockHolder), so it cannot land in that window. A row
// can still go there by replication: a delete run by an older binary, which
// takes no lease; a removed host's rows deleted from another host; an LWW
// tombstone. Booting the domain then leaves a running guest that no record
// names. On the lab that guest (icr4-1) had no disks — the delete had already
// dropped its disk rows — and ran for 25 minutes, visible only to the
// capacity evaluator: the managed stamp the orphan-runtime report recognises
// is adopted only from a live row, so it carried none.
//
// So the start re-reads the row immediately before it boots the domain and
// boots nothing when the row is gone or names another host. And because the
// boot itself cannot be atomic with a replicated tombstone, it looks once
// more after the boot: a guest it started a moment ago for a row that is now
// gone is stopped (startedForGoneRow).

// startRowGone re-reads name's row right before its domain is booted. It
// returns why the start must not go ahead — the row is gone, names another
// host, or cannot be read (a start that cannot confirm its row does not
// boot; the next pass retries) — or "" when the row is still this host's.
func (r *Reconciler) startRowGone(ctx context.Context, name string) string {
	row, err := corrosion.GetVM(ctx, r.db, name)
	switch {
	case err != nil:
		return "its record could not be re-read: " + err.Error()
	case row == nil:
		return "its record is gone (deleted)"
	case row.HostName != r.hostName:
		return "its record now names host " + row.HostName
	}
	return ""
}

// startedForGoneRow handles a guest this pass booted whose row was gone by
// the time the boot returned. It reports whether that was the case.
//
// Only an ABSENT row counts — read without error and not there. A read error
// proves nothing, and a row that names another host is ownership moving
// under a running guest, which the owner-epoch and dual-run machinery own.
//
// What it does is bounded by what is provably this pass's own doing:
//
//   - the guest is stopped. It was booted here a moment ago from a record
//     that no longer exists, so stopping it returns the host to where it was
//     before this pass, and it keeps the guest off disks a delete may be
//     freeing;
//   - a disk-less domain is undefined. It references no disk, so nothing in
//     it can be wanted; firmware state is kept all the same (the delete's to
//     wipe, not the reconciler's);
//   - a domain with disks is kept, shut off, and given the managed stamp with
//     the incarnation it was started for. The orphan-runtime report then
//     names it (vm_orphan_runtime) and docs/diagnostics.md has the reap
//     procedure. Its disks may belong to a tombstone the operator did not
//     intend; undefining it is not the reconciler's call.
func (r *Reconciler) startedForGoneRow(ctx context.Context, vm corrosion.VMRecord, disks int) bool {
	row, err := corrosion.GetVM(ctx, r.db, vm.Name)
	if err != nil || row != nil {
		return false
	}
	slog.Error("reconciler: the VM's record was deleted while this pass booted its domain — stopping the guest it just started",
		"vm", vm.Name, "disks", disks)
	if err := r.virt.DestroyDomain(vm.Name); err != nil {
		slog.Error("reconciler: could not stop a guest started for a deleted record; it is running with no record",
			"vm", vm.Name, "error", err)
	}
	if disks == 0 {
		if err := r.virt.UndefineDomainPreservingState(vm.Name); err != nil {
			slog.Error("reconciler: could not undefine a disk-less domain started for a deleted record",
				"vm", vm.Name, "error", err)
		} else {
			slog.Warn("reconciler: removed the disk-less domain it had started for a deleted record", "vm", vm.Name)
			return true
		}
	}
	state, _ := r.virt.DomainState(vm.Name)
	if err := r.virt.SetDomainManagedIncarnation(vm.Name, corrosion.IncarnationOf(vm.CreatedAt), state == RuntimeRunning); err != nil {
		slog.Error("reconciler: could not stamp a domain started for a deleted record; the orphan report cannot name it",
			"vm", vm.Name, "error", err)
	} else {
		slog.Warn("reconciler: kept the domain started for a deleted record, shut off, for the orphan-runtime report — not reaped",
			"vm", vm.Name, "state", state)
	}
	return true
}
