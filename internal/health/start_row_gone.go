package health

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
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
// boots nothing when the row is gone, is another incarnation, or names
// another host. And because the boot itself cannot be atomic with a
// replicated tombstone, it looks once more after the boot: a guest it started
// a moment ago for a row that is now gone is stopped (startedForGoneRow).
//
// "Gone" includes a row of the same name with another created_at: a delete
// and a re-create inside one start. The domain this pass built is the old
// incarnation's — its spec, its disks — and must not run as the new one.

// startRowGone re-reads name's row right before its domain is booted. It
// returns why the start must not go ahead — the row is gone, is another
// incarnation than createdAt, names another host, or cannot be read
// (unreadable: retried next pass) — or "" when the row is still the one this
// start was decided from.
func (r *Reconciler) startRowGone(ctx context.Context, name, createdAt string) (why string, unreadable bool) {
	row, err := corrosion.GetVM(ctx, r.db, name)
	if r.startRowReadFault != nil {
		if ferr := r.startRowReadFault(name); ferr != nil {
			row, err = nil, ferr
		}
	}
	switch {
	case err != nil:
		return "its record could not be re-read: " + err.Error(), true
	case row == nil:
		return "its record is gone (deleted)", false
	case row.CreatedAt != createdAt:
		return "its record was deleted and created again (created_at " + row.CreatedAt + ", not " + createdAt + ")", false
	case row.HostName != r.hostName:
		return "its record now names host " + row.HostName, false
	}
	return "", false
}

// nvramExists reports whether name's UEFI vars file is present, for the
// before-define snapshot startedForGoneRow judges ownership by. A stat that
// fails for any reason but absence counts as present: never proven ours.
func nvramExists(fw *lv.FirmwareStore, name string) bool {
	_, err := os.Stat(fw.NvramPath(name))
	return !errors.Is(err, fs.ErrNotExist)
}

// startedForGoneRow handles a guest this pass booted whose row was gone by
// the time the boot returned: absent, or another incarnation of the name. It
// reports whether that was the case.
//
// A read error proves nothing, and a row of the same incarnation that names
// another host is ownership moving under a running guest, which the
// owner-epoch and dual-run machinery own; neither counts.
//
// What it does is bounded by what is provably this pass's own doing:
//
//   - the guest is stopped. It was booted here a moment ago from a record
//     that no longer exists, so stopping it returns the host to where it was
//     before this pass, and it keeps the guest off disks a delete may be
//     freeing. What the hardware pre-start claimed for it (releaseHW) is
//     given back once it is down;
//   - a disk-less domain is undefined. It references no disk, so nothing in
//     it can be wanted. Its UEFI vars are removed only when this pass's boot
//     created them — absent before the define (nvramBefore false) and no row
//     of the name left to own them — because the file is name-keyed and a
//     later create of the name is refused while it exists. Vars that were
//     there before are kept and named in the log: a `delete --keep-disks`
//     keeps them on purpose. vTPM state is uuid-keyed, blocks no create, and
//     is never touched;
//   - a domain with disks is kept, shut off, and given the managed stamp with
//     the incarnation it was started for. The orphan-runtime report then
//     names it (vm_orphan_runtime) and docs/diagnostics.md has the reap
//     procedure. Its disks may belong to a tombstone the operator did not
//     intend; undefining it is not the reconciler's call.
func (r *Reconciler) startedForGoneRow(ctx context.Context, vm corrosion.VMRecord, disks int, releaseHW func(), nvramBefore bool) bool {
	row, err := corrosion.GetVM(ctx, r.db, vm.Name)
	if err != nil || (row != nil && row.CreatedAt == vm.CreatedAt) {
		return false
	}
	slog.Error("reconciler: the VM's record was deleted while this pass booted its domain — stopping the guest it just started",
		"vm", vm.Name, "disks", disks, "record_recreated", row != nil)
	if err := r.virt.DestroyDomain(vm.Name); err != nil {
		slog.Error("reconciler: could not stop a guest started for a deleted record; it is running with no record",
			"vm", vm.Name, "error", err)
	} else if releaseHW != nil {
		releaseHW()
	}
	if disks == 0 {
		if err := r.virt.UndefineDomainPreservingState(vm.Name); err != nil {
			slog.Error("reconciler: could not undefine a disk-less domain started for a deleted record",
				"vm", vm.Name, "error", err)
		} else {
			nvram := r.fwStore.NvramPath(vm.Name)
			switch {
			case !nvramExists(r.fwStore, vm.Name):
				slog.Warn("reconciler: removed the disk-less domain it had started for a deleted record", "vm", vm.Name)
			case !nvramBefore && row == nil:
				if rerr := r.fwStore.RemoveNvram(vm.Name); rerr != nil {
					slog.Warn("reconciler: removed the disk-less domain it had started for a deleted record; "+
						"the UEFI vars its boot created could not be removed and block a create of the name until they are",
						"vm", vm.Name, "nvram", nvram, "error", rerr)
				} else {
					slog.Warn("reconciler: removed the disk-less domain it had started for a deleted record, and the UEFI vars its boot created",
						"vm", vm.Name, "nvram", nvram)
				}
			default:
				slog.Warn("reconciler: removed the disk-less domain it had started for a deleted record; "+
					"UEFI vars it did not create are kept and block a create of the name (docs/diagnostics.md)",
					"vm", vm.Name, "nvram", nvram)
			}
			return true
		}
	}
	state, _ := r.virt.DomainState(vm.Name)
	if err := r.virt.SetDomainManagedIncarnation(vm.Name, corrosion.IncarnationOf(vm.CreatedAt), state == RuntimeRunning); err != nil {
		slog.Error("reconciler: could not stamp a domain started for a deleted record; the orphan report cannot name it",
			"vm", vm.Name, "error", err)
	} else {
		slog.Warn("reconciler: kept the domain started for a deleted record, shut off, for the orphan-runtime report — not reaped",
			"vm", vm.Name, "state", state, "nvram", r.fwStore.NvramPath(vm.Name))
	}
	return true
}
