package health

import (
	"context"
	"log/slog"

	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// A deleted VM's leftovers on a host a failover moved it off.
//
// A VM restarted elsewhere by a failover leaves its real disk on the failed
// host, which sets it aside once it is back (stranded_disk.go), and its
// cloud-init seed (<data_dir>/cloudinit/<name>.iso). `lv rm` runs on the VM's
// owner and frees what is there. On lab 1 (hdv-1, 2026-10-15) the old host
// kept both, with vm_disk_stranded raised, until they were removed by hand.
//
// Once its replica holds the VM's tombstone and no live row, the host the
// record names, on its own reconciler pass — a host that was down during the
// delete, once it is back:
//
//   - keeps every copy already set aside. A copy is the only line of the
//     VM's data from before a failover, and the retention for a deleted VM's
//     copies (superseded_retention.go, superseded_disk_retention_days) is the
//     undo for `lv rm`: the hourly sweep removes it when it is old enough;
//   - sets aside a disk of that VM still at its path (the host was down when
//     the VM was deleted), by the rule the host sets one aside by while the
//     VM exists (setAsideStrandedFile), so it enters the same retention.
//     Nothing is deleted. Only an entry recorded for the incarnation the
//     tombstone names (created_at), at one of the disk paths the VM's rows
//     record, is set aside; any other file stays where it is. The replica is
//     read again for a live row of the name immediately before the rename: a
//     VM created again under the name is never touched (noLiveRow);
//   - removes the VM's own cloud-init seed: one stamped with the deleted VM's
//     spec uuid (cloudinit/seed_owner.go), and only while no domain of the
//     name is live here. An unstamped seed, or one of another VM of the name,
//     is left alone, and is never reused by another VM;
//   - resolves the record. It stays open while the disk at its path cannot be
//     set aside yet: a domain of the name is live here, or the storage does
//     not answer.
//
// Nothing here starts, stops, undefines or adopts a domain, and nothing is
// written to a replicated table but the record itself.

// tendDeletedVMStranded decides this host's record of name's disks once no
// live row of name exists, and returns the entries the record keeps: nil
// resolves it.
func (r *Reconciler) tendDeletedVMStranded(ctx context.Context, name string, ev StrandedDisks) []StrandedDisk {
	createdAt, spec, err := corrosion.GetTombstonedVM(ctx, r.db, name)
	if err != nil {
		return ev.Disks
	}
	if createdAt == "" || r.virt == nil {
		// No tombstone (a replica reseeded, or a name never seen), or no way
		// to tell whether a domain of the name is live: nothing is acted on.
		slog.Info("reconciler: vm_disk_stranded resolved — the VM was deleted; its disk copies here follow the retention for a deleted VM's",
			"vm", name)
		return nil
	}
	var recorded map[string]bool
	var kept []StrandedDisk
	for _, d := range ev.Disks {
		if d.Copy != "" {
			continue // the retention sweep's
		}
		if recorded == nil {
			rows, err := corrosion.VMIncarnationDisks(ctx, r.db, name, createdAt)
			if err != nil {
				return ev.Disks
			}
			recorded = map[string]bool{}
			for _, row := range rows {
				recorded[row.Path] = true
			}
		}
		if d.Incarnation != createdAt || !recorded[d.Path] {
			slog.Warn("reconciler: leaving a file at a deleted VM's disk path that was not recorded for that VM",
				"vm", name, "path", d.Path, "recorded_for", d.Incarnation, "deleted", createdAt)
			continue
		}
		set, outcome := r.setAsideStrandedFile(ctx, name, d, func() bool { return r.noLiveRow(ctx, name) })
		switch outcome {
		case setAsideBlocked:
			kept = append(kept, d)
		case setAsideDone:
			slog.Warn("reconciler: set aside the real disk of a deleted VM a failover left here; it follows the retention for a deleted VM's",
				"vm", name, "disk", d.Disk, "path", d.Path, "set_aside_to", set.Copy)
		}
	}
	if r.domainAbsentOrDeadLeftover(name) {
		r.removeDeletedVMSeed(name, cloudinit.SpecUUID(spec))
	}
	if len(kept) == 0 {
		slog.Info("reconciler: vm_disk_stranded resolved — the VM was deleted; its disk copies here follow the retention for a deleted VM's",
			"vm", name)
	}
	return kept
}

// noLiveRow reports whether this host's replica holds no live row of name,
// read now. A VM of the name created again — on this host, its disk written
// before its row — is never set aside: once its row is here, the deleted-VM
// pass leaves the path alone. An unreadable row answers no.
func (r *Reconciler) noLiveRow(ctx context.Context, name string) bool {
	vm, err := corrosion.GetVM(ctx, r.db, name)
	return err == nil && vm == nil
}

// removeDeletedVMSeed removes name's cloud-init seed here when it is stamped
// as the deleted VM's, whose spec uuid is owner.
func (r *Reconciler) removeDeletedVMSeed(name, owner string) {
	if r.dataDir == "" || owner == "" {
		return
	}
	iso, err := lv.SafeCloudInitISOPath(r.dataDir, name)
	if err != nil {
		return
	}
	stamp, stamped, err := cloudinit.SeedOwner(iso)
	if err != nil || !stamped || stamp != owner {
		return
	}
	if err := cloudinit.RemoveSeed(iso); err != nil {
		slog.Warn("reconciler: could not remove a deleted VM's cloud-init seed", "vm", name, "path", iso, "error", err)
		return
	}
	slog.Info("reconciler: removed a deleted VM's cloud-init seed", "vm", name, "path", iso)
}
