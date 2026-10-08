package grpcapi

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// diskStem strips a disk path's file extension. litevirt names a data disk
// <dir>/<vm>-<disk>.qcow2, and libvirt names its external-snapshot overlays
// <dir>/<vm>-<disk>.<snapname> (same dir + stem, only the extension swapped),
// so the stem is the disk's stable identity across snapshot operations.
func diskStem(p string) string {
	return strings.TrimSuffix(p, filepath.Ext(p))
}

// reconcileDiskPaths syncs the recorded vm_disks.path to the live domain's
// active disk sources. A snapshot create/revert/delete cuts the domain over to
// an overlay (<disk>.<snapname>), and libvirt consolidates the chain on delete,
// leaving the active disk named after a (possibly deleted) snapshot. Without
// reconciliation the recorded path diverges from reality and backup, migration,
// and restart-from-record all use a stale or absent path (the observed bug:
// "no disk with source …qcow2 in domain" + a leaked overlay on VM delete).
//
// Best-effort and must run on the VM's host (where s.virt is the right libvirt).
// A failure only leaves the path stale — the prior behaviour — and never
// touches disk contents. Matching is by filename stem so it holds whether the
// extension is .qcow2 (canonical) or .<snapname> (overlay).
func (s *Server) reconcileDiskPaths(ctx context.Context, vmName string) {
	if s.virt == nil || s.db == nil {
		return
	}
	live, err := s.virt.DomainDiskSources(vmName)
	if err != nil {
		slog.Warn("snapshot: read live disk sources for reconcile failed", "vm", vmName, "error", err)
		return
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		return
	}
	// The directory is compared resolved: a record and a domain may name one
	// directory through different symlinks (review I-4).
	key := func(p string) string {
		return filepath.Join(resolvedOr(filepath.Dir(s.hostDiskFile(p))), diskStem(filepath.Base(p)))
	}
	liveByStem := make(map[string]string, len(live))
	for _, src := range live {
		liveByStem[key(src)] = src
	}
	for _, d := range disks {
		// A record on a layer marked merged moves to the file its data went
		// to (re-review 3, I-1): what reads the record — a clone, a move, a
		// backup, a cold migration — then reads the VM's current data,
		// never the stale layer. A start judges the definition, not the
		// record, and still refuses (refuseMergedLayerBoot).
		if into, merged := lv.MergedInto(resolvedOr(s.hostDiskFile(d.Path))); merged {
			if into != d.Path {
				if err := corrosion.UpdateVMDiskPath(ctx, s.db, vmName, d.DiskName, into); err != nil {
					slog.Warn("snapshot: move the record off a merged layer", "vm", vmName, "disk", d.DiskName, "error", err)
				} else {
					slog.Warn("snapshot: the record moved off a merged layer to where its data is",
						"vm", vmName, "disk", d.DiskName, "from", d.Path, "to", into)
				}
			}
			continue
		}
		src, ok := liveByStem[key(d.Path)]
		if !ok || src == d.Path {
			continue
		}
		if err := corrosion.UpdateVMDiskPath(ctx, s.db, vmName, d.DiskName, src); err != nil {
			slog.Warn("snapshot: reconcile disk path failed", "vm", vmName, "disk", d.DiskName, "error", err)
			continue
		}
		slog.Info("snapshot: reconciled disk path to live source",
			"vm", vmName, "disk", d.DiskName, "from", d.Path, "to", src)
	}
}
