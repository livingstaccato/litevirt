package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// diskStem strips a disk path's file extension. litevirt names a data disk
// <dir>/<vm>-<disk>.qcow2, and libvirt names its external-snapshot overlays
// <dir>/<vm>-<disk>.<snapname> (same dir + stem, only the extension swapped),
// so the stem is the disk's stable identity across snapshot operations.
func diskStem(p string) string {
	return strings.TrimSuffix(p, filepath.Ext(p))
}

// diskStemNamed is diskStem knowing the VM's snapshot names. libvirt names
// a snapshot's overlay <stem>.<snapshot>, and a restore of an older snapshot
// names its overlay <stem>.<snapshot>-r<time>; a snapshot name with a dot
// (v1.2) would be cut at the wrong dot by diskStem (re-review R2-M3). A
// known name — the longest that fits — is cut off whole; anything else is
// cut as diskStem cuts it, and so reads as a different disk, which keeps
// it (no record is moved to it, no file of it is taken).
func diskStemNamed(p string, snapNames []string) string {
	dir, base := filepath.Dir(p), filepath.Base(p)
	names := append([]string(nil), snapNames...)
	sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
	for _, n := range names {
		if n == "" {
			continue
		}
		if i := strings.LastIndex(base, "."+n+"-r"); i > 0 && revertSuffix(base[i+len(n)+3:]) {
			return filepath.Join(dir, base[:i])
		}
		if stem, ok := strings.CutSuffix(base, "."+n); ok && stem != "" {
			return filepath.Join(dir, stem)
		}
	}
	return diskStem(p)
}

// revertSuffix reports the <time>[-<n>] a restore's overlay name ends in.
func revertSuffix(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// snapshotNamesOf is vm's snapshot names, plus extra (a snapshot just
// deleted, whose overlay may still be the recorded path).
func (s *Server) snapshotNamesOf(ctx context.Context, vm string, extra ...string) []string {
	names := append([]string(nil), extra...)
	if snaps, err := corrosion.ListSnapshots(ctx, s.db, vm); err == nil {
		for _, sn := range snaps {
			names = append(names, sn.Name)
		}
	}
	return names
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
func (s *Server) reconcileDiskPaths(ctx context.Context, vmName string, extraSnaps ...string) {
	_ = s.reconcileDiskPathsErr(ctx, vmName, extraSnaps...)
}

// reconcileDiskPathsErr is reconcileDiskPaths, reporting whether every
// recorded path could be brought to the live source.
func (s *Server) reconcileDiskPathsErr(ctx context.Context, vmName string, extraSnaps ...string) error {
	if s.virt == nil || s.db == nil {
		return nil
	}
	live, err := s.virt.DomainDiskSources(vmName)
	if err != nil {
		slog.Warn("snapshot: read live disk sources for reconcile failed", "vm", vmName, "error", err)
		return fmt.Errorf("read the domain's disk sources: %w", err)
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		return fmt.Errorf("read the VM's disk records: %w", err)
	}
	var firstErr error
	names := s.snapshotNamesOf(ctx, vmName, extraSnaps...)
	liveByStem := make(map[string]string, len(live))
	for _, src := range live {
		liveByStem[diskStemNamed(src, names)] = src
	}
	for _, d := range disks {
		src, ok := liveByStem[diskStemNamed(d.Path, names)]
		if !ok || src == d.Path {
			continue
		}
		if err := corrosion.UpdateVMDiskPath(ctx, s.db, vmName, d.DiskName, src); err != nil {
			slog.Warn("snapshot: reconcile disk path failed", "vm", vmName, "disk", d.DiskName, "error", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("record disk %s at %s: %w", d.DiskName, src, err)
			}
			continue
		}
		slog.Info("snapshot: reconciled disk path to live source",
			"vm", vmName, "disk", d.DiskName, "from", d.Path, "to", src)
	}
	return firstErr
}
