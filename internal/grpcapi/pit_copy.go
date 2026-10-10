package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/notify"
	"github.com/litevirt/litevirt/internal/randid"
)

// Point-in-time copies of a VM disk (colonelpanik/litevirt#256).
//
// A full replica or pool copy of a disk a guest still has open used to be
// `qemu-img convert -U`: a read of a changing image with no snapshot, smeared
// across the time the read takes, so neither point-in-time nor
// crash-consistent. copyVMDiskConsistent replaces it with the strongest copy
// the host can make, in layers:
//
//  0. A disk that is definitely closed (sourceClosedForPlainCopy) is copied
//     plainly, WITHOUT -U: qemu's image lock then fails the copy closed if a
//     "stopped" record is wrong.
//  1. A full pull-mode backup session (BackupSource.BeginBackup with no
//     checkpoints): qemu exports the disk as of the instant the job starts.
//  2. When no session opens or its transfer fails: an external disk-only
//     snapshot (quiesced through the guest agent when one answers, else
//     crash-consistent), a plain copy of the now-frozen disk file, then an
//     active block-commit of the overlay back into it. Still point-in-time.
//  3. When that fails too, and the caller allows it: main's
//     `qemu-img convert -U` copy (convertImageForceShare, the only -U copy
//     left). The result is NOT point-in-time; the caller records it so
//     (replica records' not_point_in_time) and reports it with an event and a
//     notification. Nothing main allowed is refused.

// PointInTimeSnapshotter is layer 2's libvirt boundary. *libvirt.Client
// implements it; a fake stands in for tests.
type PointInTimeSnapshotter interface {
	// SnapshotDiskExternal moves the guest's writes to the disk whose
	// source is diskPath onto overlay. On error the domain is still on
	// diskPath.
	SnapshotDiskExternal(domain, diskPath, overlay string) (quiesced bool, err error)
	// CommitDiskOverlay merges overlay back into diskPath and leaves the
	// domain (live and persistent) on diskPath. A domain not on overlay is
	// left alone.
	CommitDiskOverlay(domain, diskPath, overlay string) error
	// DomainUsesFile reports whether the live or persistent definition
	// names path.
	DomainUsesFile(domain, path string) (bool, error)
}

var _ PointInTimeSnapshotter = (*lv.Client)(nil)

// SetPointInTimeSnapshotter wires layer 2.
func (s *Server) SetPointInTimeSnapshotter(p PointInTimeSnapshotter) { s.pitSnapshotter = p }

// copyMethod is how a copy was made.
type copyMethod string

const (
	copyPlain                    copyMethod = "plain copy of a shut-off disk"
	copyBackupSession            copyMethod = "backup session"
	copyExternalSnapshot         copyMethod = "external snapshot (crash-consistent)"
	copyExternalSnapshotQuiesced copyMethod = "external snapshot (quiesced)"
	copyForceShare               copyMethod = "qemu-img convert -U (NOT point-in-time)"
)

// pointInTime reports whether the copy is a single instant of the disk.
func (m copyMethod) pointInTime() bool { return m != copyForceShare }

// copyResult is a finished copy: how it was made, and, for a copy that is
// not point-in-time, why the point-in-time layers failed.
type copyResult struct {
	method copyMethod
	why    string
}

// errNoPointInTimeCopy marks a copy the caller refused to make with -U after
// every point-in-time layer failed (a retry run, pit_retry.go).
var errNoPointInTimeCopy = errors.New("no point-in-time copy of the running disk could be made")

// copyVMDiskConsistent copies vm's disk d into dst (a file the caller made
// for it) by the strongest means available (the layers above). With
// allowForceShare false, layer 3 is not tried and errNoPointInTimeCopy is
// returned instead.
func (s *Server) copyVMDiskConsistent(ctx context.Context, vm *corrosion.VMRecord, d *corrosion.DiskRecord, dst string, emit func(*pb.MoveVolumeProgress) error, allowForceShare bool) (copyResult, error) {
	if err := s.healPITOverlay(ctx, vm, d); err != nil {
		return copyResult{}, err
	}
	if s.sourceClosedForPlainCopy(vm) {
		return copyResult{method: copyPlain}, s.convertVMDisk(ctx, d, dst, emit)
	}
	var why []string
	err := s.copyViaBackupSession(ctx, vm, d, dst, emit)
	if err == nil {
		return copyResult{method: copyBackupSession}, nil
	}
	why = append(why, "backup session: "+err.Error())
	m, err := s.copyViaExternalSnapshot(ctx, vm, d, dst, emit)
	if err == nil {
		return copyResult{method: m}, nil
	}
	why = append(why, "external snapshot: "+err.Error())
	reason := strings.Join(why, "; ")
	if !allowForceShare {
		return copyResult{}, fmt.Errorf("%w (%s)", errNoPointInTimeCopy, reason)
	}
	slog.Warn("copy: no point-in-time copy of a running disk could be made; copying it with qemu-img convert -U, NOT point-in-time",
		"vm", vm.Name, "disk", d.DiskName, "state", vm.State, "why", reason)
	if err := convertImageForceShare(ctx, s.hostDiskFile(d.Path), "qcow2", s.diskChainRule(ctx, *d), dst, emit); err != nil {
		return copyResult{}, err
	}
	return copyResult{method: copyForceShare, why: reason}, nil
}

// sourceClosedForPlainCopy reports whether vm's disks are definitely closed,
// so a plain copy (no -U, no snapshot) is a copy of one instant. libvirt says
// so (sourceIsShutOff), or there is no libvirt backend on this host at all
// and the store says stopped: then no domain of ours holds the file, and the
// copy, which runs without -U, still fails on qemu's lock rather than smear if
// any qemu does.
func (s *Server) sourceClosedForPlainCopy(vm *corrosion.VMRecord) bool {
	if s.virt == nil {
		return vm.State == "stopped"
	}
	return s.sourceIsShutOff(vm)
}

// copyViaBackupSession is layer 1: a full pull-mode backup session (no
// parent, no new checkpoint, so no incremental chain is touched) read into a
// raw scratch beside dst, then converted into dst. Neither file is open to
// anything else, so the conversion needs no -U.
func (s *Server) copyViaBackupSession(ctx context.Context, vm *corrosion.VMRecord, d *corrosion.DiskRecord, dst string, emit func(*pb.MoveVolumeProgress) error) error {
	if s.backupSource == nil {
		return errors.New("no backup source on this host")
	}
	session, err := s.backupSource.BeginBackup(vm.Name, d.Path, "", "")
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer session.Close()
	extents, err := session.ChangedExtents()
	if err != nil {
		return fmt.Errorf("extents: %w", err)
	}
	f, err := os.CreateTemp(filepath.Dir(dst), ".repl-*.tmp")
	if err != nil {
		return fmt.Errorf("scratch: %w", err)
	}
	scratch := f.Name()
	defer os.Remove(scratch)
	size := session.Size()
	werr := f.Truncate(size)
	if werr == nil {
		werr = forEachExtentChunk(session, extents, size, func(off int64, data []byte) error {
			_, err := f.WriteAt(data, off)
			return err
		})
	}
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("transfer: %w", werr)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return convertImage(ctx, scratch, "raw", nil, dst, emit)
}

// pitOverlayPath is the overlay layer 2 snapshots diskPath onto: one fixed,
// dotted name beside the disk, so one left by a crash or a failed commit is
// found again (healPITOverlay) and no sweep of "<vm>-*.qcow2" matches it.
func pitOverlayPath(diskPath string) string {
	return filepath.Join(filepath.Dir(diskPath), "."+filepath.Base(diskPath)+".lv-pit")
}

// copyViaExternalSnapshot is layer 2. On every path out the overlay is gone,
// or the domain is back on its disk and the overlay removed, or — a commit
// that failed — the domain stays on the overlay with an event and a
// notification saying so, the overlay kept (it holds the guest's writes), and
// the next copy of this disk commits it first (healPITOverlay).
func (s *Server) copyViaExternalSnapshot(ctx context.Context, vm *corrosion.VMRecord, d *corrosion.DiskRecord, dst string, emit func(*pb.MoveVolumeProgress) error) (copyMethod, error) {
	if s.pitSnapshotter == nil {
		return "", errors.New("no snapshotter on this host")
	}
	overlay := pitOverlayPath(d.Path)
	quiesced, err := s.pitSnapshotter.SnapshotDiskExternal(vm.Name, d.Path, overlay)
	if err != nil {
		// Atomic: the domain is still on its disk. A file the failed
		// snapshot left behind goes, unless the domain names it after all.
		if herr := s.healPITOverlay(ctx, vm, d); herr != nil {
			return "", fmt.Errorf("snapshot: %v; and its overlay: %w", err, herr)
		}
		return "", fmt.Errorf("snapshot: %w", err)
	}
	// The disk's own file is frozen now: guest writes go to the overlay.
	copyErr := s.convertVMDisk(ctx, d, dst, emit)
	if err := s.commitPITOverlay(ctx, vm, d, overlay); err != nil {
		if copyErr != nil {
			return "", fmt.Errorf("copy of the frozen disk: %v; commit: %w", copyErr, err)
		}
		// The copy is a good point-in-time copy; the domain's state is what
		// failed, and it has been reported.
	}
	if copyErr != nil {
		return "", fmt.Errorf("copy of the frozen disk: %w", copyErr)
	}
	if quiesced {
		return copyExternalSnapshotQuiesced, nil
	}
	return copyExternalSnapshot, nil
}

// commitPITOverlay commits overlay back into d and removes it once nothing
// names it. A failure leaves the overlay where it is — the domain may be
// running on it — and says so loudly.
func (s *Server) commitPITOverlay(ctx context.Context, vm *corrosion.VMRecord, d *corrosion.DiskRecord, overlay string) error {
	err := s.pitSnapshotter.CommitDiskOverlay(vm.Name, d.Path, overlay)
	if err == nil {
		var used bool
		used, err = s.pitSnapshotter.DomainUsesFile(vm.Name, overlay)
		if err == nil && used {
			err = fmt.Errorf("the domain still names %s after the commit", overlay)
		}
	}
	if err != nil {
		detail := fmt.Sprintf("%s: the point-in-time snapshot overlay %s could not be committed back into %s (%v); the VM keeps running on the overlay, which is kept. The next replication or move of this disk commits it first; until then do not delete %s",
			d.DiskName, overlay, d.Path, err, overlay)
		slog.Error("copy: point-in-time overlay not committed; the VM runs on it", "vm", vm.Name, "disk", d.DiskName, "overlay", overlay, "error", err)
		s.recordVMEventSeverity(ctx, vm.Name, "disk.pit_overlay_stranded", "error", "error", detail)
		s.notify(ctx, notify.Notification{
			Kind: "replication.pit_overlay_stranded", Severity: notify.SevError, Subject: vm.Name, Detail: detail,
		})
		return err
	}
	if rerr := os.Remove(s.hostDiskFile(overlay)); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
		slog.Warn("copy: committed point-in-time overlay not removed", "vm", vm.Name, "overlay", overlay, "error", rerr)
	}
	return nil
}

// healPITOverlay finishes what an earlier layer-2 copy of d left: a domain
// still on the overlay (a commit that failed, or a daemon that died
// mid-copy) is committed back, and an overlay nothing names is removed. It
// fails — and the copy is not made — only when the overlay cannot be
// resolved, because any copy of d's file would then miss the guest's writes
// held in the overlay.
func (s *Server) healPITOverlay(ctx context.Context, vm *corrosion.VMRecord, d *corrosion.DiskRecord) error {
	overlay := pitOverlayPath(d.Path)
	if _, err := os.Lstat(s.hostDiskFile(overlay)); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if s.pitSnapshotter == nil {
		return fmt.Errorf("%s: a point-in-time snapshot overlay %s is present and this host has no snapshotter to commit it; the disk's file may not hold the guest's latest writes", d.DiskName, overlay)
	}
	used, err := s.pitSnapshotter.DomainUsesFile(vm.Name, overlay)
	if err != nil {
		return fmt.Errorf("%s: cannot tell whether the domain runs on the overlay %s: %w", d.DiskName, overlay, err)
	}
	if used {
		if err := s.commitPITOverlay(ctx, vm, d, overlay); err != nil {
			return fmt.Errorf("%s: the domain runs on the point-in-time overlay %s and it could not be committed: %w", d.DiskName, overlay, err)
		}
		s.recordVMEventSeverity(ctx, vm.Name, "disk.pit_overlay_committed", "ok", "info",
			fmt.Sprintf("%s: an earlier point-in-time overlay %s was committed back into %s", d.DiskName, overlay, d.Path))
		return nil
	}
	if err := os.Remove(s.hostDiskFile(overlay)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s: remove an unused point-in-time overlay %s: %w", d.DiskName, overlay, err)
	}
	return nil
}

// reportNotPointInTime is the event and notification every layer-3 copy
// gets. what names the copy ("replica <file> in <pool>").
func (s *Server) reportNotPointInTime(ctx context.Context, vm *corrosion.VMRecord, d *corrosion.DiskRecord, what, why string) {
	detail := fmt.Sprintf("%s: %s is NOT point-in-time — no backup session or external snapshot could be made of the %s disk (%s), so it was copied with qemu-img convert -U and may be inconsistent. Automatic promotion will not use it while a point-in-time replica exists, and manual promotion asks for --accept-not-point-in-time",
		d.DiskName, what, vm.State, why)
	s.recordVMEventSeverity(ctx, vm.Name, "disk.replica_not_point_in_time", "warning", "warn", detail)
	s.notify(ctx, notify.Notification{
		Kind: "replication.not_point_in_time", Severity: notify.SevWarn, Subject: vm.Name, Detail: detail,
	})
}

// recordVMEventSeverity is recordVMEvent with the severity named rather than
// derived from the result.
func (s *Server) recordVMEventSeverity(ctx context.Context, vmName, evType, result, severity, detail string) {
	if s.db != nil {
		if err := corrosion.InsertVMEvent(ctx, s.db, corrosion.VMEventRecord{
			ID: randid.New(), VMName: vmName, HostName: s.hostName, Type: evType,
			Result: result, Severity: severity, Detail: detail, Username: callerUsername(ctx),
		}); err != nil {
			slog.Warn("vm_event insert failed", "vm", vmName, "type", evType, "error", err)
		}
	}
	if s.events != nil {
		s.events.Publish(events.Event{Action: evType, Target: vmName, Detail: detail})
	}
}
