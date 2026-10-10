package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/notify"
	"github.com/litevirt/litevirt/internal/pitoverlay"
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
	// CommitDiskOverlay merges overlay back into diskPath (live, on an
	// active domain on it) and points the persistent definition back at
	// diskPath with diskFormat. An inactive domain's overlay is committed
	// offline by the caller (pitoverlay) first.
	CommitDiskOverlay(domain, diskPath, overlay, diskFormat string) error
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
// so a plain copy (no -U, no snapshot) is a copy of one instant. With libvirt
// on this host its answer is authoritative, whatever the store says: a
// domain libvirt reports shut off (not paused, not pm-suspended) is closed —
// so a VM in "error" whose domain is down is copied and moved offline as
// main did — and anything else is not. With no libvirt backend at all the
// store's "stopped" decides. Either way the copy runs without -U, so qemu's
// lock fails it closed rather than letting it smear if a qemu does hold it.
func (s *Server) sourceClosedForPlainCopy(vm *corrosion.VMRecord) bool {
	if s.virt == nil {
		return vm.State == "stopped"
	}
	st, err := s.virt.DomainStateReason(vm.Name)
	if err != nil {
		return false
	}
	return st.State == "stopped" && st.Reason != "paused" && st.Reason != "pmsuspended"
}

// domainActivity is libvirt's answer about vm's domain.
type domainActivity int

const (
	activityUnknown  domainActivity = iota // libvirt could not say
	activityInactive                       // shut off, or not defined on this host
	activityActive                         // running or paused: qemu holds its disks
)

// domainActivity asks libvirt. A domain this host has not defined is
// inactive here; a state query that errors is unknown — never taken for
// inactive, which would invite an offline commit of a disk a qemu holds.
func (s *Server) domainActivity(vm *corrosion.VMRecord) domainActivity {
	if s.virt == nil || !s.virt.DomainExists(vm.Name) {
		return activityInactive
	}
	st, err := s.virt.DomainStateReason(vm.Name)
	if err != nil {
		return activityUnknown
	}
	if st.State == "running" || st.Reason == "paused" || st.Reason == "pmsuspended" {
		return activityActive
	}
	if st.State == "stopped" {
		return activityInactive
	}
	return activityUnknown
}

// domainActive reports whether libvirt says vm's domain is running or paused
// (the states in which qemu holds its disks and a live snapshot or commit can
// run).
func (s *Server) domainActive(vm *corrosion.VMRecord) bool {
	return s.domainActivity(vm) == activityActive
}

// pitOwner is the owner d's overlay is bound to (pitoverlay.Bind).
func pitOwner(vm *corrosion.VMRecord, d *corrosion.DiskRecord) pitoverlay.Owner {
	uuid, _ := vmSpecUUID(vm.Spec)
	return pitoverlay.Owner{VM: vm.Name, VMUUID: uuid, Disk: d.DiskName}
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

// pitOverlayPath is the overlay layer 2 snapshots diskPath onto
// (pitoverlay.Path): one fixed, dotted name beside the disk on its own pool,
// so any host that sees the disk — a failover target on shared storage
// included — finds it, and no sweep of "<vm>-*.qcow2" matches it.
func pitOverlayPath(diskPath string) string { return pitoverlay.Path(diskPath) }

// pitDiskFormat is the driver type a VM disk's persistent entry is given back
// after its overlay is committed: every VM disk the copy paths read is qcow2
// (convertVMDisk).
const pitDiskFormat = "qcow2"

// copyViaExternalSnapshot is layer 2, for an ACTIVE domain only (libvirt
// would snapshot an inactive one offline, which no live commit can merge).
// On every path out the overlay is gone, or — a commit that failed — the
// domain stays on the overlay with an event and a notification saying so,
// the overlay kept (it holds the guest's writes), and every later define,
// start, move or copy of the disk commits it first (settlePITOverlays,
// health's domainXMLFor), as does the daemon's start-up sweep.
func (s *Server) copyViaExternalSnapshot(ctx context.Context, vm *corrosion.VMRecord, d *corrosion.DiskRecord, dst string, emit func(*pb.MoveVolumeProgress) error) (copyMethod, error) {
	if s.pitSnapshotter == nil {
		return "", errors.New("no snapshotter on this host")
	}
	if !s.domainActive(vm) {
		return "", errors.New("the domain is not running or paused")
	}
	overlay := pitOverlayPath(d.Path)
	quiesced, err := s.pitSnapshotter.SnapshotDiskExternal(vm.Name, d.Path, overlay)
	if err != nil {
		// Atomic: the domain is still on its disk. A file the failed
		// snapshot left behind is settled — committed, never just deleted.
		if herr := s.healPITOverlay(ctx, vm, d); herr != nil {
			return "", fmt.Errorf("snapshot: %v; and its overlay: %w", err, herr)
		}
		return "", fmt.Errorf("snapshot: %w", err)
	}
	// The disk's own file is frozen now: guest writes go to the overlay.
	// Bind the overlay to this very file, so it is never committed into
	// any other (a path reused, a disk rewritten).
	if berr := pitoverlay.Bind(s.hostDiskFile(d.Path), pitOwner(vm, d)); berr != nil {
		slog.Warn("copy: point-in-time overlay not bound to its disk; if its commit fails it will be set aside, not committed",
			"vm", vm.Name, "disk", d.DiskName, "error", berr)
	}
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

// commitPITOverlay live-commits overlay back into d (the domain is active
// and on it) and removes it once nothing names it. A failure leaves the
// overlay where it is — the domain runs on it — and says so loudly.
func (s *Server) commitPITOverlay(ctx context.Context, vm *corrosion.VMRecord, d *corrosion.DiskRecord, overlay string) error {
	// The commit writes the base: from here the binding vouches for the
	// file, not its unchanged contents.
	_ = pitoverlay.MarkCommitting(s.hostDiskFile(d.Path))
	err := s.pitSnapshotter.CommitDiskOverlay(vm.Name, d.Path, overlay, pitDiskFormat)
	if err == nil {
		var used bool
		used, err = s.pitSnapshotter.DomainUsesFile(vm.Name, overlay)
		if err == nil && used {
			err = fmt.Errorf("the domain still names %s after the commit", overlay)
		}
	}
	if err != nil {
		s.reportStrandedOverlay(ctx, vm, d, overlay, err)
		return err
	}
	if rerr := pitoverlay.Remove(s.hostDiskFile(d.Path)); rerr != nil {
		slog.Warn("copy: committed point-in-time overlay not removed", "vm", vm.Name, "overlay", overlay, "error", rerr)
	}
	return nil
}

// reportStrandedOverlay is the event and notification of an overlay that
// could not be committed.
func (s *Server) reportStrandedOverlay(ctx context.Context, vm *corrosion.VMRecord, d *corrosion.DiskRecord, overlay string, err error) {
	detail := fmt.Sprintf("%s: the point-in-time snapshot overlay %s could not be committed back into %s (%v). It holds the guest's newest writes and is kept: never delete it. Every start, move, copy or failover restart of this disk commits it first and refuses until it can; the daemon retries at start-up",
		d.DiskName, overlay, d.Path, err)
	slog.Error("point-in-time overlay not committed", "vm", vm.Name, "disk", d.DiskName, "overlay", overlay, "error", err)
	s.recordVMEventSeverity(ctx, vm.Name, "disk.pit_overlay_stranded", "error", "error", detail)
	s.notify(ctx, notify.Notification{
		Kind: "replication.pit_overlay_stranded", Severity: notify.SevError, Subject: vm.Name, Detail: detail,
	})
}

// healPITOverlay settles an overlay an earlier layer-2 copy of d left (a
// failed commit, a daemon that died mid-window, a failover that carried the
// disk to this host). An overlay that may hold data is never deleted:
//
//   - the domain is active and runs on it: live commit and pivot;
//   - the domain is not active (or not defined here) and the overlay is
//     bound to this VM's disk as the file is now (pitoverlay.Check): commit
//     it offline with qemu-img (no -U), point a persistent definition that
//     names it back at the disk, and only then remove it;
//   - anything else — the running VM uses its disk directly, or the overlay
//     belongs to another VM or another or since-written file — is set aside
//     under a new name, kept, and reported; committing it would write stale
//     blocks over newer data;
//   - libvirt cannot say whether the domain runs: nothing is touched, and the
//     caller retries later.
//
// It fails — and the caller does not proceed — when the overlay cannot be
// settled, because the disk's file would then miss the guest's writes held
// in it.
func (s *Server) healPITOverlay(ctx context.Context, vm *corrosion.VMRecord, d *corrosion.DiskRecord) error {
	disk := s.hostDiskFile(d.Path)
	if !pitoverlay.Present(disk) {
		return nil
	}
	overlay := pitOverlayPath(d.Path)
	switch s.domainActivity(vm) {
	case activityUnknown:
		return fmt.Errorf("%s: a point-in-time overlay %s is present and libvirt cannot say whether %s is running; it is left as it is — retry once libvirt answers", d.DiskName, overlay, vm.Name)
	case activityActive:
		if s.pitSnapshotter == nil {
			return fmt.Errorf("%s: a point-in-time overlay %s is present and this host has no snapshotter to commit it", d.DiskName, overlay)
		}
		used, err := s.pitSnapshotter.DomainUsesFile(vm.Name, overlay)
		if err != nil {
			return fmt.Errorf("%s: cannot tell whether the domain runs on the overlay %s: %w", d.DiskName, overlay, err)
		}
		if !used {
			return s.setAsidePITOverlay(ctx, vm.Name, d.DiskName, disk,
				fmt.Errorf("the running VM uses its disk %s directly", d.Path))
		}
		if err := s.commitPITOverlay(ctx, vm, d, overlay); err != nil {
			return fmt.Errorf("%s: the domain runs on the point-in-time overlay %s and it could not be committed: %w", d.DiskName, overlay, err)
		}
	default:
		_, err := pitoverlay.CommitOffline(ctx, disk, pitOwner(vm, d))
		if errors.Is(err, pitoverlay.ErrNotOurs) {
			return s.setAsidePITOverlay(ctx, vm.Name, d.DiskName, disk, err)
		}
		if err != nil {
			s.reportStrandedOverlay(ctx, vm, d, overlay, err)
			return fmt.Errorf("%s: commit the point-in-time overlay %s: %w", d.DiskName, overlay, err)
		}
		if s.pitSnapshotter != nil && s.virt != nil && s.virt.DomainExists(vm.Name) {
			if err := s.pitSnapshotter.CommitDiskOverlay(vm.Name, d.Path, overlay, pitDiskFormat); err != nil {
				s.reportStrandedOverlay(ctx, vm, d, overlay, err)
				return fmt.Errorf("%s: point the definition back at %s: %w", d.DiskName, d.Path, err)
			}
		}
		if err := pitoverlay.Remove(disk); err != nil {
			return fmt.Errorf("%s: remove the committed overlay %s: %w", d.DiskName, overlay, err)
		}
	}
	s.recordVMEventSeverity(ctx, vm.Name, "disk.pit_overlay_committed", "ok", "info",
		fmt.Sprintf("%s: an earlier point-in-time overlay %s was committed back into %s", d.DiskName, overlay, d.Path))
	return nil
}

// setAsidePITOverlay sets an overlay that must not be committed into disk
// aside under a new name — kept, never committed, never deleted — and says
// so, naming both files. It returns nil: the disk's own file is what the
// caller goes on with.
func (s *Server) setAsidePITOverlay(ctx context.Context, vmName, diskName, disk string, why error) error {
	overlay := pitoverlay.Path(disk)
	to, err := pitoverlay.SetAside(disk, time.Now().UTC().Format("20060102-150405"))
	if err != nil {
		return fmt.Errorf("%s: set the point-in-time overlay %s aside: %w", diskName, overlay, err)
	}
	s.ReportPITOverlaySetAside(ctx, vmName, fmt.Sprintf("%s: the point-in-time overlay %s was not committed into %s (%v): committing it could write stale blocks over newer data. It was kept as %s for an operator to inspect",
		diskName, overlay, disk, why, to))
	return nil
}

// ReportPITOverlaySetAside is the event and notification of an overlay set
// aside (here, or by the reconciler's define path).
func (s *Server) ReportPITOverlaySetAside(ctx context.Context, vmName, detail string) {
	slog.Error("point-in-time overlay set aside", "vm", vmName, "detail", detail)
	s.recordVMEventSeverity(ctx, vmName, "disk.pit_overlay_set_aside", "error", "error", detail)
	s.notify(ctx, notify.Notification{Kind: "replication.pit_overlay_set_aside", Severity: notify.SevError, Subject: vmName, Detail: detail})
}

// setAsideStaleOverlay sets aside any overlay beside a disk file that is
// about to be written afresh (an import, a restore): it cannot belong to the
// new contents.
func (s *Server) setAsideStaleOverlay(ctx context.Context, vmName, diskName, disk string) error {
	if !pitoverlay.Present(disk) {
		return nil
	}
	return s.setAsidePITOverlay(ctx, vmName, diskName, disk, errors.New("the disk is being written afresh"))
}

// settlePITOverlays heals every disk of vm (healPITOverlay): the step every
// define, start, move, migrate, backup or copy of the VM's disks takes
// first.
func (s *Server) settlePITOverlays(ctx context.Context, vm *corrosion.VMRecord) error {
	disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	if err != nil {
		return status.Errorf(codes.Internal, "list disks: %v", err)
	}
	for i := range disks {
		if disks[i].HostName != "" && disks[i].HostName != s.hostName && !pitoverlay.Present(s.hostDiskFile(disks[i].Path)) {
			continue
		}
		if err := s.healPITOverlay(ctx, vm, &disks[i]); err != nil {
			return status.Errorf(codes.FailedPrecondition, "%v", err)
		}
	}
	return nil
}

// pitSweepPoll is how often the start-up sweep asks whether this host's
// replica has caught up. A variable so tests do not wait.
var pitSweepPoll = 5 * time.Second

// SweepPITOverlays settles, at daemon start, every overlay of a VM this host
// owns: a daemon that died mid-window left its VM on an overlay with no event.
//
// It waits for caughtUp first: a host that restarts after a failover still
// lists, until its replica catches up, VMs that were re-homed away from it —
// whose disks, on a shared pool, another host may now be running. Each VM is
// then handled under its lock with its ownership re-read; a disk on a shared
// pool is touched only when this host owns the VM AND has its domain
// defined. Everything else is left to its owner's own hooks, and reported.
func (s *Server) SweepPITOverlays(ctx context.Context, caughtUp func() (bool, string)) {
	for {
		if ok, _ := caughtUp(); ok {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(pitSweepPoll):
		}
	}
	vms, err := corrosion.ListVMs(ctx, s.db, "", s.hostName)
	if err != nil {
		slog.Warn("point-in-time overlay sweep: list VMs", "error", err)
		return
	}
	for i := range vms {
		s.sweepPITOverlaysOf(ctx, vms[i].Name)
	}
}

func (s *Server) sweepPITOverlaysOf(ctx context.Context, name string) {
	unlock := s.lockVM(name)
	defer unlock()
	vm, err := corrosion.GetVM(ctx, s.db, name)
	if err != nil || vm == nil || vm.HostName != s.hostName {
		slog.Info("point-in-time overlay sweep: not this host's VM any more; left to its owner", "vm", name)
		return
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, name)
	if err != nil {
		slog.Warn("point-in-time overlay sweep: list disks", "vm", name, "error", err)
		return
	}
	for i := range disks {
		d := &disks[i]
		if !pitoverlay.Present(s.hostDiskFile(d.Path)) {
			continue
		}
		if corrosion.DiskIsShared(*d) && (s.virt == nil || !s.virt.DomainExists(name)) {
			detail := fmt.Sprintf("%s: a point-in-time overlay %s is present on shared storage and %s's domain is not defined on this host; left for the host that defines or starts it", d.DiskName, pitOverlayPath(d.Path), name)
			slog.Warn("point-in-time overlay sweep: "+detail, "vm", name)
			s.recordVMEventSeverity(ctx, name, "disk.pit_overlay_left", "ok", "warn", detail)
			continue
		}
		if err := s.healPITOverlay(ctx, vm, d); err != nil {
			slog.Error("point-in-time overlay sweep: not settled", "vm", name, "error", err)
		}
	}
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
