package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	// offline by the caller (pitoverlay) first. beforePivot, when set, runs
	// once the commit is ready and before the pivot; if it fails nothing is
	// pivoted.
	CommitDiskOverlay(domain, diskPath, overlay, diskFormat string, beforePivot func() error) error
	// DomainRunsOnFile reports whether the LIVE definition names path:
	// whether qemu runs the disk on it now.
	DomainRunsOnFile(domain, path string) (bool, error)
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
//
// No overlay is placed where it would not survive (pitoverlay.Placement: a
// /dev block disk's devtmpfs, a tmpfs); the copy goes on to the next layer.
// Before the window opens the disk is given a new window token
// (pitoverlay.OpenWindow), durably, and the binding records it.
func (s *Server) copyViaExternalSnapshot(ctx context.Context, vm *corrosion.VMRecord, d *corrosion.DiskRecord, dst string, emit func(*pb.MoveVolumeProgress) error) (copyMethod, error) {
	// No overlay before every host serving the pool understands one: an
	// older build would start the VM on the bare disk and drop the
	// window's writes. Until then the copy takes the existing path.
	if open, why := pitoverlay.FeatureOpen(); !open {
		return "", errors.New(why)
	}
	if s.pitSnapshotter == nil {
		return "", errors.New("no snapshotter on this host")
	}
	if !s.domainActive(vm) {
		return "", errors.New("the domain is not running or paused")
	}
	disk := s.hostDiskFile(d.Path)
	if err := pitoverlay.Placement(disk); err != nil {
		return "", fmt.Errorf("no overlay is placed here: %w", err)
	}
	win, err := pitoverlay.OpenWindow(disk)
	if err != nil {
		return "", err
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
	// any other (a path reused, a disk rewritten). Fail closed: without a
	// binding no commit starts — the window stays open, reported, and the
	// next settle of the disk binds and commits it.
	if berr := pitBind(disk, pitOwner(vm, d), win); berr != nil {
		s.reportStrandedOverlay(ctx, vm, d, overlay, fmt.Errorf("bind the overlay to its disk: %w", berr))
		return "", fmt.Errorf("bind the overlay: %w", berr)
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

// commitPITOverlay live-commits overlay back into d — the domain is active
// and runs on it — and removes it once nothing names it. A failure leaves the
// overlay where it is (the domain runs on it) and says so loudly.
//
// The binding follows the commit durably, so a crash at any point is
// recognised: committing before the first base write (fail closed: no
// record, no commit), pivoting just before the pivot (libvirt's beforePivot:
// no record, no pivot), and committed once the domain has left the overlay.
// A pivot that did not land puts it back to committing.
func (s *Server) commitPITOverlay(ctx context.Context, vm *corrosion.VMRecord, d *corrosion.DiskRecord, overlay string) error {
	disk := s.hostDiskFile(d.Path)
	if !pitoverlay.Bound(disk) {
		// The domain runs on the overlay, so the base has been frozen since
		// the snapshot: bind it now, under a new window token.
		if err := pitoverlay.Bind(disk, pitOwner(vm, d)); err != nil {
			err = fmt.Errorf("bind the overlay before its commit: %w", err)
			s.reportStrandedOverlay(ctx, vm, d, overlay, err)
			return err
		}
	}
	if err := pitMarkCommitting(disk); err != nil {
		err = fmt.Errorf("record the commit before it starts: %w", err)
		s.reportStrandedOverlay(ctx, vm, d, overlay, err)
		return err
	}
	stop := pitoverlay.KeepCommitting(ctx, disk)
	err := s.pitSnapshotter.CommitDiskOverlay(vm.Name, d.Path, overlay, pitDiskFormat, func() error { return pitMarkPivoting(disk) })
	stop()
	// What happened, whatever CommitDiskOverlay said. A recorded pivot on a
	// running domain that left the overlay landed: the overlay is merged.
	// Anything else is not recorded as merged: a pivot that did not land
	// goes back to committing.
	if on, qerr := s.pitSnapshotter.DomainRunsOnFile(vm.Name, overlay); qerr == nil {
		b, berr := pitoverlay.BindingOf(disk)
		switch {
		case berr != nil:
		case !on && b.State == pitoverlay.StatePivoting && s.domainActive(vm):
			if merr := pitoverlay.MarkCommitted(disk); merr != nil {
				slog.Warn("copy: a landed pivot not recorded committed; the pivoting record stands", "vm", vm.Name, "overlay", overlay, "error", merr)
			}
		case on && b.State == pitoverlay.StatePivoting:
			_ = pitMarkCommitting(disk) // the pivot did not land
		}
	}
	// The disk as this attempt left it (a binding still committing only):
	// nothing writes it until the next attempt.
	if eerr := pitoverlay.RecordAttemptEnd(disk); eerr != nil {
		slog.Warn("copy: the end of a commit attempt not recorded", "vm", vm.Name, "overlay", overlay, "error", eerr)
	}
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
	if rerr := pitoverlay.Remove(disk); rerr != nil {
		slog.Warn("copy: committed point-in-time overlay not removed", "vm", vm.Name, "overlay", overlay, "error", rerr)
		return nil
	}
	s.ClearPITOverlayHold(ctx, vm.Name, d.DiskName)
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
//   - the domain is active and runs on its disk: if the binding recorded a
//     pivot (or a finished commit) and the disk is the file it was writing,
//     the overlay is already merged — the persistent definition is pointed
//     back at the disk and the overlay removed, without a hold. Otherwise the
//     VM ran on its disk without the overlay: the binding is marked diverged
//     (so a later offline settle never commits it over the newer writes) and
//     the VM is held;
//   - the domain is not active (or not defined here): pitoverlay.Assess
//     decides. Matches or half-written: commit it offline with qemu-img (no
//     -U); pivoted: nothing to commit. Then point a persistent definition
//     that names it back at the disk, and only then remove it. Anything else
//     holds the VM;
//   - libvirt cannot say whether the domain runs: nothing is touched, and the
//     caller retries later.
//
// It fails — and the caller does not proceed — when the overlay cannot be
// settled, because the disk's file would then miss the guest's writes held
// in it.
func (s *Server) healPITOverlay(ctx context.Context, vm *corrosion.VMRecord, d *corrosion.DiskRecord) error {
	disk := s.hostDiskFile(d.Path)
	if !pitoverlay.Present(disk) {
		s.ClearPITOverlayHold(ctx, vm.Name, d.DiskName)
		return nil
	}
	overlay := pitOverlayPath(d.Path)
	owner := pitOwner(vm, d)
	if open, _ := pitoverlay.FeatureOpen(); !open {
		// Below the pit_overlay feature this host settles no overlay — not
		// even live: one present was made by a host above it. Held.
		return s.holdPITOverlay(ctx, vm, d, pitoverlay.Assess(disk, owner, false))
	}
	committed := fmt.Sprintf("%s: an earlier point-in-time overlay %s was committed back into %s", d.DiskName, overlay, d.Path)
	switch s.domainActivity(vm) {
	case activityUnknown:
		return fmt.Errorf("%s: a point-in-time overlay %s is present and libvirt cannot say whether %s is running; it is left as it is — retry once libvirt answers", d.DiskName, overlay, vm.Name)
	case activityActive:
		if s.pitSnapshotter == nil {
			return fmt.Errorf("%s: a point-in-time overlay %s is present and this host has no snapshotter to commit it", d.DiskName, overlay)
		}
		on, err := s.pitSnapshotter.DomainRunsOnFile(vm.Name, overlay)
		if err != nil {
			return fmt.Errorf("%s: cannot tell whether the domain runs on the overlay %s: %w", d.DiskName, overlay, err)
		}
		if on {
			if err := s.commitPITOverlay(ctx, vm, d, overlay); err != nil {
				return fmt.Errorf("%s: the domain runs on the point-in-time overlay %s and it could not be committed: %w", d.DiskName, overlay, err)
			}
			break
		}
		// The domain runs on its disk.
		a := pitoverlay.Assess(disk, owner, true)
		if a.Verdict == pitoverlay.Pivoted {
			// A pivot landed and the daemon died before the overlay went: it
			// is merged. Point a definition that still names it back at the
			// disk, then remove it.
			if err := s.pitSnapshotter.CommitDiskOverlay(vm.Name, d.Path, overlay, pitDiskFormat, nil); err != nil {
				s.reportStrandedOverlay(ctx, vm, d, overlay, err)
				return fmt.Errorf("%s: point the definition back at %s: %w", d.DiskName, d.Path, err)
			}
			if used, err := s.pitSnapshotter.DomainUsesFile(vm.Name, overlay); err != nil || used {
				return fmt.Errorf("%s: the domain still names the merged overlay %s (%v)", d.DiskName, overlay, err)
			}
			if err := pitoverlay.Remove(disk); err != nil {
				return fmt.Errorf("%s: remove the already-committed overlay %s: %w", d.DiskName, overlay, err)
			}
			s.ClearPITOverlayHold(ctx, vm.Name, d.DiskName)
			s.recordVMEventSeverity(ctx, vm.Name, "disk.pit_overlay_committed", "ok", "info",
				fmt.Sprintf("%s: the point-in-time overlay %s had already been committed into %s (the VM runs on the disk); it was removed", d.DiskName, overlay, d.Path))
			return nil
		}
		if b := a.Binding; b != nil && !a.BelowFeature && b.State != pitoverlay.StateDiverged && b.State != pitoverlay.StateCommitted {
			// No pivot is recorded that the disk's writes can be its own
			// after (none at all, or one recorded long before them), yet the
			// VM runs on its disk: something started it there without the
			// overlay. Its writes since are newer than the overlay's, so it
			// is never committed now.
			why := "the running VM was found on its disk, not on the overlay, with no pivot recorded that its writes follow"
			if err := pitMarkDiverged(disk, why); err != nil {
				// Unrecorded, the binding may still read half-written: hold
				// as unknown, never on the binding as it stands.
				slog.Warn("point-in-time overlay: diverged not recorded", "vm", vm.Name, "overlay", overlay, "error", err)
				a = pitoverlay.Assessment{Verdict: pitoverlay.Unknown, Binding: a.Binding, CommitBegan: a.CommitBegan,
					Current: a.Current, Backing: a.Backing, DiskMtimeNs: a.DiskMtimeNs, OverlayMtimeNs: a.OverlayMtimeNs, OverlayCurrent: a.OverlayCurrent,
					Reason: fmt.Sprintf("%s (and that could not be recorded: %v)", why, err)}
			} else {
				a = pitoverlay.Assess(disk, owner, true)
			}
		}
		return s.holdPITOverlay(ctx, vm, d, a)
	default:
		_, err := pitoverlay.CommitOffline(ctx, disk, owner)
		if errors.Is(err, pitoverlay.ErrNotOurs) {
			return s.holdPITOverlay(ctx, vm, d, pitoverlay.Assess(disk, owner, false))
		}
		if err != nil {
			s.reportStrandedOverlay(ctx, vm, d, overlay, err)
			return fmt.Errorf("%s: commit the point-in-time overlay %s: %w", d.DiskName, overlay, err)
		}
		if s.pitSnapshotter != nil && s.virt != nil && s.virt.DomainExists(vm.Name) {
			if err := s.pitSnapshotter.CommitDiskOverlay(vm.Name, d.Path, overlay, pitDiskFormat, nil); err != nil {
				s.reportStrandedOverlay(ctx, vm, d, overlay, err)
				return fmt.Errorf("%s: point the definition back at %s: %w", d.DiskName, d.Path, err)
			}
		}
		if err := pitoverlay.Remove(disk); err != nil {
			return fmt.Errorf("%s: remove the committed overlay %s: %w", d.DiskName, overlay, err)
		}
	}
	s.ClearPITOverlayHold(ctx, vm.Name, d.DiskName)
	s.recordVMEventSeverity(ctx, vm.Name, "disk.pit_overlay_committed", "ok", "info", committed)
	return nil
}

// pitBind, pitMarkCommitting and pitMarkPivoting are pitoverlay's, as
// variables so a test can make them fail.
var (
	pitBind           = pitoverlay.BindWindow
	pitMarkCommitting = pitoverlay.MarkCommitting
	pitMarkPivoting   = pitoverlay.MarkPivoting
	pitMarkDiverged   = pitoverlay.MarkDiverged
)

// The health condition of a disk held on its overlay: one per disk, subject
// "<vm>/<disk>", a warning (it degrades the cluster's health) for as long as
// the hold lasts.
const (
	pitHoldEvaluator = "pit_overlay"
	pitHoldCode      = "pit_overlay.held"
	pitHoldKind      = "disk"
)

// pitHoldRenotify is how often a hold that lasts is notified again.
var pitHoldRenotify = 24 * time.Hour

// vmEventPITOverlayHeld is the event of a VM held because an overlay could
// not be verified.
const vmEventPITOverlayHeld = "disk.pit_overlay_held"

// pitHoldEvidence is the held condition's evidence.
type pitHoldEvidence struct {
	VM         string `json:"vm"`
	Disk       string `json:"disk"`
	Detail     string `json:"detail"`
	NotifiedAt string `json:"notified_at"`
}

// holdPITOverlay refuses to go on with a disk whose overlay may hold the
// guest's newest writes but cannot be verified against the disk: starting
// the VM on the bare disk would drop them silently, and committing could
// write stale blocks over newer data. The overlay is left exactly as it is;
// the hold names both files, the verdict, and what the admin should do for
// that verdict. It returns the error the caller refuses with.
func (s *Server) holdPITOverlay(ctx context.Context, vm *corrosion.VMRecord, d *corrosion.DiskRecord, a pitoverlay.Assessment) error {
	disk := s.hostDiskFile(d.Path)
	detail := pitoverlay.HoldDetail(vm.Name, d.DiskName, disk, a)
	s.ReportPITOverlayHeld(ctx, vm.Name, d.DiskName, detail)
	return status.Error(codes.FailedPrecondition, detail)
}

// pitHoldNotifiedLocal is the fallback when the condition cannot be read or
// written: the last notice per host and disk, in this process.
var pitHoldNotifiedLocal sync.Map

// ReportPITOverlayHeld records a VM held on one disk's overlay (here, or by
// the reconciler's define path) as a durable health condition, and sends
// the event and notification once when the hold begins, then at most once a
// day while it lasts — not on every operation that meets it.
func (s *Server) ReportPITOverlayHeld(ctx context.Context, vmName, diskName, detail string) {
	if !s.raisePITHold(ctx, vmName, diskName, detail) {
		slog.Debug("point-in-time overlay: VM still held", "vm", vmName, "disk", diskName)
		return
	}
	slog.Error("point-in-time overlay: VM held", "vm", vmName, "disk", diskName, "detail", detail)
	s.recordVMEventSeverity(ctx, vmName, vmEventPITOverlayHeld, "error", "error", detail)
	s.notify(ctx, notify.Notification{Kind: "replication.pit_overlay_held", Severity: notify.SevError, Subject: vmName, Detail: detail})
}

// raisePITHold raises or refreshes the disk's held condition and reports
// whether to notify: the hold is new, or its last notice is pitHoldRenotify
// old. An unchanged hold that needs no notice writes nothing.
func (s *Server) raisePITHold(ctx context.Context, vmName, diskName, detail string) bool {
	subject := vmName + "/" + diskName
	now := time.Now().UTC()
	local := func() bool {
		key := s.hostName + "\x00" + subject
		if last, ok := pitHoldNotifiedLocal.Load(key); ok && now.Sub(last.(time.Time)) < pitHoldRenotify {
			return false
		}
		pitHoldNotifiedLocal.Store(key, now)
		return true
	}
	if s.db == nil {
		return local()
	}
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, pitHoldEvaluator, pitHoldCode, pitHoldKind, subject)
	if err != nil {
		slog.Warn("point-in-time overlay: read the held condition", "subject", subject, "error", err)
		return local()
	}
	open := found && row.Lifecycle != corrosion.ConditionResolved
	var ev pitHoldEvidence
	if open {
		_ = json.Unmarshal([]byte(row.Evidence), &ev)
	}
	last, perr := time.Parse(time.RFC3339Nano, ev.NotifiedAt)
	notifyNow := !open || perr != nil || now.Sub(last) >= pitHoldRenotify
	if open && !notifyNow && ev.Detail == detail {
		return false
	}
	ts := now.Format(time.RFC3339)
	if !open {
		row = corrosion.HealthCondition{Evaluator: pitHoldEvaluator, Code: pitHoldCode, SubjectKind: pitHoldKind, SubjectID: subject,
			Lifecycle: corrosion.ConditionConfirmed, FirstSeen: ts, ConfirmedAt: ts}
	}
	ev.VM, ev.Disk, ev.Detail = vmName, diskName, detail
	if notifyNow {
		ev.NotifiedAt = now.Format(time.RFC3339Nano)
	}
	b, _ := json.Marshal(ev)
	row.Evidence = string(b)
	row.Severity = corrosion.SeverityWarning
	row.Hosts = []string{s.hostName}
	row.ObserveCount++
	row.CleanCount = 0
	row.LastSeen, row.ResolvedAt, row.Reporter = ts, "", s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("point-in-time overlay: persist the held condition", "subject", subject, "error", err)
		return local()
	}
	return notifyNow
}

// ClearPITOverlayHold resolves the disk's held condition, if one is open:
// its overlay was committed, found merged, discarded, or went with its disk.
func (s *Server) ClearPITOverlayHold(ctx context.Context, vmName, diskName string) {
	subject := vmName + "/" + diskName
	pitHoldNotifiedLocal.Delete(s.hostName + "\x00" + subject)
	if s.db == nil {
		return
	}
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, pitHoldEvaluator, pitHoldCode, pitHoldKind, subject)
	if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved {
		return
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, ts, ts, s.hostName
	row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("point-in-time overlay: resolve the held condition", "subject", subject, "error", err)
	}
}

// pitOverlayHeldReason is every open hold of vmName's disks, from the
// durable conditions (one per disk); "" when none is held.
func (s *Server) pitOverlayHeldReason(ctx context.Context, vmName string) string {
	rows, err := corrosion.ListOpenHealthConditionsByCode(ctx, s.db, pitHoldEvaluator, pitHoldCode)
	if err != nil {
		return ""
	}
	var out []string
	for _, r := range rows {
		if r.SubjectKind != pitHoldKind || !strings.HasPrefix(r.SubjectID, vmName+"/") {
			continue
		}
		var ev pitHoldEvidence
		if json.Unmarshal([]byte(r.Evidence), &ev) == nil && ev.Detail != "" {
			out = append(out, ev.Detail)
		} else {
			out = append(out, strings.TrimPrefix(r.SubjectID, vmName+"/")+": held on its point-in-time overlay")
		}
	}
	return strings.Join(out, "\n")
}

// setAsideStaleOverlay sets aside any overlay beside a disk file that is
// about to be written afresh (an import): it cannot belong to the new
// contents. baseAside, when the caller moved the file the overlay was taken
// of aside too, is where that file went: the message names both, so the pair
// can be found again.
//
// No VM's writes are dropped: the disk the overlay was taken of no longer
// exists at this path (an import places only a new file), so the overlay is
// kept under a new name, never committed, and reported.
func (s *Server) setAsideStaleOverlay(ctx context.Context, vmName, diskName, disk, baseAside string) error {
	if !pitoverlay.Present(disk) {
		return nil
	}
	to, err := pitoverlay.SetAside(disk, time.Now().UTC().Format("20060102-150405"))
	if err != nil {
		return fmt.Errorf("%s: set the stale point-in-time overlay %s aside: %w", diskName, pitoverlay.Path(disk), err)
	}
	base := "the file it was taken of is no longer there"
	if baseAside != "" {
		base = "the file it was taken of was moved aside to " + baseAside + " (the overlay belongs with it)"
	}
	detail := fmt.Sprintf("%s: a point-in-time overlay %s was left where the new disk %s is written; it cannot belong to the new disk and was kept as %s, with its binding as %s.id; %s. Inspect them, then delete them",
		diskName, pitoverlay.Path(disk), disk, to, to, base)
	slog.Warn("point-in-time overlay set aside", "vm", vmName, "detail", detail)
	s.recordVMEventSeverity(ctx, vmName, "disk.pit_overlay_set_aside", "warning", "warn", detail)
	s.notify(ctx, notify.Notification{Kind: "replication.pit_overlay_set_aside", Severity: notify.SevWarn, Subject: vmName, Detail: detail})
	return nil
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
			if _, ok := status.FromError(err); ok {
				return err
			}
			return status.Errorf(codes.FailedPrecondition, "%v", err)
		}
	}
	return nil
}

// settleKeptPITOverlays settles the overlays of vm's disks a delete keeps.
// Deleted disks take their overlays with them (deleteDiskAtRecordedLocation).
func (s *Server) settleKeptPITOverlays(ctx context.Context, vm *corrosion.VMRecord, keepAll bool) error {
	disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	if err != nil {
		return status.Errorf(codes.Internal, "list disks: %v", err)
	}
	for i := range disks {
		d := &disks[i]
		if d.Path == "" || !pitoverlay.Present(s.hostDiskFile(d.Path)) {
			continue
		}
		if !keepAll && d.DeleteWithVM && !s.diskPathReferencedByOtherVM(ctx, vm.Name, d) {
			continue
		}
		if err := s.healPITOverlay(ctx, vm, d); err != nil {
			if _, ok := status.FromError(err); ok {
				return err
			}
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
	logged := false
	for {
		ok, why := caughtUp()
		if ok {
			break
		}
		if !logged {
			slog.Info("point-in-time overlay sweep: waiting for this host's replica to be trusted", "why", why)
			logged = true
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

// PITSweepReady is the start-up sweep's readiness: this host's replica is
// trusted (corrosion.ReplicaTrusted — caught up with a peer, or this host is
// the cluster's only member, which has no peer to catch up with and would
// otherwise never sweep).
func (s *Server) PITSweepReady(ctx context.Context) func() (bool, string) {
	return s.pitSweepReady(ctx, s.db.ReplicaCaughtUp)
}

func (s *Server) pitSweepReady(ctx context.Context, caughtUp func() (bool, string)) func() (bool, string) {
	return func() (bool, string) { return corrosion.ReplicaTrusted(ctx, s.db, s.hostName, caughtUp) }
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
