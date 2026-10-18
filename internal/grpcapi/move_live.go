package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/diskmode"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// LiveMover is the boundary the live-motion orchestrator calls into.
// Production = a thin shim around internal/libvirt.Client; tests use
// a fake to exercise the orchestration logic without a real qemu.
//
// The orchestrator's job:
//
//  1. Pre-create the destination file at the right size (qemu-img
//     will receive writes via the mirror, but the file must exist).
//  2. Start the block-copy job.
//  3. Poll until cur >= end (mirror in sync).
//  4. Repoint the PERSISTENT domain config to the destination, then commit the DB
//     placement — BOTH before the pivot.
//  5. Pivot. The pivot is the irreversible commit (the guest writes to the
//     destination once it lands), so persistent config + DB are moved first and are
//     never rolled back to the source after a *successful* pivot. This ordering is
//     deliberate — do NOT "simplify" it back to pivot-then-update: that would lose
//     acknowledged post-pivot writes on a failure, or boot a restarted guest from the
//     stale source. See liveMoveVolume for the rollback/auto-pivot handling.
type LiveMover interface {
	StartBlockCopy(domain, disk, destXML string, flags uint32) error
	BlockJobStatus(domain, disk string) (LiveMoverStatus, error)
	PivotBlockCopy(domain, disk string) error
	CancelBlockCopy(domain, disk string) error
}

// LiveMoverStatus mirrors libvirt.BlockJobStatus at the gRPC layer
// boundary — keeps internal/grpcapi from importing internal/libvirt
// at the test surface.
type LiveMoverStatus struct {
	Found bool
	Cur   uint64
	End   uint64
}

// LiveMoverPollInterval controls how often the orchestrator checks
// in-flight progress. 250ms keeps emit-progress chunks frequent
// enough for a responsive UI without hammering libvirt.
var LiveMoverPollInterval = 250 * time.Millisecond

// LiveMoverPivotTimeout caps the wait for "mirror caught up". A
// healthy mirror reaches steady state in seconds for small disks;
// we abort after this so a stalled mirror doesn't block forever.
var LiveMoverPivotTimeout = 30 * time.Minute

// liveMoveVolume drives the BlockCopy → poll → pivot dance for a
// VM that is not definitely shut off (running, paused, an unknown state).
// Called from moveOneVolume.
// Progress frames go through send (the caller owns the transport).
func (s *Server) liveMoveVolume(
	ctx context.Context,
	vm *corrosion.VMRecord,
	src *corrosion.DiskRecord,
	destPath string,
	targetPool string,
	dstPool StoragePoolRef,
	deleteSource bool,
	send func(*pb.MoveVolumeProgress) error,
) error {
	if s.liveMover == nil {
		return status.Error(codes.Unimplemented,
			"live storage motion requires a wired LiveMover (running VM); "+
				"stop the VM (lv stop), move the volume, then start it again")
	}
	if !isFileBasedDriver(src.StorageType) || !isFileBasedDriver(dstPool.Driver) {
		return status.Error(codes.Unimplemented,
			"live storage motion supported only between file-based pools today")
	}

	// Preflight BEFORE touching destPath: if the guest already runs on destPath — a
	// prior partial move pivoted but its DB catch-up didn't land — preallocating or
	// mirroring would CLOBBER the live disk. Catch up persistent + DB instead.
	if s.virt != nil {
		liveSrc, lerr := s.movedDiskLiveSource(vm, src, destPath)
		if lerr != nil {
			return status.Errorf(codes.Internal, "inspect active disk source: %v", lerr)
		}
		if liveSrc == destPath {
			return s.liveCatchUpAtDest(ctx, vm, src, destPath, targetPool, dstPool, deleteSource, send)
		}
	}

	// 1. Pre-create the destination. REUSE_EXT (below) makes libvirt open the
	// destination as an existing qcow2 and mirror into it, so it must be a
	// VALID qcow2 of the source's virtual size — a raw/truncated file fails
	// blockdev-add with "Image is not in qcow2 format".
	// 0711, not 0750: libvirt labels the file, never the directory, so a
	// non-root qemu must be able to search a new one (internal/diskmode).
	if err := diskmode.MkdirAll(filepath.Dir(destPath)); err != nil {
		return status.Errorf(codes.Internal, "mkdir destination: %v", err)
	}
	virtualSize := src.SizeBytes
	if info, ierr := qcow2.Info(src.Path); ierr == nil && info.VirtualSize > 0 {
		virtualSize = int64(info.VirtualSize)
	}
	// A new file only: preallocate refuses one that exists (AlreadyExists),
	// so the cleanups below only ever remove what this move created.
	if err := preallocate(destPath, virtualSize); err != nil {
		if status.Code(err) == codes.AlreadyExists {
			return err
		}
		return status.Errorf(codes.Internal, "preallocate destination: %v", err)
	}

	if err := send(&pb.MoveVolumeProgress{
		Phase:  pb.MoveVolumeProgress_MIRROR,
		Status: fmt.Sprintf("starting blockdev-mirror %s → %s", src.Path, destPath),
	}); err != nil {
		_ = os.Remove(destPath) // best-effort: don't leak the just-preallocated dest
		return err
	}

	// 2. Kick off the mirror.
	destXML := buildDiskXML(destPath)
	// flags = VIR_DOMAIN_BLOCK_COPY_REUSE_EXT (0x2) | _TRANSIENT_JOB (0x4).
	// These MUST match libvirt's DomainBlockCopyFlags values.
	//
	// TRANSIENT_JOB is REQUIRED, not optional: our domains are persistent
	// (DomainDefineXML), and libvirt refuses block-copy on a persistent domain
	// without it ("Requested operation is not valid: domain is not transient").
	//
	// KNOWN LIMITATION: on libvirt 10.0.0 + AppArmor this trips a virt-aa-helper
	// bug — it can't parse a transient block-copy job's <mirror> element
	// ("unknown mirror job type ''"), so the destination's security label fails
	// to apply and the mirror aborts mid-copy with "Error in input stream".
	// There is no flag that avoids both (dropping TRANSIENT_JOB makes libvirt
	// reject the copy outright), so the live path can't be fixed here for that
	// libvirt build — relax AppArmor for qemu, or use an offline stop→convert→
	// start move (MoveVolume on a stopped VM).
	const flagReuseExt = 0x2
	const flagTransientJob = 0x4
	if err := s.liveMover.StartBlockCopy(vm.Name, src.Path, destXML, flagReuseExt|flagTransientJob); err != nil {
		_ = os.Remove(destPath)
		return status.Errorf(codes.Internal, "start block copy: %v", err)
	}

	// 3. Poll progress.
	deadline := time.Now().Add(LiveMoverPivotTimeout)
	// ready is set only when the job reported the copy caught up (cur >= end).
	// A job that ended before that (aborted, or failed mid-copy) left a copy
	// that may be partial, and no config may ever name it.
	ready := false
	for {
		select {
		case <-ctx.Done():
			_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
			_ = os.Remove(destPath)
			return ctx.Err()
		default:
		}
		if time.Now().After(deadline) {
			_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
			_ = os.Remove(destPath)
			return status.Error(codes.DeadlineExceeded, "mirror did not reach steady state in time")
		}
		st, err := s.liveMover.BlockJobStatus(vm.Name, src.Path)
		if err != nil {
			// A transient libvirtd hiccup mid-mirror must not orphan the
			// block-copy job (it pins the disk → "block job already active" on
			// the next op) or leak the preallocated dest. Cancel + clean up,
			// like the ctx-cancel and deadline branches (bug-sweep #5).
			_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
			_ = os.Remove(destPath)
			return status.Errorf(codes.Internal, "block job status: %v", err)
		}
		if !st.Found {
			// The job ended on its own — usually because libvirt
			// already pivoted (TRANSIENT_JOB completes when synced).
			break
		}
		var pct float32
		if st.End > 0 {
			pct = float32(st.Cur) * 100 / float32(st.End)
		}
		_ = send(&pb.MoveVolumeProgress{
			Phase:       pb.MoveVolumeProgress_MIRROR,
			CopyPct:     pct,
			BytesCopied: int64(st.Cur),
		})
		if st.Cur >= st.End && st.End > 0 {
			// Caught up — drop out of the polling loop.
			ready = true
			break
		}
		time.Sleep(LiveMoverPollInterval)
	}

	// 4. Cutover. The PIVOT is the irreversible commit — once it lands the guest
	// writes to dest — so we move the PERSISTENT config and the DB to dest BEFORE
	// pivoting, and never roll them back to src after a *successful* pivot. That
	// keeps the invariant: srcPath is never the durable restart path post-pivot, and
	// no acknowledged post-pivot write is lost.
	commit := func() error {
		if err := corrosion.UpdateDiskPlacement(ctx, s.db, vm.Name, src.DiskName, vm.HostName, destPath, dstPool.Driver, targetPool); err != nil {
			return err
		}
		s.clearBackingIfFlattened(ctx, vm.Name, src.DiskName, destPath)
		return nil
	}
	done := func() error {
		if deleteSource {
			s.deleteSourceIfUnreferenced(ctx, vm, src, send)
		}
		// The move is committed: a dropped stream must not skip the caller's
		// compose sync and event.
		_ = sendLiveDone(src, send)
		return nil
	}

	// No libvirt backend (libvirt-less test context): there is no persistent config
	// to keep in sync, so fall back to pivot → commit → delete, for a copy that
	// caught up only.
	if s.virt == nil {
		if !ready {
			_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
			_ = os.Remove(destPath)
			return status.Errorf(codes.Internal,
				"block-copy job ended before the copy caught up; the copy %s was removed and the disk row still names %s", destPath, src.Path)
		}
		if err := s.liveMover.PivotBlockCopy(vm.Name, src.Path); err != nil {
			_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
			_ = os.Remove(destPath)
			return status.Errorf(codes.Internal, "pivot: %v", err)
		}
		if err := commit(); err != nil {
			return liveMovePlacementErr(err)
		}
		return done()
	}

	// After the mirror job ends, the ACTIVE disk source is the truth — libvirt may
	// end a job for reasons other than a clean pivot, so we reason from the inspected
	// source, not from job state.
	liveSrc, lerr := s.movedDiskLiveSource(vm, src, destPath)
	if lerr != nil {
		_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
		_ = os.Remove(destPath)
		return status.Errorf(codes.Internal, "inspect active disk source: %v", lerr)
	}

	switch liveSrc {
	case destPath:
		// Auto-pivoted during this mirror — the guest is on dest. Catch up forward-only.
		return s.liveCatchUpAtDest(ctx, vm, src, destPath, targetPool, dstPool, deleteSource, send)
	case src.Path:
		// Not pivoted yet — the safe ordering below, but only for a copy that
		// caught up. A job that ended before that left a copy that may be
		// partial: remove it before any define can name it.
		if !ready {
			_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
			_ = os.Remove(destPath)
			return status.Errorf(codes.Internal,
				"block-copy job ended before the copy caught up; the guest is still on %s, the copy %s was removed and nothing was redefined", src.Path, destPath)
		}
	default:
		// Can't prove which path is live — abort WITHOUT destructive cleanup (don't
		// remove dst or src, don't roll back); the operator inspects.
		return status.Errorf(codes.Internal,
			"live move: active disk source %q is neither old %q nor new %q — aborting without cleanup", liveSrc, src.Path, destPath)
	}

	// The unresolved-move record goes down before the define: from here a fault
	// can leave the guest, the persistent config and the disk row naming
	// different files (moveMarker).
	mk, merr := s.beginMoveMarker(vm, src, destPath, dstPool.Driver, targetPool, true, false)
	if merr != nil {
		_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
		_ = os.Remove(destPath)
		return merr
	}
	defer mk.done()

	// Still on src. Redefine persistent → commit DB → pivot, rolling back on failure.
	cs, defined, rerr := s.redefineMovedDiskSource(vm, src, destPath)
	if rerr != nil {
		if !defined {
			// No define was issued (the config could not be read or rewritten), so
			// the config never named the copy this move made.
			_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
			_ = os.Remove(destPath)
			return status.Errorf(codes.Internal, "redefine persistent config (cutover aborted, nothing was defined; the copy %s was removed): %v", destPath, rerr)
		}
		// The define may have been stored despite the error. Point the persistent
		// config back at src while the mirror still tracks it, then stop the mirror;
		// the dest is removed only once the config is back on src.
		if !s.rollbackCutover(cutoverRedefined, vm, src, destPath) {
			return s.liveUnrolledDefine(ctx, vm, src, destPath, targetPool, commit, deleteSource, send,
				fmt.Sprintf("redefine persistent config failed (%v)", rerr), rerr, mk)
		}
		_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
		_ = os.Remove(destPath)
		return status.Errorf(codes.Internal, "redefine persistent config (cutover aborted): %v", rerr)
	}
	if err := commit(); err != nil {
		// Roll persistent back. The mirror stops and the dest is removed only once
		// the config is back on src: a config that may still name the dest is a
		// double fault, settled as one (the mirror keeps the dest current until the
		// guest and the config agree).
		if !s.rollbackCutover(cs, vm, src, destPath) {
			return s.liveUnrolledDefine(ctx, vm, src, destPath, targetPool, commit, deleteSource, send,
				fmt.Sprintf("the disk row could not be updated (%v)", err), err, mk)
		}
		_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
		_ = os.Remove(destPath)
		return liveMovePlacementErr(err)
	}

	// Persistent + DB are now at dest. A dropped progress stream must NOT abort before
	// the pivot — that would strand the guest on src while durable state points at dest.
	// Send best-effort, then complete the cutover.
	_ = send(&pb.MoveVolumeProgress{Phase: pb.MoveVolumeProgress_CUTOVER, Status: "pivoting to destination"})
	if err := s.liveMover.PivotBlockCopy(vm.Name, src.Path); err != nil {
		// Pivot did not occur (guest still on src). Roll DB back to src, roll persistent
		// back (only the redefined case can; already-at-dst keeps dest), keep the source,
		// and remove the dest only if persistent no longer references it.
		rowPath := src.Path
		dbErr := corrosion.UpdateDiskPlacement(ctx, s.db, vm.Name, src.DiskName, src.HostName, src.Path, src.StorageType, src.StorageVolume)
		if dbErr != nil {
			rowPath = destPath
			slog.Error("live move: pivot failed and DB rollback to src also failed — DB records dest but guest is on src; operator must reconcile",
				"vm", vm.Name, "disk", src.DiskName, "pivot_error", err, "db_rollback_error", dbErr)
		}
		if !s.rollbackCutover(cs, vm, src, destPath) {
			return s.liveUnrolledPivot(vm, src, destPath, targetPool, rowPath, err, dbErr, mk)
		}
		_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
		_ = os.Remove(destPath)
		if dbErr != nil {
			return mk.keep(status.Errorf(codes.Internal,
				"pivot: %v; the disk row could not be pointed back at the source (%v): the guest and the persistent config name %s, "+
					"but the disk row names %s, which was removed. The next start, cold migration or backup of the VM points the row back at %s first",
				err, dbErr, src.Path, destPath, src.Path))
		}
		return status.Errorf(codes.Internal, "pivot: %v", err)
	}

	// Pivot succeeded: live=dest, persistent=dest, DB=dest all agree.
	mk.pivoted()
	return done()
}

// sendLiveDone sends the terminal frame of a completed live move.
func sendLiveDone(src *corrosion.DiskRecord, send func(*pb.MoveVolumeProgress) error) error {
	return send(&pb.MoveVolumeProgress{
		Phase:       pb.MoveVolumeProgress_DONE,
		Status:      "live move complete",
		BytesCopied: src.SizeBytes,
		CopyPct:     100,
	})
}

// liveUnrolledDefine handles a double fault on the live path: a step after the
// redefine of the persistent config failed (cause: the redefine itself, or the
// disk row commit), and pointing the config back at src failed too, so the
// config may name destPath. The running guest and the persistent config must
// name the same file. The caller reaches this only with a copy that caught up
// (the job reported cur >= end), so the job can still be pivoted.
//
// When the config names destPath, the guest is pivoted onto it and the disk row
// follows; the move then completes as a normal one does, with a warning, and the
// source is deleted only when that was asked for and the config does not name it.
// When the pivot fails, or the config cannot be read, the mirror is left running
// rather than cancelled: it keeps destPath current with every write the guest
// makes to src, so whichever file the config names holds the guest's data.
// Cancelling it would leave a config that names a copy no longer receiving
// writes, and the next cold start would boot stale data. Nothing is deleted
// except a source the completed move was asked to delete. Every state that
// leaves the config and the row possibly apart keeps the unresolved-move
// record (mk).
func (s *Server) liveUnrolledDefine(ctx context.Context, vm *corrosion.VMRecord, src *corrosion.DiskRecord, destPath, targetPool string, commit func() error, deleteSource bool, send func(*pb.MoveVolumeProgress) error, cause string, causeErr error, mk *moveMarker) error {
	pivotCmd, abortCmd := blockjobCmds(vm, src)

	cs, _, perr := s.planCutover(vm, src, destPath)
	switch {
	case perr == nil && cs == cutoverAlreadyAtDst:
		if err := s.liveMover.PivotBlockCopy(vm.Name, src.Path); err != nil {
			slog.Error("live move: a cutover step failed, the rollback failed, and the pivot onto the copy the config names failed — mirror left running, both files kept; operator must pivot or roll back",
				"vm", vm.Name, "disk", src.DiskName, "config_names", destPath, "guest_writes", src.Path, "first_error", causeErr, "pivot_error", err)
			return mk.keep(status.Errorf(codes.Internal,
				"%s and the persistent config could not be pointed back at %s, and the pivot onto the copy failed (%v): "+
					"the persistent config names %s, but the guest is writing %s. The block-copy mirror into %s is left running so the copy stays current; "+
					"both files are kept and the disk row still names %s. Do not stop or restart the VM until this is resolved: the mirror ends with the guest. "+
					"Operator: either run `%s` and then retry `lv move-volume %s %s %s`, which points the disk row at %s, or define the persistent config back to %s and then run `%s`",
				cause, src.Path, err, destPath, src.Path, destPath, src.Path, pivotCmd, vm.Name, src.DiskName, targetPool, destPath, src.Path, abortCmd))
		}
		mk.pivoted()
		if err := commit(); err != nil {
			slog.Error("live move: pivoted onto the copy the config names after a failed cutover step and rollback, but the disk row could not follow; operator must point the disk row at the copy",
				"vm", vm.Name, "disk", src.DiskName, "dest", destPath, "error", err)
			return mk.keep(status.Errorf(codes.Internal,
				"%s and the persistent config could not be pointed back at %s, so the guest was pivoted onto %s, which the persistent config names; "+
					"the disk row could not be updated (%v) and still names %s: retry `lv move-volume %s %s %s`, which points it at %s. The source %s is kept",
				cause, src.Path, destPath, err, src.Path, vm.Name, src.DiskName, targetPool, destPath, src.Path))
		}
		// Completed: the guest, the persistent config and the disk row name the
		// copy. A cutover step reported an error on the way, so say so.
		detail := fmt.Sprintf("%s: %s and the persistent config could not be pointed back, so the guest was pivoted onto %s, which the persistent config names; the move completed",
			src.DiskName, cause, destPath)
		slog.Warn("live move: "+detail, "vm", vm.Name)
		s.recordVMEventSeverity(ctx, vm.Name, "disk.moved", "ok", "warning", detail)
		_ = send(&pb.MoveVolumeProgress{Phase: pb.MoveVolumeProgress_CUTOVER, Status: "warning: " + detail})
		if deleteSource {
			// This path saw a cutover error: delete the source only when the
			// persistent config is read and does not name it.
			if s.persistentNamesPath(vm, src.Path) {
				_ = send(&pb.MoveVolumeProgress{
					Phase:  pb.MoveVolumeProgress_CLEANUP,
					Status: "source kept: the persistent config may still name " + src.Path,
				})
			} else {
				s.deleteSourceIfUnreferenced(ctx, vm, src, send)
			}
		}
		_ = sendLiveDone(src, send)
		return nil
	case perr == nil && cs == cutoverRedefined:
		// The config names src after all (the rollback failed to read or define
		// it, not because it names the copy): the guest, the config and the row
		// agree, so the mirror can stop. The copy is kept.
		_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
		return status.Errorf(codes.Internal,
			"%s (cutover aborted; the guest, the persistent config and the disk row name %s; the copy %s is kept)",
			cause, src.Path, destPath)
	default:
		slog.Error("live move: a cutover step failed, the rollback failed, and the persistent config could not be read or names neither file — mirror left running, both files kept; operator must reconcile",
			"vm", vm.Name, "disk", src.DiskName, "dest", destPath, "guest_writes", src.Path, "first_error", causeErr, "read_error", perr)
		return mk.keep(status.Errorf(codes.Internal,
			"%s and the persistent config could not be pointed back at %s, and the persistent config could not be read or names neither file (%v), so it may name %s or %s: "+
				"the guest is writing %s and the block-copy mirror into %s is left running so both files stay current; both are kept and the disk row still names %s. "+
				"Do not stop or restart the VM until this is resolved: the mirror ends with the guest. "+
				"Operator: read the config (virsh dumpxml --inactive %s); if it names %s, run `%s` and retry `lv move-volume %s %s %s`, otherwise run `%s`",
			cause, src.Path, perr, src.Path, destPath, src.Path, destPath, src.Path, vm.Name, destPath, pivotCmd, vm.Name, src.DiskName, targetPool, abortCmd))
	}
}

// liveUnrolledPivot handles a pivot that failed after the persistent config and
// the disk row were moved to destPath, when pointing the config back at src
// failed too. The guest still writes src. The pivot is not retried. When the
// config names destPath, or cannot be read, the mirror is left running so the
// copy stays current, both files are kept, and the operator pivots or rolls
// back. When the config names src after all, the mirror stops and the copy is
// kept. rowPath is what the disk row names now (src unless its rollback
// failed too, as dbErr says).
func (s *Server) liveUnrolledPivot(vm *corrosion.VMRecord, src *corrosion.DiskRecord, destPath, targetPool, rowPath string, pivotErr, dbErr error, mk *moveMarker) error {
	pivotCmd, abortCmd := blockjobCmds(vm, src)
	rowNote := "the disk row names " + rowPath
	if dbErr != nil {
		rowNote = fmt.Sprintf("the disk row could not be pointed back at the source (%v) and names %s", dbErr, rowPath)
	}
	cs, _, perr := s.planCutover(vm, src, destPath)
	switch {
	case perr == nil && cs == cutoverAlreadyAtDst:
		slog.Error("live move: the pivot failed and the persistent config could not be pointed back at the source — mirror left running, both files kept; operator must pivot or roll back",
			"vm", vm.Name, "disk", src.DiskName, "config_names", destPath, "guest_writes", src.Path, "row_names", rowPath, "pivot_error", pivotErr)
		return mk.keep(status.Errorf(codes.Internal,
			"pivot failed (%v) and the persistent config could not be pointed back at %s: the persistent config names %s, but the guest is writing %s. "+
				"The block-copy mirror into %s is left running so the copy stays current; both files are kept and %s. "+
				"Do not stop or restart the VM until this is resolved: the mirror ends with the guest. "+
				"Operator: either run `%s` and then retry `lv move-volume %s %s %s`, which points the disk row at %s, or define the persistent config back to %s and then run `%s`",
			pivotErr, src.Path, destPath, src.Path, destPath, rowNote, pivotCmd, vm.Name, src.DiskName, targetPool, destPath, src.Path, abortCmd))
	case perr == nil && cs == cutoverRedefined:
		// The config names src after all: the guest and the config agree, so the
		// mirror can stop. The copy is kept.
		_ = s.liveMover.CancelBlockCopy(vm.Name, src.Path)
		if dbErr != nil {
			return mk.keep(status.Errorf(codes.Internal,
				"pivot: %v; the guest and the persistent config name %s and the copy %s is kept, but %s. The next start, cold migration or backup of the VM points the row back at %s first",
				pivotErr, src.Path, destPath, rowNote, src.Path))
		}
		return status.Errorf(codes.Internal, "pivot: %v (the guest, the persistent config and the disk row name %s; the copy %s is kept)", pivotErr, src.Path, destPath)
	default:
		slog.Error("live move: the pivot failed, the config rollback failed, and the persistent config could not be read or names neither file — mirror left running, both files kept; operator must reconcile",
			"vm", vm.Name, "disk", src.DiskName, "dest", destPath, "guest_writes", src.Path, "row_names", rowPath, "pivot_error", pivotErr, "read_error", perr)
		return mk.keep(status.Errorf(codes.Internal,
			"pivot failed (%v) and the persistent config could not be pointed back at %s, and it could not be read or names neither file (%v), so it may name %s or %s: "+
				"the guest is writing %s and the block-copy mirror into %s is left running so both files stay current; both are kept and %s. "+
				"Do not stop or restart the VM until this is resolved: the mirror ends with the guest. "+
				"Operator: read the config (virsh dumpxml --inactive %s); if it names %s, run `%s` and retry `lv move-volume %s %s %s`, otherwise run `%s`",
			pivotErr, src.Path, perr, src.Path, destPath, src.Path, destPath, rowNote, vm.Name, destPath, pivotCmd, vm.Name, src.DiskName, targetPool, abortCmd))
	}
}

// blockjobCmds are the virsh commands that pivot or abort the moved disk's
// block-copy job.
func blockjobCmds(vm *corrosion.VMRecord, src *corrosion.DiskRecord) (pivot, abort string) {
	disk := src.TargetDev
	if disk == "" {
		disk = src.Path
	}
	return fmt.Sprintf("virsh blockjob %s %s --pivot", vm.Name, disk), fmt.Sprintf("virsh blockjob %s %s --abort", vm.Name, disk)
}

// liveMovePlacementErr maps the strict UpdateDiskPlacement error to a deliberate gRPC
// code: a vanished/soft-deleted disk row → Aborted (concurrent change), else Internal.
func liveMovePlacementErr(err error) error {
	if errors.Is(err, corrosion.ErrNoRowsAffected) {
		return status.Error(codes.Aborted, "disk record changed during live move; aborted")
	}
	return status.Errorf(codes.Internal, "update disk placement: %v", err)
}

// liveCatchUpAtDest completes a live move whose guest ALREADY runs on destPath (a
// prior move pivoted — possibly auto-pivoted — without committing the DB). It is
// FORWARD-ONLY: it ensures the persistent config points at destPath, commits the DB,
// and NEVER touches destPath (the live disk) or rolls back to src. On a commit failure
// it keeps dest and surfaces a reconcile error. No block-copy job runs here.
func (s *Server) liveCatchUpAtDest(ctx context.Context, vm *corrosion.VMRecord, src *corrosion.DiskRecord, destPath, targetPool string, dstPool StoragePoolRef, deleteSource bool, send func(*pb.MoveVolumeProgress) error) error {
	mk, merr := s.beginMoveMarker(vm, src, destPath, dstPool.Driver, targetPool, true, true)
	if merr != nil {
		return merr
	}
	defer mk.done()
	if _, _, rerr := s.redefineMovedDiskSource(vm, src, destPath); rerr != nil {
		return mk.keep(status.Errorf(codes.Internal,
			"redefine persistent config (guest already on dest): %v. The guest is writing %s, but the persistent config may still name %s, and the disk row names %s. "+
				"Do not stop or restart the VM until this is resolved; retry `lv move-volume %s %s %s`",
			rerr, destPath, src.Path, src.Path, vm.Name, src.DiskName, targetPool))
	}
	if err := corrosion.UpdateDiskPlacement(ctx, s.db, vm.Name, src.DiskName, vm.HostName, destPath, dstPool.Driver, targetPool); err != nil {
		slog.Error("live move: guest already on the new path but DB catch-up commit failed — leaving persistent at dest (a restart follows the post-pivot path); operator must reconcile the disk row",
			"vm", vm.Name, "disk", src.DiskName, "dest", destPath, "error", err)
		return mk.keep(liveMovePlacementErr(err))
	}
	s.clearBackingIfFlattened(ctx, vm.Name, src.DiskName, destPath)
	if deleteSource {
		s.deleteSourceIfUnreferenced(ctx, vm, src, send)
	}
	// Committed: a dropped stream must not skip the caller's compose sync and event.
	_ = send(&pb.MoveVolumeProgress{
		Phase:       pb.MoveVolumeProgress_DONE,
		Status:      "live move complete (guest already on destination)",
		BytesCopied: src.SizeBytes,
		CopyPct:     100,
	})
	return nil
}

// movedDiskLiveSource returns the moved disk's CURRENT active <source file>. A row
// with a recorded target dev reads that dev; a legacy row without one resolves by
// matching either the old or new path among the live sources (returns "" when
// neither is present, so the caller treats it as indeterminate).
func (s *Server) movedDiskLiveSource(vm *corrosion.VMRecord, src *corrosion.DiskRecord, dstPath string) (string, error) {
	srcs, err := s.virt.DomainDiskSources(vm.Name)
	if err != nil {
		return "", err
	}
	if src.TargetDev != "" {
		return srcs[src.TargetDev], nil
	}
	for _, v := range srcs {
		if v == src.Path || v == dstPath {
			return v, nil
		}
	}
	return "", nil
}

// preallocate creates an empty file of size bytes — `qemu-img create`
// would also work, but the truncate path is simpler and adequate for
// REUSE_EXT (libvirt fills in the qcow2 header).
// preallocate creates the destination as an empty qcow2 of the given virtual
// size. The live mirror uses REUSE_EXT, so the destination must already be a
// valid qcow2 (a raw/truncated file fails blockdev-add with "Image is not in
// qcow2 format").
func preallocate(path string, virtualSize int64) error {
	if virtualSize <= 0 {
		return fmt.Errorf("destination virtual size must be > 0")
	}
	// qcow2.Create publishes exclusively: an existing path is refused.
	return existAsAlreadyExists(qcow2.Create(path, uint64(virtualSize), nil))
}

// buildDiskXML produces the small <disk> snippet libvirt's BlockCopy
// accepts as the destination. Format is qcow2 by convention since
// the rest of the file-based path uses it.
func buildDiskXML(destPath string) string {
	return fmt.Sprintf(
		`<disk type="file" device="disk"><driver name="qemu" type="qcow2"/><source file="%s"/></disk>`,
		destPath,
	)
}
