package grpcapi

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cmdbound"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/diskmode"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/pitoverlay"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/storage"
)

// MoveVolume copies a single VM disk from its current pool to target_pool
// on the same host, then updates the libvirt source so qemu reads from
// the new path. Cross-host moves use MigrateVM(with_storage=true).
//
// scope: file-based pools only (local, nfs, dir, btrfs).
// Block backends (ceph, zfs, iscsi, lvm-thin) require backend-specific
// copy primitives — they return Unimplemented until the corresponding
// driver Mover lands.
//
// Live cutover is wired: any VM not definitely shut off (running, paused,
// partition-paused, an unknown state) routes to liveMoveVolume (libvirt
// block-copy → pivot, see move_live.go); a shut-off VM does an offline copy
// without qemu-img's -U. Only the block-backend gap above remains.
func (s *Server) MoveVolume(req *pb.MoveVolumeRequest, stream grpc.ServerStreamingServer[pb.MoveVolumeProgress]) error {
	ctx := stream.Context()
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return err
	}
	if req.VmName == "" || req.DiskName == "" || req.TargetPool == "" {
		return status.Error(codes.InvalidArgument, "vm_name, disk_name, target_pool required")
	}

	vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return status.Errorf(codes.NotFound, "vm %q not found", req.VmName)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.move", "operator"); err != nil {
		return err
	}
	// MoveVolume runs on the host owning the VM (it touches local disk files).
	// If we're not that host, forward to the owner and relay its progress, so
	// any daemon — e.g. the one serving the UI/CLI — can drive the move.
	if vm.HostName != s.hostName {
		client, conn, perr := s.peerClient(ctx, vm.HostName)
		if perr != nil {
			return status.Errorf(codes.FailedPrecondition, "reach host %q owning vm %q: %v", vm.HostName, req.VmName, perr)
		}
		defer conn.Close()
		rs, perr := client.MoveVolume(ctx, req)
		if perr != nil {
			return perr
		}
		for {
			frame, rerr := rs.Recv()
			if errors.Is(rerr, io.EOF) {
				return nil
			}
			if rerr != nil {
				return rerr
			}
			if serr := stream.Send(frame); serr != nil {
				return serr
			}
		}
	}

	unlock := s.lockVMAs(req.VmName, "volume move")
	defer unlock()

	disks, err := corrosion.GetVMDisks(ctx, s.db, req.VmName)
	if err != nil {
		return status.Errorf(codes.Internal, "list disks: %v", err)
	}
	var src *corrosion.DiskRecord
	for i := range disks {
		if disks[i].DiskName == req.DiskName {
			src = &disks[i]
			break
		}
	}
	if src == nil {
		return status.Errorf(codes.NotFound, "vm %q has no disk %q", req.VmName, req.DiskName)
	}
	// An unresolved move of this disk this host recorded is settled first, or
	// refuses the retry: a "nothing to do" must not hide it.
	if settled, err := s.settleBeforeMove(ctx, vm, src); err != nil {
		return err
	} else if settled != nil {
		src = settled
	}
	if src.StorageVolume == req.TargetPool {
		// Idempotent no-op: the disk is already where the caller asked for it
		// (e.g. re-running a move that already completed). Emit a terminal
		// success frame instead of FailedPrecondition so the UI/CLI shows
		// "done", not "failed", for a move whose desired end-state already holds.
		return stream.Send(&pb.MoveVolumeProgress{
			Phase:      pb.MoveVolumeProgress_DONE,
			Status:     fmt.Sprintf("disk %q is already in pool %q — nothing to do", req.DiskName, req.TargetPool),
			CopyPct:    100,
			BytesTotal: src.SizeBytes,
		})
	}

	return s.moveOneVolume(ctx, vm, src, req.TargetPool, req.DeleteSource, stream.Send)
}

// moveOneVolume performs a single disk's pool-to-pool motion for a VM the
// daemon owns locally. It is the shared core behind the MoveVolume RPC and
// the MigrateStackVolumes orchestrator (which calls it directly for local
// VMs and via a peer MoveVolume RPC for remote ones). Progress frames are
// delivered through send; the caller owns the transport — a raw gRPC
// stream.Send for MoveVolume, a translating closure for MigrateStackVolumes.
//
// Precondition: vm.HostName == s.hostName — it touches local disk files.
func (s *Server) moveOneVolume(
	ctx context.Context,
	vm *corrosion.VMRecord,
	src *corrosion.DiskRecord,
	targetPool string,
	deleteSource bool,
	send func(*pb.MoveVolumeProgress) error,
) error {
	// A caller that is not MoveVolume (MigrateStackVolumes) reaches here
	// directly: an unresolved move of this disk is settled first, or refuses
	// the move with a health.MoveUnresolvedError.
	if settled, err := s.settleBeforeMove(ctx, vm, src); err != nil {
		return err
	} else if settled != nil {
		src = settled
	}
	// Already there (a stack migration dispatches a disk whose move was
	// recorded even when its row names the target pool): nothing to do.
	if src.StorageVolume == targetPool {
		return send(&pb.MoveVolumeProgress{
			Phase:      pb.MoveVolumeProgress_DONE,
			Status:     fmt.Sprintf("disk %q is already in pool %q — nothing to do", src.DiskName, targetPool),
			CopyPct:    100,
			BytesTotal: src.SizeBytes,
		})
	}
	// A VM snapshot makes the disk an overlay over a (possibly host-local) backing
	// base. qemu-img convert flattens the DATA, but the snapshot metadata and the
	// backing reference don't survive a pool move — the moved overlay can end up
	// pointing at a base that isn't on the target pool/host, which then breaks a
	// later cross-host migration ("Cannot access storage file …"). Refuse rather
	// than silently produce that state; the operator flattens by removing the
	// snapshots first (G1 drill finding).
	if snaps, serr := corrosion.ListSnapshots(ctx, s.db, vm.Name); serr == nil && len(snaps) > 0 {
		return status.Errorf(codes.FailedPrecondition,
			"VM %q has %d snapshot(s); a disk with a snapshot overlay can't be moved between pools (its backing chain would be orphaned) — remove them first (`lv snapshot rm %s <name>`), then move", vm.Name, len(snaps), vm.Name)
	}

	// A shared disk whose row names another host not proven off is judged as
	// a start judges it (review c4): copying it while that host may still be
	// writing it moves a disk two hosts write, and re-points its row here.
	if _, withheld := s.judgeSharedDiskRows(ctx, []corrosion.DiskRecord{*src}); len(withheld) > 0 {
		return status.Errorf(codes.FailedPrecondition, "move-volume of %s's disk %s refused: %s",
			vm.Name, src.DiskName, corrosion.WithheldSharedDiskDetail(vm.Name, s.hostName, withheld))
	}

	// Project isolation: the VM's project may move a disk only onto a global pool or
	// one it owns (the target pool is on this host — moveOneVolume is local).
	if err := s.admitVMPoolUse(ctx, vm, s.hostName, targetPool); err != nil {
		return err
	}
	dstPool, ok := s.lookupStoragePool(targetPool)
	if !ok {
		return status.Errorf(codes.NotFound, "target pool %q not configured on host %q", targetPool, s.hostName)
	}
	if !isFileBasedDriver(src.StorageType) {
		return status.Errorf(codes.Unimplemented,
			"source pool driver %q: storage motion not yet implemented", src.StorageType)
	}
	if !isFileBasedDriver(dstPool.Driver) {
		return status.Errorf(codes.Unimplemented,
			"target pool driver %q: storage motion not yet implemented", dstPool.Driver)
	}

	// Resolve the destination directory. We piggyback on the storage
	// driver's Prepare to ensure it's mounted/ready, then derive a
	// per-VM filename.
	if err := s.checkPoolForWrite(ctx, targetPool, dstPool); err != nil {
		return err
	}
	drv, err := storage.New(s.dataDir, storage.Config{
		Driver:  dstPool.Driver,
		Source:  dstPool.Source,
		Target:  dstPool.Target,
		Options: dstPool.Options,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "construct target driver: %v", err)
	}
	dstDir, err := fileBasedPoolDir(s.dataDir, dstPool)
	if err != nil {
		return status.Errorf(codes.Internal, "resolve target dir: %v", err)
	}
	if err := prepareTargetPool(ctx, drv, dstDir); err != nil {
		return prepareTargetPoolStatus(err)
	}
	dstPath := filepath.Join(dstDir, fmt.Sprintf("%s-%s.qcow2", vm.Name, src.DiskName))
	if dstPath == src.Path {
		return status.Error(codes.FailedPrecondition, "source and destination resolve to the same path")
	}
	if err := refuseSymlinkTarget(dstPath); err != nil {
		return err
	}

	// Every frame carries the disk's total size for the caller's bar.
	totalBytes := src.SizeBytes
	emit := func(p *pb.MoveVolumeProgress) error {
		p.BytesTotal = totalBytes
		return send(p)
	}

	// A point-in-time overlay an earlier copy left holds writes the disk's
	// file lacks: settle it before either path reads the disk.
	if err := s.healPITOverlay(ctx, vm, src); err != nil {
		return status.Errorf(codes.FailedPrecondition, "%v", err)
	}

	// Anything not definitely shut off goes through libvirt blockdev-mirror,
	// so the disk swap is online and the copy is never read from an image a
	// qemu holds open: a paused or pm-suspended domain (which the store folds
	// into "stopped"), a partition-paused one, or a state this code does not
	// recognise. Only a disk that is definitely closed takes the offline
	// qemu-img convert below — without -U, so a wrong "stopped" fails on
	// qemu's lock instead of copying a smeared disk.
	if !s.sourceClosedForPlainCopy(vm) {
		if err := s.liveMoveVolume(ctx, vm, src, dstPath, targetPool, dstPool, deleteSource, emit); err != nil {
			return err
		}
		s.syncStackComposeForMovedDisk(ctx, vm, src.DiskName, targetPool)
		s.recordVMEvent(ctx, vm.Name, "disk.moved", "ok",
			fmt.Sprintf("%s: %s → %s", src.DiskName, poolLabel(src.StorageVolume), targetPool))
		return nil
	}

	// Preflight the persistent cutover WITHOUT changing anything. A prior partial move
	// may have left the persistent config already booting from dstPath (with possibly
	// newer guest writes than src.Path); re-copying src→dst would clobber it. So decide
	// the cutover BEFORE the copy.
	// defineErr holds a define error the move completed through (a double fault
	// whose config names the copy), for the source-delete guard below.
	var defineErr error
	cs, _, perr := s.planCutover(vm, src, dstPath)
	if perr != nil {
		s.recordVMEvent(ctx, vm.Name, "disk.moved", "error",
			fmt.Sprintf("%s: cutover preflight failed: %v", src.DiskName, perr))
		return status.Errorf(codes.Internal, "inspect persistent domain config (cutover aborted, source preserved): %v", perr)
	}

	// The unresolved-move record: written before the first step that can leave the
	// persistent config and the disk row naming different files, removed when the
	// move returns with them agreeing (moveMarker).
	var mk *moveMarker
	defer func() { mk.done() }()
	// unresolvedCommitErr is the error of a commit that failed while the config
	// may name the copy: the row still names the source, so the record stays.
	unresolvedCommitErr := func(err error) error {
		if errors.Is(err, corrosion.ErrNoRowsAffected) {
			return mk.keep(status.Errorf(codes.Aborted, "disk %q/%q changed during move; aborted before completing (the persistent config may name %s; both files are kept)", vm.Name, src.DiskName, dstPath))
		}
		return mk.keep(status.Errorf(codes.Internal,
			"update disk placement: %v. The persistent config may name %s while the disk row names %s; both files are kept. "+
				"Retry `lv move-volume %s %s %s`; a start of the VM first points the disk row at the file the config names",
			err, dstPath, src.Path, vm.Name, src.DiskName, targetPool))
	}

	if cs == cutoverAlreadyAtDst {
		// Persistent already boots from dstPath — it is authoritative (and may hold
		// newer writes than src). Do NOT re-copy; just commit the DB to catch up. On
		// failure keep dstPath (the VM boots from it) so a later retry can complete.
		var merr error
		if mk, merr = s.beginMoveMarker(ctx, vm, src, dstPath, dstPool.Driver, targetPool, false, false, true); merr != nil {
			return merr
		}
		if err := corrosion.UpdateDiskPlacement(ctx, s.db, vm.Name, src.DiskName, vm.HostName, dstPath, dstPool.Driver, targetPool); err != nil {
			slog.Error("move: persistent domain already at the new path; DB catch-up commit failed — keeping the new file so the VM boots, operator must reconcile the disk row",
				"vm", vm.Name, "disk", src.DiskName, "dest", dstPath, "error", err)
			return unresolvedCommitErr(err)
		}
	} else {
		// Forward path: copy src→dst, then (if libvirt) repoint the persistent config,
		// then commit — redefine before commit so a single fault is fully reversible.
		if err := emit(&pb.MoveVolumeProgress{
			Phase:  pb.MoveVolumeProgress_COPY,
			Status: fmt.Sprintf("copying %s → %s", src.Path, dstPath),
		}); err != nil {
			return err
		}
		// A new file, never one already there: in a shared pool the derived
		// "<vm>-<disk>.qcow2" can be another VM's disk (VM "a" disk "b-root"
		// against VM "a-b" disk "root"). A failed copy leaves nothing at
		// dstPath, so nothing here removes a file this move did not create.
		if err := s.copyNoClobber(ctx, src, dstPath, emit); err != nil {
			return err
		}
		// The copy can take minutes. Plan again on the persistent config as it is now,
		// so the define carries any change made to it meanwhile (an owner-epoch or
		// managed-stamp write) with only the disk's source repointed. A config whose
		// disk no longer reads src (or dst) is refused: the VM keeps booting from
		// whatever it names, and the copy is removed only if the config does not name
		// it.
		cs2, newXML, rerr := s.planCutover(vm, src, dstPath)
		if rerr != nil {
			kept := s.keptCopyNote(vm, dstPath)
			s.recordVMEvent(ctx, vm.Name, "disk.moved", "error",
				fmt.Sprintf("%s: the domain changed during the copy; cutover aborted (source preserved%s): %v", src.DiskName, kept, rerr))
			return status.Errorf(codes.Aborted, "the persistent domain config changed during the copy (cutover aborted, source preserved%s): %v", kept, rerr)
		}
		cs = cs2
		var merr error
		if mk, merr = s.beginMoveMarker(ctx, vm, src, dstPath, dstPool.Driver, targetPool, false, false, false); merr != nil {
			if kept := s.keptCopyNote(vm, dstPath); kept != "" {
				return status.Errorf(codes.Internal, "%v%s", merr, kept)
			}
			return merr
		}
		if cs == cutoverRedefined {
			// The stopped VM must be redefined or it fails to start with "Cannot access
			// storage file" once the old path is removed.
			if derr := s.virt.DefineDomain(newXML); derr != nil {
				if s.rollbackCutover(cutoverRedefined, vm, src, dstPath) {
					_ = os.Remove(dstPath)
					s.recordVMEvent(ctx, vm.Name, "disk.moved", "error",
						fmt.Sprintf("%s: cutover aborted (source preserved): %v", src.DiskName, derr))
					return status.Errorf(codes.Internal, "redefine inactive domain (cutover aborted, source preserved): %v", derr)
				}
				// A double fault: the define reported an error and the config could
				// not be pointed back. The row must name the file the config names, so
				// a later start, cold migration or backup reads the file the VM uses.
				if err := s.offlineUnrolledDefine(ctx, vm, src, dstPath, targetPool, derr, mk); err != nil {
					return err
				}
				defineErr = derr
			}
		}
		if err := corrosion.UpdateDiskPlacement(ctx, s.db, vm.Name, src.DiskName, vm.HostName, dstPath, dstPool.Driver, targetPool); err != nil {
			// Roll the cutover back; only remove the copy if the persistent config no
			// longer points at it. A clean rollback leaves DB recording the old pool, so
			// a retry is a fresh move.
			if !s.rollbackCutover(cs, vm, src, dstPath) {
				return unresolvedCommitErr(err)
			}
			_ = os.Remove(dstPath)
			if errors.Is(err, corrosion.ErrNoRowsAffected) {
				return status.Errorf(codes.Aborted, "disk %q/%q changed during move; aborted before completing", vm.Name, src.DiskName)
			}
			return status.Errorf(codes.Internal, "update disk placement: %v", err)
		}
	}
	if defineErr != nil {
		// Completed onto the copy the config names, through a define error.
		detail := fmt.Sprintf("%s: the define of the new path reported an error (%v) and could not be undone; the persistent config names %s, so the move completed onto it",
			src.DiskName, defineErr, dstPath)
		slog.Warn("move: "+detail, "vm", vm.Name)
		s.recordVMEventSeverity(ctx, vm.Name, "disk.moved", "ok", "warning", detail)
	}
	s.clearBackingIfFlattened(ctx, vm.Name, src.DiskName, dstPath)
	s.syncStackComposeForMovedDisk(ctx, vm, src.DiskName, targetPool)

	if err := emit(&pb.MoveVolumeProgress{
		Phase: pb.MoveVolumeProgress_CUTOVER, Status: "disk record updated",
	}); err != nil {
		return err
	}

	if deleteSource {
		if defineErr != nil && s.persistentNamesPath(vm, src.Path) {
			// This move saw a libvirt define error: delete the source only when the
			// persistent config is read and does not name it.
			_ = emit(&pb.MoveVolumeProgress{
				Phase:  pb.MoveVolumeProgress_CLEANUP,
				Status: "source kept: the persistent config may still name " + src.Path,
			})
		} else {
			s.deleteSourceIfUnreferenced(ctx, vm, src, emit)
		}
	}

	s.recordVMEvent(ctx, vm.Name, "disk.moved", "ok",
		fmt.Sprintf("%s: %s → %s", src.DiskName, poolLabel(src.StorageVolume), targetPool))
	return emit(&pb.MoveVolumeProgress{
		Phase:       pb.MoveVolumeProgress_DONE,
		Status:      "move complete",
		BytesCopied: totalBytes,
		CopyPct:     100,
	})
}

// cutoverState records what redefineMovedDiskSource did to the PERSISTENT domain
// config. It decides post-failure cleanup: the destination file is safe to remove
// only when the persistent config does NOT point at it.
type cutoverState int

const (
	cutoverNoVirt       cutoverState = iota // no libvirt backend (tests) — nothing references dst
	cutoverRedefined                        // rewrote the disk source src→dst this call
	cutoverAlreadyAtDst                     // the persistent config already pointed the disk at dst
)

// planCutover INSPECTS the persistent domain config and decides the cutover WITHOUT
// changing anything (no DefineDomain, no file writes). The move paths run it as a
// read-only preflight *before* copying, so a prior partial cutover that already points
// the persistent config at dstPath is detected before the (possibly stale) source
// could clobber the authoritative destination. The offline path runs it again right
// before the define, so newXML is the config as it is then with only the disk's
// source changed.
//   - cutoverNoVirt       — no libvirt backend (tests)
//   - cutoverAlreadyAtDst — persistent already boots the disk from dstPath (newXML "")
//   - cutoverRedefined    — needs DefineDomain(newXML) to repoint src→dst
func (s *Server) planCutover(vm *corrosion.VMRecord, src *corrosion.DiskRecord, dstPath string) (cs cutoverState, newXML string, err error) {
	if s.virt == nil {
		return cutoverNoVirt, "", nil
	}
	xml, derr := s.virt.DumpXMLInactive(vm.Name)
	if derr != nil {
		return cutoverNoVirt, "", fmt.Errorf("dump inactive domain xml: %w", derr)
	}
	// Backing-aware: a zfs, lvm-thin or iscsi disk carries <source dev=> and a
	// ceph one <source name=>, so the file-only spelling would refuse them.
	out, changed, derr := libvirt.RewriteDiskSource(xml, src.TargetDev, src.Path, dstPath)
	if derr != nil {
		return cutoverNoVirt, "", derr
	}
	if !changed {
		return cutoverAlreadyAtDst, "", nil
	}
	return cutoverRedefined, out, nil
}

// redefineMovedDiskSource repoints the moved disk's <source> in the VM's PERSISTENT
// domain config from src.Path to dstPath and reports whether a libvirt define was
// performed, so the caller can roll it back. It is the precise, hard cutover gate
// shared by the offline and live MoveVolume paths: any error must abort/roll back the
// move rather than leave the persistent config stale (which fails the next start with
// "Cannot access storage file").
//
// It reads the INACTIVE config (DumpXMLInactive): for a running domain the live
// config may already show the new path post-pivot, but the persistent config — what
// a restart loads — is what must be rewritten. It is idempotent: if the config
// already points the disk at dstPath it defines nothing, so a retry after a partial
// cutover heals cleanly. When there is no libvirt backend (tests) it is a no-op.
// defined reports whether a define was issued: false with an error means the
// config was not touched (it could not be read or rewritten).
func (s *Server) redefineMovedDiskSource(vm *corrosion.VMRecord, src *corrosion.DiskRecord, dstPath string) (cs cutoverState, defined bool, err error) {
	cs, newXML, err := s.planCutover(vm, src, dstPath)
	if err != nil {
		return cs, false, err
	}
	if cs == cutoverRedefined {
		if derr := s.virt.DefineDomain(newXML); derr != nil {
			return cutoverNoVirt, true, fmt.Errorf("define domain: %w", derr)
		}
		return cs, true, nil
	}
	return cs, false, nil
}

// rollbackCutover undoes redefineMovedDiskSource after a failed move and reports
// whether the destination file is now safe to remove. It reads the persistent config
// as it is now and repoints only the disk's source from dst back to src, so a change
// made to the config since the define (an owner-epoch or managed-stamp write) is kept.
// It NEVER reports safe while the persistent config still points the disk at dst
// (removing it would strand the domain).
func (s *Server) rollbackCutover(cs cutoverState, vm *corrosion.VMRecord, src *corrosion.DiskRecord, dstPath string) (safeToRemoveDst bool) {
	switch cs {
	case cutoverRedefined:
		cur, err := s.virt.DumpXMLInactive(vm.Name)
		if err == nil {
			var back string
			var changed bool
			back, changed, err = libvirt.RewriteDiskSource(cur, src.TargetDev, dstPath, src.Path)
			if err == nil && changed {
				err = s.virt.DefineDomain(back)
			}
		}
		if err != nil {
			slog.Error("move: cutover rollback failed — persistent domain still points at the new path; keeping the new file so the VM boots, operator must reconcile the disk row",
				"vm", vm.Name, "error", err)
			return false
		}
		return true // persistent restored to the source path
	case cutoverAlreadyAtDst:
		// Persistent already pointed at dst before this move; there is no source XML to
		// restore, so keep the file (the VM boots from it) and surface for reconcile.
		slog.Error("move: persistent domain already pointed at the new path before this move and the commit failed — keeping the new file so the VM boots, operator must reconcile the disk row",
			"vm", vm.Name)
		return false
	default: // cutoverNoVirt — no persistent config references dst
		return true
	}
}

// keptCopyNote removes the copy at path unless the VM's persistent config names
// it, and returns "" when it was removed or a note naming the kept copy.
func (s *Server) keptCopyNote(vm *corrosion.VMRecord, path string) string {
	if !s.persistentNamesPath(vm, path) {
		_ = os.Remove(path)
		return ""
	}
	return fmt.Sprintf("; the copy %s is kept because the persistent config names it", path)
}

// offlineUnrolledDefine handles an offline double fault: the define of the
// cutover reported an error and the config could not be pointed back at the
// source. It reads the config again. When the config names the copy, it
// returns nil and the caller completes the move onto it (the copy is complete
// and the VM is stopped, so the row follows the config), with a warning once
// the row is committed. When the config names the source after all, the copy
// is kept and an error says so. When the config cannot be read or names
// neither file, the row stays on the source, both files are kept, the
// unresolved-move record stays (mk.keep), and the error says the two may
// disagree.
func (s *Server) offlineUnrolledDefine(ctx context.Context, vm *corrosion.VMRecord, src *corrosion.DiskRecord, dstPath, targetPool string, derr error, mk *moveMarker) error {
	cs, _, perr := s.planCutover(vm, src, dstPath)
	switch {
	case perr == nil && cs == cutoverAlreadyAtDst:
		return nil
	case perr == nil && cs == cutoverRedefined:
		s.recordVMEvent(ctx, vm.Name, "disk.moved", "error",
			fmt.Sprintf("%s: cutover aborted; the persistent config names the source; the copy %s is kept: %v", src.DiskName, dstPath, derr))
		return status.Errorf(codes.Internal,
			"redefine inactive domain (cutover aborted; the persistent config and the disk row name %s; the copy %s is kept): %v", src.Path, dstPath, derr)
	default:
		slog.Error("move: define failed, the rollback failed, and the persistent config could not be read or names neither file — disk row left on the source, both files kept; operator must reconcile",
			"vm", vm.Name, "disk", src.DiskName, "src", src.Path, "dest", dstPath, "define_error", derr, "read_error", perr)
		s.recordVMEvent(ctx, vm.Name, "disk.moved", "error",
			fmt.Sprintf("%s: cutover aborted; the persistent config could not be read or names neither file; the disk row names %s and the copy %s is kept: %v", src.DiskName, src.Path, dstPath, derr))
		return mk.keep(status.Errorf(codes.Internal,
			"redefine inactive domain failed (%v) and could not be pointed back at %s, and the persistent config could not be read or names neither file (%v): "+
				"the disk row names %s, but the config may name the copy %s; both files are kept. "+
				"A start of the VM first points the disk row at the file the config names, and is refused while the config cannot be read. "+
				"Operator: read the config (virsh dumpxml --inactive %s) and retry `lv move-volume %s %s %s` once it names the copy",
			derr, src.Path, perr, src.Path, dstPath, vm.Name, vm.Name, src.DiskName, targetPool))
	}
}

// persistentNamesPath reports whether the VM's persistent config names path. An
// unreadable config counts as naming it, so a caller never removes a file the
// domain may boot from.
func (s *Server) persistentNamesPath(vm *corrosion.VMRecord, path string) bool {
	if s.virt == nil {
		return false
	}
	cur, err := s.virt.DumpXMLInactive(vm.Name)
	if err != nil {
		return true
	}
	return libvirt.DomainXMLNamesPath(cur, path)
}

// referenceKind names HOW d depends on path, for the message an operator reads
// when a disk is kept. The three kinds are the three DisksReferencingPath
// matches on, and they are not interchangeable: "linked clone" says the file is
// a backing chain that other disks are layered on, which is the case where
// deleting it destroys data that is not its own.
func referenceKind(d *corrosion.DiskRecord, path string) string {
	switch {
	case d.BackingDisk == path:
		return "linked clone"
	case d.BackingImage == path:
		return "backing image"
	default:
		return "disk file"
	}
}

// deleteSourceIfUnreferenced removes the moved disk's old file after a
// successful cutover — but ONLY if no other disk still references that exact
// path, either as its own file or as a backing image. This guards against the
// destructive case the bare os.Remove had: the source being a shared disk or a
// base image other overlays depend on. Best-effort: a skipped, failed, or
// unverifiable delete is reported via send and logged, never fatal — the move
// itself already succeeded and the disk is live on the new pool.
// pathStillReferenced reports whether the disk file at `path` is still needed by
// something OTHER than (excludeVM, excludeDisk): another VM's disk at that path,
// a disk using it as a backing_image, OR a linked clone whose backing_disk
// points at it (which DisksReferencingPath does NOT check). Returns a
// human-readable reason for logging. On a query error it returns referenced=true
// so callers keep the file rather than risk deleting one still in use.
//
// Shared by the storage-motion delete path and the post-migration source-disk
// cleanup — both must never os.Remove a file that backs a linked clone or
// another VM (the bug-sweep found migrate deleting a clone's backing chain).
func (s *Server) pathStillReferenced(ctx context.Context, path, excludeVM, excludeDisk string) (bool, string, error) {
	if held, why := s.keptHolds(ctx, path); held {
		return true, why, nil
	}
	refs, err := corrosion.DisksReferencingPath(ctx, s.db, path)
	if err != nil {
		return true, "usage check failed: " + err.Error(), err
	}
	for _, d := range refs {
		if d.VMName == excludeVM && d.DiskName == excludeDisk {
			continue // the disk being moved/migrated (record repointed)
		}
		return true, fmt.Sprintf("%s/%s (as %s)", d.VMName, d.DiskName,
			referenceKind(&d, path)), nil
	}
	// Redundant since DisksReferencingPath gained its backing_disk clause — the
	// loop above now reports a linked clone itself. Kept deliberately: this is a
	// destructive path, and a second, independent query costs one SELECT.
	clones, err := corrosion.LinkedCloneNames(ctx, s.db, path)
	if err != nil {
		return true, "linked-clone check failed: " + err.Error(), err
	}
	for _, c := range clones {
		if c != excludeVM {
			return true, "linked clone " + c, nil
		}
	}
	return false, "", nil
}

func (s *Server) deleteSourceIfUnreferenced(ctx context.Context, vm *corrosion.VMRecord, src *corrosion.DiskRecord, send func(*pb.MoveVolumeProgress) error) {
	referenced, reason, err := s.pathStillReferenced(ctx, src.Path, vm.Name, src.DiskName)
	if err != nil {
		// Couldn't verify — keep the source rather than risk deleting a
		// file still in use. The operator can remove it manually.
		slog.Warn("move: source-usage check failed; keeping source disk", "path", src.Path, "error", err)
		_ = send(&pb.MoveVolumeProgress{
			Phase:  pb.MoveVolumeProgress_CLEANUP,
			Status: "source kept (usage check failed): " + err.Error(),
		})
		return
	}
	if referenced {
		slog.Warn("move: source disk still referenced — NOT deleting", "path", src.Path, "referenced_by", reason)
		_ = send(&pb.MoveVolumeProgress{
			Phase:  pb.MoveVolumeProgress_CLEANUP,
			Status: "source NOT deleted — still referenced by " + reason,
		})
		return
	}
	if err := os.Remove(src.Path); err != nil {
		slog.Warn("move: delete source after move", "path", src.Path, "error", err)
		_ = send(&pb.MoveVolumeProgress{
			Phase:  pb.MoveVolumeProgress_CLEANUP,
			Status: "source remove failed: " + err.Error(),
		})
		return
	}
	_ = send(&pb.MoveVolumeProgress{
		Phase:  pb.MoveVolumeProgress_CLEANUP,
		Status: "source removed: " + src.Path,
	})
}

// deleteRecordedVMDiskVolumes frees every disk a VM owns at its RECORDED
// location, dispatched through that disk's storage driver. This is what makes
// VM deletion honour non-default pools: a disk relocated by MoveVolume, or one
// living on a ceph/zfs/lvm-thin/iscsi/nfs/dir backend, is actually released
// instead of orphaned. (The default-dir glob in Store.DeleteVMDisks only ever
// saw <dataDir>/disks/<vm>-*.qcow2, so anything elsewhere leaked.)
//
// It mirrors MoveVolume's driver resolution and reuses the same shared-disk
// guard as deleteSourceIfUnreferenced, so a disk path still referenced by
// another VM (shared volume / backing image) is never removed. Best-effort:
// every failure is logged, never fatal — VM teardown must still complete.
//
// Callers MUST invoke this BEFORE tombstoning the VM's corrosion records, since
// it reads vm_disks. The glob-based Store.DeleteVMDisks remains as the fallback
// for default-dir / cloud-init debris not represented in vm_disks.
//
// It returns the ceph images left in their pool (a client still had one
// open): the delete goes on, best-effort, but each such image is named to the
// caller and by ceph_image_leftover (ceph_kept.go), never left unnamed.
func (s *Server) deleteRecordedVMDiskVolumes(ctx context.Context, vmName string) []KeptCephImage {
	disks, err := corrosion.GetVMDisks(ctx, s.db, vmName)
	if err != nil {
		slog.Warn("delete: list disks for volume cleanup — falling back to default-dir glob only",
			"vm", vmName, "error", err)
		return nil
	}
	// Best-effort by design on this path: the caller globs the default dir next.
	kept, _ := s.deleteRecordedVMDiskVolumeRecordsKept(ctx, vmName, disks)
	return kept
}

// deleteRecordedVMDiskVolumeRecords frees an ALREADY-READ set of disk records.
// Split out for cutover, which has to capture the replaced VM's rows before the
// rekey moves them to its retired name and hands the name itself to the
// replacement — reading them afterwards returns the REPLACEMENT's disks.
// It reports the first failure rather than only logging it, because a caller that
// records the cleanup as DONE must not do so while a volume is still there — the
// record is what stops a restart from retrying. Skipping a path another VM still
// references is a success, not a failure.
//
// The rbd disks are deleted together: each may wait for the clients still
// watching it to go (a dead client's watch lasts about 30 s, and a live one
// is waited for up to 45 s before the delete is refused as in use), and
// those waits run at once within one bound, not one after another — which
// for three or more disks outlasted the owner proxy's 2 minutes.
func (s *Server) deleteRecordedVMDiskVolumeRecords(
	ctx context.Context, vmName string, disks []corrosion.DiskRecord,
) error {
	_, err := s.deleteRecordedVMDiskVolumeRecordsKept(ctx, vmName, disks)
	return err
}

// deleteRecordedVMDiskVolumeRecordsKept is deleteRecordedVMDiskVolumeRecords,
// also returning the ceph images it left in their pool, each recorded for
// ceph_image_leftover.
func (s *Server) deleteRecordedVMDiskVolumeRecordsKept(
	ctx context.Context, vmName string, disks []corrosion.DiskRecord,
) ([]KeptCephImage, error) {
	errs := make([]error, len(disks))
	var wg sync.WaitGroup
	for i := range disks {
		d := &disks[i]
		if d.Path == "" {
			continue
		}
		// delete_with_vm=false: the file is not the VM's to remove (an
		// adopted disk). Kept, as the rows of a VM deleted on another host
		// are (deleted_vm_leftovers.go).
		if !d.DeleteWithVM {
			slog.Info("delete: keeping a disk recorded delete_with_vm=false", "vm", vmName, "disk", d.DiskName, "path", d.Path)
			continue
		}
		if s.diskPathReferencedByOtherVM(ctx, vmName, d) {
			continue
		}
		del := func() {
			if err := s.deleteDiskAtRecordedLocation(ctx, d); err != nil {
				slog.Warn("delete: free disk volume",
					"vm", vmName, "disk", d.DiskName, "path", d.Path,
					"storage_type", d.StorageType, "pool", poolLabel(d.StorageVolume), "error", err)
				errs[i] = err
			}
		}
		if strings.HasPrefix(d.Path, "rbd:") {
			wg.Add(1)
			go func() {
				defer wg.Done()
				del()
			}()
			continue
		}
		del()
	}
	wg.Wait()
	kept := s.keptFromErrs(vmName, disks, errs)
	for _, err := range errs {
		if err != nil {
			return kept, err
		}
	}
	return kept, nil
}

// deleteDiskAtRecordedLocation resolves the storage driver for a disk's pool
// and asks it to delete the disk at its recorded path. For file-based pools
// (local/dir/nfs/btrfs) the driver does os.Remove; for block/object backends
// it runs the backend primitive (ceph rbd rm, zfs destroy, lvremove). When the
// disk names a configured pool we use that pool's full config (Source/Options
// matter for ceph); otherwise we fall back to the recorded StorageType, and to
// "local" when even that is blank (legacy rows).
func (s *Server) deleteDiskAtRecordedLocation(ctx context.Context, d *corrosion.DiskRecord) error {
	if !strings.HasPrefix(d.Path, "rbd:") {
		if held, why := s.keptHolds(ctx, d.Path); held {
			s.reportKeptNoteHold(ctx, d.VMName, "the delete of disk "+d.DiskName, d.Path, why)
			return nil
		}
	}
	drv, err := s.diskDriver(ctx, d)
	if err != nil {
		return err
	}
	// hostDiskFile is the recorded path itself, except under the per-node file
	// root a multi-node test gives each node.
	if err := drv.DeleteDisk(ctx, s.hostDiskFile(d.Path)); err != nil {
		return err
	}
	// The disk's data is destroyed by intent: a point-in-time overlay of it
	// (and its binding) goes with it, so a disk re-created at this path never
	// meets it. One already set aside (.orphan-*) is kept.
	if err := pitoverlay.Remove(s.hostDiskFile(d.Path)); err != nil {
		slog.Warn("delete: point-in-time overlay of a deleted disk not removed", "disk", d.Path, "error", err)
		return nil
	}
	if d.VMName != "" {
		s.ClearPITOverlayHold(ctx, d.VMName, d.DiskName)
	}
	return nil
}

// diskDriver is the storage driver that serves a disk at its recorded
// location (deleteDiskAtRecordedLocation).
// An rbd disk's driver is rbdDiskConfig's: on the cluster its domain is
// given, or none.
func (s *Server) diskDriver(ctx context.Context, d *corrosion.DiskRecord) (storage.Driver, error) {
	cfg := storage.Config{Driver: d.StorageType}
	if strings.HasPrefix(d.Path, "rbd:") {
		var err error
		if cfg, err = s.rbdDiskConfig(ctx, d); err != nil {
			return nil, err
		}
	} else if pool, ok := s.lookupStoragePool(d.StorageVolume); ok {
		cfg = storage.Config{Driver: pool.Driver, Source: pool.Source, Target: pool.Target, Options: pool.Options}
	} else if strings.EqualFold(cfg.Driver, "dir") {
		// A `dir` disk whose pool is not on this host: it was moved here from
		// the host that has the pool (a cold move keeps the disk record's
		// pool name), or its pool was removed here. The dir driver's Target
		// only roots creates; removing a file is by its recorded path, as
		// the local driver does, so the delete frees the file where it is
		// rather than failing with "dir driver requires Target" and leaving
		// the VM half deleted. The file is still checked afterwards
		// (freeRecordedVMDisks), so one that is not removed is named. With no
		// pool to anchor it, the path itself must be one of this host's disk
		// places, or in a directory a pool may write into (not a system
		// directory, the PKI directory or litevirt state).
		if !s.withinDiskArtifactRoot(d.Path) && storage.CheckWriteRoot(filepath.Dir(filepath.Clean(d.Path)), s.dataDir, s.pkiDir) != nil {
			return nil, fmt.Errorf("disk %s: its pool %q is not on this host and its path %s is not in a disk place of this host; it is not removed",
				d.DiskName, d.StorageVolume, d.Path)
		}
		cfg.Driver = "local"
	}
	if cfg.Driver == "" {
		cfg.Driver = "local"
	}
	drv, err := storage.New(s.dataDir, cfg)
	if err != nil {
		return nil, fmt.Errorf("construct %s driver: %w", cfg.Driver, err)
	}
	return drv, nil
}

// rbdDiskConfig is the driver configuration an rbd disk's image is acted on
// with: its locator's litevirt pool as this host has it now (cephPoolRef: a
// host pool, read from the table when the loaded list does not hold it yet,
// or a compose stack's volume), whose current monitors a domain defined now
// is given. A locator that names no litevirt pool is acted on as its own
// identity, as the renderer gives it a cluster by its own options; the row's
// storage_volume is not consulted. Never on monitors the locator recorded
// (mon_host) when its pool is not here: they may no longer be its cluster's,
// and may be another's, with another image of the same name on it. Anything
// that cannot be told so (the pool, the stack or the pool's monitors cannot
// be read, a pool of the name that is not ceph, a locator conf that cannot be
// read or names no monitor, or an option the renderer does not know) is an
// error, and nothing is run against any cluster.
func (s *Server) rbdDiskConfig(ctx context.Context, d *corrosion.DiskRecord) (storage.Config, error) {
	l, ok := storage.ParseCephLocator(d.Path)
	if !ok {
		return storage.Config{}, fmt.Errorf("disk %s: %q is not an rbd image locator", d.DiskName, d.Path)
	}
	refuse := func(format string, a ...any) (storage.Config, error) {
		return storage.Config{}, fmt.Errorf("rbd image %s (disk %s) is not acted on: "+format+
			"; nothing was run against any Ceph cluster", append([]any{l.Spec, d.DiskName}, a...)...)
	}
	name := l.Opts["lvpool"]
	if name != "" {
		ref, found, err := s.cephPoolRef(ctx, name)
		switch {
		case err != nil:
			return refuse("whether this host has its pool %s cannot be read (%v)", name, err)
		case found && !strings.EqualFold(ref.Driver, "ceph"):
			return refuse("its pool %s is a %s pool on this host, not a ceph one", name, ref.Driver)
		case found:
			if _, ok := cephRefMonitors(ref); !ok {
				return refuse("the monitors of its pool %s on this host cannot be read", name)
			}
			return storage.Config{Driver: ref.Driver, Source: ref.Source, Target: ref.Target, Options: ref.Options}, nil
		}
	}
	if _, known := rbdLocatorMonitors(l, s.CephMonitorsForPool); !known {
		return refuse("the Ceph cluster its domain is given cannot be told (an option it does not know, or its conf %s cannot be read or names no monitor)", l.Opts["conf"])
	}
	if mh, ok := l.Opts["mon_host"]; ok {
		which := "it names no litevirt pool"
		if name != "" {
			which = "its pool " + name + " is not on this host"
		}
		return refuse("%s, and the monitors its locator recorded (%s) may no longer be its cluster's. "+
			"litevirt does not remove it: find the Ceph cluster that holds it and remove it there by hand "+
			"(rbd -m <that cluster's monitors> rm %s)", which, mh, l.Spec)
	}
	// The identity its own locator names: with no --id and --keyring the rbd
	// CLI would act as client.admin, which a node holding only a restricted
	// key cannot.
	return storage.Config{Driver: "ceph", Source: l.Pool, Options: rbdPathOptions(d.Path)}, nil
}

// diskPathReferencedByOtherVM reports whether a disk's path is still in use by a
// VM other than vmName — as either a disk file or another disk's backing image.
// If so (or if the check itself fails) the caller must keep the file: deleting a
// shared volume or a base image other overlays depend on would be destructive.
// protectedDiskPaths returns the disk paths of vmName that another VM still
// depends on, so the default-dir glob can skip them.
//
// The recorded-volume pass already consults diskPathReferencedByOtherVM per
// disk; this exists because the glob that runs AFTER it does not look at
// records at all. It matches every <vm>-*.qcow2 in the shared disk dir, which
// is how a base still carrying linked-clone overlays was deleted even once the
// recorded pass had correctly declined to free it.
//
// Fails CLOSED in both directions: an unreadable disk list protects nothing it
// cannot name, but diskPathReferencedByOtherVM itself already answers "yes" on
// a read error, so an unreadable REFERENCE check keeps the file. The remaining
// gap — we cannot list this VM's own disks — is logged rather than silent.
// protectedDiskPathsFrom takes the candidate list the caller already holds, so
// that ONE listing drives both the protection and the deletion.
//
// There is deliberately no listing variant of this. The old one returned an
// EMPTY keep set on a listing failure — protecting nothing — and every caller
// that paired it with a re-listing delete was one transient error away from
// sweeping a live clone base. Removing it rather than guarding it is what makes
// that pairing unwriteable instead of merely discouraged.
func (s *Server) protectedDiskPathsFrom(ctx context.Context, vmName string, candidates []string) map[string]bool {
	keep := make(map[string]bool, len(candidates))
	kept := s.keptDiskFiles(ctx, vmName)
	for _, path := range candidates {
		// A disk of this VM recorded delete_with_vm=false, or a layer under
		// one: not the VM's to remove.
		if kept == nil || kept[filepath.Clean(path)] {
			keep[path] = true
			continue
		}
		// A user's upload (an older one, from before uploads into
		// <data_dir>/disks went to disks/uploads) is a project's file, not a
		// VM's debris, whatever its name. Unreadable records protect. A
		// replica's or replicate-volume copy's record does not: the sweep
		// takes what it always took (a run's replicas, stamped, are never
		// among its candidates).
		recs, rerr := s.recordsOf(ctx, path)
		if rerr != nil || slices.ContainsFunc(recs, func(u poolUpload) bool { return u.VM == "" && !u.Peer }) {
			keep[path] = true
			continue
		}
		referrers, rerr := corrosion.DisksReferencingPath(ctx, s.db, path)
		if rerr != nil {
			// FAIL CLOSED, which is what this function's comment always claimed
			// and its old `return nil` did the opposite of: a read that failed is
			// not evidence that nothing references this file. A transient
			// SQLITE_BUSY was enough to sweep a live clone base.
			slog.Error("delete: cannot tell whether a disk file is still referenced; "+
				"protecting it rather than deleting on a guess",
				"vm", vmName, "path", path, "error", rerr)
			keep[path] = true
			continue
		}
		for i := range referrers {
			// Another VM still names it — as its own disk, its backing_image, or
			// its linked-clone backing_disk. Our OWN live rows are not a reason to
			// keep anything: deleting them is the point.
			if referrers[i].VMName != vmName {
				keep[path] = true
				break
			}
		}
		// A clone whose record does not say what it backs on is found by its
		// qcow2 header, as the snapshot guards find it.
		if !keep[path] && s.headerUsersKeep(ctx, vmName, path) {
			keep[path] = true
		}
	}
	return keep
}

func (s *Server) diskPathReferencedByOtherVM(ctx context.Context, vmName string, d *corrosion.DiskRecord) bool {
	used, err := s.diskUsedByOtherVM(ctx, vmName, d)
	if err != nil {
		slog.Warn("delete: shared-disk check failed; keeping disk to avoid removing a shared volume",
			"vm", vmName, "disk", d.DiskName, "path", d.Path, "error", err)
		return true
	}
	return used
}

// diskUsedByOtherVM is diskPathReferencedByOtherVM with "cannot tell" kept
// apart: err is set when whether another VM uses the disk could not be read
// (its records, or another VM's qcow2 chain: storage.IsFSNoAnswer when that
// chain's storage did not answer). A caller that must not report a disk
// removed when it was kept on a guess (DeleteVM) refuses on it.
func (s *Server) diskUsedByOtherVM(ctx context.Context, vmName string, d *corrosion.DiskRecord) (bool, error) {
	path := s.hostDiskFile(d.Path)
	users, err := s.snapshotFileUsers(ctx, vmName, []string{path})
	if err != nil {
		return false, fmt.Errorf("read whether another VM backs on it: %w", err)
	}
	if len(users) > 0 {
		slog.Warn("delete: another VM backs on a disk file of this VM; keeping it",
			"vm", vmName, "path", path, "users", users)
		return true, nil
	}
	refs, err := corrosion.DisksReferencingPath(ctx, s.db, d.Path)
	if err != nil {
		return false, fmt.Errorf("read the disk records that name it: %w", err)
	}
	// An rbd image is named by its spec, whatever options a row's locator
	// carries: two rows can name one image with different suffixes.
	if l, ok := storage.ParseCephLocator(d.Path); ok {
		more, err := corrosion.DisksNamingRBDImage(ctx, s.db, l.Spec)
		if err != nil {
			return false, fmt.Errorf("read the disk records that name its rbd image: %w", err)
		}
		refs = append(refs, more...)
	}
	for _, r := range refs {
		if r.VMName == vmName {
			continue // our own record(s) for this VM
		}
		rel := referenceKind(&r, d.Path)
		slog.Warn("delete: disk path still referenced by another VM — NOT deleting",
			"vm", vmName, "path", d.Path,
			"referenced_by_vm", r.VMName, "referenced_by_disk", r.DiskName, "as", rel)
		return true, nil
	}
	return false, nil
}

// diskPathReferencedByAnyLiveVM is the cleanup-time variant: it exempts NO VM.
//
// The ordinary check exempts the VM being deleted, because its own rows describe
// the volume it is entitled to free. A journaled cutover cleanup has no such VM —
// the records it holds were captured from a name that now belongs to the
// replacement, and the temporary name they were replaced from is FREE and
// reusable. Exempting either would mean exempting whatever VM happens to hold
// that name when the cleanup finally runs, which can be a VM created after the
// crash that legitimately references the volume. So every live reference is a
// reason to keep the file.
func (s *Server) diskPathReferencedByAnyLiveVM(ctx context.Context, d *corrosion.DiskRecord) bool {
	refs, err := corrosion.DisksReferencingPath(ctx, s.db, d.Path)
	if err != nil {
		slog.Warn("cutover cleanup: shared-disk check failed; keeping the volume",
			"disk", d.DiskName, "path", d.Path, "error", err)
		return true
	}
	for _, r := range refs {
		rel := "disk file"
		if r.BackingImage == d.Path {
			rel = "backing image"
		}
		slog.Warn("cutover cleanup: volume still referenced by a live VM — NOT deleting",
			"path", d.Path, "referenced_by_vm", r.VMName, "referenced_by_disk", r.DiskName, "as", rel)
		return true
	}
	return false
}

// deleteCapturedVMDiskVolumes frees an already-read set of disk records that no
// VM owns any more — a journaled cutover cleanup. It reports the first failure
// rather than only logging it, because a caller that records the cleanup as DONE
// must not do so while a volume is still there.
func (s *Server) deleteCapturedVMDiskVolumes(ctx context.Context, disks []corrosion.DiskRecord) error {
	var firstErr error
	for i := range disks {
		d := &disks[i]
		if d.Path == "" {
			continue
		}
		if s.diskPathReferencedByAnyLiveVM(ctx, d) {
			continue
		}
		if err := s.deleteDiskAtRecordedLocation(ctx, d); err != nil {
			slog.Warn("cutover cleanup: free volume",
				"disk", d.DiskName, "path", d.Path, "storage_type", d.StorageType,
				"pool", poolLabel(d.StorageVolume), "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// syncStackComposeForMovedDisk keeps a stack's stored compose YAML in sync with
// a disk's new pool after a move, so `lv compose export` / the UI Export reflect
// the change and a re-deploy is idempotent (rather than reverting the disk).
// No-op for VMs not in a stack. Best-effort: failures are logged, not fatal —
// the disk move itself already succeeded.
func (s *Server) syncStackComposeForMovedDisk(ctx context.Context, vm *corrosion.VMRecord, diskName, pool string) {
	if vm.StackName == "" {
		return
	}
	st, err := corrosion.GetStack(ctx, s.db, vm.StackName)
	if err != nil || st == nil || st.ComposeYAML == "" {
		return
	}
	f, perr := compose.ParseStored([]byte(st.ComposeYAML))
	if perr != nil {
		slog.Warn("move: parse stack compose for sync", "stack", st.Name, "error", perr)
		return
	}
	def, vmKey := compose.FindVMDef(f, vm.Name)
	if def == nil || vmKey == "" {
		return
	}
	if def.EffectiveReplicas() > 1 {
		// Per-replica pool placement can't be expressed in a shared compose def;
		// leave the YAML alone rather than rewriting every replica's pool.
		slog.Info("move: stack VM is replicated — compose YAML not patched (per-replica pool not expressible)",
			"stack", st.Name, "vm", vm.Name)
		return
	}
	updated, changed, perr := compose.PatchDiskStorage(st.ComposeYAML, vmKey, diskName, pool)
	if perr != nil {
		slog.Warn("move: patch stack compose yaml", "stack", st.Name, "vm", vm.Name, "error", perr)
		return
	}
	if !changed {
		return
	}
	st.ComposeYAML = updated
	st.ComposeHash = fmt.Sprintf("%x", sha256.Sum256([]byte(updated)))
	if err := corrosion.UpsertStack(ctx, s.db, *st); err != nil {
		slog.Warn("move: upsert stack after compose patch", "stack", st.Name, "error", err)
		return
	}
	slog.Info("move: synced stack compose YAML with disk pool change",
		"stack", st.Name, "vm", vm.Name, "disk", diskName, "pool", pool)
}

// poolLabel renders a storage-pool name for display, mapping the unnamed
// default pool ("") to "default".
func poolLabel(name string) string {
	if name == "" {
		return "default"
	}
	return name
}

// isFileBasedDriver reports whether a storage driver returns plain file
// paths (rather than block devices or rbd:// identifiers). Only those
// can be moved with qemu-img convert today.
func isFileBasedDriver(driver string) bool {
	switch strings.ToLower(driver) {
	case "", "local", "nfs", "dir", "btrfs":
		return true
	}
	return false
}

// fileBasedPoolDir resolves the on-disk directory used by a file-based
// driver. NFS pools are mounted at <dataDir>/mounts/<safe-source> by
// default; local/dir use the explicit Target or <dataDir>/disks.
func fileBasedPoolDir(dataDir string, p StoragePoolRef) (string, error) {
	switch strings.ToLower(p.Driver) {
	case "", "local":
		if p.Target != "" {
			return p.Target, nil
		}
		return filepath.Join(dataDir, "disks"), nil
	case "dir":
		if p.Target == "" {
			return "", errors.New("dir pool missing Target")
		}
		return p.Target, nil
	case "nfs":
		if p.Target != "" {
			return p.Target, nil
		}
		safe := strings.NewReplacer("/", "_", ":", "_").Replace(p.Source)
		return filepath.Join(dataDir, "mounts", safe), nil
	case "btrfs":
		// btrfs CreateDisk would create a per-VM subvolume — for motion
		// we land the qcow2 directly in Source; subvolume management
		// is the operator's call.
		return p.Source, nil
	}
	return "", fmt.Errorf("driver %q: not a file-based pool", p.Driver)
}

// qemuImgAvailable reports whether qemu-img is on PATH. Callers that would
// otherwise fall back to a verbatim byte copy must NOT do so for a raw source
// (the copy would land raw bytes in a qcow2-declared file) — see promote.
func qemuImgAvailable() bool {
	_, err := exec.LookPath("qemu-img")
	return err == nil
}

// convertVMDisk converts a VM disk — a qcow2 the daemon created — to a new
// qcow2 at dst. Every file of its backing chain is pre-checked and judged by
// diskChainRule; a raw backing is accepted only as the backing_disk recorded
// on the layer naming it (a --no-localize promotion's replica), and qemu-img
// reads it as raw, as declared.
func (s *Server) convertVMDisk(ctx context.Context, d *corrosion.DiskRecord, dst string, emit func(*pb.MoveVolumeProgress) error) error {
	return convertImage(ctx, s.hostDiskFile(d.Path), "qcow2", s.diskChainRule(ctx, *d), dst, emit)
}

// convertImage is the one place a disk image is converted with qemu-img. It
// invokes qemu-img convert -p (progress on stdout), parsing "(NN.NN/100%)"
// lines into progress chunks.
//
// qemu-img never probes: the source format is NAMED (-f) by the caller from
// what it knows — a VM disk is qcow2, a replica's format is in its record. A
// probe on bytes a guest wrote (raw guest content) would obey a qcow2 header
// the guest planted and read the backing or data file it names. A qcow2
// source's header is pre-checked before qemu-img opens it: no external data
// file, one backing format at most, and a backing file only where rule
// accepts it (nil: none at all). The output, a fresh qcow2, must be
// standalone.
//
// Without qemu-img a qcow2 source is byte-copied (it was pre-checked); a raw
// source cannot be, since the copy would land raw bytes in a qcow2-declared
// file.
//
// It never passes -U: an image a running qemu holds open fails on qemu's lock
// instead of being read smeared. The one copy that still forces the share is
// convertImageForceShare (point-in-time copy layer 3, pit_copy.go).
func convertImage(ctx context.Context, src, srcFormat string, rule chainRule, dst string, emit func(*pb.MoveVolumeProgress) error) error {
	return convertImageWith(ctx, src, srcFormat, rule, dst, emit, false)
}

// convertImageForceShare is convertImage with qemu-img's -U (force-share):
// it reads an image a running qemu holds open. Such a copy is smeared across
// the time the read takes — NOT point-in-time and not crash-consistent — so
// it is only the last layer of copyVMDiskConsistent, whose callers mark what
// it produced as not point-in-time.
func convertImageForceShare(ctx context.Context, src, srcFormat string, rule chainRule, dst string, emit func(*pb.MoveVolumeProgress) error) error {
	return convertImageWith(ctx, src, srcFormat, rule, dst, emit, true)
}

// qemuImgCommand builds the qemu-img process. A variable so a test can see
// the argv.
var qemuImgCommand = cmdbound.Command

func convertImageWith(ctx context.Context, src, srcFormat string, rule chainRule, dst string, emit func(*pb.MoveVolumeProgress) error, forceShare bool) error {
	// qemu-img follows symlinks; on an NFS export mounted without
	// nosymfollow (a kernel before 5.10) none is handed to it.
	for _, p := range []string{src, dst} {
		if err := storage.CheckPoolPathNoSymlinks(p); err != nil {
			return status.Errorf(codes.FailedPrecondition, "%v", err)
		}
	}
	switch srcFormat {
	case "qcow2":
		if _, err := precheckChain(src, rule); err != nil {
			return status.Errorf(codes.FailedPrecondition, "%s: %v", filepath.Base(src), err)
		}
	case "raw":
	default:
		return status.Errorf(codes.InvalidArgument, "source format %q: only raw or qcow2 is converted", srcFormat)
	}
	if !qemuImgAvailable() {
		if srcFormat != "qcow2" {
			return status.Error(codes.FailedPrecondition, "converting a raw image needs qemu-img")
		}
		return copyFileWithProgress(ctx, src, dst, emit)
	}
	args := []string{"convert"}
	if forceShare {
		args = append(args, "-U")
	}
	args = append(args, "-p", "-f", srcFormat, "-O", "qcow2", src, dst)
	cmd := qemuImgCommand(ctx, "qemu-img", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	buf := make([]byte, 256)
	for {
		n, rerr := stdout.Read(buf)
		if n > 0 {
			pct := parseQemuImgProgress(string(buf[:n]))
			if pct >= 0 {
				_ = emit(&pb.MoveVolumeProgress{
					Phase:   pb.MoveVolumeProgress_COPY,
					CopyPct: pct,
				})
			}
		}
		if rerr != nil {
			break
		}
	}
	if err := cmd.Wait(); err != nil {
		return err
	}
	// Every caller hands qemu-img a 0600 file it made, whose mode qemu-img
	// keeps; a dst qemu-img had to create itself is 0644 less the umask, and
	// is narrowed to its owner before anything uses it (internal/diskmode),
	// best effort: a filesystem that refuses chmod never fails the copy.
	diskmode.NarrowBestEffort(dst)
	if err := qcow2.AssertStandalone(dst); err != nil {
		return status.Errorf(codes.FailedPrecondition, "converted image is not standalone: %v", err)
	}
	return nil
}

// copyNoClobber converts src into a NEW file at dst: into a temp beside dst,
// then placed no-clobber (placeNoClobber). An existing dst — a file, a symlink, a
// disk another VM uses — is refused with AlreadyExists, never written through,
// and a failed copy leaves nothing at dst.
func (s *Server) copyNoClobber(ctx context.Context, src *corrosion.DiskRecord, dst string, emit func(*pb.MoveVolumeProgress) error) error {
	if err := refuseExistingFile(dst); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(dst), ".repl-*.tmp")
	if err != nil {
		return status.Errorf(codes.Internal, "create copy temp: %v", err)
	}
	tmp := f.Name()
	_ = f.Close()
	defer os.Remove(tmp) // gone after a successful place
	if err := s.convertVMDisk(ctx, src, tmp, emit); err != nil {
		if _, ok := status.FromError(err); ok {
			return err
		}
		return status.Errorf(codes.Internal, "qemu-img convert: %v", err)
	}
	return placeNoClobber(tmp, dst)
}

// copyNoClobberConsistent is copyNoClobber with copyVMDiskConsistent's copy
// (pit_copy.go): point-in-time for a running or paused source, and main's -U
// copy, reported as not point-in-time, only when nothing else can be made.
func (s *Server) copyNoClobberConsistent(ctx context.Context, vm *corrosion.VMRecord, src *corrosion.DiskRecord, dst string, emit func(*pb.MoveVolumeProgress) error) (copyResult, error) {
	if err := refuseExistingFile(dst); err != nil {
		return copyResult{}, err
	}
	f, err := os.CreateTemp(filepath.Dir(dst), ".repl-*.tmp")
	if err != nil {
		return copyResult{}, status.Errorf(codes.Internal, "create copy temp: %v", err)
	}
	tmp := f.Name()
	_ = f.Close()
	defer os.Remove(tmp) // gone after a successful place
	res, err := s.copyVMDiskConsistent(ctx, vm, src, tmp, emit, true)
	if err != nil {
		if _, ok := status.FromError(err); ok {
			return copyResult{}, err
		}
		return copyResult{}, status.Errorf(codes.Internal, "copy: %v", err)
	}
	return res, placeNoClobber(tmp, dst)
}

// parseQemuImgProgress extracts "    (12.34/100%)" → 12.34. Returns -1
// when no progress token is present.
func parseQemuImgProgress(s string) float32 {
	i := strings.LastIndex(s, "(")
	j := strings.LastIndex(s, "/100%")
	if i < 0 || j < 0 || j <= i {
		return -1
	}
	var pct float32
	_, err := fmt.Sscanf(s[i+1:j], "%f", &pct)
	if err != nil {
		return -1
	}
	return pct
}

// copyFileWithProgress is the fallback when qemu-img is unavailable
// (e.g. test environments). Less efficient than qemu-img convert
// because it doesn't drop sparse holes, but functionally correct.
func copyFileWithProgress(ctx context.Context, src, dst string, emit func(*pb.MoveVolumeProgress) error) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	total := st.Size()

	// Never through a symlink at dst: the pool may be somewhere others write.
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, diskmode.File)
	if err != nil {
		return err
	}
	defer out.Close()

	buf := make([]byte, 1<<20)
	var copied int64
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, rerr := in.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return werr
			}
			copied += int64(n)
			if time.Since(last) > 250*time.Millisecond {
				last = time.Now()
				pct := float32(0)
				if total > 0 {
					pct = float32(copied) * 100 / float32(total)
				}
				_ = emit(&pb.MoveVolumeProgress{
					Phase:       pb.MoveVolumeProgress_COPY,
					CopyPct:     pct,
					BytesCopied: copied,
				})
			}
		}
		if rerr == io.EOF {
			// Flush to stable storage before reporting the copy complete — a
			// crash here must not leave a truncated disk that looks done (F7).
			if err := out.Sync(); err != nil {
				return fmt.Errorf("sync destination: %w", err)
			}
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

// _ touches the context import used only when qemu-img is present.
var _ context.Context

// sweepVMDiskDebris removes leftover <vm>-*.qcow2 files, protecting any a live
// row still references.
//
// The two steps go together: the keep set is derived from the same candidate
// list the glob walks, and if that list cannot be built there is nothing to
// derive protection FROM — so the sweep is skipped rather than run with an empty
// keep set. Callers used to pass protectedDiskPaths straight into DeleteVMDisks,
// which on a listing failure meant "delete everything, protect nothing", and was
// survivable only because DeleteVMDisks re-listed and failed identically.
func (s *Server) sweepVMDiskDebris(ctx context.Context, vmName string) {
	candidates, err := s.images.VMDiskCandidates(vmName)
	if err != nil {
		slog.Error("delete: skipping the disk debris sweep; its candidate list is unreadable",
			"vm", vmName, "error", err)
		return
	}
	s.sweepVMDiskDebrisIn(ctx, vmName, candidates)
}

// sweepVMDiskDebrisIn is the sweep over a candidate list, which is also the
// seam its test drives.
//
// Taking the list is what lets a test show WHICH list the deletion walks,
// without a package-level hook sitting in the live delete path of createVM,
// DeleteVM and RebuildVM. The first version of this used such a hook; a
// test-only mutable global steering production deletes is a worse trade than
// one more parameter.
func (s *Server) sweepVMDiskDebrisIn(ctx context.Context, vmName string, candidates []string) {
	// ONE list, used for both halves. Deriving the keep set from a second
	// listing and deleting against a third left the guarantee resting on all
	// three agreeing: a file appearing after the keep set was built is in no
	// keep set and would be swept with no reference check ever run against it.
	keep := s.protectedDiskPathsFrom(ctx, vmName, candidates)
	// A file a kept-disk note holds is a disk an earlier VM of the name was
	// deleted with and kept, or one it backs on: never this VM's debris.
	for _, c := range candidates {
		if keep[c] {
			continue
		}
		if held, why := s.keptHolds(ctx, c); held {
			keep[c] = true
			s.reportKeptNoteHold(ctx, vmName, "the disk debris sweep", c, why)
		}
	}
	if err := s.images.DeleteVMDisksIn(vmName, candidates, keep); err != nil {
		slog.Warn("delete: disk debris sweep failed", "vm", vmName, "error", err)
	}
}

// clearBackingIfFlattened clears a moved disk's backing_disk/backing_image
// when the file now at path is standalone — a move copies the whole chain, so
// the old base is no longer this disk's — and leaves it when the copy kept a
// backing (the byte copy without qemu-img). A stale record would make a later
// in-place restore rebuild the disk as an overlay on the old base.
func (s *Server) clearBackingIfFlattened(ctx context.Context, vmName, diskName, path string) {
	info, err := qcow2.Info(s.hostDiskFile(path))
	if err != nil || info.BackingFile != "" {
		return
	}
	if err := corrosion.ClearDiskBacking(ctx, s.db, vmName, diskName, path); err != nil {
		slog.Warn("move: clearing the flattened disk's backing record failed", "vm", vmName, "disk", diskName, "error", err)
	}
}
