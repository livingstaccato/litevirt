package grpcapi

import (
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// ReplicateVolume copies a VM disk into a target pool without cutting
// the VM over. The source remains the VM's authoritative disk; the
// target receives a point-in-time copy suitable for off-site DR.
//
// first cut:
//   - File-based source AND target only (local, nfs, dir, btrfs).
//   - Crash-consistent: we don't quiesce the guest. For application
//     consistency the operator should snapshot the VM first
//     (snapshot + replicate is the common pattern).
//   - Full copy every call. Incremental sync arrives with the
//     scheduler in
//
// Block backends (ceph, zfs, iscsi, lvm-thin) return Unimplemented;
// each will eventually reach for native send/receive primitives
// (rbd export-diff | rbd import-diff, zfs send | zfs recv) which
// out-perform a raw byte stream by several orders of magnitude.
func (s *Server) ReplicateVolume(req *pb.ReplicateVolumeRequest, stream grpc.ServerStreamingServer[pb.ReplicateVolumeProgress]) error {
	ctx := stream.Context()
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return err
	}
	if req.VmName == "" || req.DiskName == "" || req.TargetPool == "" {
		return status.Error(codes.InvalidArgument, "vm_name, disk_name, target_pool required")
	}
	// Naming the destination is admin only: a global pool is a directory every
	// project shares, and the copy lands wherever the name points.
	if req.TargetPath != "" {
		if err := s.requireAdminTargetPath(ctx); err != nil {
			return err
		}
	}

	unlock := s.lockVM(req.VmName)
	defer unlock()

	vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return status.Errorf(codes.NotFound, "vm %q not found", req.VmName)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.replicate", "operator"); err != nil {
		return err
	}
	if vm.HostName != s.hostName {
		return status.Errorf(codes.FailedPrecondition,
			"vm %q lives on %q; run ReplicateVolume on that host", req.VmName, vm.HostName)
	}

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

	// Project isolation: the VM's project may replicate only into a global pool or
	// one it owns (target pool resolved on this host — ReplicateVolume runs locally).
	if err := s.admitVMPoolUse(ctx, vm, s.hostName, req.TargetPool); err != nil {
		return err
	}
	dstPool, ok := s.resolvePool(ctx, req.TargetPool)
	if !ok {
		return status.Errorf(codes.NotFound, "target pool %q not configured on this host", req.TargetPool)
	}

	// Every write into the target pool goes through the write check — the
	// native send/recv below included.
	if err := s.checkPoolForWrite(ctx, req.TargetPool, dstPool); err != nil {
		return err
	}

	// There is no native send/recv branch. The one that was here passed the
	// target POOL NAME as the receive destination — `zfs recv -F -- <pool>`,
	// `rbd import-diff - <pool>`, `btrfs receive <pool>` — so a pool named like
	// a host dataset was force-received over, against the rule that a copy
	// never replaces what is there. A btrfs disk takes the file copy below;
	// zfs and ceph are refused until a receive into a fresh, daemon-derived
	// dataset or image exists.
	if !isFileBasedDriver(src.StorageType) {
		return status.Errorf(codes.Unimplemented,
			"source pool driver %q: replication not yet implemented", src.StorageType)
	}
	if !isFileBasedDriver(dstPool.Driver) {
		return status.Errorf(codes.Unimplemented,
			"target pool driver %q: replication not yet implemented", dstPool.Driver)
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
	if err := drv.Prepare(ctx); err != nil {
		return status.Errorf(codes.FailedPrecondition, "prepare target pool: %v", err)
	}

	dstDir, err := fileBasedPoolDir(s.dataDir, dstPool)
	if err != nil {
		return status.Errorf(codes.Internal, "resolve target dir: %v", err)
	}
	// The destination is a new file: daemon-named
	// ("<vm>-<disk>-copy-<time>-<id>.qcow2") unless an admin named it, and
	// never one that exists. The old fixed "<vm>-<disk>.qcow2" was also the
	// name of other disks in a shared pool (VM "a" disk "b-root" against VM
	// "a-b" disk "root"), and qemu-img convert writes over what it is given.
	var dstPath string
	if req.TargetPath == "" {
		if dstPath, err = derivedDiskFile(dstDir, req.VmName, req.DiskName, "copy", ".qcow2"); err != nil {
			return err
		}
	} else if dstPath, err = s.resolveAdminTarget(ctx, req.TargetPath, dstDir); err != nil {
		return err
	}
	if dstPath == src.Path {
		return status.Error(codes.FailedPrecondition, "source and destination resolve to the same path")
	}

	send := func(p *pb.ReplicateVolumeProgress) error {
		p.BytesTotal = src.SizeBytes
		return stream.Send(p)
	}

	if err := send(&pb.ReplicateVolumeProgress{
		Phase:  pb.ReplicateVolumeProgress_SNAPSHOT,
		Status: "skipping in-guest quiesce; copy is crash-consistent",
	}); err != nil {
		return err
	}

	// Reuse the qemu-img convert helper; the only difference vs MoveVolume
	// is that we don't update the VM's disk record afterwards.
	emit := func(p *pb.MoveVolumeProgress) error {
		return send(&pb.ReplicateVolumeProgress{
			Phase:       pb.ReplicateVolumeProgress_COPY,
			CopyPct:     p.CopyPct,
			BytesCopied: p.BytesCopied,
		})
	}
	if err := copyNoClobber(ctx, src.Path, dstPath, emit); err != nil {
		return err
	}

	s.recordVMEvent(ctx, req.VmName, "disk.replicated", "ok",
		fmt.Sprintf("%s → %s", req.DiskName, req.TargetPool))
	return send(&pb.ReplicateVolumeProgress{
		Phase:       pb.ReplicateVolumeProgress_DONE,
		Status:      "replication complete",
		BytesCopied: src.SizeBytes,
		CopyPct:     100,
		TargetPath:  dstPath,
	})
}
