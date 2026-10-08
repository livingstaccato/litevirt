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

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/randid"
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/storage"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// ReplicateVolume copies a VM disk into a target pool without cutting
// the VM over. The source remains the VM's authoritative disk; the
// target receives a point-in-time copy suitable for off-site DR.
//
//   - File-based pools (local, nfs, dir, btrfs) get a qemu-img copy into a
//     new daemon-named file (convertImage: format named, input pre-checked).
//   - zfs→zfs and ceph→ceph use native send/receive into a new daemon-named
//     dataset or image (replicateVolumeNative), never an existing one.
//   - btrfs→btrfs sends a standalone disk alone in its own subvolume with
//     btrfs send | receive, and places it as that same new file
//     (replicateBtrfsNative); anything else takes the qemu-img copy.
//   - Crash-consistent: we don't quiesce the guest. For application
//     consistency the operator should snapshot the VM first.
//   - Full copy every call.
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

	// Native send/receive between two pools of the same block driver (zfs,
	// ceph). The destination is a NEW dataset or image the daemon names in
	// the target pool — "<pool source>/<vm>-<disk>-copy-<time>-<id>", or an
	// admin's target_path as the leaf — never the pool itself and never an
	// existing one: the driver refuses an existing destination before
	// sending, receives without -F (zfs) or with a creating import (rbd), and
	// writes the copy's owner record (project, VM, disk) onto it.
	if src.StorageType == dstPool.Driver && (src.StorageType == "zfs" || src.StorageType == "ceph") {
		return s.replicateVolumeNative(ctx, req, vm, src, dstPool, stream)
	}
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
	native, err := s.replicateBtrfsNative(ctx, src, dstPool, drv, dstDir, dstPath, send)
	if err != nil {
		return err
	}
	if !native {
		if err := s.copyNoClobber(ctx, src, dstPath, emit); err != nil {
			return err
		}
	}
	// A copy into the pool's directory is the operator's copy of the disk,
	// whatever it is named: recorded as the VM's project's, promotable by
	// name, and never taken for a replication run's replica — not pruned,
	// not the newest, not an increment's base.
	// A record that cannot be written leaves the copy where it is, and the
	// operator is told so in the final status.
	done := "replication complete"
	if native {
		done = "replication complete (native btrfs send/receive)"
	}
	if filepath.Dir(dstPath) == filepath.Clean(dstDir) {
		recErr := errors.New("its VM's row cannot be read")
		if k, ok := s.replicaKeyFor(ctx, req.VmName, req.DiskName); ok {
			recErr = s.recordPoolCopy(ctx, req.TargetPool, k, dstPath)
		}
		if recErr != nil {
			slog.Warn("replicate: copy written but not recorded as the VM's; an admin can still promote it by name", "path", dstPath, "error", recErr)
			done = fmt.Sprintf("replication complete, but the copy is not recorded as %s's (%v): an admin can still promote it by name", req.VmName, recErr)
		}
	}

	s.recordVMEvent(ctx, req.VmName, "disk.replicated", "ok",
		fmt.Sprintf("%s → %s", req.DiskName, req.TargetPool))
	return send(&pb.ReplicateVolumeProgress{
		Phase:       pb.ReplicateVolumeProgress_DONE,
		Status:      done,
		BytesCopied: src.SizeBytes,
		CopyPct:     100,
		TargetPath:  dstPath,
	})
}

// replicateVolumeNative is ReplicateVolume's zfs/ceph send/receive.
func (s *Server) replicateVolumeNative(ctx context.Context, req *pb.ReplicateVolumeRequest, vm *corrosion.VMRecord, src *corrosion.DiskRecord, dstPool StoragePoolRef, stream grpc.ServerStreamingServer[pb.ReplicateVolumeProgress]) error {
	leaf, err := nativeCopyLeaf(req, dstPool.Driver)
	if err != nil {
		return err
	}
	srcRef, dstRef, err := nativeRefs(src, dstPool, leaf)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	drv, err := storage.New(s.dataDir, storage.Config{
		Driver: dstPool.Driver, Source: dstPool.Source, Options: dstPool.Options,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "construct driver: %v", err)
	}
	rep := storage.AsReplicator(drv)
	if rep == nil {
		return status.Errorf(codes.Unimplemented, "driver %q has no native replication", dstPool.Driver)
	}
	if err := stream.Send(&pb.ReplicateVolumeProgress{
		Phase: pb.ReplicateVolumeProgress_SNAPSHOT, Status: fmt.Sprintf("native %s send/recv → %s", dstPool.Driver, dstRef),
		BytesTotal: src.SizeBytes,
	}); err != nil {
		return err
	}
	// The source side runs with the SOURCE pool's own options (its ceph
	// cluster and identity), never the destination's.
	var srcOpts map[string]string
	if src.StorageVolume != "" {
		srcPool, ok := s.resolvePool(ctx, src.StorageVolume)
		if !ok {
			return status.Errorf(codes.FailedPrecondition, "the disk's pool %q is not configured on this host", src.StorageVolume)
		}
		srcOpts = srcPool.Options
		if srcOpts == nil {
			srcOpts = map[string]string{}
		}
	} else if o := rbdPathOptions(src.Path); len(o) > 0 {
		// A pool-less ceph disk names its cluster and identity in its own
		// path (rbd:<pool>/<image>:conf=…:keyring=…:id=…): its source side
		// runs with those. With none there, it is the destination's cluster,
		// as before.
		srcOpts = o
	}
	if err := rep.Replicate(ctx, storage.ReplicateOptions{
		SrcRef: srcRef, DstRef: dstRef, SrcOptions: srcOpts,
		Record: map[string]string{"project": tenancy.NormalizeProject(vm.Project), "vm": vm.Name, "disk": src.DiskName},
	}); err != nil {
		if errors.Is(err, storage.ErrDestinationExists) {
			return status.Errorf(codes.AlreadyExists, "%v", err)
		}
		return status.Errorf(codes.Internal, "native replicate: %v", err)
	}
	s.recordVMEvent(ctx, req.VmName, "disk.replicated", "ok", fmt.Sprintf("%s → %s", req.DiskName, dstRef))
	return stream.Send(&pb.ReplicateVolumeProgress{
		Phase: pb.ReplicateVolumeProgress_DONE, Status: "native replication complete",
		TargetPath: dstRef, BytesTotal: src.SizeBytes, CopyPct: 100,
	})
}

// nativeRefs derives the source and destination of a native copy: the
// source from the disk's own recorded path (/dev/zvol/<dataset>, or
// rbd:<pool>/<image>[:opts]), the destination as leaf under the target pool's
// dataset or ceph pool.
func nativeRefs(src *corrosion.DiskRecord, dstPool StoragePoolRef, leaf string) (string, string, error) {
	if dstPool.Source == "" || strings.HasPrefix(dstPool.Source, "-") {
		return "", "", fmt.Errorf("target pool has no usable source dataset/pool")
	}
	switch src.StorageType {
	case "zfs":
		ds, ok := strings.CutPrefix(src.Path, "/dev/zvol/")
		if !ok || ds == "" || strings.HasPrefix(ds, "-") {
			return "", "", fmt.Errorf("zfs disk path %q is not /dev/zvol/<dataset>", src.Path)
		}
		return ds, strings.TrimSuffix(dstPool.Source, "/") + "/" + leaf, nil
	case "ceph":
		img, ok := strings.CutPrefix(src.Path, "rbd:")
		if !ok {
			return "", "", fmt.Errorf("ceph disk path %q is not rbd:<pool>/<image>", src.Path)
		}
		img, _, _ = strings.Cut(img, ":")
		if img == "" || strings.HasPrefix(img, "-") || !strings.Contains(img, "/") {
			return "", "", fmt.Errorf("ceph disk path %q is not rbd:<pool>/<image>", src.Path)
		}
		return img, dstPool.Source + "/" + leaf, nil
	}
	return "", "", fmt.Errorf("driver %q has no native replication", src.StorageType)
}

// rbdPathOptions is the conf, keyring and id an "rbd:<pool>/<image>[:k=v...]"
// disk path names for its cluster.
func rbdPathOptions(path string) map[string]string {
	rest, ok := strings.CutPrefix(path, "rbd:")
	if !ok {
		return nil
	}
	parts := strings.Split(rest, ":")
	out := map[string]string{}
	for _, kv := range parts[1:] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || v == "" {
			continue
		}
		switch k {
		case "conf", "keyring", "id":
			out[k] = v
		}
	}
	return out
}

// nativeCopyLeaf is the name of a native copy in its pool: daemon-chosen
// ("<vm>-<disk>-copy-<time>-<id>"), or an admin's target_path (checked by the
// caller) as a leaf name — never a path, never starting with "-".
func nativeCopyLeaf(req *pb.ReplicateVolumeRequest, driver string) (string, error) {
	leaf := req.TargetPath
	if leaf == "" {
		return fmt.Sprintf("%s-%s-copy-%s-%s", req.VmName, req.DiskName,
			time.Now().UTC().Format("20060102-150405"), randid.New()[:8]), nil
	}
	if err := safename.ValidateName(leaf); err != nil || strings.HasPrefix(leaf, "-") {
		return "", status.Errorf(codes.InvalidArgument, "target_path on a %s pool is a dataset/image name: %v", driver, err)
	}
	return leaf, nil
}

// btrfsDiskSubvolume is the subvolume a btrfs disk can be sent from: the
// disk's own directory, directly under its pool's root, a btrfs subvolume,
// holding the disk file and nothing else (a send copies the whole subvolume).
// ok is false for anything else — a disk file in the pool's directory
// (storage motion puts them there), a disk with no pool, a subvolume holding
// other files — which keeps the file copy.
func (s *Server) btrfsDiskSubvolume(ctx context.Context, src *corrosion.DiskRecord) (string, bool) {
	if src.StorageVolume == "" {
		return "", false
	}
	pool, ok := s.resolvePool(ctx, src.StorageVolume)
	if !ok || pool.Driver != "btrfs" || !filepath.IsAbs(pool.Source) {
		return "", false
	}
	file := filepath.Clean(src.Path)
	sub := filepath.Dir(file)
	name := filepath.Base(sub)
	if filepath.Dir(sub) != filepath.Clean(pool.Source) || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "-") {
		return "", false
	}
	if fi, err := os.Lstat(sub); err != nil || !fi.IsDir() {
		return "", false
	}
	des, err := os.ReadDir(sub)
	if err != nil || len(des) != 1 || des[0].Name() != filepath.Base(file) || !des[0].Type().IsRegular() {
		return "", false
	}
	return sub, storage.IsBtrfsSubvolume(ctx, sub)
}

// replicateBtrfsNative makes the copy at dstPath with btrfs send | receive
// when it can: a btrfs disk into a btrfs pool, alone in its own subvolume
// (btrfsDiskSubvolume), standalone — no backing file, no external data file:
// a copy never depends on a file outside itself, so a disk on a base image
// keeps the flattening qemu-img copy — and dstPath a file directly in the
// pool's directory. The copy is then the same new file a qemu-img copy would
// be (the driver places it with a rename that refuses an existing name), so
// everything that finds copies by name or record finds it. native false: the
// caller makes the file copy instead.
func (s *Server) replicateBtrfsNative(ctx context.Context, src *corrosion.DiskRecord, dstPool StoragePoolRef, drv storage.Driver, dstDir, dstPath string, send func(*pb.ReplicateVolumeProgress) error) (native bool, err error) {
	if src.StorageType != "btrfs" || dstPool.Driver != "btrfs" ||
		filepath.Dir(dstPath) != filepath.Clean(dstDir) || strings.HasPrefix(filepath.Base(dstPath), ".") {
		return false, nil
	}
	if _, ok := s.btrfsDiskSubvolume(ctx, src); !ok {
		return false, nil
	}
	srcPool, ok := s.resolvePool(ctx, src.StorageVolume)
	if !ok {
		return false, nil
	}
	if err := qcow2.AssertStandalone(src.Path); err != nil {
		return false, nil
	}
	rep := storage.AsReplicator(drv)
	if rep == nil {
		return false, nil
	}
	if err := send(&pb.ReplicateVolumeProgress{Phase: pb.ReplicateVolumeProgress_COPY, Status: "native btrfs send/receive"}); err != nil {
		return true, err
	}
	err = rep.Replicate(ctx, storage.ReplicateOptions{
		SrcRef: src.Path, DstRef: dstPath, SrcRoot: srcPool.Source,
		// What was received is checked again: the copy placed is standalone
		// whatever the disk's header said when it was looked at above.
		Verify: qcow2.AssertStandalone,
		InUse:  s.btrfsStagingInUse,
	})
	switch {
	case errors.Is(err, storage.ErrDestinationExists):
		return true, status.Errorf(codes.AlreadyExists, "%q already exists; a restore or copy never replaces a file", dstPath)
	case err != nil:
		return true, status.Errorf(codes.Internal, "native btrfs replicate: %v", err)
	}
	return true, nil
}

// btrfsStagingInUse reports whether anything records the file at path — a
// disk (live or kept), or a pool record — so a sweep of btrfs replicate
// staging never removes it. An error reading either is taken as in use.
func (s *Server) btrfsStagingInUse(path string) bool {
	ctx := context.Background()
	if d, err := corrosion.DisksReferencingPath(ctx, s.db, path); err != nil || len(d) > 0 {
		return true
	}
	if d, err := corrosion.TombstonedDisksReferencingPath(ctx, s.db, path); err != nil || len(d) > 0 {
		return true
	}
	s.poolUploadsMu.Lock()
	m, err := s.readPoolUploads()
	s.poolUploadsMu.Unlock()
	if err != nil {
		return true
	}
	_, recorded := m[filepath.Clean(path)]
	return recorded
}
