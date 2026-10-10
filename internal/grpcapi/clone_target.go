package grpcapi

// Clone to another host or into a storage pool (`lv clone --host --pool`).
//
// A clone is made where its source's disks are. With target_host it ends up on
// another host by the one route that already moves a stopped VM and its
// host-local disks between hosts: the clone is made here as a full copy (a
// linked clone is an overlay on a file no other host holds), then moved with
// the cold migration (migrate_cold_disk.go), whose disk transfer runs over the
// peer connection's mTLS, verifies a checksum, refuses a file it did not make,
// and removes the staged copy only after the handoff commits. target_pool
// places the clone's disks in a pool: directly, on the source's host; after the
// move, with MoveVolume, on another host.
//
// Permissions are the clone's own (backup.create on the source, vm.create in the
// clone's project, and the project's right to use the pool, admitPoolAttach,
// which every path that targets a pool enforces), plus what the extra steps
// need: vm.migrate for the move, vm.delete for the cleanup of a failed move,
// vm.move for a pool on another host and vm.start for --start. All are checked
// as the caller, up front, before a byte is copied. The steps run as the caller
// too: the forwarded bearer is relayed (pki.RelayForwardedBearer), and a request
// that arrived forwarded where forwarded identity is not enforced is refused
// rather than run as a cluster peer.
//
// A failed move removes the staged copy. A daemon crash between staging and the
// move's commit does not: the staged clone is then a complete stopped VM on the
// source host (its events show vm.clone.staged without vm.clone.moved), and
// `lv rm` removes it.

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/safename"
)

// validateCloneTarget checks target_host and target_pool before any work is
// done, on whichever node entered the call and again on the source's host.
func (s *Server) validateCloneTarget(ctx context.Context, req *pb.CloneVMRequest, src *corrosion.VMRecord, project string) error {
	poolHost := src.HostName
	if th := req.DestinationHost; th != "" && th != src.HostName {
		h, err := corrosion.GetHost(ctx, s.db, th)
		if err != nil || h == nil {
			return status.Errorf(codes.NotFound, "target host %q not found", th)
		}
		if h.State != "active" {
			return status.Errorf(codes.FailedPrecondition, "target host %q is %s, not active", th, h.State)
		}
		if h.IsWitness() {
			return status.Errorf(codes.FailedPrecondition, "target host %q is a witness and runs no VMs", th)
		}
		if req.Mode == "linked" {
			return status.Error(codes.InvalidArgument,
				"a linked clone cannot be made on another host: it is an overlay on its source's disk, which only "+src.HostName+" holds; use --mode full")
		}
		poolHost = th
		// Every permission the whole clone needs, before a byte is copied: the
		// move runs as the caller (so vm.migrate), a pool on that host takes a
		// move-volume (vm.move), --start a start, and a move that fails is
		// cleaned up by deleting the staged copy (vm.delete). A caller who lacks
		// one is refused now, not after the copy.
		newVM := vmRBACPathFor(project, req.Target)
		verbs := []string{"vm.migrate", "vm.delete"}
		if req.TargetPool != "" {
			verbs = append(verbs, "vm.move")
		}
		if req.Start {
			verbs = append(verbs, "vm.start")
		}
		for _, v := range verbs {
			if err := s.RequirePerm(ctx, newVM, v, "operator"); err != nil {
				return err
			}
		}
	}
	if req.TargetPool == "" {
		return nil
	}
	if req.Mode == "linked" {
		return status.Error(codes.InvalidArgument,
			"a linked clone cannot be placed in a storage pool: it is an overlay on its source's disk; use --mode full")
	}
	if err := s.admitPoolAttach(ctx, project, poolHost, req.TargetPool); err != nil {
		return err
	}
	if poolHost != s.hostName {
		if _, ok, err := corrosion.GetStoragePool(ctx, s.db, poolHost, req.TargetPool); err != nil {
			return status.Errorf(codes.Internal, "look up pool %q on %s: %v", req.TargetPool, poolHost, err)
		} else if !ok {
			return status.Errorf(codes.NotFound, "storage pool %q not found on host %s", req.TargetPool, poolHost)
		}
	}
	return nil
}

// cloneTargetPool is a file-based pool on this host the clone's disks go into.
type cloneTargetPool struct {
	name string
	ref  StoragePoolRef
	dir  string
}

// storageType is what the clone's disk rows record, as MoveVolume records it.
func (p *cloneTargetPool) storageType() string {
	if p.ref.Driver == "" {
		return "local"
	}
	return p.ref.Driver
}

// diskPath is where the clone's disk goes: <pool dir>/<vm>-<disk>.qcow2, the
// name MoveVolume gives a disk it moves there.
func (p *cloneTargetPool) diskPath(vm, disk string) (string, error) {
	if err := safename.ValidateVMName(vm); err != nil {
		return "", err
	}
	if err := safename.ValidateDiskName(disk); err != nil {
		return "", err
	}
	path := filepath.Join(p.dir, fmt.Sprintf("%s-%s.qcow2", vm, disk))
	if !safename.Contains(p.dir, path) {
		return "", fmt.Errorf("disk path %q is outside pool %q", path, p.name)
	}
	return path, nil
}

// cloneTargetPoolFor resolves and checks the pool on THIS host: the project may
// use it, it is file-based and writable (an NFS export mounted hardened), and
// it has room for the clone's disks.
func (s *Server) cloneTargetPoolFor(ctx context.Context, project, name string, srcDisks []corrosion.DiskRecord) (*cloneTargetPool, error) {
	if err := s.admitPoolAttach(ctx, project, s.hostName, name); err != nil {
		return nil, err
	}
	ref, ok := s.resolvePool(ctx, name)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "storage pool %q not configured on host %s", name, s.hostName)
	}
	if !isFileBasedDriver(ref.Driver) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"pool %q (driver %q) is not file-based; a clone can be placed only in a file pool (local, dir, nfs, btrfs)", name, ref.Driver)
	}
	dir, err := s.poolDirForWrite(ctx, name, ref)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, status.Errorf(codes.Internal, "prepare pool dir: %v", err)
	}
	var need int64
	for _, d := range srcDisks {
		need += d.SizeBytes
	}
	if err := s.admitPoolCapacity(ctx, s.hostName, name, need); err != nil {
		return nil, err
	}
	return &cloneTargetPool{name: name, ref: ref, dir: dir}, nil
}

// requireCloneSpace refuses a full clone whose copy would not fit in dir with
// the headroom a cold migration also leaves (requireDiskSpace): the thin disks
// of the guests running on that filesystem pause when it fills, so a copy that
// would take it that far is refused before it starts. need is the allocated size
// of each source disk's chain, never less than the flatten's own estimate.
func (s *Server) requireCloneSpace(ctx context.Context, dir string, srcDisks []corrosion.DiskRecord, why string) error {
	var need uint64
	for _, d := range srcDisks {
		src := s.hostDiskFile(d.Path)
		alloc, aerr := chainAllocated(src)
		info, ierr := qcow2.Info(src)
		if aerr != nil || ierr != nil {
			need += uint64(max(d.SizeBytes, 0)) // cannot measure: the declared size
			continue
		}
		need += coldFlattenEstimate(alloc, info.VirtualSize)
	}
	probe := nearestExistingDir(s.hostDiskFile(dir))
	avail, total, err := s.diskSpace(probe)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "clone: cannot read the free space of %s on %s: %v", dir, s.hostName, err)
	}
	headroom := coldDiskHeadroom(total)
	if avail < need || avail-need < headroom {
		return status.Errorf(codes.FailedPrecondition,
			"cloning needs about %d MiB for %s in %s on %s, where %d MiB are free; it keeps at least %d MiB free there, because the "+
				"thin-provisioned disks of the guests running on that filesystem pause when it fills. Free space there, "+
				"clone to a pool or host with room, or clone the VM where its disks already are",
			need>>20, why, dir, s.hostName, avail>>20, headroom>>20)
	}
	return nil
}

// finishCrossHostClone moves the staged clone to req.DestinationHost, puts its disks
// in req.TargetPool, and starts it when asked. Each step leaves a complete VM
// behind if the next fails, and the error says where it is and the command that
// finishes the job.
func (s *Server) finishCrossHostClone(ctx context.Context, req *pb.CloneVMRequest) (*pb.VM, error) {
	th, name := req.DestinationHost, req.Target
	// Detached from the request, with a deadline: a client that goes away after
	// the copy is made must not strand a staged VM on the wrong host with nothing
	// saying where it was going (the event below says).
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 4*time.Hour)
	defer cancel()
	// The pool step and the start run on the destination as the caller: a request
	// that reached this host forwarded carries the caller's bearer under the
	// forwarded-identity key, which the dial would not copy by itself.
	ctx = pki.RelayForwardedBearer(ctx)
	s.recordVMEvent(ctx, name, "vm.clone.staged", "ok", fmt.Sprintf("staged on %s for %s (pool %q, start %t)", s.hostName, th, req.TargetPool, req.Start))
	if err := s.MigrateVM(&pb.MigrateVMRequest{
		VmName: name, TargetHost: th, Strategy: pb.MigrateStrategy_MIGRATE_COLD,
	}, &discardMigrateStream{ctx: ctx}); err != nil {
		code := status.Code(err)
		if code == codes.OK || code == codes.Unknown {
			code = codes.Internal
		}
		// The staged copy is only a copy: it holds nothing the source does not,
		// and the target-side files of the failed move were removed by the move's
		// own abort. Remove it, so a failed clone leaves nothing on the source
		// host's disks. If the delete itself fails, say where it is.
		if _, derr := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: name}); derr != nil {
			return nil, status.Errorf(code,
				"VM %q was cloned on %s but could not be moved to %s: %s. The staged copy could not be removed (%s): "+
					"it is a complete, stopped VM on %s; delete it with `lv rm %s`, or move it with `lv migrate %s %s --cold`",
				name, s.hostName, th, status.Convert(err).Message(), status.Convert(derr).Message(), s.hostName, name, name, th)
		}
		s.recordVMEvent(ctx, name, "vm.clone.staged", "error", "the move to "+th+" failed and the staged copy was removed: "+status.Convert(err).Message())
		return nil, status.Errorf(code,
			"VM %q could not be cloned onto %s: %s. The staged copy on %s was removed; nothing is left behind",
			name, th, status.Convert(err).Message(), s.hostName)
	}
	s.recordVMEvent(ctx, name, "vm.clone.moved", "ok", fmt.Sprintf("cloned on %s, moved to %s", s.hostName, th))

	client, conn, err := s.peerClient(ctx, th)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable,
			"VM %q was cloned and moved to %s, but %s cannot reach it to finish (pool, start): %v", name, th, s.hostName, err)
	}
	defer conn.Close()

	if req.TargetPool != "" {
		disks, derr := corrosion.GetVMDisks(ctx, s.db, name)
		if derr != nil {
			return nil, status.Errorf(codes.Internal, "VM %q is on %s; read its disks to move them into pool %q: %v", name, th, req.TargetPool, derr)
		}
		for _, d := range disks {
			stream, merr := client.MoveVolume(ctx, &pb.MoveVolumeRequest{
				VmName: name, DiskName: d.DiskName, TargetPool: req.TargetPool, DeleteSource: true,
			})
			for merr == nil {
				if _, merr = stream.Recv(); merr == io.EOF {
					merr = nil
					break
				}
			}
			if merr != nil {
				return nil, status.Errorf(status.Code(merr),
					"VM %q was cloned and moved to %s, but its disk %q could not be moved into pool %q: %s. "+
						"It is a complete, stopped VM on %s with its disks in the default directory: "+
						"finish with `lv move-volume %s %s %s`",
					name, th, d.DiskName, req.TargetPool, status.Convert(merr).Message(), th, name, d.DiskName, req.TargetPool)
			}
		}
	}
	if req.Start {
		if _, err := client.StartVM(ctx, &pb.StartVMRequest{Name: name}); err != nil {
			return nil, status.Errorf(status.Code(err),
				"VM %q was cloned on %s but did not start: %s; start it with `lv start %s`",
				name, th, status.Convert(err).Message(), name)
		}
	}
	s.audit(ctx, "vm.clone", name, fmt.Sprintf("source=%s host=%s pool=%s", req.Source, th, req.TargetPool), "ok")
	vm, err := client.InspectVM(ctx, &pb.InspectVMRequest{Name: name})
	if err != nil {
		return nil, status.Errorf(status.Code(err), "VM %q was cloned to %s; read it back: %s", name, th, strings.TrimSpace(status.Convert(err).Message()))
	}
	return vm, nil
}
