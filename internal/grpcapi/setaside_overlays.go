package grpcapi

import (
	"context"
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
	"github.com/litevirt/litevirt/internal/pitoverlay"
	"github.com/litevirt/litevirt/internal/storage"
)

// Set-aside point-in-time overlays.
//
// An overlay that cannot belong to its disk any more (a restore or an import
// wrote the disk afresh) is never deleted: pitoverlay.SetAside renames it, and
// its binding, to <overlay>.orphan-<time> beside the disk, and they are kept
// until an admin removes them. lv pit-overlays ls lists them, on the VM's host;
// lv pit-overlays rm removes one, refused while it is in use:
//
//   - it is the set-aside evidence of the disk's current window
//     (pitoverlay.OrphanIsEvidence): a start relies on it to point a stopped
//     domain's definition that still names the overlay back at the disk;
//   - a VM disk on any host references the file;
//   - the VM's domain definition names it, or that cannot be read;
//   - the disk is held on its point-in-time overlay (lv resolve-pit-overlay
//     decides that first);
//   - its storage does not answer.

// setAsideOverlayInUse says why orphan, set aside beside d's file disk, is in
// use; "" when it may be removed.
func (s *Server) setAsideOverlayInUse(ctx context.Context, vm *corrosion.VMRecord, d *corrosion.DiskRecord, disk, orphan string) string {
	evidence, err := storage.Bounded("read the binding of", orphan, func() (bool, error) {
		return pitoverlay.OrphanIsEvidence(disk, orphan), nil
	})
	if err != nil {
		return "its storage does not answer: " + err.Error()
	}
	if evidence {
		return "it is the set-aside evidence of the disk's current point-in-time window"
	}
	if owners, err := s.diskReferencesAnyHost(ctx, orphan); err != nil {
		return "whether a VM disk references it cannot be told: " + err.Error()
	} else if len(owners) > 0 {
		return fmt.Sprintf("VM %s's disk %s references it", owners[0].VMName, owners[0].DiskName)
	}
	if s.pitSnapshotter != nil && s.virt != nil && s.virt.DomainExists(vm.Name) {
		used, err := s.pitSnapshotter.DomainUsesFile(vm.Name, orphan)
		if err != nil {
			return "whether the VM's domain names it cannot be told: " + err.Error()
		}
		if used {
			return "the VM's domain definition names it"
		}
	}
	if s.pitOverlayHeldOn(ctx, vm.Name, d.DiskName) {
		return fmt.Sprintf("disk %s is held on its point-in-time overlay; resolve that first (lv resolve-pit-overlay %s %s)", d.DiskName, vm.Name, d.DiskName)
	}
	return ""
}

// pitOverlayHeldOn reports whether vm's disk has an open point-in-time hold.
func (s *Server) pitOverlayHeldOn(ctx context.Context, vmName, diskName string) bool {
	rows, err := corrosion.ListOpenHealthConditionsByCode(ctx, s.db, pitHoldEvaluator, pitHoldCode)
	if err != nil {
		return true // cannot tell: kept
	}
	for _, r := range rows {
		if r.SubjectKind == pitHoldKind && r.SubjectID == vmName+"/"+diskName {
			return true
		}
	}
	return false
}

// setAsideAt is the time an orphan's name records ("" when unreadable).
func setAsideAt(disk, orphan string) string {
	stamp := strings.TrimPrefix(filepath.Base(orphan), filepath.Base(pitoverlay.Path(disk))+".orphan-")
	if len(stamp) >= 15 {
		if t, err := time.Parse("20060102-150405", stamp[:15]); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return ""
}

// localDisks is vm's disks whose files are on this host.
func (s *Server) localDisks(ctx context.Context, vm *corrosion.VMRecord) ([]corrosion.DiskRecord, error) {
	disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
	if err != nil {
		return nil, err
	}
	var out []corrosion.DiskRecord
	for _, d := range disks {
		if (d.HostName == "" || d.HostName == s.hostName) && d.Path != "" {
			out = append(out, d)
		}
	}
	return out, nil
}

// ListSetAsideOverlays is lv pit-overlays ls.
func (s *Server) ListSetAsideOverlays(ctx context.Context, req *pb.ListSetAsideOverlaysRequest) (*pb.ListSetAsideOverlaysResponse, error) {
	if err := s.requirePermPrecheck(ctx, "viewer"); err != nil {
		return nil, err
	}
	target := req.GetHost()
	var only *corrosion.VMRecord
	if req.GetVmName() != "" {
		vm, err := corrosion.GetVM(ctx, s.db, req.GetVmName())
		if err != nil || vm == nil || !s.canReadVMRecord(ctx, vm) {
			return nil, status.Errorf(codes.NotFound, "vm %q not found", req.GetVmName())
		}
		only, target = vm, vm.HostName
	}
	if target != "" && target != s.hostName {
		client, conn, err := s.peerClient(ctx, target)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", target, err)
		}
		defer conn.Close()
		return client.ListSetAsideOverlays(ctx, req)
	}
	var vms []*corrosion.VMRecord
	if only != nil {
		vms = []*corrosion.VMRecord{only}
	} else {
		names, err := corrosion.VMsOnHost(ctx, s.db, s.hostName)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "list this host's VMs: %v", err)
		}
		for _, n := range names {
			if vm, err := corrosion.GetVM(ctx, s.db, n); err == nil && vm != nil && s.canReadVMRecord(ctx, vm) {
				vms = append(vms, vm)
			}
		}
	}
	resp := &pb.ListSetAsideOverlaysResponse{Host: s.hostName}
	for _, vm := range vms {
		disks, err := s.localDisks(ctx, vm)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "list the disks of %s: %v", vm.Name, err)
		}
		for i := range disks {
			d := &disks[i]
			disk := s.hostDiskFile(d.Path)
			orphans, err := storage.Bounded("look for set-aside point-in-time overlays of", disk, func() ([]string, error) {
				return pitoverlay.Orphans(disk)
			})
			if err != nil {
				return nil, status.Errorf(codes.Unavailable, "look for set-aside overlays of %s disk %s: %v", vm.Name, d.DiskName, err)
			}
			for _, o := range orphans {
				ov := &pb.SetAsideOverlay{
					VmName: vm.Name, DiskName: d.DiskName, Name: filepath.Base(o), Path: o,
					DiskPath: disk, SetAsideAt: setAsideAt(disk, o),
				}
				if fi, err := storage.Bounded("read the size of", o, func() (os.FileInfo, error) { return os.Lstat(o) }); err == nil {
					ov.SizeBytes = fi.Size()
				}
				ov.InUse = s.setAsideOverlayInUse(ctx, vm, d, disk, o)
				resp.Overlays = append(resp.Overlays, ov)
			}
		}
	}
	return resp, nil
}

// RemoveSetAsideOverlay is lv pit-overlays rm: admin, on the VM's host,
// refused while the overlay is in use, audited.
func (s *Server) RemoveSetAsideOverlay(ctx context.Context, req *pb.RemoveSetAsideOverlayRequest) (*pb.RemoveSetAsideOverlayResponse, error) {
	if err := s.requirePermPrecheck(ctx, "admin"); err != nil {
		return nil, err
	}
	if err := s.RequirePerm(ctx, "/", verbStorageHostPath, "admin"); err != nil {
		return nil, status.Error(codes.PermissionDenied, "removing a set-aside point-in-time overlay deletes a file on the host and requires the admin role")
	}
	if req.GetVmName() == "" || req.GetDiskName() == "" || req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name, disk_name and name required")
	}
	vm, err := corrosion.GetVM(ctx, s.db, req.GetVmName())
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "vm %q not found", req.GetVmName())
	}
	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach host %q owning vm %q: %v", vm.HostName, vm.Name, err)
		}
		defer conn.Close()
		return client.RemoveSetAsideOverlay(ctx, req)
	}
	unlock := s.lockVM(vm.Name)
	defer unlock()
	disks, err := s.localDisks(ctx, vm)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list disks: %v", err)
	}
	var d *corrosion.DiskRecord
	for i := range disks {
		if disks[i].DiskName == req.GetDiskName() {
			d = &disks[i]
		}
	}
	if d == nil {
		return nil, status.Errorf(codes.NotFound, "vm %q has no disk %q on host %s", vm.Name, req.GetDiskName(), s.hostName)
	}
	disk := s.hostDiskFile(d.Path)
	orphan, err := pitoverlay.OrphanPath(disk, req.GetName())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	fi, err := storage.Bounded("look for", orphan, func() (os.FileInfo, error) { return os.Lstat(orphan) })
	if err != nil {
		if os.IsNotExist(err) {
			return nil, status.Errorf(codes.NotFound, "no set-aside overlay %s beside disk %s of vm %q", req.GetName(), d.DiskName, vm.Name)
		}
		return nil, status.Errorf(codes.Unavailable, "look for %s: %v", orphan, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, status.Errorf(codes.FailedPrecondition, "%s is not a regular file; it is not removed", orphan)
	}
	target := vm.Name + "/" + d.DiskName + "/" + req.GetName()
	if why := s.setAsideOverlayInUse(ctx, vm, d, disk, orphan); why != "" {
		s.audit(ctx, "pit.overlay.remove", target, "refused: "+why, "denied")
		return nil, status.Errorf(codes.FailedPrecondition, "set-aside overlay %s is not removed: %s", orphan, why)
	}
	if _, err := storage.Bounded("remove", orphan, func() (struct{}, error) { return struct{}{}, pitoverlay.RemoveOrphan(orphan) }); err != nil {
		s.audit(ctx, "pit.overlay.remove", target, err.Error(), "error")
		return nil, status.Errorf(codes.Internal, "remove %s: %v", orphan, err)
	}
	detail := fmt.Sprintf("removed the set-aside point-in-time overlay %s (%d bytes) and its binding", orphan, fi.Size())
	slog.Info("set-aside point-in-time overlay removed", "vm", vm.Name, "disk", d.DiskName, "path", orphan, "bytes", fi.Size())
	s.audit(ctx, "pit.overlay.remove", target, detail, "ok")
	s.recordVMEventSeverity(ctx, vm.Name, "disk.pit_overlay_removed", "ok", "info", detail)
	return &pb.RemoveSetAsideOverlayResponse{Host: s.hostName, Path: orphan, SizeBytes: fi.Size()}, nil
}
