package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pitoverlay"
)

// ResolvePITOverlay is an admin's explicit decision about a point-in-time
// copy overlay that holds a VM because it could not be verified against its
// disk (holdPITOverlay): commit it into the disk, or discard it. Without
// confirm it only reports the two files and the overlay's binding. It runs on
// the VM's host, with the VM's domain not running, and is audited.
//
// Admin only: it rewrites or removes a file on the host without the checks
// every automatic path applies (storage.hostpath at the cluster root).
func (s *Server) ResolvePITOverlay(ctx context.Context, req *pb.ResolvePITOverlayRequest) (*pb.ResolvePITOverlayResponse, error) {
	if err := s.requirePermPrecheck(ctx, "admin"); err != nil {
		return nil, err
	}
	if err := s.RequirePerm(ctx, "/", verbStorageHostPath, "admin"); err != nil {
		return nil, status.Error(codes.PermissionDenied, "resolving a point-in-time overlay rewrites or removes a file on the host and requires the admin role")
	}
	if req.GetVmName() == "" || req.GetDiskName() == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name and disk_name required")
	}
	if req.GetAction() != "commit" && req.GetAction() != "discard" {
		return nil, status.Errorf(codes.InvalidArgument, "action %q: want commit or discard", req.GetAction())
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
		return client.ResolvePITOverlay(ctx, req)
	}
	unlock := s.lockVM(vm.Name)
	defer unlock()

	disks, err := corrosion.GetVMDisks(ctx, s.db, vm.Name)
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
		return nil, status.Errorf(codes.NotFound, "vm %q has no disk %q", vm.Name, req.GetDiskName())
	}
	disk := s.hostDiskFile(d.Path)
	resp := &pb.ResolvePITOverlayResponse{Overlay: pitoverlay.Path(disk), Disk: disk}
	if !pitoverlay.Present(disk) {
		return nil, status.Errorf(codes.NotFound, "disk %q of vm %q has no point-in-time overlay (%s)", d.DiskName, vm.Name, resp.Overlay)
	}
	if b, berr := pitoverlay.BindingOf(disk); berr == nil {
		j, _ := json.Marshal(b)
		resp.Binding = string(j)
	} else {
		resp.Binding = "none: " + berr.Error()
	}
	if s.domainActivity(vm) != activityInactive {
		return nil, status.Errorf(codes.FailedPrecondition, "vm %q is running or its state is unknown; stop it before resolving its overlay", vm.Name)
	}
	if !req.GetConfirm() {
		verb := "commit the overlay's writes into the disk (overwriting what the disk holds there)"
		if req.GetAction() == "discard" {
			verb = "delete the overlay and its writes for good"
		}
		resp.Status = fmt.Sprintf("would %s; nothing done — repeat with --confirm", verb)
		return resp, nil
	}
	switch req.GetAction() {
	case "commit":
		if err := pitoverlay.ForceCommit(ctx, disk); err != nil {
			s.audit(ctx, "vm.pit_overlay.commit", vm.Name, fmt.Sprintf("%s → %s: %v", resp.Overlay, disk, err), "error")
			return nil, status.Errorf(codes.FailedPrecondition, "commit %s into %s: %v", resp.Overlay, disk, err)
		}
		if s.pitSnapshotter != nil && s.virt != nil && s.virt.DomainExists(vm.Name) {
			if err := s.pitSnapshotter.CommitDiskOverlay(vm.Name, d.Path, pitOverlayPath(d.Path), pitDiskFormat); err != nil {
				return nil, status.Errorf(codes.Internal, "committed, but point the definition back at %s: %v", d.Path, err)
			}
		}
		resp.Status = "committed into the disk; the overlay is gone"
	case "discard":
		if err := pitoverlay.Remove(disk); err != nil {
			s.audit(ctx, "vm.pit_overlay.discard", vm.Name, fmt.Sprintf("%s: %v", resp.Overlay, err), "error")
			return nil, status.Errorf(codes.Internal, "discard %s: %v", resp.Overlay, err)
		}
		if s.pitSnapshotter != nil && s.virt != nil && s.virt.DomainExists(vm.Name) {
			if err := s.pitSnapshotter.CommitDiskOverlay(vm.Name, d.Path, pitOverlayPath(d.Path), pitDiskFormat); err != nil {
				return nil, status.Errorf(codes.Internal, "discarded, but point the definition back at %s: %v", d.Path, err)
			}
		}
		resp.Status = "discarded; the disk is used as it is"
	}
	resp.Done = true
	detail := fmt.Sprintf("%s: %s (%s, disk %s; binding %s)", d.DiskName, resp.Status, resp.Overlay, disk, resp.Binding)
	s.audit(ctx, "vm.pit_overlay."+req.GetAction(), vm.Name, detail, "ok")
	s.recordVMEventSeverity(ctx, vm.Name, "disk.pit_overlay_resolved", "ok", "warn", "resolved by an admin: "+detail)
	return resp, nil
}
