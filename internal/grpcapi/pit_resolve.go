package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pitoverlay"
)

// ResolvePITOverlay is an admin's explicit decision about a point-in-time
// copy overlay that holds a VM because it could not be verified against its
// disk (holdPITOverlay): commit it into the disk, or discard it. It runs on
// the VM's host, with the VM's domain not running, and is audited.
//
// Without confirm it only reports: the verdict (pitoverlay.Assess — the base
// matches the binding, is half-written, already has the overlay merged, or
// unknown), the recorded and current identity, and what each action would
// do. With it:
//
//   - commit goes through only on a verdict that says a commit is safe
//     (matches, half-written), through the same identity checks as every
//     automatic commit. force_commit is an expert's override of the verdict;
//     the one check it keeps is that the overlay's backing file is this disk,
//     so it never repoints an overlay at another file;
//   - discard of a disk a commit had begun writing (half-written, or unknown
//     after a commit began) is refused without accept_torn_disk: the disk
//     would stay inconsistent, and a restore from a backup or a replica is
//     the alternative.
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
	switch req.GetAction() {
	case "commit", "discard":
	case "":
		if req.GetConfirm() {
			return nil, status.Error(codes.InvalidArgument, "--confirm carries out --commit or --discard; give one")
		}
	default:
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
		s.ClearPITOverlayHold(ctx, vm.Name, d.DiskName)
		return nil, status.Errorf(codes.NotFound, "disk %q of vm %q has no point-in-time overlay (%s)", d.DiskName, vm.Name, resp.Overlay)
	}
	if b, berr := pitoverlay.BindingOf(disk); berr == nil {
		j, _ := json.Marshal(b)
		resp.Binding = string(j)
	} else {
		resp.Binding = "none: " + berr.Error()
	}
	owner := pitOwner(vm, d)
	activity := s.domainActivity(vm)
	a := pitoverlay.Assess(disk, owner, false)
	resp.Verdict, resp.VerdictReason = string(a.Verdict), a.Reason
	resp.Current, resp.BackingFile, resp.OverlayCurrent = a.Current, a.Backing, a.OverlayCurrent
	resp.IfCommit, resp.IfDiscard = a.Consequences()
	resp.Recommendation = pitoverlay.HoldAdvice(vm.Name, d.DiskName, a)
	// A commit of an overlay already in the disk writes the window's old
	// blocks over everything the guest wrote since.
	mergedAlready := a.Verdict == pitoverlay.Pivoted || (a.Binding != nil && a.Binding.State == pitoverlay.StateCommitted)
	resp.NeedsOverwriteNewerWrites = mergedAlready
	if !req.GetConfirm() {
		// The dry run answers whatever the VM does: a hold on a running VM
		// points the admin here.
		resp.Status = fmt.Sprintf("verdict %s; nothing done — repeat with --commit or --discard, and --confirm", a.Verdict)
		if activity != activityInactive {
			resp.Status = fmt.Sprintf("verdict %s (the VM is running, so the disk may change); nothing done — stop the VM, then repeat with --commit or --discard, and --confirm", a.Verdict)
		}
		return resp, nil
	}
	if activity != activityInactive {
		return nil, status.Errorf(codes.FailedPrecondition, "vm %q is running or its state is unknown; stop it before resolving its overlay", vm.Name)
	}
	repoint := func() error {
		if s.pitSnapshotter != nil && s.virt != nil && s.virt.DomainExists(vm.Name) {
			return s.pitSnapshotter.CommitDiskOverlay(vm.Name, d.Path, pitOverlayPath(d.Path), pitDiskFormat, nil)
		}
		return nil
	}
	switch req.GetAction() {
	case "commit":
		safe := a.Verdict == pitoverlay.Matches || a.Verdict == pitoverlay.HalfWritten
		if !safe && req.GetForceCommit() && mergedAlready && !req.GetOverwriteNewerWrites() {
			s.audit(ctx, "vm.pit_overlay.commit", vm.Name, fmt.Sprintf("%s → %s: forced commit refused, the overlay is already in the disk (verdict %s)", resp.Overlay, disk, a.Verdict), "denied")
			return nil, status.Errorf(codes.FailedPrecondition,
				"forced commit refused: the overlay is already in the disk (verdict %s), so committing it again writes the window's old blocks over everything the guest has written to %s since — a silent rollback of part of the disk. Discard it instead (--discard --confirm). Only --overwrite-newer-writes, with --force-commit, overrides this",
				a.Verdict, disk)
		}
		if !safe && !req.GetForceCommit() {
			s.audit(ctx, "vm.pit_overlay.commit", vm.Name, fmt.Sprintf("%s → %s: refused, verdict %s (%s)", resp.Overlay, disk, a.Verdict, a.Reason), "denied")
			return nil, status.Errorf(codes.FailedPrecondition,
				"commit refused: the verdict is %s (%s), so a commit is not known to be safe — it %s. Run `lv resolve-pit-overlay %s %s` (no --confirm) for the verdict; --force-commit overrides it",
				a.Verdict, a.Reason, strings.TrimPrefix(resp.IfCommit, "REFUSED without --force-commit: "), vm.Name, d.DiskName)
		}
		if safe {
			if _, err = pitoverlay.CommitOffline(ctx, disk, owner); err == nil {
				if err = repoint(); err == nil {
					err = pitoverlay.Remove(disk)
				}
			}
			resp.Status = fmt.Sprintf("committed into the disk (verdict %s); the overlay is gone", a.Verdict)
		} else {
			if err = pitoverlay.ForceCommit(ctx, disk); err == nil {
				err = repoint()
			}
			resp.Status = fmt.Sprintf("FORCED commit into the disk against verdict %s (%s); the overlay is gone", a.Verdict, a.Reason)
			if mergedAlready {
				resp.Status = fmt.Sprintf("FORCED commit with --overwrite-newer-writes: the overlay's old blocks were written over the guest's newer writes (verdict %s); the overlay is gone", a.Verdict)
			}
		}
		if err != nil {
			s.audit(ctx, "vm.pit_overlay.commit", vm.Name, fmt.Sprintf("%s → %s: %v", resp.Overlay, disk, err), "error")
			return nil, status.Errorf(codes.FailedPrecondition, "commit %s into %s: %v", resp.Overlay, disk, err)
		}
	case "discard":
		torn := a.Verdict == pitoverlay.HalfWritten || (a.Verdict == pitoverlay.Unknown && a.CommitBegan)
		if torn && !req.GetAcceptTornDisk() {
			s.audit(ctx, "vm.pit_overlay.discard", vm.Name, fmt.Sprintf("%s: refused, verdict %s, a commit had begun", resp.Overlay, a.Verdict), "denied")
			return nil, status.Errorf(codes.FailedPrecondition,
				"discard refused: a commit had begun writing %s (verdict %s), so without the overlay the disk would be inconsistent — partly as it was, partly the overlay's writes — and the guest may not boot or may corrupt its filesystem. Restoring the disk from a backup or a replica is the alternative. --accept-torn-disk discards anyway",
				disk, a.Verdict)
		}
		if err := pitoverlay.Remove(disk); err != nil {
			s.audit(ctx, "vm.pit_overlay.discard", vm.Name, fmt.Sprintf("%s: %v", resp.Overlay, err), "error")
			return nil, status.Errorf(codes.Internal, "discard %s: %v", resp.Overlay, err)
		}
		if err := repoint(); err != nil {
			return nil, status.Errorf(codes.Internal, "discarded, but point the definition back at %s: %v", d.Path, err)
		}
		resp.Status = "discarded; the disk is used as it is"
		if torn {
			resp.Status = "discarded with --accept-torn-disk; the disk is used as it is, partly written"
		}
	}
	resp.Done = true
	s.ClearPITOverlayHold(ctx, vm.Name, d.DiskName)
	detail := fmt.Sprintf("%s: %s (%s, disk %s; binding %s)", d.DiskName, resp.Status, resp.Overlay, disk, resp.Binding)
	s.audit(ctx, "vm.pit_overlay."+req.GetAction(), vm.Name, detail, "ok")
	s.recordVMEventSeverity(ctx, vm.Name, "disk.pit_overlay_resolved", "ok", "warn", "resolved by an admin: "+detail)
	return resp, nil
}
