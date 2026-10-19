package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/pitoverlay"
	"github.com/litevirt/litevirt/internal/storage"
)

// Set-aside point-in-time overlays.
//
// An overlay that cannot belong to its disk any more (a restore or an import
// wrote the disk afresh) is never deleted: pitoverlay.SetAside renames it, and
// its binding, to <overlay>.orphan-<time> beside the disk, and they are kept,
// also when the disk itself is deleted or moved away, until an admin removes
// them. lv pit-overlays ls lists them on a host: beside a live VM's disk, or
// DETACHED (no live disk at the path it was set aside beside any more, its
// owner read from its binding). lv pit-overlays rm removes one, refused while
// it is in use:
//
//   - it is the set-aside evidence of the disk's current window
//     (pitoverlay.OrphanInUse, which keeps it whenever its binding or the
//     disk's window token cannot be read): a start relies on it to point a
//     stopped domain's definition that still names the overlay back at the
//     disk;
//   - a VM disk on any host references the file;
//   - a domain on this host names it, or whether one does cannot be told;
//   - the disk is held on its point-in-time overlay (lv resolve-pit-overlay
//     decides that first);
//   - its storage does not answer.
//
// The listing is filtered by the caller's own read on the node the caller
// entered (a forwarded call arrives on the answering host as the peer): a
// VM's overlays need its vm.read, a detached overlay vm.read at the root.

// pitOverlayRemoveAction is the audit action of a removal.
const pitOverlayRemoveAction = "pit.overlay.remove"

// boundedRefs is diskReferencesAnyHost under the network-filesystem bound
// (it resolves the path through symlinks).
func (s *Server) boundedRefs(ctx context.Context, path string) ([]corrosion.DiskRecord, error) {
	return storage.Bounded("look for disks referencing", path, func() ([]corrosion.DiskRecord, error) {
		return s.diskReferencesAnyHost(ctx, path)
	})
}

// domainNamesFile says why the domain of vmName may name path; "" when it
// positively does not (no such domain, or a definition read without it).
func (s *Server) domainNamesFile(vmName, path string) string {
	if s.virt == nil {
		return ""
	}
	_, err := s.virt.DomainIsActive(vmName)
	switch {
	case err == nil:
	case lv.IsNoDomain(err):
		return ""
	default:
		return "whether VM " + vmName + "'s domain names it cannot be told: " + err.Error()
	}
	if s.pitSnapshotter == nil {
		return "whether VM " + vmName + "'s domain names it cannot be told: no definition reader"
	}
	used, err := s.pitSnapshotter.DomainUsesFile(vmName, path)
	if err != nil {
		return "whether VM " + vmName + "'s domain names it cannot be told: " + err.Error()
	}
	if used {
		return "VM " + vmName + "'s domain definition names it"
	}
	return ""
}

// anyDomainNamesFile is domainNamesFile over every VM recorded on this host.
func (s *Server) anyDomainNamesFile(ctx context.Context, path string) string {
	names, err := corrosion.VMsOnHost(ctx, s.db, s.hostName)
	if err != nil {
		return "this host's VMs cannot be read: " + err.Error()
	}
	for _, n := range names {
		if why := s.domainNamesFile(n, path); why != "" {
			return why
		}
	}
	return ""
}

// setAsideOverlayInUse says why orphan, set aside beside d's file disk, is in
// use; "" when it may be removed.
func (s *Server) setAsideOverlayInUse(ctx context.Context, vm *corrosion.VMRecord, d *corrosion.DiskRecord, disk, orphan string) string {
	uuid, _ := vmSpecUUID(vm.Spec)
	why, err := storage.Bounded("read the binding of", orphan, func() (string, error) {
		return pitoverlay.OrphanInUse(disk, orphan, uuid), nil
	})
	if err != nil {
		return "its storage does not answer: " + err.Error()
	}
	if why != "" {
		return why
	}
	if owners, err := s.boundedRefs(ctx, orphan); err != nil {
		return "whether a VM disk references it cannot be told: " + err.Error()
	} else if len(owners) > 0 {
		return fmt.Sprintf("VM %s's disk %s references it", owners[0].VMName, owners[0].DiskName)
	}
	if why := s.domainNamesFile(vm.Name, orphan); why != "" {
		return why
	}
	if s.pitOverlayHeldOn(ctx, vm.Name, d.DiskName) {
		return fmt.Sprintf("disk %s is held on its point-in-time overlay; resolve that first (lv resolve-pit-overlay %s %s)", d.DiskName, vm.Name, d.DiskName)
	}
	return ""
}

// detachedOverlayInUse says why a detached orphan may not be removed; "" when
// it may. With no live disk at its base path there is no window, so evidence
// does not apply.
func (s *Server) detachedOverlayInUse(ctx context.Context, orphan, base string) string {
	if owners, err := s.boundedRefs(ctx, base); err != nil {
		return "whether a live disk is at " + base + " cannot be told: " + err.Error()
	} else if len(owners) > 0 {
		return fmt.Sprintf("VM %s's disk %s is at %s: remove it with lv pit-overlays rm %s %s <name>",
			owners[0].VMName, owners[0].DiskName, base, owners[0].VMName, owners[0].DiskName)
	}
	if owners, err := s.boundedRefs(ctx, orphan); err != nil {
		return "whether a VM disk references it cannot be told: " + err.Error()
	} else if len(owners) > 0 {
		return fmt.Sprintf("VM %s's disk %s references it", owners[0].VMName, owners[0].DiskName)
	}
	return s.anyDomainNamesFile(ctx, orphan)
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
func setAsideAt(orphan string) string {
	name := filepath.Base(orphan)
	i := strings.Index(name, pitoverlay.Suffix+".orphan-")
	if i < 0 {
		return ""
	}
	stamp := name[i+len(pitoverlay.Suffix+".orphan-"):]
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

// localFilePoolDirs is the directory of every file-based pool of this host,
// and <data_dir>/disks.
func (s *Server) localFilePoolDirs(ctx context.Context) []string {
	seen := map[string]bool{}
	var out []string
	add := func(d string) {
		if d = filepath.Clean(d); d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	add(filepath.Join(s.dataDir, "disks"))
	pools, err := corrosion.ListStoragePoolsForHost(ctx, s.db, s.hostName)
	if err != nil {
		return out
	}
	for _, p := range pools {
		if !isFileBasedDriver(p.Driver) {
			continue
		}
		if ref, ok := s.resolvePool(ctx, p.Name); ok {
			if d, err := fileBasedPoolDir(s.dataDir, ref); err == nil {
				add(d)
			}
		}
	}
	sort.Strings(out)
	return out
}

// listSetAsideOverlaysHere is every set-aside overlay on this host (only
// vm's, when vm is set), unfiltered.
func (s *Server) listSetAsideOverlaysHere(ctx context.Context, only *corrosion.VMRecord) ([]*pb.SetAsideOverlay, error) {
	var vms []*corrosion.VMRecord
	if only != nil {
		vms = []*corrosion.VMRecord{only}
	} else {
		names, err := corrosion.VMsOnHost(ctx, s.db, s.hostName)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "list this host's VMs: %v", err)
		}
		for _, n := range names {
			if vm, err := corrosion.GetVM(ctx, s.db, n); err == nil && vm != nil {
				vms = append(vms, vm)
			}
		}
	}
	var out []*pb.SetAsideOverlay
	listed := map[string]bool{}
	for _, vm := range vms {
		disks, err := s.localDisks(ctx, vm)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "list the disks of %s: %v", vm.Name, err)
		}
		uuid, _ := vmSpecUUID(vm.Spec)
		for i := range disks {
			d := &disks[i]
			disk := s.hostDiskFile(d.Path)
			orphans, err := pitoverlay.OrphansBounded(disk)
			if err != nil {
				return nil, status.Errorf(codes.Unavailable, "look for set-aside overlays of %s disk %s: %v", vm.Name, d.DiskName, err)
			}
			for _, o := range orphans {
				listed[o] = true
				ov := &pb.SetAsideOverlay{
					VmName: vm.Name, DiskName: d.DiskName, Name: filepath.Base(o), Path: o,
					DiskPath: disk, SetAsideAt: setAsideAt(o), OwnerVmUuid: uuid,
				}
				if fi, err := storage.Bounded("read the size of", o, func() (os.FileInfo, error) { return os.Lstat(o) }); err == nil {
					ov.SizeBytes = fi.Size()
				}
				ov.InUse = s.setAsideOverlayInUse(ctx, vm, d, disk, o)
				out = append(out, ov)
			}
		}
	}
	if only != nil {
		return out, nil
	}
	for _, dir := range s.localFilePoolDirs(ctx) {
		matches, err := storage.Bounded("look for set-aside point-in-time overlays in", dir, func() ([]string, error) {
			return filepath.Glob(filepath.Join(dir, ".*"+pitoverlay.Suffix+".orphan-*"))
		})
		if err != nil {
			slog.Warn("set-aside overlays: a pool directory did not answer; its overlays are not listed", "dir", dir, "error", err)
			continue
		}
		for _, o := range matches {
			base, ok := pitoverlay.DiskOfOrphan(o)
			if !ok || listed[o] {
				continue
			}
			if owners, err := s.boundedRefs(ctx, base); err != nil || len(owners) > 0 {
				continue // beside a live disk: listed by its own VM's host
			}
			ov := &pb.SetAsideOverlay{Name: filepath.Base(o), Path: o, DiskPath: base, SetAsideAt: setAsideAt(o), Detached: true}
			if owner, err := storage.Bounded("read the binding of", o, func() (pitoverlay.Owner, error) { return pitoverlay.OrphanOwner(o) }); err == nil {
				ov.VmName, ov.DiskName, ov.OwnerVmUuid = owner.VM, owner.Disk, owner.VMUUID
			}
			if fi, err := storage.Bounded("read the size of", o, func() (os.FileInfo, error) { return os.Lstat(o) }); err == nil {
				ov.SizeBytes = fi.Size()
			}
			ov.InUse = s.detachedOverlayInUse(ctx, o, base)
			out = append(out, ov)
		}
	}
	return out, nil
}

// readableSetAsideOverlay reports whether the caller may see o: its VM's
// vm.read, or vm.read at the root for a detached one.
func (s *Server) readableSetAsideOverlay(ctx context.Context, o *pb.SetAsideOverlay) bool {
	if o.GetDetached() {
		return s.RequirePerm(ctx, "/", "vm.read", "viewer") == nil
	}
	return s.canReadVM(ctx, o.GetVmName())
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
	var resp *pb.ListSetAsideOverlaysResponse
	if target != "" && target != s.hostName {
		client, conn, err := s.peerClient(ctx, target)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", target, err)
		}
		defer conn.Close()
		if resp, err = client.ListSetAsideOverlays(ctx, req); err != nil {
			return nil, err
		}
	} else {
		all, err := s.listSetAsideOverlaysHere(ctx, only)
		if err != nil {
			return nil, err
		}
		resp = &pb.ListSetAsideOverlaysResponse{Host: s.hostName, Overlays: all}
	}
	// Filtered here, by this caller: the answering host saw the peer.
	kept := resp.Overlays[:0]
	for _, o := range resp.GetOverlays() {
		if s.readableSetAsideOverlay(ctx, o) {
			kept = append(kept, o)
		}
	}
	resp.Overlays = kept
	return resp, nil
}

// RemoveSetAsideOverlay is lv pit-overlays rm: admin, on the overlay's host,
// refused while the overlay is in use, audited as the operator who asked.
func (s *Server) RemoveSetAsideOverlay(ctx context.Context, req *pb.RemoveSetAsideOverlayRequest) (*pb.RemoveSetAsideOverlayResponse, error) {
	if err := s.requirePermPrecheck(ctx, "admin"); err != nil {
		return nil, err
	}
	if err := s.RequirePerm(ctx, "/", verbStorageHostPath, "admin"); err != nil {
		return nil, status.Error(codes.PermissionDenied, "removing a set-aside point-in-time overlay deletes a file on the host and requires the admin role")
	}
	// The operator who asked, carried to the host that removes, which writes
	// the audit row (a forwarded call arrives as the peer).
	actor := s.repairActor(ctx)
	forward := func(host string) (*pb.RemoveSetAsideOverlayResponse, error) {
		client, conn, err := s.peerClient(ctx, host)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach host %q: %v", host, err)
		}
		defer conn.Close()
		return client.RemoveSetAsideOverlay(metadata.AppendToOutgoingContext(ctx, repairActorMDKey, actor), req)
	}
	if req.GetPath() != "" {
		if req.GetVmName() != "" || req.GetDiskName() != "" || req.GetName() != "" {
			return nil, status.Error(codes.InvalidArgument, "give a path (a detached overlay) or vm_name, disk_name and name, not both")
		}
		if h := req.GetHost(); h != "" && h != s.hostName {
			return forward(h)
		}
		return s.removeDetachedOverlay(ctx, actor, req.GetPath())
	}
	if req.GetVmName() == "" || req.GetDiskName() == "" || req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name, disk_name and name required")
	}
	vm, err := corrosion.GetVM(ctx, s.db, req.GetVmName())
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "vm %q not found", req.GetVmName())
	}
	if vm.HostName != s.hostName {
		return forward(vm.HostName)
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
	target := vm.Name + "/" + d.DiskName + "/" + req.GetName()
	fi, err := s.statOrphan(orphan, req.GetName(), "beside disk "+d.DiskName+" of vm "+vm.Name)
	if err != nil {
		return nil, err
	}
	if why := s.setAsideOverlayInUse(ctx, vm, d, disk, orphan); why != "" {
		s.auditAs(ctx, actor, pitOverlayRemoveAction, target, "refused: "+why, "denied")
		return nil, status.Errorf(codes.FailedPrecondition, "set-aside overlay %s is not removed: %s", orphan, why)
	}
	resp, err := s.removeOrphan(ctx, actor, target, orphan, fi)
	if err == nil {
		s.recordVMEventSeverity(ctx, vm.Name, "disk.pit_overlay_removed", "ok", "info",
			fmt.Sprintf("removed the set-aside point-in-time overlay %s (%d bytes) and its binding", orphan, fi.Size()))
	}
	return resp, err
}

// statOrphan is the orphan's Lstat, bounded: NotFound when it is not there,
// Unavailable on any other error, FailedPrecondition when it is not a regular
// file.
func (s *Server) statOrphan(orphan, name, where string) (os.FileInfo, error) {
	fi, err := storage.Bounded("look for", orphan, func() (os.FileInfo, error) { return os.Lstat(orphan) })
	if err != nil {
		if os.IsNotExist(err) {
			return nil, status.Errorf(codes.NotFound, "no set-aside overlay %s %s", name, where)
		}
		return nil, status.Errorf(codes.Unavailable, "look for %s: %v", orphan, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, status.Errorf(codes.FailedPrecondition, "%s is not a regular file; it is not removed", orphan)
	}
	return fi, nil
}

// removeOrphan removes orphan and its binding, bounded, and audits it.
func (s *Server) removeOrphan(ctx context.Context, actor, target, orphan string, fi os.FileInfo) (*pb.RemoveSetAsideOverlayResponse, error) {
	if _, err := storage.Bounded("remove", orphan, func() (struct{}, error) { return struct{}{}, pitoverlay.RemoveOrphan(orphan) }); err != nil {
		s.auditAs(ctx, actor, pitOverlayRemoveAction, target, err.Error(), "error")
		return nil, status.Errorf(codes.Internal, "remove %s: %v", orphan, err)
	}
	detail := fmt.Sprintf("removed the set-aside point-in-time overlay %s (%d bytes) and its binding on %s", orphan, fi.Size(), s.hostName)
	slog.Info("set-aside point-in-time overlay removed", "path", orphan, "bytes", fi.Size(), "actor", actor)
	s.auditAs(ctx, actor, pitOverlayRemoveAction, target, detail, "ok")
	return &pb.RemoveSetAsideOverlayResponse{Host: s.hostName, Path: orphan, SizeBytes: fi.Size()}, nil
}

// removeDetachedOverlay removes a detached set-aside overlay by its path: one
// directly in a file-based pool directory of this host, named as SetAside
// names one, a regular file, with no live disk at the path it was set aside
// beside and nothing referencing it.
func (s *Server) removeDetachedOverlay(ctx context.Context, actor, path string) (*pb.RemoveSetAsideOverlayResponse, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, status.Errorf(codes.InvalidArgument, "%q is not a clean absolute path", path)
	}
	base, ok := pitoverlay.DiskOfOrphan(path)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "%q is not a set-aside point-in-time overlay (.<disk file>%s.orphan-<time>)", path, pitoverlay.Suffix)
	}
	inPool := false
	for _, d := range s.localFilePoolDirs(ctx) {
		if filepath.Dir(path) == d {
			inPool = true
		}
	}
	if !inPool {
		return nil, status.Errorf(codes.InvalidArgument, "%s is not in a file-based pool directory of host %s", path, s.hostName)
	}
	fi, err := s.statOrphan(path, filepath.Base(path), "on host "+s.hostName)
	if err != nil {
		return nil, err
	}
	if why := s.detachedOverlayInUse(ctx, path, base); why != "" {
		s.auditAs(ctx, actor, pitOverlayRemoveAction, path, "refused: "+why, "denied")
		return nil, status.Errorf(codes.FailedPrecondition, "set-aside overlay %s is not removed: %s", path, why)
	}
	return s.removeOrphan(ctx, actor, path, path, fi)
}
