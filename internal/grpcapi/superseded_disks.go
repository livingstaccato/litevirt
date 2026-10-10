package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/notify"
)

// SupersededNamedOnlySec is the older_than_sec a client sends with purge set
// alongside remove_paths or restore_path (service.proto, SupersededDisksRequest):
// about 285 years, so no copy is that old, and short enough that
// older_than_sec seconds still fit a time.Duration. An older host that does
// not know the named fields then requires admin and purges nothing.
const SupersededNamedOnlySec = 9_000_000_000

// SetSupersededDiskRetentionDays records superseded_disk_retention_days, which
// a SupersededDisks answer reports (the sweep itself runs in the daemon).
func (s *Server) SetSupersededDiskRetentionDays(days int) { s.supersededRetentionDays = days }

// SupersededDisks is `lv host superseded-disks <host>`: the disk copies a
// failover set aside on a host (health/superseded_retention.go); with purge,
// the removal of every one neither retained nor held; with remove_paths, the
// removal of exactly the named copies; with restore_path, the named copy put
// back as its VM's disk. The copies are files on that host, so the request is
// answered there.
func (s *Server) SupersededDisks(ctx context.Context, req *pb.SupersededDisksRequest) (*pb.SupersededDisksResponse, error) {
	named := len(req.RemovePaths) > 0 || req.RestorePath != ""
	role := "viewer"
	if req.Purge || named {
		role = "admin" // it deletes or replaces disk data
	}
	if err := RequireRole(ctx, role); err != nil {
		return nil, err
	}
	if req.Host != "" && req.Host != s.hostName {
		client, conn, err := s.peerClient(ctx, req.Host)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", req.Host, err)
		}
		defer conn.Close()
		return client.SupersededDisks(ctx, req)
	}
	if req.OlderThanSec < 0 {
		return nil, status.Error(codes.InvalidArgument, "older_than_sec must not be negative")
	}
	if len(req.RemovePaths) > 0 && req.RestorePath != "" {
		return nil, status.Error(codes.InvalidArgument, "remove and restore are separate requests")
	}

	copies, err := health.ListSupersededDisks(ctx, s.db, s.dataDir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list superseded disk copies: %v", err)
	}
	resp := &pb.SupersededDisksResponse{Host: s.hostName, RetentionDays: int32(s.supersededRetentionDays)}
	removed := map[string]bool{}
	switch {
	case req.RestorePath != "":
		got, rerr := s.restoreSupersededDisk(ctx, req.RestorePath)
		if rerr != nil {
			return nil, rerr
		}
		resp.Restored, resp.RestoredTo, resp.SetAside = got.Restored, got.DiskPath, got.SetAside
		if copies, err = health.ListSupersededDisks(ctx, s.db, s.dataDir); err != nil {
			return nil, status.Errorf(codes.Internal, "list superseded disk copies: %v", err)
		}
	case len(req.RemovePaths) > 0:
		// Named copies only: the purge flag a client sends beside them is for
		// older hosts (SupersededNamedOnlySec), never a bulk purge here.
		gone, rerr := health.RemoveSupersededDisks(ctx, s.db, s.dataDir, req.RemovePaths)
		var bytes int64
		var names []string
		for _, c := range gone {
			removed[c.Path] = true
			bytes += c.SizeBytes
			names = append(names, c.Path)
		}
		result, detail := "ok", fmt.Sprintf("removed %d named superseded disk copies (%d bytes) on %s: %s",
			len(gone), bytes, s.hostName, strings.Join(names, ", "))
		if rerr != nil {
			result, detail = "error", detail+": "+rerr.Error()
		}
		s.audit(ctx, "host.superseded_disks.remove", s.hostName, detail, result)
		if rerr != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "%s", detail)
		}
	case req.Purge:
		gone, perr := health.PurgeSupersededDisks(ctx, s.db, s.dataDir, time.Duration(req.OlderThanSec)*time.Second, time.Now())
		var bytes int64
		for _, c := range gone {
			removed[c.Path] = true
			bytes += c.SizeBytes
		}
		result, detail := "ok", fmt.Sprintf("removed %d superseded disk copies (%d bytes) on %s", len(gone), bytes, s.hostName)
		if perr != nil {
			result, detail = "error", detail+": "+perr.Error()
		}
		s.audit(ctx, "host.superseded_disks.purge", s.hostName, detail, result)
		if perr != nil {
			return nil, status.Errorf(codes.Internal, "%s", detail)
		}
	}

	for _, c := range copies {
		resp.Disks = append(resp.Disks, &pb.SupersededDisk{
			Path: c.Path, DiskPath: c.DiskPath, SetAsideAt: c.SetAsideAt.UTC().Format(time.RFC3339),
			SizeBytes: c.SizeBytes, VmName: c.VM, VmState: c.VMState, Held: c.Held, Removed: removed[c.Path],
			Retained: c.Retained,
		})
	}
	return resp, nil
}

// restoreSupersededDisk is the restore half of SupersededDisks, under the
// VM's lock so a start cannot land between the checks and the swap.
func (s *Server) restoreSupersededDisk(ctx context.Context, copyPath string) (health.RestoredCopy, error) {
	copies, err := health.ListSupersededDisks(ctx, s.db, s.dataDir)
	if err != nil {
		return health.RestoredCopy{}, status.Errorf(codes.Internal, "list superseded disk copies: %v", err)
	}
	vmName := ""
	for _, c := range copies {
		if c.Path == copyPath {
			vmName = c.VM
		}
	}
	if vmName != "" {
		defer s.lockVM(vmName)()
	}
	running := func(name string) bool {
		if s.virt == nil || !s.virt.DomainExists(name) {
			return false
		}
		// libvirt's own activity question: DomainState reports a paused
		// domain, whose disk is open, as "stopped".
		active, err := s.virt.DomainIsActive(name)
		return err != nil || active
	}
	got, err := health.RestoreSupersededDisk(ctx, s.db, s.dataDir, s.hostName, copyPath, running, time.Now())
	detail := fmt.Sprintf("restore %s on %s", copyPath, s.hostName)
	if err != nil {
		s.audit(ctx, "host.superseded_disks.restore", s.hostName, detail+": "+err.Error(), "error")
		if errors.Is(err, health.ErrRestoreRefused) {
			return got, status.Errorf(codes.FailedPrecondition, "%v", err)
		}
		return got, status.Errorf(codes.Internal, "%v", err)
	}
	detail = fmt.Sprintf("restored %s as disk %s of VM %s at %s on %s", got.Restored, got.Disk, got.VM, got.DiskPath, s.hostName)
	if got.SetAside != "" {
		detail += "; the disk it replaced is kept as " + got.SetAside
	}
	s.audit(ctx, "host.superseded_disks.restore", s.hostName, detail, "ok")
	s.recordVMEvent(ctx, got.VM, "vm.disk.restored", "ok", detail)
	return got, nil
}

// NotifyVMDiskStranded is the failover coordinator's and the reconciler's
// callback for a VM disk left on, or set aside on, a host
// (health/stranded_disk.go): a vm.disk.stranded notification.
func (s *Server) NotifyVMDiskStranded(vm, host, detail string) {
	s.notify(context.Background(), notify.Notification{
		Kind: "vm.disk.stranded", Severity: notify.SevWarn, Subject: vm,
		Detail: host + ": " + detail,
	})
}

// NotifyCTRootfsStranded is the coordinator's callback for a container
// relocation that left the container's own rootfs on its failed host
// (health/stranded_rootfs.go): a ct.rootfs.stranded notification.
func (s *Server) NotifyCTRootfsStranded(ct, host, detail string) {
	s.notify(context.Background(), notify.Notification{
		Kind: "ct.rootfs.stranded", Severity: notify.SevWarn, Subject: ct,
		Detail: host + ": " + detail,
	})
}
