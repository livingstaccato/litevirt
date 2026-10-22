package grpcapi

import (
	"context"
	"path/filepath"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// keepDisksSnapshotRefusal refuses `lv rm --keep-disks` of a VM that has
// snapshot records, before anything is done. A kept disk with snapshots is a
// backing chain whose base sits at the path a later VM of the same name
// creates its disk at, and the kept snapshots' records, memory images and
// firmware bundles are keyed by the VM's name, so that later VM would list
// them and remove or overwrite them. Removing the snapshots first (`lv
// snapshot rm`, which merges each into its disk) or deleting without
// --keep-disks leaves nothing of the kind. Records that cannot be read
// refuse too. A snapshot libvirt holds with no record here is refused by
// libvirt itself: the keep-state undefine passes no SNAPSHOTS_METADATA.
func (s *Server) keepDisksSnapshotRefusal(ctx context.Context, req *pb.DeleteVMRequest) error {
	if !req.KeepDisks {
		return nil
	}
	snaps, err := corrosion.ListSnapshots(ctx, s.db, req.Name)
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"cannot delete VM %q with --keep-disks: its snapshot records cannot be read (%v); nothing was done (retry is safe)", req.Name, err)
	}
	if len(snaps) == 0 {
		return nil
	}
	names := make([]string, 0, len(snaps))
	for _, sn := range snaps {
		names = append(names, sn.Name)
	}
	return status.Errorf(codes.FailedPrecondition,
		"cannot delete VM %q with --keep-disks: it has %d snapshot(s) (%s), and a later VM of the name could overwrite the "+
			"kept disks' snapshot chain and remove the snapshots' memory images and firmware bundles; remove them first "+
			"(`lv snapshot rm %s <snapshot>`), or delete without --keep-disks; nothing was done",
		req.Name, len(snaps), strings.Join(names, ", "), req.Name)
}

// keepDisksChainRefusal refuses `lv rm --keep-disks` of a VM one of whose
// host-local disks here is an overlay on another of the VM's own disk files
// (<vm>-<disk>.qcow2), before anything is done: as a snapshot that libvirt
// deleted as metadata only leaves it. The delete keeps, and notes, only the
// file the disk's record names; a later VM of the name would set aside or
// write over the file under it, which leaves the kept overlay backing on
// that VM's disk. A disk whose chain cannot be read refuses too.
func (s *Server) keepDisksChainRefusal(ctx context.Context, req *pb.DeleteVMRequest) error {
	if !req.KeepDisks || s.images == nil {
		return nil
	}
	disks, err := corrosion.GetVMDisks(ctx, s.db, req.Name)
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"cannot delete VM %q with --keep-disks: its disk records cannot be read (%v); nothing was done (retry is safe)", req.Name, err)
	}
	candidates, err := s.images.VMDiskCandidates(req.Name)
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"cannot delete VM %q with --keep-disks: the disk files a later VM of the name would take cannot be listed (%v); nothing was done (retry is safe)", req.Name, err)
	}
	taken := map[string]bool{}
	for _, c := range candidates {
		taken[filepath.Clean(c)] = true
	}
	for _, d := range disks {
		if d.Path == "" || (d.HostName != "" && d.HostName != s.hostName) || !isHostLocalDiskDriver(d.StorageType) {
			continue
		}
		top := filepath.Clean(s.hostDiskFile(d.Path))
		var under string
		if _, err := chainReaches(top, "", func(p string) bool {
			if p := filepath.Clean(p); p != top && taken[p] {
				under = p
				return true
			}
			return false
		}); err != nil {
			return status.Errorf(codes.Unavailable,
				"cannot delete VM %q with --keep-disks: the backing chain of its disk %s cannot be read (%v); nothing was done (retry is safe)",
				req.Name, d.DiskName, err)
		}
		if under != "" {
			return status.Errorf(codes.FailedPrecondition,
				"cannot delete VM %q with --keep-disks: its disk %s (%s) is an overlay on %s, which a later VM of the name would set "+
					"aside or write over, leaving the kept overlay on that VM's disk; delete without --keep-disks, or copy the disk "+
					"out to a standalone image first; nothing was done",
				req.Name, d.DiskName, d.Path, under)
		}
	}
	return nil
}
