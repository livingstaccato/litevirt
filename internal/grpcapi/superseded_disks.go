package grpcapi

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/health"
)

// SetSupersededDiskRetentionDays records superseded_disk_retention_days, which
// a SupersededDisks answer reports (the sweep itself runs in the daemon).
func (s *Server) SetSupersededDiskRetentionDays(days int) { s.supersededRetentionDays = days }

// SupersededDisks is `lv host superseded-disks <host>`: the disk copies a
// failover start set aside on a host (health/superseded_retention.go), and,
// with purge, the removal of every one not held. The copies are files on that
// host, so the request is answered there.
func (s *Server) SupersededDisks(ctx context.Context, req *pb.SupersededDisksRequest) (*pb.SupersededDisksResponse, error) {
	role := "viewer"
	if req.Purge {
		role = "admin" // it deletes disk data
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

	copies, err := health.ListSupersededDisks(ctx, s.db, s.dataDir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list superseded disk copies: %v", err)
	}
	removed := map[string]bool{}
	if req.Purge {
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

	resp := &pb.SupersededDisksResponse{Host: s.hostName, RetentionDays: int32(s.supersededRetentionDays)}
	for _, c := range copies {
		resp.Disks = append(resp.Disks, &pb.SupersededDisk{
			Path: c.Path, DiskPath: c.DiskPath, SetAsideAt: c.SetAsideAt.UTC().Format(time.RFC3339),
			SizeBytes: c.SizeBytes, VmName: c.VM, VmState: c.VMState, Held: c.Held, Removed: removed[c.Path],
		})
	}
	return resp, nil
}
