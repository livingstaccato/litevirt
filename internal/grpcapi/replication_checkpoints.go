package grpcapi

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ListReplicationCheckpoints is lv replication checkpoints ls: the live
// incremental-replication anchors of the VMs the caller may read. A row of a
// VM that has no live row is listed to a reader at the cluster root only.
func (s *Server) ListReplicationCheckpoints(ctx context.Context, req *pb.ListReplicationCheckpointsRequest) (*pb.ListReplicationCheckpointsResponse, error) {
	if err := s.requirePermPrecheck(ctx, "viewer"); err != nil {
		return nil, err
	}
	live, err := corrosion.ListBackupSchedules(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list schedules: %v", err)
	}
	rows, err := corrosion.LiveReplicationCheckpoints(ctx, s.db, req.GetVmName())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	resp := &pb.ListReplicationCheckpointsResponse{}
	for _, r := range rows {
		vm, verr := corrosion.GetVM(ctx, s.db, r.VMName)
		deleted := verr == nil && vm == nil
		if !s.canReadVM(ctx, r.VMName) {
			continue
		}
		resp.Checkpoints = append(resp.Checkpoints, &pb.ReplicationCheckpointRow{
			VmName: r.VMName, TargetPool: r.Repo, Checkpoint: r.Checkpoint, UpdatedAt: r.UpdatedAt,
			InUse: checkpointInUse(live, r.VMName, r.Repo), VmDeleted: deleted,
		})
	}
	return resp, nil
}

// DeleteReplicationCheckpoint is lv replication checkpoints rm: admin,
// refused while a live replication schedule uses the row, audited as the
// operator who asked. The next run of a schedule added later for the VM and
// pool is a full copy. It is carried out on the VM's host when the VM is live
// (forwarded), so the anchor's libvirt bitmap is dropped there too; the
// response says what became of the bitmap. An older VM host answers
// Unimplemented: the row is then retired here and the bitmap is reported left
// on that host.
func (s *Server) DeleteReplicationCheckpoint(ctx context.Context, req *pb.DeleteReplicationCheckpointRequest) (*pb.DeleteReplicationCheckpointResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.GetVmName() == "" || req.GetTargetPool() == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name and target_pool required")
	}
	actor := s.repairActor(ctx)
	target := req.GetVmName() + "/" + req.GetTargetPool()
	vm, err := corrosion.GetVM(ctx, s.db, req.GetVmName())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read vm %q: %v", req.GetVmName(), err)
	}
	bitmapLeft := ""
	if vm != nil && vm.HostName != s.hostName {
		client, conn, derr := s.peerClient(ctx, vm.HostName)
		if derr == nil {
			defer conn.Close()
			resp, ferr := client.DeleteReplicationCheckpoint(metadata.AppendToOutgoingContext(ctx, repairActorMDKey, actor), req)
			if status.Code(ferr) != codes.Unimplemented {
				return resp, ferr
			}
			bitmapLeft = fmt.Sprintf("left on %s (it runs an older build)", vm.HostName)
		} else {
			bitmapLeft = fmt.Sprintf("left on %s (not reachable: %v)", vm.HostName, derr)
		}
	}
	rows, err := corrosion.LiveReplicationCheckpoints(ctx, s.db, req.GetVmName())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	var row *corrosion.ReplicationCheckpointRow
	for i := range rows {
		if rows[i].Repo == req.GetTargetPool() {
			row = &rows[i]
		}
	}
	if row == nil {
		return nil, status.Errorf(codes.NotFound, "no replication checkpoint for vm %q into %q", req.GetVmName(), req.GetTargetPool())
	}
	live, err := corrosion.ListBackupSchedules(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list schedules: %v", err)
	}
	if checkpointInUse(live, row.VMName, row.Repo) {
		s.auditAs(ctx, actor, "replication.checkpoint.delete", target, "refused: a live replication schedule uses it", "denied")
		return nil, status.Errorf(codes.FailedPrecondition,
			"the checkpoint of vm %q into %q is used by a live replication schedule; remove the schedule first (lv replication schedule rm)", row.VMName, row.Repo)
	}
	if err := corrosion.SetReplicationCheckpoint(ctx, s.db, row.VMName, row.Repo, ""); err != nil {
		s.auditAs(ctx, actor, "replication.checkpoint.delete", target, err.Error(), "error")
		return nil, status.Errorf(codes.Internal, "retire the checkpoint: %v", err)
	}
	bitmap := "none"
	switch {
	case row.Checkpoint == "" || vm == nil:
	case bitmapLeft != "":
		bitmap = bitmapLeft
	case s.backupSource == nil:
		bitmap = "left on " + s.hostName + " (no backup source here)"
	default:
		if derr := s.backupSource.DeleteCheckpoint(row.VMName, row.Checkpoint); derr != nil {
			bitmap = fmt.Sprintf("left on %s (drop failed: %v)", s.hostName, derr)
		} else {
			bitmap = "dropped"
		}
	}
	s.auditAs(ctx, actor, "replication.checkpoint.delete", target, fmt.Sprintf("retired checkpoint %s; bitmap %s", row.Checkpoint, bitmap), "ok")
	return &pb.DeleteReplicationCheckpointResponse{Checkpoint: row.Checkpoint, Bitmap: bitmap, Host: s.hostName}, nil
}
