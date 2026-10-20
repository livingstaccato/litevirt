package grpcapi

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// GetVMOperation returns the operation currently holding a VM's mutation barrier
// (F1 admin recovery inspect). has_active=false when the VM has no in-flight
// operation. Admin-only.
func (s *Server) GetVMOperation(ctx context.Context, req *pb.GetVMOperationRequest) (*pb.GetVMOperationResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.VmName == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name is required")
	}
	view, found, err := corrosion.GetVMActiveOperation(ctx, s.db, req.VmName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get active operation: %v", err)
	}
	resp := &pb.GetVMOperationResponse{}
	if !found {
		return resp, nil // has_active = false
	}
	resp.HasActive = true
	resp.OperationId = view.ActiveOperationID
	resp.CurrentState = view.State
	resp.Faulted = view.Faulted
	resp.VmOwnerEpoch = view.OwnerEpoch
	resp.SpecGeneration = view.SpecGeneration
	if view.Operation != nil {
		resp.OperationKind = view.Operation.OperationKind
	} else {
		resp.HeaderMissing = true
	}
	for _, st := range view.Steps {
		resp.Steps = append(resp.Steps, &pb.OperationStepInfo{
			StepName: st.StepName, OwnerEpoch: st.OwnerEpoch, CreatedAt: st.CreatedAt,
		})
	}
	return resp, nil
}

// AbortVMOperation force-clears a wedged operation's mutation barrier so the VM
// is mutable again. Deliberate admin recovery: requires force, and clears the
// barrier only via the exact owner/generation CAS (a superseded op can't clear a
// newer one). With operation_id it is refused unless that operation is the
// active one. Admin-only.
// abortForwardedMD marks an AbortVMOperation forwarded to the VM's host, so
// it is not forwarded again.
const abortForwardedMD = "x-litevirt-abort-forwarded"

func (s *Server) AbortVMOperation(ctx context.Context, req *pb.AbortVMOperationRequest) (*pb.AbortVMOperationResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.VmName == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name is required")
	}
	if !req.Force {
		return nil, status.Error(codes.FailedPrecondition, "aborting an operation requires force")
	}
	// A drain's move of the VM runs on the VM's host, detached from the
	// drain's client: an unscoped abort reaching another host goes there
	// (once). A scoped one (operation_id) never does: it cancels no drain
	// move, its compare-and-swap works on any host, and a VM host on an older
	// build drops operation_id and would abort whatever operation is active.
	if md, _ := metadata.FromIncomingContext(ctx); req.OperationId == "" && len(md.Get(abortForwardedMD)) == 0 {
		if vm, verr := corrosion.GetVM(ctx, s.db, req.VmName); verr == nil && vm != nil && vm.HostName != s.hostName {
			if client, conn, perr := s.peerClient(ctx, vm.HostName); perr == nil {
				resp, ferr := client.AbortVMOperation(metadata.AppendToOutgoingContext(ctx, abortForwardedMD, "1"), req)
				conn.Close()
				// A host that cannot be reached runs no move of it: the
				// recorded operation is aborted here, as before.
				if status.Code(ferr) != codes.Unavailable {
					return resp, ferr
				}
			}
		}
	}
	// A drain's move of the VM on this host: cancelled, it rolls back as its
	// own failure paths do.
	drainCancelled := req.OperationId == "" && s.cancelDrainMove(req.VmName)
	if drainCancelled {
		slog.Warn("drain move of the VM cancelled by admin", "vm", req.VmName)
		s.audit(ctx, "operation.abort", req.VmName, "drain move cancelled", "ok")
	}
	view, found, err := corrosion.GetVMActiveOperation(ctx, s.db, req.VmName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get active operation: %v", err)
	}
	// A scoped abort (operation_id) acts on that operation only: one that
	// has finished, or been followed by another, is not this one's to clear.
	// The CAS below then carries the same id, so it cannot clear a later one.
	if req.OperationId != "" && (!found || view.ActiveOperationID != req.OperationId) {
		active := "no operation"
		if found {
			active = "operation " + view.ActiveOperationID
		}
		return nil, status.Errorf(codes.FailedPrecondition,
			"%s has %s active, not %s; re-inspect with lv operation show %s", req.VmName, active, req.OperationId, req.VmName)
	}
	if !found {
		if drainCancelled {
			return &pb.AbortVMOperationResponse{Aborted: true,
				Detail: "cancelled the drain's move of the VM: a live move's migration job is aborted and the VM keeps running where it was, " +
					"unless libvirt had already cut it over; a cold move rolls back (started again where it was, if it had been shut down)"}, nil
		}
		return &pb.AbortVMOperationResponse{Aborted: false, Detail: "no active operation"}, nil
	}
	applied, err := s.db.AbortVMOperation(ctx, req.VmName, view.ActiveOperationID, view.OwnerEpoch, view.SpecGeneration)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "abort operation: %v", err)
	}
	if !applied {
		return &pb.AbortVMOperationResponse{
			Aborted: false, PreviousOperationId: view.ActiveOperationID,
			Detail: "operation state changed concurrently; re-inspect before retrying",
		}, nil
	}
	slog.Warn("operation force-aborted by admin", "vm", req.VmName, "op", view.ActiveOperationID,
		"epoch", view.OwnerEpoch, "generation", view.SpecGeneration)
	s.audit(ctx, "operation.abort", req.VmName,
		fmt.Sprintf("op=%s epoch=%d gen=%d", view.ActiveOperationID, view.OwnerEpoch, view.SpecGeneration), "ok")
	return &pb.AbortVMOperationResponse{Aborted: true, PreviousOperationId: view.ActiveOperationID}, nil
}
