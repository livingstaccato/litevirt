package grpcapi

import (
	"context"
	"fmt"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// Who may push a replica.
//
// A replica is promotable data, so only the workload's current owner may add
// one. The sender checks its own standing before it reads a byte
// (mayReplicateVMAsOwner, mayReplicateAsOwner), but a host coming back from a
// fence or a partition is exactly the host whose own view is stale: it still
// sees its row and its schedule. So the TARGET checks too, on receipt, against
// its own view: the pushing host must not be fenced or gone, and the workload's
// row there must name that host at no later owner epoch than the push carries.
// A target that holds no row for the workload does not judge (its view lags the
// push); a stale push it cannot judge is still never promoted over the current
// owner's data: a container replica is promoted only from the very row being
// relocated (containerReplicaFor), and a VM's records carry the source and epoch.

// replicaSourceMD and replicaEpochMD carry, on a VM replica push, the host the
// replica was taken on and the VM row's owner epoch there. An older sender sends
// neither; the push is then judged by the caller's certificate alone.
const (
	replicaSourceMD = "litevirt-replica-source"
	replicaEpochMD  = "litevirt-replica-owner-epoch"
)

// withReplicaOwner attaches this host's claim to own vm to an outgoing replica
// push.
func (s *Server) withReplicaOwner(ctx context.Context, vm *corrosion.VMRecord) context.Context {
	return metadata.AppendToOutgoingContext(ctx, replicaSourceMD, s.hostName, replicaEpochMD, strconv.FormatInt(vm.OwnerEpoch, 10))
}

// forwardReplicaOwner carries an incoming push's owner claim onto the
// outgoing call when an entry node forwards it to the pool's host.
func forwardReplicaOwner(ctx context.Context) context.Context {
	return forwardReplicaOwnerFrom(ctx, ctx)
}

// forwardReplicaOwnerFrom is forwardReplicaOwner onto an outgoing context
// already prepared from in.
func forwardReplicaOwnerFrom(in, ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(in)
	if !ok {
		return ctx
	}
	for _, k := range []string{replicaSourceMD, replicaEpochMD} {
		if v := md.Get(k); len(v) > 0 {
			ctx = metadata.AppendToOutgoingContext(ctx, k, v[0])
		}
	}
	return ctx
}

// admitVMReplicaSource is the target's check of a VM replica push (above).
func (s *Server) admitVMReplicaSource(ctx context.Context, project, vmName string) error {
	if s.db == nil {
		return nil
	}
	source := callerMTLSCommonName(ctx)
	epoch, haveEpoch := int64(0), false
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get(replicaSourceMD); len(v) > 0 && v[0] != "" {
			source = v[0]
		}
		if v := md.Get(replicaEpochMD); len(v) > 0 {
			if e, err := strconv.ParseInt(v[0], 10, 64); err == nil {
				epoch, haveEpoch = e, true
			}
		}
	}
	if source == "" {
		return nil
	}
	h, err := corrosion.GetHost(ctx, s.db, source)
	if err != nil {
		return status.Errorf(codes.Unavailable, "read host %q: %v", source, err)
	}
	if h == nil || h.State == "fenced" || h.State == "removed" {
		return status.Errorf(codes.FailedPrecondition,
			"refusing a replica of %s from %q: that host is fenced or not a cluster member here", vmName, source)
	}
	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil {
		return status.Errorf(codes.Unavailable, "read vm %q: %v", vmName, err)
	}
	if vm == nil || tenancy.NormalizeProject(vm.Project) != tenancy.NormalizeProject(project) {
		return nil
	}
	// Aborted, not a failure: the VM has just moved, or this host has not
	// seen the move yet. The owner's next run lands (replErrorClass).
	if vm.HostName != source {
		return status.Errorf(codes.Aborted,
			"refusing a replica of %s from %q: the VM's row here is on %q", vmName, source, vm.HostName)
	}
	if haveEpoch && vm.OwnerEpoch > epoch {
		return status.Errorf(codes.Aborted,
			"refusing a replica of %s from %q at owner epoch %d: the row here is at %d", vmName, source, epoch, vm.OwnerEpoch)
	}
	return nil
}

// notOwnerNowError is mayReplicateVMAsOwner's refusal: this host may not act
// as the VM's owner now. It is not the schedule failing: the VM may have
// moved while this host was fenced or partitioned, and its owner runs the
// schedule (RunReplication reports it as scheduler.ErrRunSkipped).
type notOwnerNowError struct{ msg string }

func (e *notOwnerNowError) Error() string { return e.msg }

// mayReplicateVMAsOwner refuses a run on a host that may no longer be the VM's
// owner: one that has self-fenced or lost the execution gate, is not an active
// member in its own view, or whose host-local owner-epoch marker is ahead of the
// row it reads (its view is behind the runtime it holds).
func (s *Server) mayReplicateVMAsOwner(ctx context.Context, vm *corrosion.VMRecord) error {
	if reason, refused := s.execGateForAction(ctx, false); refused {
		return &notOwnerNowError{fmt.Sprintf("this host may not act as the VM's owner now (%s)", reason)}
	}
	if h, err := corrosion.GetHost(ctx, s.db, s.hostName); err == nil && h != nil && h.State != "active" && h.State != "maintenance" {
		return &notOwnerNowError{fmt.Sprintf("this host is %s, not an active member, so it does not replicate", h.State)}
	}
	if s.dataDir != "" {
		if marker, found, err := health.ReadVMOwnerEpochMarker(s.dataDir, vm.Name); err == nil && found && marker > vm.OwnerEpoch {
			return &notOwnerNowError{fmt.Sprintf("the VM's owner-epoch marker here (%d) is ahead of its row (%d); this host's view is not current", marker, vm.OwnerEpoch)}
		}
	}
	return nil
}

// replicaSourceOf is the host a received replica push says it was taken on, or
// the pushing peer's certificate name.
func replicaSourceOf(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get(replicaSourceMD); len(v) > 0 && v[0] != "" {
			return v[0]
		}
	}
	return callerMTLSCommonName(ctx)
}
