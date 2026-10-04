package grpcapi

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// Deleting a workload recorded on a host removed from the cluster.
//
// DeleteVM and DeleteContainer forward to the workload's recorded host, which
// stops it and frees what it holds there. A removed host has no address left
// to dial, so on the kvm003 lab (drill 6, main-e004c250) `lv rm --force app`
// and `lv ct rm blct --host node-4` both failed, and the name could not be
// re-admitted while the rows stayed (corrosion.WorkloadsOnRemovedHost). Its
// certificate is revoked and it never comes back, so there is nothing on it
// to stop or free: the delete removes the cluster's rows, here, and is
// audited as a delete on a removed host. Disks on shared storage are left, as
// --keep-disks leaves them.

// workloadHostRemoved reports whether host, a workload's recorded host other
// than this one, has been removed from the cluster.
func (s *Server) workloadHostRemoved(ctx context.Context, host string) (bool, error) {
	if host == "" || host == s.hostName {
		return false, nil
	}
	removed, err := corrosion.HostRemoved(ctx, s.db, host)
	if err != nil {
		return false, status.Errorf(codes.Unavailable, "read whether host %s was removed: %v", host, err)
	}
	return removed, nil
}

// deleteVMOnRemovedHost deletes the rows of vm, recorded on a removed host.
// The caller holds the VM's lock and has checked its operation barrier.
func (s *Server) deleteVMOnRemovedHost(ctx context.Context, vm *corrosion.VMRecord) (*emptypb.Empty, error) {
	if err := s.checkNoRemotePCIOwner(ctx, vm.Name); err != nil {
		return nil, err
	}
	s.releaseNICLeasesBestEffort(ctx, vm, "delete-on-removed-host")
	if err := corrosion.DeleteVM(ctx, s.db, vm.Name); err != nil {
		s.audit(ctx, "vm.delete", vm.Name, "recorded on removed host "+vm.HostName+": "+err.Error(), "error")
		return nil, status.Errorf(codes.Internal, "delete VM %q recorded on removed host %s: %v", vm.Name, vm.HostName, err)
	}
	s.clearDeviceLease(vm.Name)
	s.audit(ctx, "vm.delete", vm.Name, "recorded on removed host "+vm.HostName+
		": cluster rows deleted, nothing on that machine touched, disks on shared storage kept", "ok")
	slog.Info("VM recorded on a removed host deleted", "vm", vm.Name, "host", vm.HostName)
	return &emptypb.Empty{}, nil
}

// deleteContainerOnRemovedHost deletes the rows of container name, recorded on
// the removed host.
func (s *Server) deleteContainerOnRemovedHost(ctx context.Context, host, name, project string) (*emptypb.Empty, error) {
	unlock := s.LockContainer(name)
	defer unlock()
	rec, err := corrosion.GetContainer(ctx, s.db, host, name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup container: %v", err)
	}
	dnsStack := ""
	if rec != nil {
		if rec.ActiveOperationID != "" {
			return nil, status.Errorf(codes.FailedPrecondition,
				"cannot delete container %q: an operation is in progress on it", name)
		}
		// A restore-relocation in flight lands a row on its target, and the
		// coordinator then retires this one: deleting it now would leave the
		// container live on the target. Let it settle.
		if _, _, restoring := corrosion.RelocateRestoreMarker(rec.State, rec.StateDetail); restoring {
			return nil, status.Errorf(codes.FailedPrecondition,
				"cannot delete container %q: the failover coordinator is relocating it; retry once that settles", name)
		}
		dnsStack = containerStackLabel(*rec)
	}
	derr := corrosion.DeleteContainerStrict(ctx, s.db, host, name)
	if derr != nil && !errors.Is(derr, corrosion.ErrNoRowsAffected) {
		s.audit(ctx, "ct.delete", name, "project="+project+" recorded on removed host "+host, "error")
		return nil, status.Errorf(codes.Internal, "delete: remove cluster row: %v", derr)
	}
	nicErr := network.ReleaseContainerLeases(ctx, s.db, host, name)
	if e := corrosion.DeleteContainerInterfaces(ctx, s.db, host, name); e != nil && nicErr == nil {
		nicErr = e
	}
	s.deleteContainerDNS(ctx, name, dnsStack)
	if err := corrosion.DeleteContainerRestartState(ctx, s.db, host, name); err != nil {
		slog.Warn("container delete: failed to clear restart state (harmless, GC'able)", "name", name, "error", err)
	}
	if nicErr != nil {
		s.audit(ctx, "ct.delete", name, "project="+project+" recorded on removed host "+host, "error")
		return nil, status.Errorf(codes.Internal, "delete: release managed NICs: %v", nicErr)
	}
	detail := "project=" + project + " recorded on removed host " + host +
		": cluster rows deleted, nothing on that machine touched"
	if errors.Is(derr, corrosion.ErrNoRowsAffected) {
		detail += " (already absent)"
	}
	s.audit(ctx, "ct.delete", name, detail, "ok")
	slog.Info("container recorded on a removed host deleted", "name", name, "host", host)
	return &emptypb.Empty{}, nil
}
