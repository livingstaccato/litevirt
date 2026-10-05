package grpcapi

// Host drain's cold moves: a VM that drain cannot live-migrate moves the way
// `lv migrate --cold` moves a stopped VM (migrateOwnedVM, then
// coldMigrateStoppedVM), with its host-local disks. Drain used to move such a
// VM by its row alone, which left its host-local disks on the drained host and
// its domain undefined on the target.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/obs"
)

// drainOwnershipWait bounds how long a drain waits, after a running VM's cold
// move, for the target's copy of the VM row to name the target, before it
// asks the target to start the VM. StartVM forwards to the host its row
// names, so asking earlier would bounce the start back here.
var drainOwnershipWait = time.Minute

// drainColdMove runs one drain cold move through migrateOwnedVM, under the
// per-VM "vm.migrate" span MigrateVM opens for an explicit migration. vm's
// State must be "stopped": the move keeps it, and the handoff records it.
func (s *Server) drainColdMove(ctx context.Context, vm *corrosion.VMRecord, target string, unlock func(), adopted *bool, opts ownedMigrateOpts) error {
	ctx, span := obs.Span(ctx, "vm.migrate")
	span.SetAttribute("vm.name", vm.Name)
	span.SetAttribute("vm.target_host", target)
	defer span.End()
	req := &pb.MigrateVMRequest{VmName: vm.Name, TargetHost: target, Strategy: pb.MigrateStrategy_MIGRATE_COLD}
	discard := func(pb.MigratePhase, float32, float32) error { return nil }
	return s.migrateOwnedVM(ctx, req, vm, discard, unlock, adopted, opts)
}

// drainStoppedVM drains a STOPPED VM through the same path as `lv migrate
// <vm> <target> --cold`, with the same preconditions and refusals: capacity on
// the target, a Secure-Boot/vTPM VM's shared-storage requirement, snapshots on
// a host-local disk, a disk that cannot be flattened, free space, a target too
// old for the disk copy. The caller holds the VM's lock and has re-checked
// ownership and quorum.
//
// A VM it cannot move stays on this host, stopped, with its disks and rows —
// a failed attempt takes back what it put on the target — and is reported as
// failed, which leaves the drain incomplete. It is never reassigned by its row
// alone.
func (s *Server) drainStoppedVM(ctx context.Context, vm *corrosion.VMRecord, target corrosion.HostRecord, unlock func(), adopted *bool) *pb.DrainProgress {
	progress := &pb.DrainProgress{
		VmName: vm.Name, TargetHost: target.Name, Strategy: pb.MigrateStrategy_MIGRATE_COLD,
	}
	if err := s.drainColdMove(ctx, vm, target.Name, unlock, adopted, ownedMigrateOpts{}); err != nil {
		slog.Warn("drain: stopped VM not moved; it stays on this host", "vm", vm.Name, "target", target.Name, "error", err)
		progress.Status = "failed"
		progress.Error = "not moved, left stopped on " + s.hostName + " with its disks: " + status.Convert(err).Message()
		return progress
	}
	progress.Status = "done"
	progress.ProgressPct = 100
	return progress
}

// drainRunningVMCold drains a RUNNING VM that cannot be live-migrated — it has
// a host-local disk, or its live migration failed — as a cold move:
//
//  1. every check of the move runs while the VM still runs: migrateOwnedVM's
//     (target, CPU, PCI, snapshots, and the destination's capacity lease, the
//     only lease the move takes), then coldMovePreflight's (hostdevs, each
//     disk's format and flattenable backing chain, free space on both ends,
//     what the target would refuse). A refusal leaves the VM running here;
//  2. the VM is recorded stopped and shut down, and the move waits until its
//     domain is shut off (shutDownForColdMove);
//  3. it is cold-moved with its disks (coldMigrateStoppedVM), and then
//     started on the target, as it was running before the drain.
//
// A move that fails after the shutdown leaves the VM, its disks and its rows
// here, and the VM is started here again. If that start fails too, the frame
// says so, naming the VM, which is then stopped here with its disks. The VM is
// never moved by its row alone.
func (s *Server) drainRunningVMCold(ctx context.Context, vm *corrosion.VMRecord, target corrosion.HostRecord, unlock func(), adopted *bool) *pb.DrainProgress {
	progress := &pb.DrainProgress{
		VmName: vm.Name, TargetHost: target.Name, Strategy: pb.MigrateStrategy_MIGRATE_COLD,
	}
	stopped := *vm
	stopped.State = "stopped"
	shutDown := false
	err := s.drainColdMove(ctx, &stopped, target.Name, unlock, adopted, ownedMigrateOpts{
		beforeMove: func(ctx context.Context) error {
			if err := s.coldMovePreflight(ctx, vm, target.Name); err != nil {
				return err
			}
			shutDown = true
			return s.shutDownForColdMove(ctx, vm)
		},
	})
	if err == nil {
		if serr := s.startMovedVMOnTarget(ctx, vm.Name, target.Name); serr != nil {
			slog.Error("drain: VM moved with its disks but did not start on the target; it is stopped there",
				"vm", vm.Name, "target", target.Name, "error", serr)
			progress.Status = "done"
			progress.ProgressPct = 100
			progress.Error = fmt.Sprintf("moved to %s with its disks, but did not start there (%s); it is stopped on %s — start it with `lv start %s`",
				target.Name, status.Convert(serr).Message(), target.Name, vm.Name)
			return progress
		}
		progress.Status = "done"
		progress.ProgressPct = 100
		return progress
	}
	reason := status.Convert(err).Message()
	if !shutDown {
		slog.Warn("drain: running VM not moved; it stays running on this host", "vm", vm.Name, "target", target.Name, "error", err)
		progress.Status = "failed"
		progress.Error = "not moved, left running on " + s.hostName + " with its disks: " + reason
		return progress
	}
	if rerr := s.restartAfterFailedColdMove(ctx, vm.Name); rerr != nil {
		slog.Error("drain: VM was shut down for a cold move that failed, and could NOT be started again; it is STOPPED on this host",
			"vm", vm.Name, "host", s.hostName, "move_error", err, "start_error", rerr)
		s.recordVMEvent(context.WithoutCancel(ctx), vm.Name, "vm.drain", "error",
			"shut down for a cold move to "+target.Name+" that failed, and not started again: "+status.Convert(rerr).Message())
		progress.Status = "error"
		progress.Error = fmt.Sprintf("VM %s was shut down for a cold move that failed (%s) and could NOT be started again on %s (%s); it is STOPPED there with its disks — start it with `lv start %s`",
			vm.Name, reason, s.hostName, status.Convert(rerr).Message(), vm.Name)
		return progress
	}
	slog.Warn("drain: cold move failed after the shutdown; the VM was started again on this host",
		"vm", vm.Name, "target", target.Name, "error", err)
	progress.Status = "failed"
	progress.Error = "not moved, started again on " + s.hostName + " with its disks: " + reason
	return progress
}

// shutDownForColdMove stops a running VM for its cold move and returns once
// its domain is shut off. The row is recorded stopped by the operator first:
// a guest that shuts down under a row that says running reads as a crash to
// the domain-event handler and the restart policy, which would start it again
// while its disk is being copied. If the domain is not shut off within the
// VM's stop timeout the move fails (it is not forced off); the caller starts
// the VM again.
func (s *Server) shutDownForColdMove(ctx context.Context, vm *corrosion.VMRecord) error {
	if err := s.persistVMState(ctx, vm.Name, "stopped", operatorStopDetail, corrosion.OpVMState); err != nil {
		return status.Errorf(codes.Internal, "record VM %q stopped for its cold move: %v", vm.Name, err)
	}
	if err := s.virt.ShutdownDomain(vm.Name); err != nil {
		return status.Errorf(codes.Internal, "shut down VM %q for its cold move: %v", vm.Name, err)
	}
	// ShutdownDomain only asks the guest (ACPI) and returns at once.
	timeout := time.Duration(resolveStopTimeout(0, vm.Spec)) * time.Second
	s.virt.WaitForShutdown(vm.Name, timeout)
	if active, err := s.virt.DomainIsActive(vm.Name); err != nil || active {
		if err == nil {
			err = fmt.Errorf("its domain is still active")
		}
		return status.Errorf(codes.DeadlineExceeded,
			"VM %q did not shut down within its stop timeout of %s, so it is not moved: %v", vm.Name, timeout, err)
	}
	return nil
}

// restartAfterFailedColdMove starts a VM this drain shut down for a cold move
// that then failed. It starts it only while its row still names this host;
// the caller holds the VM's lock.
func (s *Server) restartAfterFailedColdMove(ctx context.Context, name string) error {
	// The VM was running when the drain found it: bring it back even if the
	// request that drove the drain has gone away.
	ctx = context.WithoutCancel(ctx)
	cur, err := corrosion.GetVM(ctx, s.db, name)
	if err != nil || cur == nil {
		return status.Errorf(codes.Internal, "re-read VM %q: %v", name, err)
	}
	if cur.HostName != s.hostName {
		return status.Errorf(codes.FailedPrecondition, "its record now names %s, so it is not started here", cur.HostName)
	}
	if reason, refused := s.execGateRefused(ctx); refused {
		s.noteGateRefused(corrosion.ActionReschedule, reason)
		return status.Errorf(codes.FailedPrecondition, "start refused: %s", reason)
	}
	_, err = s.startVMLocked(ctx, cur)
	return err
}

// startMovedVMOnTarget starts a VM a drain has just cold-moved to target, as
// it was running before the drain. It first waits, bounded by
// drainOwnershipWait, until target's own copy of the VM row names target:
// StartVM forwards to the host its row names, and that row is replicating.
func (s *Server) startMovedVMOnTarget(ctx context.Context, name, target string) error {
	client, closeConn, err := s.dialPeer(ctx, target)
	if err != nil {
		return status.Errorf(codes.Unavailable, "reach %s: %v", target, err)
	}
	defer closeConn()
	deadline := time.Now().Add(drainOwnershipWait)
	for {
		resp, lerr := client.ListVMs(ctx, &pb.ListVMsRequest{HostName: target})
		if lerr == nil {
			for _, v := range resp.GetVms() {
				if v.GetName() == name && v.GetHostName() == target {
					_, serr := client.StartVM(ctx, &pb.StartVMRequest{Name: name})
					return serr
				}
			}
		}
		if time.Now().After(deadline) {
			return status.Errorf(codes.DeadlineExceeded, "%s did not record itself as the owner within %s (last error: %v)", target, drainOwnershipWait, lerr)
		}
		select {
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}
