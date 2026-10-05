package grpcapi

// Host drain's cold moves: a VM that drain cannot live-migrate moves the way
// `lv migrate --cold` moves a stopped VM (migrateOwnedVM, then
// coldMigrateStoppedVM), with its host-local disks. Drain used to move such a
// VM by its row alone, which left its host-local disks on the drained host and
// its domain undefined on the target.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
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

// drainLateShutdownWait bounds how much longer, past the VM's stop timeout,
// a drain waits for a guest whose shutdown it requested to finish it. The
// ACPI request cannot be withdrawn: a guest slower than its stop timeout
// still powers off, so the VM can only be started again once it has.
var drainLateShutdownWait = 5 * time.Minute

// drainStartTimeout bounds the start of a moved VM on its target, past the
// wait for the target to record itself the owner.
const drainStartTimeout = 2 * time.Minute

// errDrainCrashed is drainRunningVMCold stopping where the drainCrashAt test
// seam said a daemon died: it returns at once, with nothing cleaned up and
// the journal left as the crash would leave it.
var errDrainCrashed = errors.New("drain: test crash point reached")

// SetDrainCrashForTest installs the drainCrashAt test seam.
func (s *Server) SetDrainCrashForTest(f func(point string) bool) { s.drainCrashAt = f }

func (s *Server) drainCrashed(point string) bool {
	return s.drainCrashAt != nil && s.drainCrashAt(point)
}

// drainRunningVMCold drains a RUNNING VM that cannot be live-migrated — it has
// a host-local disk, or its live migration failed — as a cold move:
//
//  1. every check of the move runs while the VM still runs: migrateOwnedVM's
//     (target, CPU, PCI, snapshots, and the destination's capacity lease, the
//     only lease the move takes), then coldMovePreflight's (hostdevs, each
//     disk's format and flattenable backing chain, free space on both ends,
//     what the target would refuse). A refusal leaves the VM running here;
//  2. the move is journaled (corrosion.BeginDrainColdMove): the VM was running
//     and must run again. A daemon that dies from here on finishes the move
//     when it starts again (ResumeDrainColdMoves);
//  3. the VM is recorded stopped and shut down, and the move waits until its
//     domain is shut off (shutDownForColdMove);
//  4. it is cold-moved with its disks (coldMigrateStoppedVM), and then
//     started on the target, as it was running before the drain.
//
// A move that fails after the shutdown leaves the VM, its disks and its rows
// here, and the VM is started here again once its domain is shut off — a
// guest slower than its stop timeout is waited for (drainLateShutdownWait),
// and one that never shuts off is reported as it is. The VM is never moved
// by its row alone.
func (s *Server) drainRunningVMCold(ctx context.Context, vm *corrosion.VMRecord, target corrosion.HostRecord, unlock func(), adopted *bool) *pb.DrainProgress {
	progress := &pb.DrainProgress{
		VmName: vm.Name, TargetHost: target.Name, Strategy: pb.MigrateStrategy_MIGRATE_COLD,
	}
	stopped := *vm
	stopped.State = "stopped"
	var journal *corrosion.DrainColdMove
	shutDown, shutdownRequested := false, false
	err := s.drainColdMove(ctx, &stopped, target.Name, unlock, adopted, ownedMigrateOpts{
		beforeMove: func(ctx context.Context) error {
			if err := s.coldMovePreflight(ctx, vm, target.Name); err != nil {
				return err
			}
			m, err := corrosion.BeginDrainColdMove(ctx, s.db, *vm, s.hostName, target.Name, uuid.NewString())
			if err != nil {
				return status.Errorf(codes.Internal, "journal the cold move of VM %q: %v", vm.Name, err)
			}
			journal = &m
			if s.drainCrashed("journaled") {
				return errDrainCrashed
			}
			shutDown = true
			if err := s.shutDownForColdMove(ctx, vm, m, &shutdownRequested); err != nil {
				return err
			}
			if s.drainCrashed("shut_off") {
				return errDrainCrashed
			}
			return nil
		},
	})
	if errors.Is(err, errDrainCrashed) {
		progress.Status = "error"
		progress.Error = err.Error()
		return progress
	}
	finish := func(outcome string) {
		if journal == nil {
			return
		}
		if ferr := corrosion.FinishDrainColdMove(context.WithoutCancel(ctx), s.db, *journal, outcome); ferr != nil {
			slog.Error("drain: could not record the cold move finished; a restart will finish it again",
				"vm", vm.Name, "operation", journal.OperationID, "error", ferr)
		}
	}
	if err == nil {
		if s.drainCrashed("handed_off") {
			progress.Status = "error"
			progress.Error = errDrainCrashed.Error()
			return progress
		}
		if serr := s.startMovedVMOnTarget(ctx, vm.Name, target.Name); serr != nil {
			finish("moved to " + target.Name + "; not started there: " + status.Convert(serr).Message())
			progress.Status = "done"
			progress.ProgressPct = 100
			progress.Error = fmt.Sprintf("moved to %s with its disks, but did not start there (%s); it is stopped on %s — start it with `lv start %s`",
				target.Name, status.Convert(serr).Message(), target.Name, vm.Name)
			return progress
		}
		finish("moved to " + target.Name + " and started there")
		progress.Status = "done"
		progress.ProgressPct = 100
		return progress
	}
	reason := status.Convert(err).Message()
	if !shutDown {
		slog.Warn("drain: running VM not moved; it stays running on this host", "vm", vm.Name, "target", target.Name, "error", err)
		finish("not moved; never shut down")
		progress.Status = "failed"
		progress.Error = "not moved, left running on " + s.hostName + " with its disks: " + reason
		return progress
	}
	// The move failed after the VM was recorded stopped. If its shutdown was
	// requested, the guest is shutting down, and starting it again means
	// waiting until it has.
	if shutdownRequested {
		if active, aerr := s.virt.DomainIsActive(vm.Name); aerr != nil || active {
			s.virt.WaitForShutdown(vm.Name, drainLateShutdownWait)
		}
		if active, aerr := s.virt.DomainIsActive(vm.Name); aerr == nil && active {
			return s.reportStillShuttingDown(ctx, vm.Name, target.Name, reason, progress, finish)
		}
	}
	if rerr := s.restartAfterFailedColdMove(ctx, vm.Name); rerr != nil {
		slog.Error("drain: VM was shut down for a cold move that failed, and could NOT be started again; it is STOPPED on this host",
			"vm", vm.Name, "host", s.hostName, "move_error", err, "start_error", rerr)
		s.recordVMEvent(context.WithoutCancel(ctx), vm.Name, "vm.drain", "error",
			"shut down for a cold move to "+target.Name+" that failed, and not started again: "+status.Convert(rerr).Message())
		finish("not moved; not started again: " + status.Convert(rerr).Message())
		progress.Status = "error"
		progress.Error = fmt.Sprintf("VM %s was shut down for a cold move that failed (%s) and could NOT be started again on %s (%s); it is STOPPED there with its disks — %s",
			vm.Name, reason, s.hostName, status.Convert(rerr).Message(), startOnDrainedHostHint(vm.Name, s.hostName))
		return progress
	}
	finish("not moved; started again on " + s.hostName)
	if !shutdownRequested {
		slog.Warn("drain: cold move failed before the shutdown was requested; the VM still runs on this host",
			"vm", vm.Name, "target", target.Name, "error", err)
		progress.Status = "failed"
		progress.Error = "not moved, left running on " + s.hostName + " with its disks: " + reason
		return progress
	}
	slog.Warn("drain: cold move failed after the shutdown; the VM was started again on this host",
		"vm", vm.Name, "target", target.Name, "error", err)
	progress.Status = "failed"
	progress.Error = "not moved, started again on " + s.hostName + " with its disks: " + reason
	return progress
}

// startOnDrainedHostHint is how an operator starts a VM left stopped on a
// host a drain made `draining`. `lv start` alone is refused there while the
// host is draining (a draining host runs no workload it does not already
// run), so it names the two ways that work: undrain the host first, or move
// the VM off, which a draining host allows, and start it where it lands.
func startOnDrainedHostHint(vm, host string) string {
	return fmt.Sprintf("start it with `lv start %s` once %s is no longer draining (`lv host undrain %s`), "+
		"or move it off with `lv migrate %s <target-host> --cold` and start it there", vm, host, host, vm)
}

// reportStillShuttingDown is the end of a failed cold move whose guest was
// asked to shut down and has not, even after drainLateShutdownWait past its
// stop timeout. The VM is still running here and is not started or stopped
// by the drain: its row is put back to running, which is what it is, and the
// frame says that it will power off if the guest completes the shutdown.
func (s *Server) reportStillShuttingDown(ctx context.Context, name, target, reason string, progress *pb.DrainProgress, finish func(string)) *pb.DrainProgress {
	ctx = context.WithoutCancel(ctx)
	if werr := s.persistVMState(ctx, name, "running", "drain: shutdown requested, still in progress", corrosion.OpVMState); werr != nil {
		slog.Error("drain: could not record a still-running VM as running", "vm", name, "error", werr)
	}
	msg := fmt.Sprintf("VM %s was not moved (%s). Its shutdown was requested and its domain on %s is still active after waiting %s more than its stop timeout: it is still running there, and will power off if the guest completes the shutdown — then %s",
		name, reason, s.hostName, drainLateShutdownWait, startOnDrainedHostHint(name, s.hostName))
	slog.Error("drain: "+msg, "vm", name, "target", target)
	s.recordVMEvent(ctx, name, "vm.drain", "error", msg)
	finish("not moved; shutdown requested and still in progress")
	progress.Status = "error"
	progress.Error = msg
	return progress
}

// shutDownForColdMove stops a running VM for its cold move and returns once
// its domain is shut off. The row is recorded stopped first, with the move's
// own stop detail (health.DrainStopDetail), which every health decision
// treats as an operator stop: a guest that shuts down under a row that says
// running reads as a crash to the domain-event handler and the restart
// policy, which would start it again while its disk is being copied. The
// detail names the move, so its crash recovery can tell this stop from any
// later start or stop of the VM. The journal's "stopped" step is recorded
// before the shutdown is requested, so a daemon that dies after the request
// knows to wait for the guest. If the domain is not shut off within the VM's
// stop timeout the move fails (it is not forced off), and *requested tells
// the caller the guest may still be shutting down.
func (s *Server) shutDownForColdMove(ctx context.Context, vm *corrosion.VMRecord, m corrosion.DrainColdMove, requested *bool) error {
	if err := s.persistVMState(ctx, vm.Name, "stopped", health.DrainStopDetail(m.OperationID), corrosion.OpVMState); err != nil {
		return status.Errorf(codes.Internal, "record VM %q stopped for its cold move: %v", vm.Name, err)
	}
	if s.drainCrashed("recorded") {
		return errDrainCrashed
	}
	if err := corrosion.MarkDrainColdMoveShutdownRequested(ctx, s.db, m); err != nil {
		return status.Errorf(codes.Internal, "journal the shutdown of VM %q: %v", vm.Name, err)
	}
	if err := s.virt.ShutdownDomain(vm.Name); err != nil {
		return status.Errorf(codes.Internal, "shut down VM %q for its cold move: %v", vm.Name, err)
	}
	*requested = true
	// ShutdownDomain only asks the guest (ACPI) and returns at once.
	timeout := time.Duration(resolveStopTimeout(0, vm.Spec)) * time.Second
	s.virt.WaitForShutdown(vm.Name, timeout)
	if active, err := s.virt.DomainIsActive(vm.Name); err != nil || active {
		if err == nil {
			err = fmt.Errorf("its domain is still active")
		}
		if s.drainCrashed("stop_timed_out") {
			return errDrainCrashed
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
	// The drain gate: this host is draining, and starting the VM again puts
	// back what the drain itself took down — it is not new work on the host.
	if reason, refused := s.drainGateRefused(ctx); refused {
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
//
// It runs detached from the request, under its own bound: the move has
// happened, and a client that goes away must not leave the VM stopped on the
// target. A start that fails is recorded as a VM event.
func (s *Server) startMovedVMOnTarget(ctx context.Context, name, target string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), drainOwnershipWait+drainStartTimeout)
	defer cancel()
	err := s.startOnOwner(ctx, name, target)
	if err != nil {
		s.recordVMEvent(ctx, name, "vm.drain", "error",
			"moved to "+target+" with its disks, but not started there: "+status.Convert(err).Message())
	}
	return err
}

func (s *Server) startOnOwner(ctx context.Context, name, target string) error {
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

// drainRecoveryRetry is how often RunDrainColdMoveRecovery retries moves it
// could not finish yet, and drainRecoveryAttempts how many times in all.
var (
	drainRecoveryRetry    = 30 * time.Second
	drainRecoveryAttempts = 20
)

// SetDrainRecoveryRetryForTest sets RunDrainColdMoveRecovery's attempts and
// interval, and returns the function that restores them.
func SetDrainRecoveryRetryForTest(attempts int, every time.Duration) (restore func()) {
	oldN, oldD := drainRecoveryAttempts, drainRecoveryRetry
	drainRecoveryAttempts, drainRecoveryRetry = attempts, every
	return func() { drainRecoveryAttempts, drainRecoveryRetry = oldN, oldD }
}

// RunDrainColdMoveRecovery finishes, at daemon startup, the drain cold moves a
// previous process of this host left journaled (ResumeDrainColdMoves), and
// retries what it could not finish yet — a start the split-brain gate refuses
// until this host sees its quorum, a target not reachable yet — for a bounded
// time. A move still unfinished after the last attempt is closed as failed,
// with a VM event naming the VM: a later restart never takes it up again,
// when the VM may long since have been started, stopped or moved on purpose.
//
// The daemon starts it with the runtime loops, after the startup recovery
// barrier: it starts VMs, as they do.
func (s *Server) RunDrainColdMoveRecovery(ctx context.Context) {
	for i := 1; ; i++ {
		last := i >= drainRecoveryAttempts
		left, err := s.resumeDrainColdMoves(ctx, last)
		if err != nil {
			slog.Warn("drain: resuming journaled cold moves", "error", err)
		}
		if (err == nil && left == 0) || last {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(drainRecoveryRetry):
		}
	}
}

// ResumeDrainColdMoves is one pass of RunDrainColdMoveRecovery that never
// gives up on a move: it returns how many it could not finish yet, which stay
// journaled.
func (s *Server) ResumeDrainColdMoves(ctx context.Context) (int, error) {
	return s.resumeDrainColdMoves(ctx, false)
}

// resumeDrainColdMoves finishes every drain cold move this host journaled and
// never finished — the work of a daemon that died mid-move. It acts only on a
// VM still exactly as the drain left it (resumeDrainColdMove), which was
// running when the drain found it, and ends running on exactly one host. A
// VM changed since — started, stopped, moved or deleted by anyone else — is
// left as it is, and the move is closed with a VM event saying so. With
// giveUp, a move it cannot finish is closed as failed, with a VM event.
func (s *Server) resumeDrainColdMoves(ctx context.Context, giveUp bool) (int, error) {
	pending, err := corrosion.ListDrainColdMoves(ctx, s.db, s.hostName)
	if err != nil {
		return 0, err
	}
	// A system call, as the health checker's migrations are: the operator who
	// drove the drain is gone.
	ctx = context.WithValue(context.WithValue(ctx, ctxKeyRole, "admin"), ctxKeyUsername, "system:drain-recovery")
	left := 0
	for _, m := range pending {
		outcome, changed, rerr := s.resumeDrainColdMove(ctx, m)
		switch {
		case rerr != nil && !giveUp:
			left++
			slog.Error("drain: could not finish a journaled cold move yet; it stays journaled",
				"vm", m.VM, "target", m.Target, "operation", m.OperationID, "error", rerr)
			continue
		case rerr != nil:
			msg := fmt.Sprintf("an interrupted drain cold move of VM %s to %s could not be finished (%v), and is given up: "+
				"the VM may be stopped (`lv inspect %s` names its host). On %s, %s; on any other host, start it with `lv start %s`",
				m.VM, m.Target, rerr, m.VM, m.Source, startOnDrainedHostHint(m.VM, m.Source), m.VM)
			slog.Error("drain: "+msg, "vm", m.VM, "operation", m.OperationID)
			s.recordVMEvent(ctx, m.VM, "vm.drain", "error", msg)
			if ferr := corrosion.FailDrainColdMove(ctx, s.db, m, msg); ferr != nil {
				left++
				slog.Error("drain: could not record a given-up cold move", "vm", m.VM, "error", ferr)
			}
			continue
		case changed:
			msg := "an interrupted drain cold move to " + m.Target + " was not finished: " + outcome + "; the VM was left as it is"
			slog.Warn("drain: "+msg, "vm", m.VM, "operation", m.OperationID)
			s.recordVMEvent(ctx, m.VM, "vm.drain", "warn", msg)
		default:
			slog.Warn("drain: finished a cold move a previous process left journaled", "vm", m.VM, "outcome", outcome)
			s.recordVMEvent(ctx, m.VM, "vm.drain", "warn", "interrupted cold move to "+m.Target+" finished at startup: "+outcome)
		}
		if ferr := corrosion.FinishDrainColdMove(ctx, s.db, m, outcome); ferr != nil {
			left++
			slog.Error("drain: could not record a resumed cold move finished", "vm", m.VM, "error", ferr)
		}
	}
	return left, nil
}

// resumeDrainColdMove finishes one journaled move, if the VM is still exactly
// as the drain left it — the only state in which the drain's intent ("it was
// running, run it again") still holds:
//
//   - on the source, at the journaled owner epoch: running (the drain died
//     before it stopped it; nothing to do), or stopped with this move's own
//     stop detail. Then a domain still active is left running — after waiting
//     out a shutdown the move requested — and its row put back to running, and
//     a domain shut off is started here;
//   - on the target, at the journaled epoch + 1 (the handoff advances it once),
//     stopped with the empty detail the handoff writes: started there, through
//     its owner.
//
// Anything else — another owner or epoch, an operator's later start or stop,
// no row, no domain — returns changed with what it found, and nothing is done
// to the VM. err means try again later.
func (s *Server) resumeDrainColdMove(ctx context.Context, m corrosion.DrainColdMove) (outcome string, changed bool, err error) {
	vm, err := corrosion.GetVM(ctx, s.db, m.VM)
	if err != nil {
		return "", false, err
	}
	if vm == nil {
		return "the VM no longer exists", true, nil
	}
	found := fmt.Sprintf("it is now %s/%q on %s at owner epoch %d", vm.State, vm.StateDetail, vm.HostName, vm.OwnerEpoch)
	switch {
	case vm.HostName == m.Target && vm.OwnerEpoch == m.OwnerEpoch+1:
		if vm.State != "stopped" || vm.StateDetail != "" {
			return found, true, nil
		}
		// The handoff committed: the VM is the owner's to start, under a bound
		// (a target that hangs must not stall recovery), and without this VM's
		// lock, which is never held across a peer call.
		sctx, cancel := context.WithTimeout(ctx, drainOwnershipWait+drainStartTimeout)
		defer cancel()
		if err := s.startOnOwner(sctx, m.VM, vm.HostName); err != nil {
			return "", false, fmt.Errorf("start it on %s, its owner: %w", vm.HostName, err)
		}
		return "started on " + vm.HostName + ", where it was moved", false, nil
	case vm.HostName == m.Source && vm.OwnerEpoch == m.OwnerEpoch && m.Source == s.hostName:
		return s.resumeDrainColdMoveHere(ctx, m)
	default:
		return found, true, nil
	}
}

// resumeDrainColdMoveHere is resumeDrainColdMove for a VM still owned here at
// the journaled epoch, under its lock.
func (s *Server) resumeDrainColdMoveHere(ctx context.Context, m corrosion.DrainColdMove) (string, bool, error) {
	unlock := s.lockVM(m.VM)
	defer unlock()
	vm, err := corrosion.GetVM(ctx, s.db, m.VM)
	if err != nil {
		return "", false, err
	}
	if vm == nil || vm.HostName != s.hostName || vm.OwnerEpoch != m.OwnerEpoch {
		return "it changed owner while recovery waited for it", true, nil
	}
	if vm.State == "running" {
		// The drain died before it stopped the VM, or the VM was started since:
		// either way it runs, and there is nothing to finish.
		return "not moved; it is running here", false, nil
	}
	if vm.State != "stopped" || vm.StateDetail != health.DrainStopDetail(m.OperationID) {
		return fmt.Sprintf("it is now %s/%q here, not stopped by this move", vm.State, vm.StateDetail), true, nil
	}
	if s.virt == nil {
		return "", false, fmt.Errorf("libvirt not connected")
	}
	if !s.virt.DomainExists(m.VM) {
		return "it has no domain here", true, nil
	}
	active, aerr := s.virt.DomainIsActive(m.VM)
	if aerr != nil {
		return "", false, aerr
	}
	if active && m.ShutdownRequested {
		s.virt.WaitForShutdown(m.VM, drainLateShutdownWait)
		if active, aerr = s.virt.DomainIsActive(m.VM); aerr != nil {
			return "", false, aerr
		}
	}
	if active {
		// Never shut down (the daemon died before asking), or a shutdown that
		// is still not done: it runs here, and its row says so.
		if werr := s.persistVMState(ctx, m.VM, "running", "drain cold move interrupted; the domain kept running", corrosion.OpVMState); werr != nil {
			return "", false, werr
		}
		if m.ShutdownRequested {
			return "not moved; its shutdown was requested and is still in progress: it still runs here and will power off if the guest completes it — then " + startOnDrainedHostHint(m.VM, s.hostName), false, nil
		}
		return "not moved; it kept running here", false, nil
	}
	if err := s.restartAfterFailedColdMove(ctx, m.VM); err != nil {
		return "", false, fmt.Errorf("start it again here: %w", err)
	}
	return "not moved; started again here", false, nil
}
