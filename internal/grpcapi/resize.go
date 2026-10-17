package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

const (
	// resizeApplyAttempts bounds the synchronous retry of an incomplete dimension
	// before the operation is left nonterminal for recovery.
	resizeApplyAttempts = 3
	// resourceRecoveryInterval is the reconciler cadence for resuming resize
	// operations that crashed after committing their desired spec.
	resourceRecoveryInterval = 60 * time.Second
)

// resizeVMLive is the single lock-owning combined live-resize coordinator: it grows
// vCPUs (within the running hotplug ceiling) and/or reballoons memory (within the
// domain's band) in ONE operation. It takes the FULL desired spec but applies ONLY
// the cpu and memory dimensions onto a fresh clone of the STORED spec — so a live
// resize never clobbers server-owned fields (UUID / resolved MACs / addresses /
// unknown fields). Callers must NOT hold the VM lock. Returns nil when there is
// nothing to do.
func (s *Server) resizeVMLive(ctx context.Context, name string, desired *pb.VMSpec, idemKey string) error {
	unlock := s.lockVM(name)
	defer unlock()

	vm, err := corrosion.GetVM(ctx, s.db, name)
	if err != nil || vm == nil {
		return status.Errorf(codes.NotFound, "VM %q not found", name)
	}
	if vm.HostName != s.hostName {
		return status.Errorf(codes.Aborted, "ownership of %q moved to %s mid-operation; retry", name, vm.HostName)
	}
	if vm.ActiveOperationID != "" {
		return status.Errorf(codes.FailedPrecondition, "cannot resize %q: an operation is in progress", name)
	}
	if vm.State != "running" {
		return status.Errorf(codes.FailedPrecondition, "VM %q must be running to live-resize (current: %s)", name, vm.State)
	}

	stored := &pb.VMSpec{}
	if vm.Spec != "" {
		if err := json.Unmarshal([]byte(vm.Spec), stored); err != nil {
			return status.Errorf(codes.Internal, "parse stored spec: %v", err)
		}
	}

	wantCPU := desired.Cpu
	if wantCPU == 0 {
		wantCPU = stored.Cpu
	}
	wantMem := desired.MemoryMib
	if wantMem == 0 {
		wantMem = stored.MemoryMib
	}
	cpuDelta := int(wantCPU) - int(stored.Cpu)
	memDelta := int(wantMem) - int(stored.MemoryMib)
	if cpuDelta == 0 && memDelta == 0 {
		return nil
	}

	// Preflight BOTH dimensions BEFORE mutating either — a change that can't be
	// applied live is a Restart-class refusal, never a partial apply.
	if cpuDelta != 0 {
		if wantCPU < stored.Cpu {
			return status.Errorf(codes.FailedPrecondition,
				"live resize only grows vCPUs; stop %q to shrink from %d to %d", name, stored.Cpu, wantCPU)
		}
		if stored.Resources != nil && len(stored.Resources.CpuPinning) > 0 {
			return status.Errorf(codes.FailedPrecondition,
				"VM %q has pinned vCPUs and cannot live-grow CPUs; stop it and update, or pass --restart-if-needed", name)
		}
		inactiveXML, xerr := s.virt.DumpXMLInactive(name)
		if xerr != nil {
			return status.Errorf(codes.Internal, "read domain XML for %q: %v", name, xerr)
		}
		if ceiling := lv.MaxVCPUFromXML(inactiveXML); ceiling < int(wantCPU) {
			return status.Errorf(codes.FailedPrecondition,
				"VM %q boots with a vCPU ceiling of %d; growing to %d needs a restart — set max_cpu (≥%d) and restart, or pass --restart-if-needed",
				name, ceiling, wantCPU, wantCPU)
		}
	}
	if memDelta != 0 && stored.MemoryHotplugMaxMib > 0 {
		// Memory hot-add: plug or unplug virtio-mem blocks within the band the
		// domain booted with. The boot cell itself cannot be unplugged.
		base, max := stored.MemoryHotplugBaseMib, stored.MemoryHotplugMaxMib
		if wantMem > max {
			return status.Errorf(codes.FailedPrecondition,
				"live resize target %d MiB exceeds %q's hot-add maximum %d MiB; raise it (`lv update --memory-hotplug-max`) and restart", wantMem, name, max)
		}
		if wantMem < base {
			return status.Errorf(codes.FailedPrecondition,
				"live resize target %d MiB is below %q's boot memory %d MiB, which cannot be unplugged; stop it to shrink further", wantMem, name, base)
		}
		if (wantMem-base)%2 != 0 {
			return status.Errorf(codes.InvalidArgument,
				"live resize target %d MiB must be the boot memory %d MiB plus a multiple of 2 MiB", wantMem, base)
		}
		// The running domain must actually have the region: one defined
		// without it (by an older build, say) cannot plug anything, and a
		// committed change it can never apply would hold the VM's operation
		// barrier forever. Refused before anything is committed.
		if live, xerr := s.virt.DumpXML(name); xerr != nil {
			return status.Errorf(codes.Internal, "read domain XML for %q: %v", name, xerr)
		} else if !lv.HasVirtioMem(live) {
			return status.Errorf(codes.FailedPrecondition,
				"VM %q runs without a virtio-mem device although its spec has memory hot-add; stop it and redefine it (lv update %s --memory-hotplug-max %d), then start it",
				name, name, max)
		}
	} else if memDelta != 0 {
		ceiling := stored.MaxMemoryMib
		if ceiling == 0 {
			ceiling = stored.MemoryMib
		}
		if wantMem > ceiling {
			return status.Errorf(codes.FailedPrecondition,
				"live resize target %d MiB exceeds %q's balloon ceiling %d MiB; raise max-memory and restart", wantMem, name, ceiling)
		}
		if stored.MinMemoryMib > 0 && wantMem < stored.MinMemoryMib {
			return status.Errorf(codes.FailedPrecondition,
				"live resize target %d MiB is below %q's minimum %d MiB", wantMem, name, stored.MinMemoryMib)
		}
	}

	target := proto.Clone(stored).(*pb.VMSpec)
	target.Cpu = wantCPU
	target.MemoryMib = wantMem

	// Observe the changed dimension(s) at the new value; keep the untouched
	// dimension's real actual (a cpu-only grow must not clobber a ballooned mem_actual).
	obsCPU := vm.CPUActual
	if cpuDelta != 0 {
		obsCPU = int(wantCPU)
	}
	obsMem := vm.MemActual
	if memDelta != 0 {
		obsMem = int(wantMem)
	}

	if s.operationProtocolActive(ctx) {
		return s.resizeVMLiveCoordinated(ctx, vm, stored, target, obsCPU, obsMem, idemKey)
	}

	// Pre-latch path keeps its direct resource check. The coordinated path moves
	// admission into a provisional, race-safe reservation and only then claims the
	// mutation barrier.
	if err := s.checkResourceAdmission(ctx, vm.HostName, vm.Project, posOnly(cpuDelta), posOnly(memDelta)); err != nil {
		return err
	}

	// Pre-latch direct path: apply persistent-then-live (per the fixed primitives),
	// then persist the desired spec + observed actuals under the barrier discipline.
	// Documented best-effort — no F1 durability/recovery.
	if err := s.applyLiveResize(ctx, name, target, stored); err != nil {
		if errors.Is(err, lv.ErrNoVirtioMem) {
			return status.Errorf(codes.FailedPrecondition, "live resize of %q: %v", name, err)
		}
		return status.Errorf(codes.Internal, "live resize: %v", err)
	}
	obsMem = s.hotplugHeldMiB(name, target, obsMem)
	applied, newGen, err := corrosion.MutateDesiredSpec(ctx, s.db, name, func(old string) (string, error) {
		fresh := &pb.VMSpec{}
		if old != "" {
			if uerr := json.Unmarshal([]byte(old), fresh); uerr != nil {
				return "", uerr
			}
		}
		fresh.Cpu = wantCPU
		fresh.MemoryMib = wantMem
		b, merr := json.Marshal(fresh)
		return string(b), merr
	})
	if err != nil {
		return status.Errorf(codes.Internal, "persist resize: %v", err)
	}
	if !applied {
		return status.Errorf(codes.FailedPrecondition, "cannot resize %q: an operation is in progress", name)
	}
	if _, err := corrosion.UpdateObservedActuals(ctx, s.db, name, obsCPU, obsMem, vm.OwnerEpoch, newGen); err != nil {
		slog.Error("resizeVMLive: persisting actuals failed — accounting will lag until reconciled", "vm", name, "error", err)
	}
	slog.Info("vm live-resized", "vm", name, "cpu", wantCPU, "mem_mib", wantMem)
	s.recordVMEvent(ctx, name, "vm.resized", "ok", fmt.Sprintf("cpu=%d mem=%dMiB", wantCPU, wantMem))
	return nil
}

// resizeVMLiveCoordinated is the post-latch (operation_protocol) combined resize: ONE
// BeginVMOperation atomically commits the full desired spec (cpu+mem), bumps the
// generation, and claims the mutation barrier; the apply then runs under the F1
// durability discipline. Caller holds the VM lock.
func (s *Server) resizeVMLiveCoordinated(ctx context.Context, vm *corrosion.VMRecord, stored, target *pb.VMSpec, obsCPU, obsMem int, idemKey string) error {
	principal := callerUsername(ctx) + "@" + callerRealm(ctx)
	_, _ = s.ensureProjectAuthority(ctx, vm.Project) // best-effort D1 authority establishment

	cpuDelta := posOnly(int(target.Cpu) - int(stored.Cpu))
	memDelta := posOnly(int(target.MemoryMib) - int(stored.MemoryMib))
	if idemKey == "" {
		// No client key: mint a per-attempt id so distinct resizes never collide on
		// one deterministic operation id (each deploy attempt is its own operation).
		idemKey = uuid.NewString()
	}
	opID := corrosion.DeterministicOperationID("ResizeVMLive", principal, vm.Project, vm.Name, idemKey)

	lease, aerr := s.admitResizeReservation(
		ctx, opID, "ResizeVMLive", principal, idemKey, vm, cpuDelta, memDelta,
		int(target.Cpu), int(target.MemoryMib))
	if aerr != nil {
		return aerr
	}
	// One cleanup discipline for every return. Before BeginVMOperation commits,
	// the WHOLE lease is freed — including the two early error returns below,
	// which previously leaked it. After the commit, only the delegated QUOTA
	// half: the local op row is the workload operation itself (terminated by
	// CompleteVMOperation, or left nonterminal for recovery), but the holder's
	// quota lease is a separate row nothing else terminates — the success path
	// previously never released it, so every delegated resize permanently
	// consumed project quota as an eternal earlier claimant. Releasing it
	// post-commit is sound: the desired spec is durably committed at the new
	// size, and the settle rule holds the charge until usage reflects it.
	committed := false
	defer func() {
		if committed {
			lease.releaseQuota(ctx)
			return
		}
		lease.release(ctx)
	}()

	resJSON, err := (corrosion.ReservationVector{
		Project: vm.Project, ProjectCPU: cpuDelta, ProjectMemMiB: memDelta,
		TargetHost: vm.HostName, TargetCPU: cpuDelta, TargetMemMiB: memDelta,
	}).Encode()
	if err != nil {
		return status.Errorf(codes.Internal, "encode reservation: %v", err)
	}
	targetJSON, err := json.Marshal(target)
	if err != nil {
		return status.Errorf(codes.Internal, "marshal spec: %v", err)
	}

	op := resizeOperationRecord(opID, "ResizeVMLive", principal, idemKey, vm, target.Cpu, target.MemoryMib, resJSON)
	// FENCE before BeginVMOperation commits the desired spec; see CreateVM.
	if ferr := lease.allowCommit(ctx); ferr != nil {
		return ferr
	}
	applied, err := s.db.BeginVMOperation(ctx, op, string(targetJSON), vm.OwnerEpoch, vm.SpecGeneration)
	if err != nil {
		return status.Errorf(codes.Internal, "begin operation: %v", err)
	}
	if !applied {
		return status.Errorf(codes.FailedPrecondition, "cannot resize %q: an operation is in progress or the VM changed underneath", vm.Name)
	}
	committed = true
	newGen := vm.SpecGeneration + 1
	return s.driveResourceUpdate(ctx, vm, op.ID, vm.OwnerEpoch, newGen, target, stored, obsCPU, obsMem)
}

// admitResizeReservation performs reserve-then-verify for a resize operation
// using the same deterministic operation id that will eventually own the mutation
// barrier.
//
// Using the workload operation id for the reservation is intentional: once
// BeginVMOperation claims the VM, the same id becomes the authoritative
// persistence record and drives recovery. Marking the operation as a transient
// CAPACITY lease would let stale-lease expiry free real in-flight reservations.
//
// The header written here is the one BeginVMOperation keeps (INSERT OR IGNORE),
// so it is written as that header: at the VM's owner epoch, with the request
// hash and idempotency key. The epoch is what lets the operation's own terminal
// (CompleteVMOperation, FailVMOperation, recovery — all at the VM's epoch)
// release the reservation; aggregation reduces by (id, header epoch).
func (s *Server) admitResizeReservation(
	ctx context.Context, opID, method, principal, idemKey string, vm *corrosion.VMRecord, cpuDelta, memDelta, wantCPU, wantMem int,
) (*reservationLease, error) {
	// The same host-safety gate as the equivalent UpdateVM grow
	// (admitGrowWithReservation → admitReserved → checkHostSafety): a resize is
	// not new residency, but a grow of a DISPUTED workload — or onto a host
	// involved in an active ownership condition — must refuse here exactly as
	// it does on every other admission path. Before the zero-delta fast path,
	// same as everywhere else.
	if err := s.checkHostSafety(ctx, vm.HostName, corrosion.WorkloadVM, vm.Name, false,
		cpuDelta > 0 || memDelta > 0); err != nil {
		return nil, err
	}
	if cpuDelta <= 0 && memDelta <= 0 {
		return &reservationLease{}, nil
	}

	delegated := s.projectAuthorityActive(ctx)
	// The subject carries the ABSOLUTE resize target: the VM's row is already
	// visible at its old size, so a released lease may only settle once the row
	// contributes the grown size — presence alone would free it instantly while
	// the holder's usage still counted the smaller spec.
	subject := quotaSubject{
		Kind: corrosion.WorkloadVM, Host: vm.HostName, Name: vm.Name,
		Want: corrosion.QuotaAmount{VCPU: wantCPU, MemMiB: wantMem},
	}
	rv := corrosion.ReservationVector{
		Project:    vm.Project,
		TargetHost: vm.HostName, TargetCPU: cpuDelta, TargetMemMiB: memDelta,
		Provisional: true,
	}
	if !delegated {
		rv.ProjectCPU, rv.ProjectMemMiB = cpuDelta, memDelta
		rv.Workload, rv.WorkloadKind, rv.WorkloadHost = subject.Name, subject.Kind, subject.Host
		rv.WantCPU, rv.WantMemMiB = subject.Want.VCPU, subject.Want.MemMiB
	}
	resJSON, err := rv.Encode()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode reservation: %v", err)
	}

	op := resizeOperationRecord(opID, method, principal, idemKey, vm, int32(wantCPU), int32(wantMem), resJSON)
	extra := s.runtimeLoad(ctx, vm.HostName) // outside admissionMu: see checkHostCapacityBefore
	lease, err := s.decideReservation(ctx, op, vm.Project, "reserve capacity", func(id string) error {
		if err := s.checkHostCapacityBefore(ctx, vm.HostName, cpuDelta, memDelta, id, extra); err != nil {
			return err
		}
		if !delegated {
			return s.checkProjectQuotaBefore(ctx, vm.Project, corrosion.QuotaAmount{VCPU: cpuDelta, MemMiB: memDelta}, id)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !delegated {
		return lease, nil
	}

	holder, quotaLease, epoch, qerr := s.admitProjectQuota(ctx, method, vm.Project, "vm:"+vm.Name, subject, corrosion.QuotaAmount{VCPU: cpuDelta, MemMiB: memDelta})
	if qerr != nil {
		lease.release(ctx)
		return nil, qerr
	}
	lease.quotaHolder, lease.quotaProject, lease.quotaLease = holder, vm.Project, quotaLease
	lease.quotaEpoch = epoch
	return lease, nil
}

// driveResourceUpdate applies target cpu+mem to a VM whose mutation barrier is
// ALREADY held by opID (freshly begun, or found by recovery), records the operation
// steps, persists observed actuals, and completes the operation. The desired spec is
// already committed durably (BeginVMOperation), so the operation is DURABLE, not
// runtime-atomic: on an apply failure it is left NONTERMINAL (recoverable) — never
// aborted, never force-completed — and startup/reconciler recovery resumes it toward
// the committed desired spec. applyPrev selects which dimensions still need applying
// (stored for the first attempt, observed actuals for recovery). Caller holds the
// VM lock.
func (s *Server) driveResourceUpdate(ctx context.Context, vm *corrosion.VMRecord, opID string, ownerEpoch, newGen int64, target, applyPrev *pb.VMSpec, obsCPU, obsMem int) error {
	s.appendOpStep(ctx, opID, ownerEpoch, corrosion.OpResourceUpdateRunning, corrosion.OpStepDesiredPersisted)

	var applyErr error
	for attempt := 0; attempt < resizeApplyAttempts; attempt++ {
		if applyErr = s.applyLiveResize(ctx, vm.Name, target, applyPrev); applyErr == nil || errors.Is(applyErr, lv.ErrNoVirtioMem) {
			break
		}
	}
	if errors.Is(applyErr, lv.ErrNoVirtioMem) {
		// The definition has no hot-add region (it drifted from the spec):
		// no retry can apply this, so the operation ends here, failed, with
		// the barrier cleared and the desired memory put back to what the
		// domain holds — never left for a recovery that would retry forever.
		if _, ferr := s.db.FailVMOperation(ctx, vm.Name, opID, ownerEpoch, newGen, "no virtio-mem device"); ferr != nil {
			slog.Error("resize: failing an unappliable hot-add failed", "vm", vm.Name, "op", opID, "error", ferr)
		}
		if _, _, merr := corrosion.MutateDesiredSpec(ctx, s.db, vm.Name, func(old string) (string, error) {
			fresh := &pb.VMSpec{}
			if old != "" {
				if uerr := json.Unmarshal([]byte(old), fresh); uerr != nil {
					return "", uerr
				}
			}
			fresh.MemoryMib = applyPrev.MemoryMib
			b, err := json.Marshal(fresh)
			return string(b), err
		}); merr != nil {
			slog.Error("resize: restoring the desired memory after an unappliable hot-add failed", "vm", vm.Name, "error", merr)
		}
		s.recordVMEvent(ctx, vm.Name, "vm.resized", "error", "memory hot-add refused: the domain has no virtio-mem device")
		return status.Errorf(codes.FailedPrecondition, "live resize of %q: %v", vm.Name, applyErr)
	}
	if applyErr != nil {
		// Persistent-config failure or an incomplete dimension: leave the operation
		// nonterminal for recovery (desired is already committed) — do NOT abort.
		slog.Error("resize: apply incomplete after retries — operation left recoverable", "vm", vm.Name, "op", opID, "error", applyErr)
		return status.Errorf(codes.Internal, "live resize partially applied for %q; recovery will converge: %v", vm.Name, applyErr)
	}
	s.appendOpStep(ctx, opID, ownerEpoch, corrosion.OpResourceUpdateRunning, corrosion.OpStepConfigApplied)
	s.appendOpStep(ctx, opID, ownerEpoch, corrosion.OpResourceUpdateRunning, corrosion.OpStepLiveApplied)
	obsMem = s.hotplugHeldMiB(vm.Name, target, obsMem)

	if _, err := corrosion.UpdateObservedActuals(ctx, s.db, vm.Name, obsCPU, obsMem, ownerEpoch, newGen); err != nil {
		slog.Error("resize: persisting actuals failed — accounting will lag until reconciled", "vm", vm.Name, "error", err)
	}
	s.appendOpStep(ctx, opID, ownerEpoch, corrosion.OpResourceUpdateRunning, corrosion.OpStepObserved)

	if _, err := s.db.CompleteVMOperation(ctx, vm.Name, opID, ownerEpoch, newGen); err != nil {
		slog.Error("resize: completing operation failed — recovery will reconcile", "vm", vm.Name, "op", opID, "error", err)
	}
	slog.Info("vm live-resized (coordinated)", "vm", vm.Name, "cpu", target.Cpu, "mem_mib", target.MemoryMib)
	s.recordVMEvent(ctx, vm.Name, "vm.resized", "ok", fmt.Sprintf("cpu=%d mem=%dMiB", target.Cpu, target.MemoryMib))
	return nil
}

// applyLiveResize applies the changed dimensions to the domain via the config-first
// libvirt primitives (persistent config first, then live, then verify). A dimension
// whose target already equals applyPrev is skipped. The primitives are idempotent,
// so re-running this during recovery is safe.
func (s *Server) applyLiveResize(ctx context.Context, name string, target, applyPrev *pb.VMSpec) error {
	if target.Cpu != applyPrev.Cpu {
		if err := s.virt.SetVCPUs(name, int(target.Cpu)); err != nil {
			return fmt.Errorf("vcpus: %w", err)
		}
	}
	if target.MemoryMib != applyPrev.MemoryMib {
		if target.MemoryHotplugMaxMib > 0 {
			// Hot-add domain: memory above the boot cell is virtio-mem, so the
			// change is how much of the region is plugged, not a balloon target.
			if err := s.virt.SetVirtioMemRequested(name, int(target.MemoryMib-target.MemoryHotplugBaseMib)); err != nil {
				return fmt.Errorf("memory hot-add: %w", err)
			}
			return nil
		}
		if err := s.virt.SetMemory(name, int(target.MemoryMib)); err != nil {
			return fmt.Errorf("memory: %w", err)
		}
	}
	return nil
}

// applyLiveMetadata patches ONLY the named live-metadata fields from `desired` onto
// the VM's stored spec, via MutateDesiredSpec (barrier-respecting, applied to the
// FRESH stored spec). It must never overwrite the whole spec — that would discard
// server-owned fields (UUID, resolved addresses/MACs, unknown fields). The reconciler
// / vmcheck read these fields fresh each sweep, so no domain redefine is needed.
func (s *Server) applyLiveMetadata(ctx context.Context, name string, desired *pb.VMSpec, fields []string) error {
	if limitFields, rest := splitLimitFields(fields); len(limitFields) > 0 {
		// Applied through UpdateVM, which forwards to the owning host, tells
		// libvirt (config and the running domain) and persists the spec.
		if _, err := s.UpdateVM(ctx, limitUpdateFromDesired(name, desired, limitFields)); err != nil {
			return err
		}
		fields = rest
	}
	if len(fields) == 0 {
		return nil
	}
	// Defining a lifecycle hook needs admin (hooks run as root on the host;
	// see CreateVM) — changing one through an update is no different.
	for _, f := range fields {
		if f == "hooks" && hooksDefined(desired.GetHooks()) {
			if err := RequireRole(ctx, "admin"); err != nil {
				return status.Error(codes.PermissionDenied,
					"changing VM lifecycle hooks requires the admin role (hooks execute as root on the target host)")
			}
		}
	}
	// A disk's I/O throttle is applied to the running domain, which only its
	// owner can do: SetDiskIO forwards there, throttles and records it in the
	// spec itself, so it has nothing left for the spec patch below.
	for _, f := range fields {
		if f == "disk_io" {
			if err := s.applyDesiredDiskIO(ctx, name, desired); err != nil {
				return err
			}
		}
	}
	// A NIC's security-group binding and guard live on the rows the firewall
	// enforces from, which those RPCs write; nothing is left for the spec.
	var nicSec, rest []string
	for _, f := range fields {
		if _, _, ok := nicSecurityField(f); ok {
			nicSec = append(nicSec, f)
		} else {
			rest = append(rest, f)
		}
	}
	if len(nicSec) > 0 {
		if err := s.applyDesiredNICSecurity(ctx, name, desired, nicSec); err != nil {
			return err
		}
		if len(rest) == 0 {
			slog.Info("vm live metadata applied", "vm", name, "fields", fields)
			s.recordVMEvent(ctx, name, "vm.updated", "ok", fmt.Sprintf("live metadata: %v", fields))
			return nil
		}
	}
	// Made on the VM's owner, which serialises its spec edits (spec_owner.go).
	applied, err := s.patchSpecAtOwner(ctx, name, desired, rest)
	if err != nil {
		return status.Errorf(codes.Internal, "apply live metadata for %q: %v", name, err)
	}
	if !applied {
		return status.Errorf(codes.FailedPrecondition, "cannot update %q: an operation is in progress", name)
	}
	slog.Info("vm live metadata applied", "vm", name, "fields", fields)
	s.recordVMEvent(ctx, name, "vm.updated", "ok", fmt.Sprintf("live metadata: %v", fields))
	return nil
}

// appendOpStep appends a legal step to an operation, logging (never failing the
// caller) on an illegal step or a write error — a lost step is reduced correctly on
// the next observe/recovery.
func (s *Server) appendOpStep(ctx context.Context, opID string, ownerEpoch int64, kind corrosion.OperationKind, step string) {
	if !corrosion.IsLegalStep(kind, step) {
		slog.Error("resize: refusing to append illegal operation step", "op", opID, "kind", kind, "step", step)
		return
	}
	if err := corrosion.AppendOperationStep(ctx, s.db, corrosion.OperationStepRecord{
		OperationID: opID, OwnerEpoch: ownerEpoch, StepName: step,
	}); err != nil {
		slog.Warn("resize: append operation step", "op", opID, "step", step, "error", err)
	}
}

// RecoverResourceOperations resumes locally-owned VMs whose mutation barrier points
// at a NONTERMINAL resource_update_running operation — a resize that crashed after
// committing its desired spec but before observing/completing. It converges the
// domain to the committed desired spec and completes the operation, so a partial
// failure converges instead of wedging active_operation_id. It takes the VM lock per
// VM (serializing with any in-flight resize) and re-checks terminality under it, so
// it never races a live handler. Safe at startup and on a reconciler tick.
func (s *Server) RecoverResourceOperations(ctx context.Context) {
	vms, err := corrosion.ListVMsWithActiveOperation(ctx, s.db, s.hostName)
	if err != nil {
		slog.Warn("resource op recovery: list wedged VMs failed", "error", err)
		return
	}
	for i := range vms {
		s.recoverOneResourceOperation(ctx, vms[i].Name)
	}
}

func (s *Server) recoverOneResourceOperation(ctx context.Context, name string) {
	unlock := s.lockVM(name)
	defer unlock()

	vm, err := corrosion.GetVM(ctx, s.db, name)
	if err != nil || vm == nil || vm.HostName != s.hostName || vm.ActiveOperationID == "" {
		return
	}
	view, ok, err := corrosion.GetVMActiveOperation(ctx, s.db, name)
	if err != nil || !ok || view.Operation == nil {
		return
	}
	if view.Operation.OperationKind != string(corrosion.OpResourceUpdateRunning) {
		return // other kinds (device leases, restart) are recovered by their own paths
	}
	if corrosion.IsOperationTerminal(view.State) {
		return
	}

	target := &pb.VMSpec{}
	if vm.Spec != "" {
		if uerr := json.Unmarshal([]byte(vm.Spec), target); uerr != nil {
			slog.Error("resource op recovery: parse committed spec failed", "vm", name, "error", uerr)
			return
		}
	}
	// Apply only the un-converged dimensions (compare against the observed actuals);
	// converge observed actuals to the committed desired.
	actuals := &pb.VMSpec{Cpu: int32(vm.CPUActual), MemoryMib: int32(vm.MemActual)}
	if err := s.driveResourceUpdate(ctx, vm, view.ActiveOperationID, view.OwnerEpoch, view.SpecGeneration,
		target, actuals, int(target.Cpu), int(target.MemoryMib)); err != nil {
		slog.Warn("resource op recovery: not yet converged; will retry", "vm", name, "error", err)
		return
	}
	slog.Info("resource op recovery: converged", "vm", name)
}

// RunResourceOperationRecovery periodically resumes wedged resize operations so a
// partial failure converges without operator action.
func (s *Server) RunResourceOperationRecovery(ctx context.Context) {
	t := time.NewTicker(resourceRecoveryInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.RecoverResourceOperations(ctx)
		}
	}
}

// resizeOperationRecord is the header of a live resize's workload operation.
// admitResizeReservation writes it (for a grow) and BeginVMOperation writes it
// otherwise, keeping whichever came first (INSERT OR IGNORE), so both build it
// here: its owner epoch, request hash and idempotency key must be the same
// whichever writes it.
func resizeOperationRecord(opID, method, principal, idemKey string, vm *corrosion.VMRecord, wantCPU, wantMem int32, resJSON string) corrosion.OperationRecord {
	return corrosion.OperationRecord{
		ID:              opID,
		Method:          method,
		Principal:       principal,
		Project:         vm.Project,
		ResourceKind:    "vm",
		ResourceID:      vm.Name,
		OperationKind:   string(corrosion.OpResourceUpdateRunning),
		RequestHash:     resizeRequestHash(vm.Name, wantCPU, wantMem),
		IdempotencyKey:  idemKey,
		ReservationJSON: resJSON,
		VMOwnerEpoch:    vm.OwnerEpoch,
	}
}

// resizeRequestHash is the canonical request hash for a live resize (name + target
// cpu + target mem), so a reused idempotency key with different targets is a conflict.
func resizeRequestHash(name string, cpu, mem int32) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("resize:%s:%d:%d", name, cpu, mem)))
	return hex.EncodeToString(sum[:])
}

// posOnly clamps a delta to its positive part (only growth consumes capacity).
func posOnly(d int) int {
	if d < 0 {
		return 0
	}
	return d
}

// hotplugHeldMiB is the memory a hot-add VM holds after a resize: the boot
// cell plus the larger of what was requested and what the guest has actually
// plugged (<current> in the live XML). An unplug the guest cannot complete
// leaves the memory with QEMU, so placement and admission must keep counting
// it until the two converge. Any other VM, or a domain that reports no
// <current>, keeps obs.
func (s *Server) hotplugHeldMiB(name string, target *pb.VMSpec, obs int) int {
	if target.MemoryHotplugMaxMib <= 0 {
		return obs
	}
	live, err := s.virt.DumpXML(name)
	if err != nil {
		return obs
	}
	cur, ok := lv.VirtioMemCurrentMiB(live)
	if !ok {
		return obs
	}
	if held := int(target.MemoryHotplugBaseMib) + cur; held > obs {
		slog.Warn("memory hot-add: the guest still holds more than was requested; counting what it holds",
			"vm", name, "requested_mib", target.MemoryMib, "held_mib", held)
		return held
	}
	return obs
}
