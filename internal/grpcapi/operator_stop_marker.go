package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/hooks"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// `lv stop --force` on a host in write quarantine (health/operator_stop_marker.go).
//
// The quarantine refuses the stop's "operator-stop" record, and an
// unrecorded kill is undone: once the quarantine lifts the reconciler records
// an out-of-band destroy, which the restart policy starts again. So the
// forced stop records itself locally first, durably, and kills only once
// that record is on disk: every local start honours it, and once the
// quarantine lifts the replay below records the stop on the row through the
// ordinary stop record (persistVMState) and removes the marker. A marker
// that cannot be written refuses the stop: the guest is never killed
// without one.

// quarantinedStopDetail is what a forced stop made under write quarantine
// answers as the VM's state detail: the row itself still says what it said.
const quarantinedStopDetail = "operator-stop recorded on this host only (write quarantine); recorded on the VM once the quarantine lifts"

// quarantineRemedy is how the write quarantine lifts: release probation
// lifts by itself once a voter majority has confirmed it; any other
// quarantine needs this host upgraded again or reseeded.
func (s *Server) quarantineRemedy() string {
	if s.db != nil && s.db.InReleaseProbation() && !s.db.WALQuarantined() {
		return "wait for its release probation, which lifts by itself once a voter majority has been asked (`lv cluster upgrade-status`)"
	}
	return "upgrade this host's binary again or reseed the host (docs/upgrades.md)"
}

// quarantinedForceStopLocked is `lv stop --force` of vm on a host in write
// quarantine (reason). The caller holds the VM lock and has re-read vm
// under it. It writes the operator-stop marker, then destroys the domain.
func (s *Server) quarantinedForceStopLocked(ctx context.Context, vm *corrosion.VMRecord, reason string) (*pb.VM, error) {
	switch vm.State {
	case "pending", "starting", "creating", "migrating":
		// A start or a move is under way: its cancel or settle is a
		// replicated record, which the quarantine refuses.
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q is %s: under write quarantine (%s) the stop cannot settle it, and the stop was not applied; %s, then retry `lv stop --force %s`",
			vm.Name, vm.State, reason, s.quarantineRemedy(), vm.Name)
	}
	if err := health.WriteOperatorStopMarker(s.dataDir, health.OperatorStopMarker{
		VM:          vm.Name,
		Host:        s.hostName,
		Incarnation: corrosion.IncarnationOf(vm.CreatedAt),
		OwnerEpoch:  vm.OwnerEpoch,
		StoppedAt:   time.Now().UTC().Format(time.RFC3339),
		Quarantine:  reason,
	}); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q was not stopped: this host is in write quarantine (%s), so a forced stop must first be recorded on this "+
				"host, and that record could not be written (%v); the guest is left running. Free space or fix the data "+
				"directory (%s), then retry `lv stop --force %s`; or %s",
			vm.Name, reason, err, health.OperatorStopMarkerDir(s.dataDir), vm.Name, s.quarantineRemedy())
	}
	hspec := vmHooks(vm)
	pbVM := &pb.VM{Name: vm.Name, HostName: vm.HostName, State: pb.VMState_VM_STOPPING}
	hooks.Run(ctx, hooks.PreStop, pbVM, hspec)
	if err := s.virt.DestroyDomain(vm.Name); err != nil {
		active, aerr := s.virt.DomainIsActive(vm.Name)
		if aerr == nil && active {
			// Nothing was stopped: the marker would hold a running guest's
			// next start for a stop that did not happen.
			if rerr := health.RemoveOperatorStopMarker(s.dataDir, vm.Name); rerr != nil {
				slog.Warn("StopVM: removing the operator-stop marker of a stop that failed failed", "vm", vm.Name, "error", rerr)
			}
			return nil, status.Errorf(codes.Internal, "destroy: %v", err)
		}
		if aerr != nil && !lv.IsNoDomain(aerr) {
			return nil, status.Errorf(codes.Internal, "destroy: %v (and whether the domain still runs cannot be read: %v; the operator-stop marker is kept)", err, aerr)
		}
		slog.Info("StopVM: the domain is already not running; the forced stop is recorded on this host", "vm", vm.Name, "error", err)
	}
	slog.Warn("StopVM: forced stop under write quarantine — recorded on this host only, recorded on the VM once the quarantine lifts",
		"vm", vm.Name, "quarantine", reason)
	pbVM.State = pb.VMState_VM_STOPPED
	hooks.Run(ctx, hooks.PostStop, pbVM, hspec)
	out, err := s.vmToProto(ctx, vm.Name)
	if err != nil {
		return nil, err
	}
	out.State, out.StateDetail = pb.VMState_VM_STOPPED, quarantinedStopDetail
	return out, nil
}

// operatorStopStartRefusal is the start gate of a VM an operator-stop
// marker holds on this host. The caller holds the VM lock. Under write
// quarantine the start is refused: the marker leaves only through the
// recorded replay, and the start could not be recorded either. Out of it the
// stop is replayed first, so the start begins from the recorded stop. A
// marker that cannot be read refuses the start.
func (s *Server) operatorStopStartRefusal(ctx context.Context, vm *corrosion.VMRecord) error {
	why, corrupt := health.OperatorStopHold(s.dataDir, s.hostName, vm)
	if why == "" {
		return nil
	}
	if corrupt {
		return status.Errorf(codes.FailedPrecondition, "VM %q is held stopped on this host: %s. %s",
			vm.Name, why, health.OperatorStopMarkerCorruptRemedy(vm.Name))
	}
	if reason := s.stopQuarantineReason(); reason != "" {
		return status.Errorf(codes.FailedPrecondition,
			"VM %q was not started: %s. This host is still in write quarantine (%s), so neither that stop nor a start "+
				"can be recorded; %s, and the stop is recorded on its own; then retry `lv start %s`",
			vm.Name, why, reason, s.quarantineRemedy(), vm.Name)
	}
	m, ok, err := health.ReadOperatorStopMarker(s.dataDir, vm.Name)
	if err != nil || !ok {
		return status.Errorf(codes.Unavailable, "VM %q: read its operator-stop marker again: %v; retry", vm.Name, err)
	}
	if err := s.replayOperatorStopLocked(ctx, m); err != nil {
		if errors.Is(err, errReplayHeld) {
			return status.Errorf(codes.FailedPrecondition,
				"VM %q was not started: %s, and its row is %s, which that stop is not recorded over. Record the stop "+
					"with `lv stop %s` (which removes the marker), then retry `lv start %s`",
				vm.Name, why, vm.State, vm.Name, vm.Name)
		}
		return status.Errorf(codes.Unavailable,
			"VM %q was not started: recording the forced stop made under write quarantine failed (%v); retry `lv start %s`",
			vm.Name, err, vm.Name)
	}
	return nil
}

// clearOperatorStopMarker removes name's marker once a stop of it has been
// recorded on its row by the ordinary path: the row now says what the
// marker held. A marker that cannot be read goes too: the operator's
// recorded stop is the remedy for one.
func (s *Server) clearOperatorStopMarker(name string) {
	if s.dataDir == "" {
		return
	}
	if err := health.RemoveOperatorStopMarker(s.dataDir, name); err != nil {
		slog.Warn("removing the VM's operator-stop marker after its stop was recorded failed; the replay removes it", "vm", name, "error", err)
	}
}

// SetOperatorStopMarkerObserver wires the litevirt_operator_stop_markers
// gauge: the markers this host holds that wait for their replay, and the
// ones that cannot be read.
func (s *Server) SetOperatorStopMarkerObserver(fn func(pending, corrupt int)) {
	s.operatorStopMarkerObs = fn
}

// operatorStopReplayLog rate-limits the replay's repeated log lines, per VM.
var operatorStopReplayLog = struct {
	mu   sync.Mutex
	last map[string]time.Time
}{}

func operatorStopReplayLogDue(key string) bool {
	operatorStopReplayLog.mu.Lock()
	defer operatorStopReplayLog.mu.Unlock()
	now := time.Now()
	if t, ok := operatorStopReplayLog.last[key]; ok && now.Sub(t) < 10*time.Minute {
		return false
	}
	if operatorStopReplayLog.last == nil {
		operatorStopReplayLog.last = map[string]time.Time{}
	}
	operatorStopReplayLog.last[key] = now
	return true
}

// ReplayOperatorStopMarkers records every forced stop this host made under
// write quarantine on its VM's (or container's: replayContainerOperatorStops)
// row, once the quarantine has lifted, and
// removes each marker it has recorded (or that no longer applies). Run at the
// start of every reconciler pass, so it lands before the walk reads the
// rows. A marker that cannot be read is alerted on, never replayed. It
// reports whether a marker of this host at owner epoch 0 is still waiting
// for its replay (or the markers cannot be listed): the owner-epoch
// backfill would move that row's generation from under it. A marker at a
// later epoch is not moved by the backfill (0 to 1) and does not hold it.
func (s *Server) ReplayOperatorStopMarkers(ctx context.Context) bool {
	if s.dataDir == "" {
		return false
	}
	reason := s.stopQuarantineReason()
	ctPending, ctCorrupt, ctWait := s.replayContainerOperatorStops(ctx, reason)
	names, err := health.ListOperatorStopMarkers(s.dataDir)
	if err != nil {
		if operatorStopReplayLogDue("\x00list") {
			slog.Error("operator-stop replay: the marker directory cannot be read; every VM with a marker stays held (repeated at most every 10m)",
				"dir", health.OperatorStopMarkerDir(s.dataDir), "error", err)
		}
		return true
	}
	pending, pendingEpoch0 := ctPending, ctWait
	corrupt := map[string]string{}
	for _, name := range names {
		m, ok, rerr := health.ReadOperatorStopMarker(s.dataDir, name)
		if rerr != nil {
			corrupt[name] = rerr.Error()
			if operatorStopReplayLogDue(name) {
				slog.Error("operator-stop replay: a marker cannot be read; its VM is held stopped on this host and the stop is not replayed (repeated at most every 10m)",
					"vm", name, "error", rerr, "remedy", health.OperatorStopMarkerCorruptRemedy(name))
			}
			continue
		}
		if !ok || m.Host != s.hostName {
			continue // gone meanwhile, or another host's (a shared data dir)
		}
		if reason != "" {
			pending++
			pendingEpoch0 = pendingEpoch0 || m.OwnerEpoch == 0
			continue
		}
		unlock, locked := s.tryLockVMAs(name, "operator-stop replay")
		if !locked {
			pending++
			pendingEpoch0 = pendingEpoch0 || m.OwnerEpoch == 0
			continue // an operation holds the VM; next pass
		}
		err := s.replayOperatorStopLocked(ctx, m)
		unlock()
		if err != nil {
			pending++
			pendingEpoch0 = pendingEpoch0 || m.OwnerEpoch == 0
			if operatorStopReplayLogDue(name) {
				slog.Warn("operator-stop replay: recording the forced stop failed; the VM stays held and it is tried again next pass (repeated at most every 10m)",
					"vm", name, "error", err)
			}
		}
	}
	if s.operatorStopMarkerObs != nil {
		s.operatorStopMarkerObs(pending, len(corrupt)+ctCorrupt)
	}
	if reason == "" && s.db != nil {
		if err := health.ReportCorruptOperatorStopMarkers(ctx, s.db, s.dataDir, s.hostName, corrupt); err != nil && operatorStopReplayLogDue("\x00report") {
			slog.Warn("operator-stop replay: raising or resolving operator_stop_marker_corrupt failed (repeated at most every 10m)", "error", err)
		}
	}
	return pendingEpoch0
}

// errReplayHeld is a marker whose VM's row is in a state the replay does not
// write over; the marker is kept.
var errReplayHeld = errors.New("the VM's row is being started or moved; the stop is not recorded over it, and the VM stays held")

// replayOperatorStopLocked records m's stop on its VM's row and removes m.
// The caller holds the VM lock, and the host is out of write quarantine.
func (s *Server) replayOperatorStopLocked(ctx context.Context, m health.OperatorStopMarker) error {
	drop := func(why string) error {
		slog.Info("operator-stop replay: the marker no longer applies; removed without recording", "vm", m.VM, "why", why)
		return health.RemoveOperatorStopMarker(s.dataDir, m.VM)
	}
	vm, err := corrosion.GetVM(ctx, s.db, m.VM)
	switch {
	case err != nil:
		return fmt.Errorf("read the VM: %w", err)
	case vm == nil:
		return drop("the VM was deleted")
	case corrosion.IncarnationOf(vm.CreatedAt) != m.Incarnation:
		return drop("the VM was deleted and created again (created_at " + vm.CreatedAt + ")")
	case vm.HostName != s.hostName:
		return drop("the VM is now on host " + vm.HostName)
	case vm.OwnerEpoch != m.OwnerEpoch:
		// It left this host and came back, or was handed over again: a
		// later ownership, which this stop is not recorded over.
		return drop(fmt.Sprintf("the VM is owned under a later generation (owner epoch %d, the stop's %d)", vm.OwnerEpoch, m.OwnerEpoch))
	case vm.State == "stopped" && vm.StateDetail == "operator-stop":
		return drop("its operator stop is already recorded")
	}
	switch vm.State {
	case "running", "stopped", "error":
	default:
		return fmt.Errorf("%w (state %s)", errReplayHeld, vm.State)
	}
	active, aerr := s.virt.DomainIsActive(vm.Name)
	switch {
	case aerr == nil && active:
		// Started since by something that does not read the marker (an
		// older binary after a rollback, virsh): a stop is never recorded
		// over a running guest.
		s.recordVMEvent(ctx, vm.Name, "vm.stop.replay_skipped", "error",
			"a forced stop made under write quarantine was not recorded: the guest runs again on "+s.hostName)
		return drop("the guest runs again")
	case aerr != nil && !lv.IsNoDomain(aerr):
		return fmt.Errorf("whether the domain runs cannot be read: %w", aerr)
	}
	// As stopLocked: pre-hardware_v2 a stop releases the VM's devices
	// before it is recorded.
	if !s.hardwareV2Latched(ctx) {
		if err := s.releaseDevices(ctx, vm.Name); err != nil {
			return fmt.Errorf("release PCI device(s): %w", err)
		}
	}
	// Guarded by the MARKER's identity, not the row just read: a row that
	// moved on between that read and this write is not written.
	if err := s.persistVMStateIfOwner(ctx, vm.Name, m.Incarnation, m.OwnerEpoch, "stopped", "operator-stop", corrosion.OpVMState); err != nil {
		return fmt.Errorf("record operator-stop: %w", err)
	}
	s.recordVMEvent(ctx, vm.Name, "vm.stopped", "ok",
		"`lv stop --force` made at "+m.StoppedAt+" while "+s.hostName+" was in write quarantine, recorded once it lifted")
	go s.refreshLBForStack(context.Background(), vm.StackName)
	slog.Info("operator-stop replay: the forced stop made under write quarantine is recorded", "vm", vm.Name)
	return health.RemoveOperatorStopMarker(s.dataDir, m.VM)
}

// persistVMStateIfOwner is persistVMState for the replay: the write lands
// only while name's row is still on this host, of incarnation and at owner
// epoch (corrosion.UpdateVMStateIfOwner), so a stop made under one ownership
// is never recorded over another. ErrNoRowsAffected otherwise; the next pass
// reads the row again.
func (s *Server) persistVMStateIfOwner(ctx context.Context, name, incarnation string, epoch int64, state, detail, op string) error {
	committed := false
	err := s.publishRunning(ctx, name, state, func(ctx context.Context) error {
		committed = true
		if s.stateWriteHook != nil {
			if err := s.stateWriteHook(name, state); err != nil {
				s.noteStateWriteFail(op, err)
				return err
			}
		}
		err := corrosion.UpdateVMStateIfOwner(ctx, s.db, name, s.hostName, incarnation, epoch, state, detail)
		if err != nil {
			s.noteStateWriteFail(op, err)
		}
		return err
	})
	if err != nil && !committed {
		s.noteStateWriteFail(op, err)
	}
	return err
}

// quarantinedStartRefusal refuses `lv start` of name on a host in write
// quarantine: the start, its admission and its running state are replicated
// records, which the quarantine refuses, so a guest started now would run
// unrecorded. It says how the quarantine lifts.
func (s *Server) quarantinedStartRefusal(name string) error {
	reason := s.stopQuarantineReason()
	if reason == "" {
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"VM %q was not started: this host is in write quarantine (%s) and cannot record a start, so the guest "+
			"would run while the cluster's record of it says otherwise; nothing was changed. %s, then retry `lv start %s`",
		name, reason, capitalize(s.quarantineRemedy()), name)
}

// capitalize upper-cases s's first letter (an ASCII remedy text).
func capitalize(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return string(s[0]-'a'+'A') + s[1:]
}
