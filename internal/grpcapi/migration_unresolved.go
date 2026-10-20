package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// condMigrationUnresolved names a VM whose row a drain left migrating: its
// live move ended without libvirt's answer and the guest was not running on
// the source, so it may run on the target. Raised by that drain; resolved by
// `lv doctor repair-owner` and `lv stop`, which settle the row.
const condMigrationUnresolved = "vm.migration_unresolved"

// migrationUnresolvedEvidence is vm.migration_unresolved's evidence.
type migrationUnresolvedEvidence struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Detail string `json:"detail"`
	// LeaseID is the target's capacity reservation the move kept, released
	// when the condition is resolved.
	LeaseID string `json:"lease_id,omitempty"`
}

// raiseMigrationUnresolved raises vm.migration_unresolved for vm, left
// migrating on this host by a move to target, which keeps leaseID.
func (s *Server) raiseMigrationUnresolved(ctx context.Context, vm, target, leaseID, detail string) {
	ev, _ := json.Marshal(migrationUnresolvedEvidence{Source: s.hostName, Target: target, Detail: detail, LeaseID: leaseID})
	hosts := []string{s.hostName}
	if target != "" {
		hosts = append(hosts, target)
	}
	s.setConditionOf(ctx, drainEvaluator, condMigrationUnresolved, "vm", vm,
		hosts, true, corrosion.SeverityCritical, string(ev))
}

// resolveMigrationUnresolved resolves vm's vm.migration_unresolved, once its
// row is settled (or the VM deleted), and releases the target's capacity
// reservation the move kept. A release that fails is left to the stale-lease
// sweep.
func (s *Server) resolveMigrationUnresolved(ctx context.Context, vm string) {
	if s.db == nil {
		return
	}
	row, ok, err := corrosion.GetHealthCondition(ctx, s.db, drainEvaluator, condMigrationUnresolved, "vm", vm)
	if err != nil || !ok || row.Lifecycle == corrosion.ConditionResolved {
		return
	}
	var ev migrationUnresolvedEvidence
	if json.Unmarshal([]byte(row.Evidence), &ev) == nil && ev.LeaseID != "" && ev.Target != "" {
		lease := &reservationLease{s: s, id: ev.LeaseID, hostHolder: ev.Target}
		if !lease.released(ctx) {
			slog.Warn("vm.migration_unresolved: the target's capacity reservation was not released; the stale-lease sweep collects it",
				"vm", vm, "target", ev.Target, "lease", ev.LeaseID)
		}
	}
	s.setConditionOf(ctx, drainEvaluator, condMigrationUnresolved, "vm", vm, nil, false, corrosion.SeverityCritical, "")
}

// migrationUnresolved reports whether vm's vm.migration_unresolved is open.
func (s *Server) migrationUnresolved(ctx context.Context, vm string) bool {
	if s.db == nil {
		return false
	}
	row, ok, err := corrosion.GetHealthCondition(ctx, s.db, drainEvaluator, condMigrationUnresolved, "vm", vm)
	return err == nil && ok && row.Lifecycle != corrosion.ConditionResolved
}

// settleMigratingAdvice is what to do about a VM whose row says migrating
// and whose move is not running: find where the guest runs, and record it.
func settleMigratingAdvice(vm string) string {
	return fmt.Sprintf("if the guest runs on a host, `lv doctor repair-owner %s <host>` records it there; "+
		"if it runs on none, `lv stop %s` settles the record", vm, vm)
}

// inFlightMoveAdvice is the advice of a drain frame skipping vm, whose row
// says migrating.
func (s *Server) inFlightMoveAdvice(ctx context.Context, vm string) string {
	if s.migrationUnresolved(ctx, vm) {
		return fmt.Sprintf("its last move ended without libvirt's answer and the guest may run on the move's target "+
			"(%s, see `lv health`): %s", condMigrationUnresolved, settleMigratingAdvice(vm))
	}
	return "a move of this VM is in flight (an earlier drain's finishing in the background, or a migration); " +
		"re-run drain once it ends (`lv events " + vm + "`)"
}

// inFlightMoveRefusal refuses op (a start, restart or reconfigure of vm on
// this host, or a stop that has not asked the move's target) while vm's row
// says migrating: a move of it is in flight, or ended leaving the row so, and
// the guest may run on the move's target. A start here would make a second
// copy; a stop recorded here would let the next start make one.
func (s *Server) inFlightMoveRefusal(ctx context.Context, op string, vm *corrosion.VMRecord) error {
	if vm.State != "migrating" {
		return nil
	}
	target := migratingToward(vm.StateDetail)
	if target == "" {
		target = "its target"
	}
	why := fmt.Sprintf("a move of it to %s is in flight (`lv events %s`)", target, vm.Name)
	if s.migrationUnresolved(ctx, vm.Name) {
		why = fmt.Sprintf("its move to %s ended without libvirt's answer (%s, see `lv health`)", target, condMigrationUnresolved)
	}
	done := "nothing is started here"
	switch op {
	case "stop":
		done = "it is not recorded stopped here"
	case "reconfigure":
		done = "nothing of it is stopped, redefined or started here"
	}
	return status.Errorf(codes.FailedPrecondition,
		"%s %q refused: its record says migrating, as %s, and the guest may run on %s; %s. "+
			"Once no move of it runs, %s",
		op, vm.Name, why, target, done, settleMigratingAdvice(vm.Name))
}

// movingVMStartRefusal is the refusal EVERY start of a VM's domain passes
// through, whatever asked for it: startVMLocked, and PrepareHardwareForStart
// for the paths that start outside it (the reconciler's and the health
// checker's restarts, a restore). A row recorded migrating is not started.
// The row is read again here, so a caller's stale record does not get past
// it; one that cannot be read refuses the start as retryable, whether a move
// of the VM is in flight being unknown. A VM with no row yet (a restore's,
// written once it runs) is not a moving VM.
//
// Only a move itself brings up the guest of a row recorded migrating, on the
// target, through libvirt's migration, never through a start here: no start
// path is exempt.
func (s *Server) movingVMStartRefusal(ctx context.Context, vm *corrosion.VMRecord) error {
	if vm == nil {
		return nil
	}
	if err := s.inFlightMoveRefusal(ctx, "start", vm); err != nil {
		return err
	}
	if s.db == nil {
		return nil
	}
	row, err := corrosion.GetVM(ctx, s.db, vm.Name)
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"start %q: whether a move of it is in flight cannot be read (%v); retry", vm.Name, err)
	}
	if row == nil {
		return nil
	}
	return s.inFlightMoveRefusal(ctx, "start", row)
}

// migratingStopProbeTimeout bounds the ask of a migrating VM's target
// whether the guest runs there (migratingStopRefusal).
const migratingStopProbeTimeout = 15 * time.Second

// migratingStopRefusal is the refusal of op (a stop or a delete) of vm, whose
// row says migrating and whose guest is not running on this host, its source.
// The stop records the VM stopped here, and a later start would then make a
// second copy if the guest runs on the move's target: the target is asked
// first, and op goes ahead only when it has no domain of the VM. A target
// that cannot be asked counts as having none only when it is proven powered
// off — fenced, or no longer a member, over a proof-grade fence
// (corrosion.SharedDiskOwnerProvedOff, as a live firmware move's target is
// judged, fwTargetProvedOff). Any other target refuses.
func (s *Server) migratingStopRefusal(ctx context.Context, op string, vm *corrosion.VMRecord) error {
	target := migratingToward(vm.StateDetail)
	if target == "" || target == s.hostName {
		return status.Errorf(codes.FailedPrecondition,
			"%s %q refused: its record says migrating but names no target to ask whether the guest runs there; "+
				"find where it runs (`virsh list` on each host) and record it with `lv doctor repair-owner %s <host>`",
			op, vm.Name, vm.Name)
	}
	if h, off, perr := corrosion.SharedDiskOwnerProvedOff(ctx, s.db, target); perr == nil {
		if ok, _ := corrosion.SharedDiskOwnerVerdict(target, h, off, nil); ok {
			return nil
		}
	}
	pctx, cancel := context.WithTimeout(ctx, migratingStopProbeTimeout)
	defer cancel()
	state, err := s.CheckPeerVMRuntime(pctx, target, vm.Name)
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"%s %q refused: its record says migrating to %s, and %s cannot be asked whether the guest runs there (%v); "+
				"recording it stopped here could let a later start make a second copy. Retry once %s answers. "+
				"If %s is gone for good, power it off and confirm it with `lv host fence-confirm %s` "+
				"(`lv host rm %s --dead` then removes it): once it is proven off, the %s goes ahead",
			op, vm.Name, target, target, err, target, target, target, target, op)
	}
	switch state {
	case health.RuntimeAbsent:
		return nil
	case health.RuntimeRunning:
		return status.Errorf(codes.FailedPrecondition,
			"%s %q refused: its record says migrating, and the guest runs on %s; record it there with "+
				"`lv doctor repair-owner %s %s`, then %s it if you mean to",
			op, vm.Name, target, vm.Name, target, op)
	default:
		return status.Errorf(codes.FailedPrecondition,
			"%s %q refused: its record says migrating, and %s holds a domain of it in state %s (a paused guest reads so too); "+
				"check it there (`virsh domstate %s` on %s): if the guest runs, record it with `lv doctor repair-owner %s %s`",
			op, vm.Name, target, state, vm.Name, target, vm.Name, target)
	}
}

// RaiseLeftMigrating raises vm.migration_unresolved for each VM whose row
// says migrating on this host while no move of it runs here: a daemon that
// stopped mid-move leaves it so, and nothing settles it. A live firmware
// move's VM is its own recovery's (RecoverFirmwareMoves holds its lock), and
// a VM whose lock is held has a move or another operation running. Run at
// start, after the firmware moves' recovery.
func (s *Server) RaiseLeftMigrating(ctx context.Context) {
	if s.db == nil {
		return
	}
	vms, err := corrosion.ListVMs(ctx, s.db, "", s.hostName)
	if err != nil {
		slog.Warn("vm.migration_unresolved: could not list this host's VMs", "error", err)
		return
	}
	for _, vm := range vms {
		if vm.State != "migrating" {
			continue
		}
		if _, held := s.vmLockHolderOf(vm.Name); held {
			continue
		}
		if _, ok, merr := s.fwRecords().GetMarker(vm.Name); ok || merr != nil {
			continue
		}
		target := migratingToward(vm.StateDetail)
		detail := fmt.Sprintf("%s is recorded migrating on %s, and no move of it runs there (its daemon stopped mid-move); "+
			"it may run on %s, so nothing starts or moves it: %s", vm.Name, s.hostName, target, settleMigratingAdvice(vm.Name))
		s.raiseMigrationUnresolved(ctx, vm.Name, target, "", detail)
	}
}
