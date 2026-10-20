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
	s.setConditionOf(ctx, drainEvaluator, condMigrationUnresolved, "vm", vm,
		[]string{s.hostName, target}, true, corrosion.SeverityCritical, string(ev))
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

// inFlightMoveRefusal refuses op, a start of vm on this host, while vm's row
// says migrating: a move of it is in flight, or ended leaving the row so, and
// the guest may run on the move's target. A start here would make a second
// copy. Restart recovery does not start through here.
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
	return status.Errorf(codes.FailedPrecondition,
		"%s %q refused: its record says migrating, as %s, and the guest may run on %s; nothing is started here. "+
			"Once no move of it runs, %s",
		op, vm.Name, why, target, settleMigratingAdvice(vm.Name))
}

// migratingStopProbeTimeout bounds the ask of a migrating VM's target
// whether the guest runs there (migratingStopRefusal).
const migratingStopProbeTimeout = 15 * time.Second

// migratingStopRefusal is the refusal of a stop of vm, whose row says
// migrating, on its source. The stop records the VM stopped here, and a later
// start would then make a second copy if the guest runs on the move's target:
// the target is asked first, and the stop goes ahead only when it has no
// domain of the VM. One the target cannot be asked about is refused.
func (s *Server) migratingStopRefusal(ctx context.Context, vm *corrosion.VMRecord) error {
	target := migratingToward(vm.StateDetail)
	if target == "" || target == s.hostName {
		return status.Errorf(codes.FailedPrecondition,
			"stop %q refused: its record says migrating but names no target to ask whether the guest runs there; "+
				"find where it runs (`virsh list` on each host) and record it with `lv doctor repair-owner %s <host>`",
			vm.Name, vm.Name)
	}
	pctx, cancel := context.WithTimeout(ctx, migratingStopProbeTimeout)
	defer cancel()
	state, err := s.CheckPeerVMRuntime(pctx, target, vm.Name)
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"stop %q refused: its record says migrating to %s, and %s cannot be asked whether the guest runs there (%v); "+
				"recording it stopped here could let a later start make a second copy. Retry once %s answers",
			vm.Name, target, target, err, target)
	}
	switch state {
	case health.RuntimeAbsent:
		return nil
	case health.RuntimeRunning:
		return status.Errorf(codes.FailedPrecondition,
			"stop %q refused: its record says migrating, and the guest runs on %s; record it there with "+
				"`lv doctor repair-owner %s %s`, then stop it if you mean to",
			vm.Name, target, vm.Name, target)
	default:
		return status.Errorf(codes.FailedPrecondition,
			"stop %q refused: its record says migrating, and %s holds a domain of it in state %s (a paused guest reads so too); "+
				"check it there (`virsh domstate %s` on %s): if the guest runs, record it with `lv doctor repair-owner %s %s`",
			vm.Name, target, state, vm.Name, target, vm.Name, target)
	}
}
