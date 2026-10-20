package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
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
}

// raiseMigrationUnresolved raises vm.migration_unresolved for vm, left
// migrating on this host by a move to target.
func (s *Server) raiseMigrationUnresolved(ctx context.Context, vm, target, detail string) {
	ev, _ := json.Marshal(migrationUnresolvedEvidence{Source: s.hostName, Target: target, Detail: detail})
	s.setConditionOf(ctx, drainEvaluator, condMigrationUnresolved, "vm", vm,
		[]string{s.hostName, target}, true, corrosion.SeverityCritical, string(ev))
}

// resolveMigrationUnresolved resolves vm's vm.migration_unresolved, once its
// row is settled.
func (s *Server) resolveMigrationUnresolved(ctx context.Context, vm string) {
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
