package corrosion

import (
	"context"
	"encoding/json"
)

// vm.migration_unresolved's identity and evidence, read by the server that
// raises and resolves it (grpcapi, migration_unresolved.go) and by the
// reconciler of the move's target, which holds the copy the move left there
// while it is open (health, unresolved_move_hold.go).
const (
	// DrainEvaluator is the evaluator of the drain's conditions, this one
	// among them.
	DrainEvaluator          = "drain"
	CondMigrationUnresolved = "vm.migration_unresolved"
)

// MigrationUnresolvedEvidence is vm.migration_unresolved's evidence: the VM
// was left migrating on Source by a move to Target.
type MigrationUnresolvedEvidence struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Detail string `json:"detail"`
	// LeaseID is the target's capacity reservation the move kept, released
	// when the condition is resolved.
	LeaseID string `json:"lease_id,omitempty"`
}

// OpenMigrationUnresolved reads vm's vm.migration_unresolved: its evidence
// and whether it is open. Evidence that does not parse reads as an open
// condition naming no host.
func OpenMigrationUnresolved(ctx context.Context, c *Client, vm string) (MigrationUnresolvedEvidence, bool, error) {
	row, ok, err := GetHealthCondition(ctx, c, DrainEvaluator, CondMigrationUnresolved, "vm", vm)
	if err != nil || !ok || row.Lifecycle == ConditionResolved {
		return MigrationUnresolvedEvidence{}, false, err
	}
	var ev MigrationUnresolvedEvidence
	_ = json.Unmarshal([]byte(row.Evidence), &ev)
	return ev, true, nil
}
