package corrosion

import (
	"context"
	"fmt"
)

// InFlightResourceIDs returns the resource id ("vm:<name>", ...) of every
// operation whose reduced state is not terminal: a create, clone or restore
// that has reserved its admission and may be writing the resource's files
// before it records them.
func InFlightResourceIDs(ctx context.Context, c *Client) ([]string, error) {
	orows, err := c.Query(ctx,
		`SELECT id, resource_id, operation_kind, vm_owner_epoch FROM operations WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	if len(orows) == 0 {
		return nil, nil
	}
	srows, err := c.Query(ctx,
		`SELECT operation_id, owner_epoch, step_name FROM operation_steps WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	steps := map[string][]string{}
	for _, r := range srows {
		key := fmt.Sprintf("%s\x00%d", r.String("operation_id"), r.Int64("owner_epoch"))
		steps[key] = append(steps[key], r.String("step_name"))
	}
	var out []string
	for _, r := range orows {
		key := fmt.Sprintf("%s\x00%d", r.String("id"), r.Int64("vm_owner_epoch"))
		state, _ := ReduceOperationState(OperationKind(r.String("operation_kind")), steps[key])
		if !IsOperationTerminal(state) {
			out = append(out, r.String("resource_id"))
		}
	}
	return out, nil
}
