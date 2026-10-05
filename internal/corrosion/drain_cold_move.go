package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
)

// The operation journal of host drain's cold move of a RUNNING VM
// (OpDrainColdMove). The drain shuts the VM down, moves it with its disks and
// starts it again; a daemon that dies in between would leave the VM off with
// an operator-stop row, which nothing restarts. The journal records, before
// anything is done to the VM, that it was running and must run again, and a
// restarted daemon finishes the move from it (grpcapi ResumeDrainColdMoves).
//
// It is written with the journal's existing statements (operations header,
// operation_steps) and no reservation, so the capacity and quota aggregates,
// which read only headers with a reservation, never count it.

// drainColdMoveMethod names the operation in its deterministic id.
const drainColdMoveMethod = "DrainHost"

// DrainColdMove is one journaled drain cold move.
type DrainColdMove struct {
	OperationID string
	OwnerEpoch  int64 // the header's: every step is keyed by it
	VM          string
	Source      string
	Target      string
	// ShutdownRequested: the "stopped" step is recorded — the VM's shutdown
	// was requested, and the guest may still be completing it.
	ShutdownRequested bool
}

type drainColdMoveFacts struct {
	VM     string `json:"vm"`
	Source string `json:"source"`
	Target string `json:"target"`
}

// BeginDrainColdMove journals a cold move of the running VM vm from source to
// target as planned. attempt makes each drain attempt its own operation.
func BeginDrainColdMove(ctx context.Context, c *Client, vm VMRecord, source, target, attempt string) (DrainColdMove, error) {
	m := DrainColdMove{VM: vm.Name, Source: source, Target: target, OwnerEpoch: vm.OwnerEpoch}
	if vm.Name == "" || source == "" || target == "" || attempt == "" {
		return m, fmt.Errorf("corrosion: incomplete drain cold move")
	}
	facts, err := json.Marshal(drainColdMoveFacts{VM: vm.Name, Source: source, Target: target})
	if err != nil {
		return m, err
	}
	m.OperationID = DeterministicOperationID(drainColdMoveMethod, source, vm.Project, vm.Name, attempt)
	op := OperationRecord{
		ID: m.OperationID, Method: drainColdMoveMethod, Principal: source, Project: vm.Project,
		ResourceKind: "vm", ResourceID: vm.Name, OperationKind: string(OpDrainColdMove),
		RequestHash:    hashIdentity(string(facts)),
		IdempotencyKey: attempt, DesiredRef: target, VMOwnerEpoch: vm.OwnerEpoch,
	}
	if _, _, err := ClaimOrFindOperation(ctx, c, op); err != nil {
		return m, err
	}
	return m, AppendOperationStep(ctx, c, OperationStepRecord{
		OperationID: m.OperationID, OwnerEpoch: m.OwnerEpoch, StepName: OpStepPlanned, Facts: string(facts),
	})
}

// MarkDrainColdMoveShutdownRequested records that the VM's shutdown has been
// requested.
func MarkDrainColdMoveShutdownRequested(ctx context.Context, c *Client, m DrainColdMove) error {
	return AppendOperationStep(ctx, c, OperationStepRecord{
		OperationID: m.OperationID, OwnerEpoch: m.OwnerEpoch, StepName: OpStepStopped,
	})
}

// FinishDrainColdMove records the move as completed; outcome says how it
// ended, for an operator reading the journal.
func FinishDrainColdMove(ctx context.Context, c *Client, m DrainColdMove, outcome string) error {
	return AppendOperationStep(ctx, c, OperationStepRecord{
		OperationID: m.OperationID, OwnerEpoch: m.OwnerEpoch, StepName: OpStepCompleted, Facts: outcome,
	})
}

// ListDrainColdMoves returns every drain cold move journaled by source that
// has not completed — the work a restarted daemon on source has to finish.
func ListDrainColdMoves(ctx context.Context, c *Client, source string) ([]DrainColdMove, error) {
	rows, err := c.Query(ctx,
		`SELECT `+operationCols+` FROM operations
		 WHERE operation_kind = ? AND principal = ? AND deleted_at IS NULL ORDER BY created_at`,
		string(OpDrainColdMove), source)
	if err != nil {
		return nil, err
	}
	var out []DrainColdMove
	for _, r := range rows {
		op := scanOperation(r)
		steps, sErr := ListOperationSteps(ctx, c, op.ID, op.VMOwnerEpoch)
		if sErr != nil {
			return nil, sErr
		}
		names := make([]string, 0, len(steps))
		m := DrainColdMove{OperationID: op.ID, OwnerEpoch: op.VMOwnerEpoch, VM: op.ResourceID, Source: op.Principal, Target: op.DesiredRef}
		for _, st := range steps {
			names = append(names, st.StepName)
			if st.StepName == OpStepStopped {
				m.ShutdownRequested = true
			}
		}
		state, _ := ReduceOperationState(OpDrainColdMove, names)
		if state == "" || IsOperationTerminal(state) {
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

// FailDrainColdMove records the move as failed: its recovery gave up, and a
// later restart must not take it up again. reason says why.
func FailDrainColdMove(ctx context.Context, c *Client, m DrainColdMove, reason string) error {
	return AppendOperationStep(ctx, c, OperationStepRecord{
		OperationID: m.OperationID, OwnerEpoch: m.OwnerEpoch, StepName: OpStepFailed, Facts: reason,
	})
}
