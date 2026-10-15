package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// operationReaperEvaluator raises the conditions about this host's operation
// reaper.
const operationReaperEvaluator = "operation-reaper"

// CondOperationUnreapable is raised by a node about itself while its last
// reaper pass could not reap one or more operations that were due
// (corrosion.ReapTerminalOperations), and resolved by the first complete pass
// with none.
const CondOperationUnreapable = "operation_unreapable"

// operationUnreapableListed caps how many operations one pass logs a warning
// for, and how many the condition's evidence names; one further line and
// `count` carry the total.
const operationUnreapableListed = 20

// operationUnreapableRemedy is the condition's remedy, carried in its evidence.
const operationUnreapableRemedy = "each listed operation is retried on every reaper pass (hourly); " +
	"its error says why its steps could not be read or its tombstone written — fix that cause; " +
	"the condition resolves on the first pass in which every due operation is reaped"

type unreapableOperation struct {
	ID    string `json:"id"`
	Error string `json:"error"`
}

// reapTerminalOperations runs one operation-reaper pass. Each operation it
// could not reap is logged once, with its id and cause, and kept in the
// operation_unreapable condition until a complete pass reaps everything due.
func (d *Daemon) reapTerminalOperations(ctx context.Context, retention time.Duration) {
	reaped, failed, err := corrosion.ReapTerminalOperations(ctx, d.db, retention)
	listedN := min(len(failed), operationUnreapableListed)
	for _, f := range failed[:listedN] {
		slog.Warn("operation reaper: could not reap an operation; it is retried on the next pass",
			"operation_id", f.OperationID, "error", f.Err)
	}
	if more := len(failed) - listedN; more > 0 {
		slog.Warn("operation reaper: could not reap more operations; see the operation_unreapable condition",
			"more", more, "total", len(failed))
	}
	if err != nil {
		slog.Warn("operation reaper", "error", err, "reaped", reaped)
	} else if reaped > 0 {
		slog.Info("operation reaper", "reaped", reaped)
	}
	// An incomplete pass proves nothing about the operations it did not reach:
	// it may raise the condition, never resolve it. When it raises it, the list
	// and `count` cover only the operations reached before the pass ended, so
	// they can undercount; the next complete pass rewrites both.
	if err != nil && len(failed) == 0 {
		return
	}
	listed := make([]unreapableOperation, 0, listedN)
	for _, f := range failed[:listedN] {
		listed = append(listed, unreapableOperation{ID: f.OperationID, Error: f.Err.Error()})
	}
	d.writeSelfConditionAs(ctx, operationReaperEvaluator, CondOperationUnreapable, len(failed) > 0,
		corrosion.SeverityWarning, map[string]any{
			"count":      len(failed),
			"operations": listed,
			"remedy":     operationUnreapableRemedy,
		})
}
