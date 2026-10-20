package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A cluster default-deny owned by a live stack that nothing asks for any
// more (corrosion.UnaskedStackDeny): neither the stack's file nor the intent
// its last deploy with sg.write recorded, nor any other stack. No reconciler
// pass withdraws a deny on its own: a removal decided on one replica's view
// can outrank a newer ask it has not seen and open the cluster. It stays,
// and this condition names the stack and the commands that settle it.
const (
	unaskedDenyEvaluator = "stack_reconciler"
	unaskedDenyCode      = "stack.firewall_deny_unasked"
	unaskedDenyKind      = "cluster"
	unaskedDenySubject   = "cluster"
)

type unaskedDenyEvidence struct {
	Stack  string `json:"stack"`
	Detail string `json:"detail"`
}

// reportUnaskedDeny raises the condition for the live stack owning a deny
// nothing asks for, or resolves an open one when there is none. A failed read
// changes nothing.
func (r *StackReconciler) reportUnaskedDeny(ctx context.Context) {
	owner, err := corrosion.UnaskedStackDeny(ctx, r.db, compose.StoredStackWants)
	if err != nil {
		slog.Warn("stack-reconciler: judge whether the cluster default-deny is asked for", "error", err)
		return
	}
	row, found, err := corrosion.GetHealthCondition(ctx, r.db, unaskedDenyEvaluator, unaskedDenyCode, unaskedDenyKind, unaskedDenySubject)
	if err != nil {
		slog.Warn("stack-reconciler: read the unasked default-deny condition", "error", err)
		return
	}
	open := found && row.Lifecycle != corrosion.ConditionResolved
	ts := time.Now().UTC().Format(time.RFC3339)
	if owner == "" {
		if !open {
			return
		}
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, ts, ts, r.hostName
		row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
		if err := corrosion.UpsertHealthCondition(ctx, r.db, row); err != nil {
			slog.Warn("stack-reconciler: resolve the unasked default-deny condition", "error", err)
		}
		return
	}
	if open {
		var ev unaskedDenyEvidence
		if json.Unmarshal([]byte(row.Evidence), &ev) == nil && ev.Stack == owner {
			return
		}
	}
	detail := fmt.Sprintf("the cluster default-deny is held by stack %q, and neither its file, nor the intent its last deploy "+
		"with sg.write at the cluster root recorded, nor any other stack asks for it; it stays in force. An Admin turns it "+
		"off with `lv firewall default-deny off`, or keeps it as an operator's with `lv firewall default-deny on`; "+
		"a stack that asks for it takes it over", owner)
	slog.Warn("stack-reconciler: the cluster default-deny is asked for by nothing; kept", "stack", owner)
	if !open {
		row = corrosion.HealthCondition{Evaluator: unaskedDenyEvaluator, Code: unaskedDenyCode,
			SubjectKind: unaskedDenyKind, SubjectID: unaskedDenySubject, Lifecycle: corrosion.ConditionConfirmed,
			FirstSeen: ts, ConfirmedAt: ts}
	}
	b, _ := json.Marshal(unaskedDenyEvidence{Stack: owner, Detail: detail})
	row.Evidence, row.Severity, row.Hosts = string(b), corrosion.SeverityWarning, []string{r.hostName}
	row.ObserveCount++
	row.CleanCount = 0
	row.LastSeen, row.ResolvedAt, row.Reporter = ts, "", r.hostName
	if err := corrosion.UpsertHealthCondition(ctx, r.db, row); err != nil {
		slog.Warn("stack-reconciler: raise the unasked default-deny condition", "error", err)
	}
}
