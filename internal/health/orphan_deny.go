package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A cluster default-deny owned by a stack that was torn down, which no live
// stack asks for (corrosion.SweepOrphanStackRows). The sweep keeps it — it
// never opens the cluster on its own — and this condition says so, naming the
// stack and the command that removes it.
const (
	orphanDenyEvaluator = "stack_reconciler"
	orphanDenyCode      = "firewall.default_deny_orphaned"
	orphanDenyKind      = "cluster"
	orphanDenySubject   = "cluster"
)

type orphanDenyEvidence struct {
	Stack  string `json:"stack"`
	Detail string `json:"detail"`
}

// reportOrphanDeny raises the condition for owner, or resolves an open one
// when owner is "". An unchanged condition writes nothing, and the warning is
// logged only when the owner changes.
func (r *StackReconciler) reportOrphanDeny(ctx context.Context, owner string) {
	row, found, err := corrosion.GetHealthCondition(ctx, r.db, orphanDenyEvaluator, orphanDenyCode, orphanDenyKind, orphanDenySubject)
	if err != nil {
		slog.Warn("stack-reconciler: read the orphaned default-deny condition", "error", err)
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
			slog.Warn("stack-reconciler: resolve the orphaned default-deny condition", "error", err)
		}
		return
	}
	if open {
		var ev orphanDenyEvidence
		if json.Unmarshal([]byte(row.Evidence), &ev) == nil && ev.Stack == owner {
			return
		}
	}
	detail := fmt.Sprintf("the cluster default-deny is held by stack %q, which was torn down, and no live stack asks for it; "+
		"it stays in force: `lv firewall default-deny off` removes it, and a stack that asks for it takes it over", owner)
	slog.Warn("stack-reconciler: the cluster default-deny is owned by a torn-down stack; kept", "stack", owner, "detail", detail)
	if !open {
		row = corrosion.HealthCondition{Evaluator: orphanDenyEvaluator, Code: orphanDenyCode,
			SubjectKind: orphanDenyKind, SubjectID: orphanDenySubject, Lifecycle: corrosion.ConditionConfirmed,
			FirstSeen: ts, ConfirmedAt: ts}
	}
	b, _ := json.Marshal(orphanDenyEvidence{Stack: owner, Detail: detail})
	row.Evidence, row.Severity, row.Hosts = string(b), corrosion.SeverityWarning, []string{r.hostName}
	row.ObserveCount++
	row.CleanCount = 0
	row.LastSeen, row.ResolvedAt, row.Reporter = ts, "", r.hostName
	if err := corrosion.UpsertHealthCondition(ctx, r.db, row); err != nil {
		slog.Warn("stack-reconciler: raise the orphaned default-deny condition", "error", err)
	}
}
