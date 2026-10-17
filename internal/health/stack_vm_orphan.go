package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A live VM whose record names a stack that was torn down while the VM
// existed. A teardown deletes the members it listed, each bound to the
// incarnation it listed; a VM of a member's name made after that listing (a
// compose up running beside the compose down, or a member re-created on
// another host) is another incarnation, and is left. Nothing deletes it: this
// condition names it and the remedy.
const (
	stackVMOrphanEvaluator = "stack_reconciler"
	stackVMOrphanCode      = "stack.vm_outlived_stack"
	stackVMOrphanKind      = "vm"
)

type stackVMOrphanEvidence struct {
	Stack          string `json:"stack"`
	Host           string `json:"host"`
	CreatedAt      string `json:"created_at"`
	StackDeletedAt string `json:"stack_deleted_at"`
	Detail         string `json:"detail"`
}

// vmOfTornDownStack is a live VM that records a tombstoned stack.
type vmOfTornDownStack struct {
	name, stack, host, createdAt, stackDeletedAt string
}

// vmsOfTornDownStacks lists the live VMs whose stack was torn down while they
// existed: created before the stack's tombstone (deleted_at has whole-second
// precision, so within the second after it too). A VM created later is a
// deploy of the same stack name in progress, which writes the stack's record
// after its VMs; it is not reported. A stack with no row at all may only not
// have replicated yet, so it is not judged.
func vmsOfTornDownStacks(ctx context.Context, db *corrosion.Client) ([]vmOfTornDownStack, error) {
	rows, err := db.Query(ctx,
		`SELECT v.name AS name, v.stack_name AS stack_name, v.host_name AS host_name,
		        COALESCE(v.created_at, '') AS created_at, s.deleted_at AS stack_deleted_at
		 FROM vms v JOIN stacks s ON s.name = v.stack_name
		 WHERE v.deleted_at IS NULL AND COALESCE(v.stack_name, '') != '' AND s.deleted_at IS NOT NULL
		 ORDER BY v.name`)
	if err != nil {
		return nil, err
	}
	var out []vmOfTornDownStack
	for _, r := range rows {
		v := vmOfTornDownStack{name: r.String("name"), stack: r.String("stack_name"), host: r.String("host_name"),
			createdAt: r.String("created_at"), stackDeletedAt: r.String("stack_deleted_at")}
		created, cerr := time.Parse(time.RFC3339Nano, v.createdAt)
		gone, gerr := time.Parse(time.RFC3339Nano, v.stackDeletedAt)
		if cerr != nil || gerr != nil || !created.Before(gone.Add(time.Second)) {
			continue
		}
		out = append(out, v)
	}
	return out, nil
}

// reportVMsOfTornDownStacks raises the condition for each such VM and
// resolves an open one whose VM is gone, records another stack, or whose
// stack was deployed again. An unchanged condition writes nothing, so every
// host running this pass costs one write per change, not per pass.
func (r *StackReconciler) reportVMsOfTornDownStacks(ctx context.Context) {
	found, err := vmsOfTornDownStacks(ctx, r.db)
	if err != nil {
		slog.Warn("stack-reconciler: list VMs of torn-down stacks", "error", err)
		return
	}
	open, err := corrosion.ListOpenHealthConditionsByCode(ctx, r.db, stackVMOrphanEvaluator, stackVMOrphanCode)
	if err != nil {
		slog.Warn("stack-reconciler: read the outlived-stack conditions", "error", err)
		return
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	still := map[string]bool{}
	for _, v := range found {
		still[v.name] = true
		row, ok, gerr := corrosion.GetHealthCondition(ctx, r.db, stackVMOrphanEvaluator, stackVMOrphanCode, stackVMOrphanKind, v.name)
		if gerr != nil {
			slog.Warn("stack-reconciler: read the outlived-stack condition", "vm", v.name, "error", gerr)
			continue
		}
		isOpen := ok && row.Lifecycle != corrosion.ConditionResolved
		if isOpen {
			var ev stackVMOrphanEvidence
			if json.Unmarshal([]byte(row.Evidence), &ev) == nil && ev.Stack == v.stack && ev.CreatedAt == v.createdAt &&
				ev.Host == v.host && ev.StackDeletedAt == v.stackDeletedAt {
				continue
			}
		}
		detail := fmt.Sprintf("VM %q (on %s, created %s) records stack %q, which was torn down at %s while the VM existed; "+
			"it was not a VM the teardown listed, so the teardown left it, and nothing else deletes it: "+
			"`lv rm %s` removes it, or deploying the stack again (`lv compose up`) makes it the stack's again",
			v.name, v.host, v.createdAt, v.stack, v.stackDeletedAt, v.name)
		slog.Warn("stack-reconciler: a VM outlived its stack's teardown", "vm", v.name, "stack", v.stack, "host", v.host)
		if !isOpen {
			row = corrosion.HealthCondition{Evaluator: stackVMOrphanEvaluator, Code: stackVMOrphanCode,
				SubjectKind: stackVMOrphanKind, SubjectID: v.name, Lifecycle: corrosion.ConditionConfirmed,
				FirstSeen: ts, ConfirmedAt: ts}
		}
		b, _ := json.Marshal(stackVMOrphanEvidence{Stack: v.stack, Host: v.host, CreatedAt: v.createdAt,
			StackDeletedAt: v.stackDeletedAt, Detail: detail})
		row.Evidence, row.Severity, row.Hosts = string(b), corrosion.SeverityWarning, []string{v.host}
		row.ObserveCount++
		row.CleanCount = 0
		row.LastSeen, row.ResolvedAt, row.Reporter = ts, "", r.hostName
		if err := corrosion.UpsertHealthCondition(ctx, r.db, row); err != nil {
			slog.Warn("stack-reconciler: raise the outlived-stack condition", "vm", v.name, "error", err)
		}
	}
	for _, row := range open {
		if row.SubjectKind != stackVMOrphanKind || still[row.SubjectID] {
			continue
		}
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, ts, ts, r.hostName
		row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
		if err := corrosion.UpsertHealthCondition(ctx, r.db, row); err != nil {
			slog.Warn("stack-reconciler: resolve the outlived-stack condition", "vm", row.SubjectID, "error", err)
		}
	}
}
