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

// A stack teardown that may not remove the firewall this host holds of the
// stack. DeleteStack without sg.write at the cluster root is allowed only
// where the entry node sees no firewall for the stack, and that node's
// replica may lag: a newer deploy's security groups, ip sets, rules or
// default-deny may be on this host and not on it. Its teardown is applied
// here by name, so the reconciler keeps that firewall, keeps the stack
// "deleting", and raises this condition naming who can finish it.
const (
	firewallHoldEvaluator = "stack_reconciler"
	firewallHoldCode      = "stack.firewall_teardown_held"
	firewallHoldKind      = "stack"
)

type firewallHoldEvidence struct {
	Stack  string `json:"stack"`
	Why    string `json:"why"`
	Detail string `json:"detail"`
}

// stackFirewallHold says why the reconciler must leave the firewall of stack
// (in "deleting") in place, or "" when it may remove it: the teardown's caller
// held sg.write at the cluster root (corrosion.StackTeardownRemovesFirewall),
// or this host holds no firewall of the stack. It holds one when the stack
// owns a firewall row here or the stack's file here declares a firewall, as
// DeleteStack judges it; a file it cannot read counts as one. A failure to
// read the rows is returned as err.
func stackFirewallHold(ctx context.Context, db *corrosion.Client, stack corrosion.StackRecord) (string, error) {
	removes, notWhy := corrosion.StackTeardownRemovesFirewall(ctx, db, stack)
	if removes {
		return "", nil
	}
	held := ""
	owns, err := corrosion.StackOwnsFirewall(ctx, db, stack.Name)
	switch {
	case err != nil:
		return "", err
	case owns:
		held = "it owns firewall rows on this host"
	case stack.ComposeYAML != "":
		f, perr := compose.ParseStored([]byte(stack.ComposeYAML))
		switch {
		case perr != nil:
			held = "its stored file cannot be read, so whether it declares a firewall is unknown"
		case f.DeclaresFirewall():
			held = "its stored file declares a firewall"
		}
	}
	if held == "" {
		return "", nil
	}
	return held + ", and the teardown may not remove it: " + notWhy, nil
}

// tornDownWhy is the why of a torn-down stack whose firewall rows this host
// still holds (corrosion.TornDownStacksOwningFirewall).
const tornDownWhy = "the stack was torn down, and this host still holds security groups, ip sets, or cluster or host " +
	"rules it owns, written before the teardown"

// reportTornDownFirewalls raises the condition for each torn-down stack whose
// firewall rows this host still holds, and adds it to held.
func (r *StackReconciler) reportTornDownFirewalls(ctx context.Context, held map[string]bool) {
	stacks, err := corrosion.TornDownStacksOwningFirewall(ctx, r.db)
	if err != nil {
		slog.Warn("stack-reconciler: list the torn-down stacks that own firewall rows", "error", err)
		return
	}
	for _, stack := range stacks {
		held[stack] = true
		r.raiseFirewallHold(ctx, stack, tornDownWhy)
	}
}

// raiseFirewallHold raises the condition for stack, or leaves an open one that
// says the same. The warning is logged only when what it says changes.
func (r *StackReconciler) raiseFirewallHold(ctx context.Context, stack, why string) {
	row, found, err := corrosion.GetHealthCondition(ctx, r.db, firewallHoldEvaluator, firewallHoldCode, firewallHoldKind, stack)
	if err != nil {
		slog.Warn("stack-reconciler: read the held-firewall condition", "stack", stack, "error", err)
		return
	}
	open := found && row.Lifecycle != corrosion.ConditionResolved
	if open {
		var ev firewallHoldEvidence
		if json.Unmarshal([]byte(row.Evidence), &ev) == nil && ev.Stack == stack && ev.Why == why {
			return
		}
	}
	state := "the teardown of stack %q leaves its firewall (security groups, ip sets, cluster and host rules, " +
		"the cluster default policy) in place, and the stack stays \"deleting\": %s"
	if why == tornDownWhy {
		state = "stack %q is gone and its firewall rows stay in force: %s"
	}
	detail := fmt.Sprintf(state+". Removing it needs sg.write at the cluster root, and the node that began the "+
		"teardown saw no firewall for the stack. An Admin finishes the teardown with `lv compose down --name %s`, "+
		"record or not; `lv role grant NetworkAdmin <principal> --path / --propagate` lets another caller do it",
		stack, why, stack)
	slog.Warn("stack-reconciler: a stack teardown may not remove the firewall this host holds of it; kept",
		"stack", stack, "why", why)
	ts := time.Now().UTC().Format(time.RFC3339)
	if !open {
		row = corrosion.HealthCondition{Evaluator: firewallHoldEvaluator, Code: firewallHoldCode,
			SubjectKind: firewallHoldKind, SubjectID: stack, Lifecycle: corrosion.ConditionConfirmed,
			FirstSeen: ts, ConfirmedAt: ts}
	}
	b, _ := json.Marshal(firewallHoldEvidence{Stack: stack, Why: why, Detail: detail})
	row.Evidence, row.Severity, row.Hosts = string(b), corrosion.SeverityWarning, []string{r.hostName}
	row.ObserveCount++
	row.CleanCount = 0
	row.LastSeen, row.ResolvedAt, row.Reporter = ts, "", r.hostName
	if err := corrosion.UpsertHealthCondition(ctx, r.db, row); err != nil {
		slog.Warn("stack-reconciler: raise the held-firewall condition", "stack", stack, "error", err)
	}
}

// resolveFirewallHolds resolves an open condition whose stack this pass did
// not hold (held) once nothing is left to finish: the stack was deployed
// again, or it was torn down and owns no firewall row here. One still
// "deleting" is left to the pass that takes it up (this one may have left it
// to a compose down in flight), and one torn down while it still owns
// firewall rows stays open: those rows outlived the stack
// (reportTornDownFirewalls raises it on the host that holds them).
func (r *StackReconciler) resolveFirewallHolds(ctx context.Context, held map[string]bool) {
	open, err := corrosion.ListOpenHealthConditionsByCode(ctx, r.db, firewallHoldEvaluator, firewallHoldCode)
	if err != nil {
		slog.Warn("stack-reconciler: read the held-firewall conditions", "error", err)
		return
	}
	for _, row := range open {
		if row.SubjectKind != firewallHoldKind || held[row.SubjectID] {
			continue
		}
		rec, err := r.db.Query(ctx, `SELECT state, deleted_at FROM stacks WHERE name = ?`, row.SubjectID)
		if err != nil || len(rec) == 0 {
			continue // unknown here, or not replicated yet: not judged
		}
		gone := rec[0].String("deleted_at") != ""
		if !gone && rec[0].String("state") == "deleting" {
			continue
		}
		if gone {
			owns, oerr := corrosion.StackOwnsFirewall(ctx, r.db, row.SubjectID)
			if oerr != nil || owns {
				continue
			}
		}
		ts := time.Now().UTC().Format(time.RFC3339)
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, ts, ts, r.hostName
		row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
		if err := corrosion.UpsertHealthCondition(ctx, r.db, row); err != nil {
			slog.Warn("stack-reconciler: resolve the held-firewall condition", "stack", row.SubjectID, "error", err)
		}
	}
}
