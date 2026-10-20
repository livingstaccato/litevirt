package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Firewall state of a stack that a caller without sg.write at the cluster
// root could not remove or withdraw. DeleteStack and DeployStack without it
// are allowed only where the entry node sees no firewall for the stack, and
// that node's replica may lag: a newer deploy's security groups, ip sets,
// rules or default-deny may be on this host and not on it. A teardown is
// applied here by name, so the reconciler keeps that firewall, keeps the
// stack "deleting", and raises this condition naming who can finish it. A
// deploy replaces the stack's file here; what the stack's last deploy with
// sg.write declared (corrosion.StackFirewallIntent) still stands, and the
// condition says so.
const (
	firewallHoldEvaluator = corrosion.StackFirewallHoldEvaluator
	firewallHoldCode      = corrosion.StackFirewallHoldCode
	firewallHoldKind      = corrosion.StackFirewallHoldKind
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
// owns a firewall row here, the stack's file here declares a firewall, or the
// stack's last deploy with sg.write declared one, as DeleteStack judges it; a
// file it cannot read counts as one. A failure to read is returned as err.
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
		in, found, ierr := corrosion.StackFirewallIntentOf(ctx, db, stack)
		if ierr != nil {
			return "", ierr
		}
		if found && (in.Firewall || in.DefaultDeny) {
			held = "its last deploy by a caller with sg.write at the cluster root declared a firewall"
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
// firewall rows this host still holds, and adds it to held. It reports
// whether it read everything it judges by: a pass that could not leaves
// open conditions as they are (resolveFirewallHolds).
func (r *StackReconciler) reportTornDownFirewalls(ctx context.Context, held map[string]bool) (complete bool) {
	stacks, err := corrosion.TornDownStacksOwningFirewall(ctx, r.db)
	if err != nil {
		slog.Warn("stack-reconciler: list the torn-down stacks that own firewall rows", "error", err)
		return false
	}
	for _, stack := range stacks {
		held[stack] = true
		r.raiseFirewallHold(ctx, stack, tornDownWhy)
	}
	// A stack torn down without sg.write keeps what its last deploy with it
	// declared (corrosion.StackFirewallIntent): a default-deny it asked for
	// still passes to it.
	intents, err := corrosion.StackFirewallIntents(ctx, r.db)
	if err != nil {
		slog.Warn("stack-reconciler: read the stacks' firewall intents", "error", err)
		return false
	}
	complete = true
	for name := range intents {
		if held[name] {
			continue
		}
		rec, err := r.db.Query(ctx, `SELECT deleted_at FROM stacks WHERE name = ?`, name)
		if err != nil {
			slog.Warn("stack-reconciler: read the stack of a firewall intent", "stack", name, "error", err)
			complete = false
			continue
		}
		if len(rec) == 0 || rec[0].String("deleted_at") == "" {
			continue
		}
		held[name] = true
		r.raiseFirewallHold(ctx, name, tornDownIntentWhy)
	}
	return complete
}

// tornDownIntentWhy is the why of a torn-down stack whose firewall intent
// still stands.
const tornDownIntentWhy = "the stack was torn down, and the firewall intent its last deploy by a caller with sg.write " +
	"at the cluster root recorded still stands: the firewall (and a default-deny it asked for) still counts for its name"

// withdrawnWhy is the why of a live stack whose file no longer declares the
// firewall its last deploy with sg.write declared.
const withdrawnWhy = "its stored file no longer declares the firewall its last deploy by a caller with sg.write at the " +
	"cluster root recorded: a later deploy that recorded none replaced it (one without sg.write, or one on a host " +
	"still on the previous release), or the deploy that recorded it failed after writing its firewall and before " +
	"recording its file; what the recorded deploy declared still stands"

// unreadableWhy is the why of a live stack with a firewall intent whose
// stored file this build cannot read.
const unreadableWhy = "its stored file cannot be read, so whether it still declares the firewall its last deploy by a " +
	"caller with sg.write at the cluster root declared is unknown; what that deploy declared still stands"

// reportWithdrawnFirewalls raises the condition for each live stack, not
// being deleted, whose file no longer declares what its firewall intent does
// (security groups, ip sets or a firewall block, or the default-deny), and
// adds it to held. Such a file was written by a deploy without sg.write at
// the root from a node holding an older one, or by a previous release. It
// reports whether it read everything it judges by.
func (r *StackReconciler) reportWithdrawnFirewalls(ctx context.Context, held map[string]bool) (complete bool) {
	intents, err := corrosion.StackFirewallIntents(ctx, r.db)
	if err != nil {
		slog.Warn("stack-reconciler: read the stacks' firewall intents", "error", err)
		return false
	}
	if len(intents) == 0 {
		return true
	}
	stacks, err := corrosion.ListStacks(ctx, r.db)
	if err != nil {
		slog.Warn("stack-reconciler: list stacks", "error", err)
		return false
	}
	for _, st := range stacks {
		in, ok := intents[st.Name]
		if !ok || st.State == "deleting" || held[st.Name] || (!in.Firewall && !in.DefaultDeny) {
			continue
		}
		f, perr := compose.ParseStored([]byte(st.ComposeYAML))
		if perr != nil {
			// Every check treats it as a firewall; the condition says
			// whether the file still declares the intent is unknown.
			held[st.Name] = true
			r.raiseFirewallHold(ctx, st.Name, unreadableWhy)
			continue
		}
		deny := f.FirewallDefaults != nil && f.FirewallDefaults.DefaultDeny
		if (in.Firewall && !f.DeclaresFirewall()) || (in.DefaultDeny && !deny) {
			held[st.Name] = true
			r.raiseFirewallHold(ctx, st.Name, withdrawnWhy)
		}
	}
	return true
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
	ts := time.Now().UTC().Format(time.RFC3339)
	if open {
		var ev firewallHoldEvidence
		if json.Unmarshal([]byte(row.Evidence), &ev) == nil && ev.Stack == stack && ev.Why == why {
			// Unchanged: only a host not yet named is added.
			if !slices.Contains(row.Hosts, r.hostName) {
				row.Hosts = append(row.Hosts, r.hostName)
				row.LastSeen, row.Reporter = ts, r.hostName
				if err := corrosion.UpsertHealthCondition(ctx, r.db, row); err != nil {
					slog.Warn("stack-reconciler: add a host to the held-firewall condition", "stack", stack, "error", err)
				}
			}
			return
		}
	}
	var detail string
	if why == withdrawnWhy || why == unreadableWhy {
		detail = fmt.Sprintf("stack %q keeps the firewall its last deploy with sg.write declared: %s. Withdrawing it needs sg.write at "+
			"the cluster root. An Admin deploys the file the stack should have with `lv compose up`, or tears the stack "+
			"down with `lv compose down --name %s`; `lv role grant NetworkAdmin <principal> --path / --propagate` lets "+
			"another caller do it", stack, why, stack)
	} else {
		state := "the teardown of stack %q leaves its firewall (security groups, ip sets, cluster and host rules, " +
			"the cluster default policy) in place, and the stack stays \"deleting\": %s"
		saw := ", and the node that began the teardown saw no firewall for the stack"
		switch why {
		case tornDownWhy:
			state = "stack %q is gone and its firewall rows stay in force: %s"
		case tornDownIntentWhy:
			state = "stack %q is gone and what it declared of the firewall stands: %s"
			saw = ""
		}
		detail = fmt.Sprintf(state+". Removing it needs sg.write at the cluster root"+saw+". An Admin finishes the "+
			"teardown with `lv compose down --name %s`, record or not; `lv role grant NetworkAdmin <principal> --path / "+
			"--propagate` lets another caller do it", stack, why, stack)
	}
	slog.Warn("stack-reconciler: a caller without sg.write could not remove or withdraw a stack's firewall; kept",
		"stack", stack, "why", why)
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
// not hold (held): the stack is live and its file declares what its last
// deploy with sg.write did (reportWithdrawnFirewalls), or it was torn down
// and this host holds no row of it written before the teardown
// (reportTornDownFirewalls; a default-deny it still owns is
// firewall.default_deny_orphaned's). One still "deleting" is left to the
// pass that takes it up (this one may have left it to a compose down in
// flight). The caller skips it on a pass whose reports could not read what
// they judge by: a stack such a pass did not hold may still be held.
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
		ts := time.Now().UTC().Format(time.RFC3339)
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, ts, ts, r.hostName
		row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
		if err := corrosion.UpsertHealthCondition(ctx, r.db, row); err != nil {
			slog.Warn("stack-reconciler: resolve the held-firewall condition", "stack", row.SubjectID, "error", err)
		}
	}
}
