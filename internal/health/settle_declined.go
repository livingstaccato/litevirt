package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Reporting a declined settle.
//
// Layer 3 stops a live local copy whose row names another host only on
// positive proof. When it has none it must say so: on the lab, a stale copy
// that an older build had defined (no incarnation stamp) ran beside its
// certified replacement while settle declined every pass and logged nothing
// about why, so the operator saw only the reconciler's "NOT destroying" line
// and owner-assert's "SPLIT-BRAIN … manual intervention required", with no
// hint of which proof was missing or what to do.
//
// A decline is therefore logged with its reason and remedy — once per kind of reason (settleReasonClass),
// and again every settleDeclineLogEvery while it lasts — and, once it has
// lasted two passes, raised as vm_settle_declined with the same content.

const (
	// settleDeclinedLogMsg is the log line a decline writes.
	settleDeclinedLogMsg = "partition-settle: declined to stop a local copy whose row names another host"
	// settleDeclineLogEvery re-logs an unchanged decline, so a long-lived one
	// stays visible in a log window without repeating every reconcile pass.
	settleDeclineLogEvery = 10 * time.Minute
	// settleDeclineSightingsToReport: consecutive declining passes before the
	// condition is raised, so a copy caught mid-move does not raise it.
	settleDeclineSightingsToReport = 2
)

// settleDecline is one live local copy Layer 3 declined to stop this pass.
type settleDecline struct {
	Name          string
	RowHost       string
	Reason        string
	Local         localCopyID
	RuntimeState  string
	RuntimeReason string
}

// settleDeclinedEvidence is vm_settle_declined's evidence. It carries no
// timestamps, so an unchanged decline rewrites nothing.
type settleDeclinedEvidence struct {
	Detail        string         `json:"detail"`
	ReasonClass   string         `json:"reason_class"`
	Reason        string         `json:"reason"`
	RowHost       string         `json:"row_host"`
	RuntimeState  string         `json:"runtime_state"`
	RuntimeReason string         `json:"runtime_reason,omitempty"`
	Local         map[string]any `json:"local"`
	Remedy        string         `json:"remedy"`
}

// settleDeclineState is what the last passes saw of one declined copy.
type settleDeclineState struct {
	reason    string // the reason CLASS last logged (settleReasonClass)
	loggedAt  time.Time
	sightings int
}

// settleDeclineTracker holds the per-copy state across passes.
type settleDeclineTracker struct {
	mu   sync.Mutex
	seen map[string]*settleDeclineState
}

// settleRemedy says what an operator can do about d.
func settleRemedy(d settleDecline, self string) string {
	var b strings.Builder
	if d.Local.Incarnation == "" {
		b.WriteString("This domain carries no incarnation stamp (an older build defined it), so settle cannot tell " +
			"which incarnation of the name it is. Its UUID is not proof: a live restore or a renamed promote gives a " +
			"new incarnation an earlier one's UUID. ")
	}
	fmt.Fprintf(&b, "Settle stops a copy only on a completed recovery-claim proof for %[2]s whose certificate verifies "+
		"here for this incarnation, while %[2]s's own runtime reports the VM running. The row naming %[2]s is NOT "+
		"proof by itself: a converged-wrong host_name looks exactly like this. Before stopping anything, confirm "+
		"which copy is current: `lv cluster claim vm/%[1]s` shows the decided claim and its destination, and "+
		"`virsh domstate %[1]s` on %[2]s shows whether it runs there. Only if the claim gave %[1]s to %[2]s and %[2]s "+
		"runs it is the copy on %[3]s a superseded duplicate; stop it on %[3]s with `virsh destroy %[1]s`. Its disks "+
		"are kept; its definition and NVRAM are removed on the next reconcile pass (the leftover cleanup undefines "+
		"a destroyed domain whose row moved). Otherwise the copy on %[3]s may be the only one: leave it running, and "+
		"owner-assert reclaims the row once every peer reports the VM absent.",
		d.Name, d.RowHost, self)
	return b.String()
}

// settleReasonClass reduces a decline reason to its KIND. The raw reason can
// carry text that changes every pass for the same cause (a gRPC error string,
// a proof id), and rate-limiting on it would re-log and rewrite the condition
// every pass; the class changes only when the cause does. The strings matched
// are settleDecide's and settleCertifiedMove's own.
func settleReasonClass(reason string) string {
	switch {
	case reason == "":
		return ""
	case strings.Contains(reason, "incarnation is unknown"):
		return "incarnation_unknown"
	case strings.Contains(reason, "owner epoch is unknown"):
		return "epoch_unknown"
	case strings.Contains(reason, "row is another incarnation"):
		return "row_other_incarnation"
	case strings.Contains(reason, "does not name another host"):
		return "row_not_elsewhere"
	case strings.HasPrefix(reason, "no certificate verifier"), strings.HasPrefix(reason, "no destination runtime check"):
		return "not_wired"
	case strings.HasPrefix(reason, "proofs unreadable"):
		return "proofs_unreadable"
	case strings.HasPrefix(reason, "destroy failed"):
		return "destroy_failed"
	case strings.HasPrefix(reason, "no verified recovery-claim certificate"):
		return "no_certificate"
	case strings.Contains(reason, "not completed: no replacement is known to run"):
		return "proof_not_completed"
	case strings.Contains(reason, "was executed by"):
		return "proof_executed_elsewhere"
	case strings.Contains(reason, "' unreachable: "), strings.Contains(reason, " unreachable: "):
		return "destination_unreachable"
	case strings.Contains(reason, " reports it "):
		return "destination_not_running"
	case strings.Contains(reason, "certificate decides another incarnation"):
		return "certificate_other_incarnation"
	case strings.Contains(reason, "older than the local copy's"):
		return "certificate_older_epoch"
	case strings.HasPrefix(reason, "proof "):
		return "certificate_invalid"
	default:
		return "other"
	}
}

// reportSettleDeclines logs and raises this pass's declines and resolves the
// conditions of copies no longer declined.
//
// keep names copies whose decline status this pass could not determine — their
// row was unreadable, the row says it is migrating, or the runtime state could
// not be read. A copy absent from declines for one of those reasons has not
// stopped being declined; resolving it would only re-raise it a pass later. So
// a kept copy's tracker entry and open condition are left exactly as they are.
func (r *Reconciler) reportSettleDeclines(ctx context.Context, declines []settleDecline, keep map[string]bool) {
	now := r.now()
	t := &r.settleDeclines
	t.mu.Lock()
	if t.seen == nil {
		t.seen = map[string]*settleDeclineState{}
	}
	declined := make(map[string]bool, len(declines))
	type raised struct {
		d       settleDecline
		class   string
		refresh bool
	}
	var raise []raised
	for _, d := range declines {
		declined[d.Name] = true
		class := settleReasonClass(d.Reason)
		st := t.seen[d.Name]
		if st == nil {
			st = &settleDeclineState{}
			t.seen[d.Name] = st
		}
		st.sightings++
		refresh := st.reason != class || now.Sub(st.loggedAt) >= settleDeclineLogEvery
		if refresh {
			st.reason, st.loggedAt = class, now
			slog.Warn(settleDeclinedLogMsg,
				"vm", d.Name, "host", r.hostName, "row_host", d.RowHost,
				"reason_class", class, "reason", d.Reason,
				"local_incarnation", d.Local.Incarnation, "local_epoch", d.Local.Epoch,
				"local_epoch_known", d.Local.EpochKnown, "evidence", d.Local.Source,
				"remedy", settleRemedy(d, r.hostName))
		}
		if st.sightings >= settleDeclineSightingsToReport {
			raise = append(raise, raised{d: d, class: class, refresh: refresh})
		}
	}
	for name := range t.seen {
		if !declined[name] && !keep[name] {
			delete(t.seen, name)
		}
	}
	t.mu.Unlock()

	existing, err := corrosion.ListHealthConditions(ctx, r.db, false)
	if err != nil {
		slog.Warn("partition-settle: cannot read health conditions; decline report deferred", "error", err)
		return
	}
	suffix := "@" + r.hostName
	open := map[string]corrosion.HealthCondition{}
	for _, c := range existing {
		if c.Evaluator == corrosion.PartitionPauseEvaluator && c.Code == corrosion.CondVMSettleDeclined &&
			strings.HasSuffix(c.SubjectID, suffix) {
			open[c.SubjectID] = c
		}
	}
	ts := now.UTC().Format(time.RFC3339)
	for _, rd := range raise {
		d := rd.d
		subject := d.Name + suffix
		row, had := open[subject]
		// Written when first raised, and then on the log's cadence: a class
		// change or the interval. The raw reason riding along may differ pass to
		// pass for the same cause, and is refreshed only then.
		if had && !rd.refresh {
			continue
		}
		local := map[string]any{"incarnation": d.Local.Incarnation, "evidence": d.Local.Source}
		if d.Local.EpochKnown {
			local["owner_epoch"] = d.Local.Epoch
		}
		b, err := json.Marshal(settleDeclinedEvidence{
			Detail: "a copy of this VM runs on " + r.hostName + " while its row names " + d.RowHost +
				", and partition settle declined to stop it",
			ReasonClass: rd.class, Reason: d.Reason, RowHost: d.RowHost,
			RuntimeState: d.RuntimeState, RuntimeReason: d.RuntimeReason,
			Local: local, Remedy: settleRemedy(d, r.hostName),
		})
		if err != nil {
			continue
		}
		if had && row.Evidence == string(b) {
			continue // unchanged
		}
		if !had {
			row = corrosion.HealthCondition{
				Evaluator: corrosion.PartitionPauseEvaluator, Code: corrosion.CondVMSettleDeclined,
				SubjectKind: "vm", SubjectID: subject, FirstSeen: ts, ConfirmedAt: ts,
			}
		}
		row.Lifecycle = corrosion.ConditionConfirmed
		row.Severity = corrosion.SeverityWarning
		row.Hosts = []string{r.hostName, d.RowHost}
		row.Evidence = string(b)
		row.ObserveCount++
		row.CleanCount = 0
		row.LastSeen = ts
		row.ResolvedAt = ""
		row.Reporter = r.hostName
		if err := corrosion.UpsertHealthCondition(ctx, r.db, row); err != nil {
			slog.Warn("partition-settle: could not record vm_settle_declined", "vm", d.Name, "error", err)
		}
	}
	for subject, row := range open {
		name := strings.TrimSuffix(subject, suffix)
		if declined[name] || keep[name] {
			continue
		}
		row.Lifecycle = corrosion.ConditionResolved
		row.ResolvedAt = ts
		row.LastSeen = ts
		row.ObserveCount = 0
		row.CleanCount = 1
		row.Reporter = r.hostName
		if err := corrosion.UpsertHealthCondition(ctx, r.db, row); err != nil {
			slog.Warn("partition-settle: could not resolve vm_settle_declined", "subject", subject, "error", err)
		}
	}
}
