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
// A decline is therefore logged with its reason and remedy — once per reason,
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
	Reason        string         `json:"reason"`
	RowHost       string         `json:"row_host"`
	RuntimeState  string         `json:"runtime_state"`
	RuntimeReason string         `json:"runtime_reason,omitempty"`
	Local         map[string]any `json:"local"`
	Remedy        string         `json:"remedy"`
}

// settleDeclineState is what the last passes saw of one declined copy.
type settleDeclineState struct {
	reason    string
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
		"here for this incarnation, while %[2]s's own runtime reports the VM running. Check %[2]s: if it runs %[1]s, "+
		"the copy on %[3]s is a superseded duplicate; stop it there with `virsh destroy %[1]s` (definition and disks "+
		"are kept, and the leftover cleanup undefines it on a later pass). If %[2]s does not run it, the copy on %[3]s "+
		"may be the only one: leave it running, and owner-assert reclaims the row once every peer reports the VM absent.",
		d.Name, d.RowHost, self)
	return b.String()
}

// reportSettleDeclines logs and raises this pass's declines and resolves the
// conditions of copies no longer declined. incomplete says the pass could not
// read every row, so an absence proves nothing and nothing is resolved.
func (r *Reconciler) reportSettleDeclines(ctx context.Context, declines []settleDecline, incomplete bool) {
	now := r.now()
	t := &r.settleDeclines
	t.mu.Lock()
	if t.seen == nil {
		t.seen = map[string]*settleDeclineState{}
	}
	declined := make(map[string]bool, len(declines))
	var raise []settleDecline
	for _, d := range declines {
		declined[d.Name] = true
		st := t.seen[d.Name]
		if st == nil {
			st = &settleDeclineState{}
			t.seen[d.Name] = st
		}
		st.sightings++
		if st.reason != d.Reason || now.Sub(st.loggedAt) >= settleDeclineLogEvery {
			st.reason, st.loggedAt = d.Reason, now
			slog.Warn(settleDeclinedLogMsg,
				"vm", d.Name, "host", r.hostName, "row_host", d.RowHost, "reason", d.Reason,
				"local_incarnation", d.Local.Incarnation, "local_epoch", d.Local.Epoch,
				"local_epoch_known", d.Local.EpochKnown, "evidence", d.Local.Source,
				"remedy", settleRemedy(d, r.hostName))
		}
		if st.sightings >= settleDeclineSightingsToReport {
			raise = append(raise, d)
		}
	}
	if !incomplete {
		for name := range t.seen {
			if !declined[name] {
				delete(t.seen, name)
			}
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
	for _, d := range raise {
		local := map[string]any{"incarnation": d.Local.Incarnation, "evidence": d.Local.Source}
		if d.Local.EpochKnown {
			local["owner_epoch"] = d.Local.Epoch
		}
		b, err := json.Marshal(settleDeclinedEvidence{
			Detail: "a copy of this VM runs on " + r.hostName + " while its row names " + d.RowHost +
				", and partition settle declined to stop it",
			Reason: d.Reason, RowHost: d.RowHost, RuntimeState: d.RuntimeState, RuntimeReason: d.RuntimeReason,
			Local: local, Remedy: settleRemedy(d, r.hostName),
		})
		if err != nil {
			continue
		}
		subject := d.Name + suffix
		row, had := open[subject]
		if had && row.Evidence == string(b) {
			continue // unchanged: write on transitions only
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
	if incomplete {
		return
	}
	for subject, row := range open {
		if declined[strings.TrimSuffix(subject, suffix)] {
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
