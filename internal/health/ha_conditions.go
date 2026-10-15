package health

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// HACondition is one of the HA policy's health conditions about one host
// (corrosion.HADisarmEvaluator): ha_disarmed, ha_policy_unreadable or
// ha_disarm_peer_veto. Each row is written by the host it is about, which
// keeps one writer per row; Sync writes only when what it says changes.
type HACondition struct {
	DB       *corrosion.Client
	Host     string
	Code     string
	Severity string
	// Now is the clock (nil: time.Now).
	Now func() time.Time

	open, synced bool
	evidence     string
}

// Sync opens the condition with evidence, or resolves it when open is false.
// It reports whether the row now says so. A condition a previous process left
// open is resolved on the first Sync that finds nothing to report.
func (h *HACondition) Sync(ctx context.Context, open bool, evidence string) bool {
	if h.synced && h.open == open && (!open || h.evidence == evidence) {
		return true
	}
	now := time.Now
	if h.Now != nil {
		now = h.Now
	}
	ts := now().UTC().Format(time.RFC3339)
	row, ok, err := corrosion.GetHealthCondition(ctx, h.DB, corrosion.HADisarmEvaluator, h.Code, "host", h.Host)
	if err != nil {
		return false
	}
	switch {
	case !open && (!ok || row.Lifecycle == corrosion.ConditionResolved):
		h.open, h.synced, h.evidence = false, true, ""
		return true
	case !ok:
		row = corrosion.HealthCondition{Evaluator: corrosion.HADisarmEvaluator, Code: h.Code,
			SubjectKind: "host", SubjectID: h.Host, FirstSeen: ts}
	}
	if open {
		if row.Lifecycle == corrosion.ConditionResolved {
			row.FirstSeen, row.ConfirmedAt, row.ObserveCount = ts, "", 0
		}
		row.Lifecycle, row.ResolvedAt, row.CleanCount = corrosion.ConditionConfirmed, "", 0
		if row.ConfirmedAt == "" {
			row.ConfirmedAt = ts
		}
		row.ObserveCount++
		row.Evidence = evidence
	} else {
		row.Lifecycle, row.ResolvedAt, row.ObserveCount, row.CleanCount = corrosion.ConditionResolved, ts, 0, 1
	}
	row.Severity, row.Hosts, row.LastSeen, row.Reporter = h.Severity, []string{h.Host}, ts, h.Host
	if err := corrosion.UpsertHealthCondition(ctx, h.DB, row); err != nil {
		slog.Warn("ha-disarm: could not record a condition (retried on the next pass)", "code", h.Code, "error", err)
		return false
	}
	h.open, h.synced, h.evidence = open, true, evidence
	return true
}
