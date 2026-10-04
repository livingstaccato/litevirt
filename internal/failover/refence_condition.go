package failover

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// refence_failed (docs/diagnostics.md): a re-fence of a host whose verified
// fence was aged or in doubt failed (refence), so its recovery is held for an
// operator. Written by the lease holder; a successor reads it back from the
// replica, so it outlives a lease hand-off.
const (
	RefenceEvaluator  = "failover"
	CondRefenceFailed = "refence_failed"
)

type refenceEvidence struct {
	Detail      string `json:"detail"`
	FenceID     string `json:"fence_id"`
	Method      string `json:"method"`
	FenceDetail string `json:"fence_detail,omitempty"`
}

// noteRefenceFailed raises refence_failed for host: the re-fence of its
// recorded fence rec failed with fr.
func (c *Coordinator) noteRefenceFailed(ctx context.Context, host string, rec fenceRecord, fr fence.Result) {
	ts := c.now().UTC().Format(time.RFC3339)
	row, ok, err := corrosion.GetHealthCondition(ctx, c.db, RefenceEvaluator, CondRefenceFailed, "host", host)
	if err != nil {
		slog.Warn("failover: could not read refence_failed", "host", host, "error", err)
		return
	}
	if !ok || row.Lifecycle == corrosion.ConditionResolved {
		row = corrosion.HealthCondition{Evaluator: RefenceEvaluator, Code: CondRefenceFailed,
			SubjectKind: "host", SubjectID: host, FirstSeen: ts, ConfirmedAt: ts}
	}
	b, _ := json.Marshal(refenceEvidence{
		Detail: fmt.Sprintf("the re-fence of %s, whose verified fence %s was aged or in doubt, failed; its workloads "+
			"stay where they are. Confirm %s is powered off, then run `lv host fence-confirm %s`: the recovery resumes from it",
			host, rec.ID, host, host),
		FenceID: rec.ID, Method: fr.Method, FenceDetail: fr.Detail})
	row.Lifecycle, row.ResolvedAt, row.CleanCount = corrosion.ConditionConfirmed, "", 0
	row.ObserveCount++
	row.Evidence = string(b)
	row.Severity, row.Hosts, row.LastSeen, row.Reporter = corrosion.SeverityCritical, []string{host}, ts, c.hostName
	if err := corrosion.UpsertHealthCondition(ctx, c.db, row); err != nil {
		slog.Warn("failover: could not record refence_failed", "host", host, "error", err)
	}
}

// resolveRefenceSettled resolves each raised refence_failed whose host no
// longer needs an operator: removed, back in service ('active'), or fenced
// successfully or confirmed off by an operator after the failed attempt.
func (c *Coordinator) resolveRefenceSettled(ctx context.Context) {
	rows, err := c.db.Query(ctx, `SELECT subject_id FROM health_conditions
		WHERE evaluator = ? AND code = ? AND subject_kind = 'host' AND lifecycle != ? AND deleted_at IS NULL`,
		RefenceEvaluator, CondRefenceFailed, corrosion.ConditionResolved)
	if err != nil {
		return
	}
	for _, r := range rows {
		host := r.String("subject_id")
		if why, settled := c.refenceSettled(ctx, host); settled {
			c.resolveRefence(ctx, host, why)
		}
	}
}

// refenceSettled reports whether host's failed re-fence is behind it.
func (c *Coordinator) refenceSettled(ctx context.Context, host string) (string, bool) {
	h, err := corrosion.GetHost(ctx, c.db, host)
	if err != nil {
		return "", false
	}
	if h == nil {
		return "removed", true
	}
	if h.State == "active" {
		return "back in service", true
	}
	rows, err := c.db.Query(ctx, `SELECT result, timestamp FROM fencing_log WHERE host_name = ?`, host)
	if err != nil {
		return "", false
	}
	var failed, ok time.Time
	for _, r := range rows {
		ts, perr := time.Parse(time.RFC3339, r.String("timestamp"))
		if perr != nil {
			continue
		}
		switch r.String("result") {
		case "partial":
			if ts.After(failed) {
				failed = ts
			}
		case "fenced", "manual-confirmed":
			if ts.After(ok) {
				ok = ts
			}
		}
	}
	if !ok.IsZero() && ok.After(failed) {
		return "fenced or confirmed off since", true
	}
	return "", false
}

func (c *Coordinator) resolveRefence(ctx context.Context, host, why string) {
	row, ok, err := corrosion.GetHealthCondition(ctx, c.db, RefenceEvaluator, CondRefenceFailed, "host", host)
	if err != nil || !ok || row.Lifecycle == corrosion.ConditionResolved {
		return
	}
	ts := c.now().UTC().Format(time.RFC3339)
	row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, ts, ts, c.hostName
	row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
	if err := corrosion.UpsertHealthCondition(ctx, c.db, row); err != nil {
		slog.Warn("failover: could not resolve refence_failed", "host", host, "error", err)
		return
	}
	slog.Info("failover: refence_failed resolved", "host", host, "reason", why)
}
