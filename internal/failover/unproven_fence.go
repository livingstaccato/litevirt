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

// ha.recovery.unproven_fence (docs/diagnostics.md): a host's recoverable
// workloads are held, not recovered, because the fence that ran is not proof
// the host is off, and only an operator's confirmation (or a later fence that
// is proof) lets the recovery go ahead. It is raised for the holds a host's
// own fence choice makes:
//
//   - an SSH power-off the remote shell confirmed, on a host that does not
//     trust one (holdUntrustedSSH);
//   - a best-effort fence that proves nothing: under the safe-fence policy,
//     after a held fence (ha.fence_held), or when the host's partition pause
//     is not relied on.
//
// Before it, such a hold showed only in the coordinator's log, the
// host.recovery.stalled notification and `lv doctor fence`, never in
// `lv health` (the rc9 lab's F3).
//
// Visibility only: nothing reads it to decide anything. Written by the lease
// holder; it resolves when the recovery goes ahead (recoverFenced past its
// gates, or resumeFromConfirmation), and a successor resolves it from the
// replica once the host is removed, back in service, or has no recoverable
// workload left (resolveUnprovenSettled).
const CondRecoveryUnprovenFence = "ha.recovery.unproven_fence"

type unprovenFenceEvidence struct {
	Detail    string   `json:"detail"`
	Workloads []string `json:"workloads"`
	Remedy    string   `json:"remedy"`
}

// holdUnproven holds h's recovery on hold, a fence that is not proof h is
// off, with stale appended (noteGateHold), and raises
// ha.recovery.unproven_fence for it. why is the reason without its way out,
// for the condition's detail; sshConfirmed says the fence was an SSH power-off
// the remote shell confirmed, which the trust opt-in would have counted.
func (c *Coordinator) holdUnproven(ctx context.Context, h *corrosion.HostRecord, hold, why, stale string, sshConfirmed bool) {
	c.noteGateHold(h.Name, hold, stale)
	c.raiseUnproven(ctx, h, why, stale, sshConfirmed)
}

// raiseUnproven writes ha.recovery.unproven_fence for h. A host with no
// recoverable workload on it holds nothing back, and raises nothing. The row
// is not rewritten while it says the same: a hold can last days.
func (c *Coordinator) raiseUnproven(ctx context.Context, h *corrosion.HostRecord, why, stale string, sshConfirmed bool) {
	workloads, err := c.recoverableOn(ctx, h.Name)
	if err != nil || len(workloads) == 0 {
		return
	}
	row, ok, err := corrosion.GetHealthCondition(ctx, c.db, RefenceEvaluator, CondRecoveryUnprovenFence, "host", h.Name)
	if err != nil {
		slog.Warn("failover: could not read "+CondRecoveryUnprovenFence, "host", h.Name, "error", err)
		return
	}
	ts := c.now().UTC().Format(time.RFC3339)
	fresh := !ok || row.Lifecycle == corrosion.ConditionResolved
	if fresh {
		row = corrosion.HealthCondition{Evaluator: RefenceEvaluator, Code: CondRecoveryUnprovenFence,
			SubjectKind: "host", SubjectID: h.Name, FirstSeen: ts, ConfirmedAt: ts}
	}
	detail := fmt.Sprintf("the recovery of %s is held: %s. Its workloads are not started elsewhere until %s is proven off, "+
		"so nothing runs twice", h.Name, why, h.Name)
	if stale != "" {
		detail += "; " + stale
	}
	b, _ := json.Marshal(unprovenFenceEvidence{Detail: detail, Workloads: capList(workloads),
		Remedy: unprovenRemedy(h, sshConfirmed)})
	if !fresh && row.Evidence == string(b) && row.Severity == corrosion.SeverityCritical {
		return
	}
	row.Lifecycle, row.ResolvedAt, row.CleanCount = corrosion.ConditionConfirmed, "", 0
	row.ObserveCount++
	row.Evidence = string(b)
	row.Severity, row.Hosts, row.LastSeen, row.Reporter = corrosion.SeverityCritical, []string{h.Name}, ts, c.hostName
	if err := corrosion.UpsertHealthCondition(ctx, c.db, row); err != nil {
		slog.Warn("failover: could not record "+CondRecoveryUnprovenFence, "host", h.Name, "error", err)
	}
}

// unprovenRemedy is the way out of h's hold: the operator's confirmation,
// which the recovery resumes from; for a host whose fence does not go through
// a BMC, a fence strategy that proves a power-off next time; and, for a
// confirmed SSH power-off on a host that does not trust one, the trust
// opt-in, as the operator's choice it is. The opt-in does not reach back: a
// fence already judged not proof stays held until the confirmation.
func unprovenRemedy(h *corrosion.HostRecord, sshConfirmed bool) string {
	out := fmt.Sprintf("once %s is powered off, `lv host fence-confirm %s`, and the recovery resumes from it", h.Name, h.Name)
	switch fence.ResolveStrategy(h.FenceStrategy) {
	case "ipmi", "redfish":
	default:
		out += fmt.Sprintf(". To recover at once next time, give it a fence that proves a power-off: "+
			"`lv host config %s --fence-strategy ipmi|redfish`", h.Name)
	}
	if sshConfirmed && !trustsSSHPoweroff(h) {
		out += fmt.Sprintf(". An operator who accepts the risk that a host ignores or does not finish a confirmed SSH "+
			"power-off may instead set `lv host config %s --trust-ssh-poweroff` (not a recommendation): it counts a later "+
			"fence's confirmed power-off, not this one, which still needs `lv host fence-confirm %s`", h.Name, h.Name)
	}
	return out
}

// resolveUnproven resolves host's ha.recovery.unproven_fence, when raised.
func (c *Coordinator) resolveUnproven(ctx context.Context, host, why string) {
	row, ok, err := corrosion.GetHealthCondition(ctx, c.db, RefenceEvaluator, CondRecoveryUnprovenFence, "host", host)
	if err != nil || !ok || row.Lifecycle == corrosion.ConditionResolved {
		return
	}
	ts := c.now().UTC().Format(time.RFC3339)
	row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, ts, ts, c.hostName
	row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
	if err := corrosion.UpsertHealthCondition(ctx, c.db, row); err != nil {
		slog.Warn("failover: could not resolve "+CondRecoveryUnprovenFence, "host", host, "error", err)
		return
	}
	slog.Info("failover: "+CondRecoveryUnprovenFence+" resolved", "host", host, "reason", why)
}

// resolveUnprovenSettled resolves each raised ha.recovery.unproven_fence
// whose host no longer holds anything back on its fence: removed, or with no
// recoverable workload left on it. pending is strandedByHost's count, per
// host, which counts only a fenced or offline host, so a host back in service
// (or in maintenance) settles too. Run by the lease holder once per cycle, so
// a successor that never re-judges the fence still resolves what its
// predecessor raised.
func (c *Coordinator) resolveUnprovenSettled(ctx context.Context, pending map[string]int) {
	rows, err := c.db.Query(ctx, `SELECT subject_id FROM health_conditions
		WHERE evaluator = ? AND code = ? AND subject_kind = 'host' AND lifecycle != ? AND deleted_at IS NULL`,
		RefenceEvaluator, CondRecoveryUnprovenFence, corrosion.ConditionResolved)
	if err != nil {
		return
	}
	for _, r := range rows {
		host := r.String("subject_id")
		h, err := corrosion.GetHost(ctx, c.db, host)
		if err != nil {
			continue
		}
		switch {
		case h == nil:
			c.resolveUnproven(ctx, host, "removed")
		case pending[host] == 0:
			c.resolveUnproven(ctx, host, "no recoverable workload left on it, or it is "+h.State)
		}
	}
}
