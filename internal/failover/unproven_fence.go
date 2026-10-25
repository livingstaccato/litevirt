package failover

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
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
//     is not relied on;
//   - a failed fence of a host fenced only over SSH (its dial or power-off
//     failed), retried with backoff: a host that lost power leaves it nothing
//     to reach.
//   - a recorded unverified fence that no longer stands, declined for good
//     (noteResumeDeclined): an operator's fence judged before any observer
//     watched the host stay down (the rc10 lab's A5).
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
// for the condition's detail; trust, for a confirmed SSH power-off, is the
// fence as it was judged, whose trust note (sshTrustNote) is its remedy's.
func (c *Coordinator) holdUnproven(ctx context.Context, h *corrosion.HostRecord, hold, why, stale string, trust *trustJudged) {
	c.noteGateHold(h.Name, hold, stale)
	c.raiseUnprovenAs(ctx, h, unprovenRaise{why: why, trust: trust, hold: hold, holdNote: trust.note(h)}, stale)
}

// unprovenRaise is what ha.recovery.unproven_fence was last raised with.
type unprovenRaise struct {
	why   string
	trust *trustJudged
	// declined: the hold is a recorded fence that no longer stands
	// (noteResumeDeclined), and the remedy names `lv host undrain` too, on
	// its precondition.
	declined bool
	// hold is the hold holdUnproven noted (the host.recovery.stalled text),
	// and holdNote the trust note it embeds: the settle sweep rewrites that
	// note in it while it is still the host's hold (review m3).
	hold, holdNote string
}

// trustJudged is a confirmed SSH power-off held because the trust setting did
// not count it: the fence as it ran (before holdUntrustedSSH) and its row id.
// Its note is re-read against the host as it is now, so a setting changed
// during the hold is reflected in the remedy (the rc10 lab's N2). The hold
// itself never is: trust is never retroactive.
type trustJudged struct {
	fr fence.Result
	id string
}

// note is sshTrustNote for the fence judged, read against h; "" for none.
func (t *trustJudged) note(h *corrosion.HostRecord) string {
	if t == nil {
		return ""
	}
	return sshTrustNote(h, t.fr, t.id)
}

// unprovenOpen reports whether host's ha.recovery.unproven_fence is open. A
// read error reports false.
func (c *Coordinator) unprovenOpen(ctx context.Context, host string) bool {
	row, ok, err := corrosion.GetHealthCondition(ctx, c.db, RefenceEvaluator, CondRecoveryUnprovenFence, "host", host)
	return err == nil && ok && row.Lifecycle != corrosion.ConditionResolved
}

// raiseUnproven writes ha.recovery.unproven_fence for h. A host with no
// recoverable workload on it holds nothing back, and raises nothing. The row
// is not rewritten while it says the same: a hold can last days.
func (c *Coordinator) raiseUnproven(ctx context.Context, h *corrosion.HostRecord, why, stale string, trust *trustJudged) {
	c.raiseUnprovenAs(ctx, h, unprovenRaise{why: why, trust: trust}, stale)
}

// raiseUnprovenAs is raiseUnproven for r.
func (c *Coordinator) raiseUnprovenAs(ctx context.Context, h *corrosion.HostRecord, r unprovenRaise, stale string) {
	if c.unprovenRaised == nil {
		c.unprovenRaised = map[string]unprovenRaise{}
	}
	c.unprovenRaised[h.Name] = r
	why := r.why
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
		Remedy: unprovenRemedyOf(h, r)})
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
// confirmed SSH power-off, trustNote (sshTrustNote): why the trust setting did
// not count it, and what it would do where that is true. Trust is never
// retroactive: a fence judged untrusted stays held until the confirmation.
func unprovenRemedy(h *corrosion.HostRecord, trustNote string) string {
	out := fmt.Sprintf("once %s is powered off, `lv host fence-confirm %s`, and the recovery resumes from it", h.Name, h.Name)
	switch fence.ResolveStrategy(h.FenceStrategy) {
	case "ipmi", "redfish":
	default:
		out += fmt.Sprintf(". To recover at once next time, give it a fence that proves a power-off: "+
			"`lv host config %s --fence-strategy ipmi|redfish`", h.Name)
	}
	if trustNote != "" {
		out += ". " + sentenceStart(trustNote, h.Name)
	}
	return out
}

// refreshTrustHold rewrites the trust note in the hold r noted, while that is
// still host's hold, to what it says against h now: the stall alert follows
// a trust setting changed during the hold as the condition does. Only the
// text changes, never the hold.
func (c *Coordinator) refreshTrustHold(host string, h *corrosion.HostRecord, r *unprovenRaise) {
	if r.trust == nil || r.hold == "" || r.holdNote == "" || c.holdBase[host] != r.hold {
		return
	}
	note := r.trust.note(h)
	if note == r.holdNote || !strings.Contains(r.hold, r.holdNote) {
		return
	}
	r.hold, r.holdNote = strings.Replace(r.hold, r.holdNote, note, 1), note
	c.noteGateHold(host, r.hold, c.lastStale[host])
}

// trustRestored reports whether host's recovery is held here on a confirmed
// SSH power-off that counts again: its trust was recorded when the fence was
// judged and the host, read afresh as h, trusts one again (a revocation, then
// the setting set again). The rule is the same on every coordinator and at
// every moment, so the coordinator holding it re-decides it, as a restarted
// one would from the record. It reports a host once per restoration: a
// re-decision that holds again records its own reason.
func (c *Coordinator) trustRestored(h *corrosion.HostRecord) bool {
	r, ok := c.unprovenRaised[h.Name]
	if !ok || r.trust == nil {
		return false
	}
	fr := r.trust.fr
	if !trustedSSH(fr, fence.RecordedTrust(fr.Detail, r.trust.id) && trustsSSHPoweroff(h)) {
		return false
	}
	r.trust = nil
	c.unprovenRaised[h.Name] = r
	return true
}

// unprovenRemedyOf is unprovenRemedy for what r raised: for a recorded fence
// declined, an undrain is a way out too, on its precondition. UndrainHost
// starts nothing: it returns the host to active, and any recovery after it
// needs a fresh fence under the ordinary rules. It is safe only while the
// host answers and none of its workloads runs elsewhere, which is the
// operator's to check: an earlier resume of the same fence may have recovered
// part of them, so nothing here claims that none moved.
func unprovenRemedyOf(h *corrosion.HostRecord, r unprovenRaise) string {
	out := unprovenRemedy(h, r.trust.note(h))
	if r.declined {
		out += fmt.Sprintf(". If %[1]s is up and answering (`lv host inspect %[1]s`) and none of its workloads runs anywhere "+
			"else (`lv ls --host %[1]s` lists each one still recorded on it), `lv host undrain %[1]s` returns it to service: "+
			"the coordinator moves nothing on a declined fence. Undraining a host that does not answer only has the "+
			"coordinator judge the outage afresh: nothing moves until a new fence proves it off. If any moved, use "+
			"`lv host fence-confirm %[1]s` instead", h.Name)
	}
	return out
}

// sentenceStart is note begun as a sentence: its first letter upper-cased,
// unless it begins with the host name host, which keeps its case ("node-5's",
// never "Node-5's").
func sentenceStart(note, host string) string {
	if note == "" || strings.HasPrefix(note, host) {
		return note
	}
	return strings.ToUpper(note[:1]) + note[1:]
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
	delete(c.unprovenRaised, host)
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
		default:
			// Still held: keep the detail current with what this coordinator
			// last raised it for, the newest stale confirmation, noted after
			// the raise, and the host's trust setting as it is now (h is read
			// afresh); raiseUnproven rewrites only on a change.
			if r, ok := c.unprovenRaised[host]; ok {
				c.refreshTrustHold(host, h, &r)
				c.raiseUnprovenAs(ctx, h, r, c.lastStale[host])
			}
		}
	}
}
