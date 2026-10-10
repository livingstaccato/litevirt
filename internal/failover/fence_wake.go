package failover

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// A host this coordinator has handled for its down-episode (c.fenced) is not
// thereby settled. Two things can change underneath the cache, and both are
// read from the database every cycle (lab drill S5):
//
//   - a NEWER successful fence is on record than the one this coordinator
//     acted on — an operator's `lv host fence`, or another coordinator's
//     fence. It is the same authority a successor resumes from
//     (recordedFence, resumeActionFor), and a coordinator whose own fence
//     failed must not be the one node that cannot see it;
//   - this coordinator's own fence FAILED, and the retry backoff has passed:
//     the host is fenced again rather than parked with the lease held.
//
// Nothing here widens what counts as fence proof: an adopted fence goes
// through recordedFence and resumeActionFor exactly as a successor's would,
// and a retried fence is an ordinary fence through failover, under every gate
// a first fence passes.

const (
	// fenceRetryBase is the delay before the first retry of a failed fence;
	// each further consecutive failure doubles it up to fenceRetryMax.
	fenceRetryBase = 30 * time.Second
	// fenceRetryMax caps the retry delay. It is recentFenceWindow, the
	// horizon every other fence-recency question in the coordinator uses.
	fenceRetryMax = recentFenceWindow

	// recoveryStallAfter is how long a fenced or offline host's recoverable
	// workloads may stay on it, counted from its fence record, before the
	// leader raises a stall alert.
	recoveryStallAfter = 60 * time.Second
	// recoveryStallRepeat bounds how often the alert repeats for one host.
	recoveryStallRepeat = 10 * time.Minute

	// EventRecoveryStalled is the event action, and the notification kind,
	// of a stall alert.
	EventRecoveryStalled = "host.recovery.stalled"
)

// fenceRetryDelay is the wait after the n-th consecutive failed fence attempt
// (n >= 1) before the next one: fenceRetryBase doubling to fenceRetryMax.
func fenceRetryDelay(n int) time.Duration {
	d := fenceRetryBase
	for i := 1; i < n && d < fenceRetryMax; i++ {
		d *= 2
	}
	if d > fenceRetryMax {
		d = fenceRetryMax
	}
	return d
}

// retryableFenceMethod reports whether a failed attempt with method is worth
// repeating. A manual fence cannot succeed (the confirmation path owns it),
// and a best-effort fence already proceeded on its failure.
func retryableFenceMethod(method string) bool {
	switch method {
	case "ipmi", "ssh", "watchdog":
		return true
	}
	return false
}

// fenceRetryDue reports whether h, left 'offline' by a fence attempt that
// FAILED, is due to be fenced again, when it will be if not yet, and the
// method to fence it with: the one that failed. A retry never runs a weaker
// strategy than the attempt it repeats — a host switched to best-effort since
// an IPMI fence failed would otherwise "recover" on a failed best-effort
// fence, which proceeds anyway.
//
// It reads fencing_log, so a restart or a new leader keeps the schedule: the
// delay is fenceRetryDelay of the number of consecutive failed attempts since
// the newest successful attempt or operator confirmation, counted from the
// newest failed attempt — or from this coordinator's own last fence of the
// host, if that is later on its clock (lastFenceAt). The row is stamped with
// the clock of whoever fenced, and a row from a clock running behind ours
// must not make the retry due at once. It is not due when the newest row is
// a successful attempt or a confirmation (those resume through recordedFence
// and the confirmation paths), when the failed method cannot succeed on a
// retry, or when the host's strategy is now manual. The caller supplies that
// h is quorum-down, by construction.
func (c *Coordinator) fenceRetryDue(ctx context.Context, h *corrosion.HostRecord) (bool, time.Time, string) {
	if h == nil || h.State != "offline" || fence.ResolveStrategy(h.FenceStrategy) == "manual" {
		return false, time.Time{}, ""
	}
	rows, err := c.db.Query(ctx,
		`SELECT method, result, timestamp FROM fencing_log WHERE host_name = ?`, h.Name)
	if err != nil {
		slog.Warn("failover: fencing_log read for a fence retry failed", "host", h.Name, "error", err)
		c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
		return false, time.Time{}, ""
	}
	var settled, newestFailed time.Time // newest success/confirmation, newest failure
	var newestFailedMethod string
	type attempt struct {
		at     time.Time
		method string
	}
	var failed []attempt
	for _, r := range rows {
		ts, perr := time.Parse(time.RFC3339, r.String("timestamp"))
		if perr != nil {
			continue
		}
		switch r.String("result") {
		case fence.LogFenced, fence.LogManualConfirmed:
			if ts.After(settled) {
				settled = ts
			}
		case fence.LogPartial:
			failed = append(failed, attempt{ts, r.String("method")})
			// A same-second tie between failures keeps the first read; the
			// method of either is from the same run of failures.
			if ts.After(newestFailed) {
				newestFailed, newestFailedMethod = ts, r.String("method")
			}
		}
	}
	// A success or confirmation at or after the newest failure owns the host
	// (a failure wins a same-second tie against a success, as in
	// readNewestFenceAttempt; a confirmation in the same second is taken as
	// the operator's answer to the failure).
	if newestFailed.IsZero() || newestFailed.Before(settled) || !retryableFenceMethod(newestFailedMethod) {
		return false, time.Time{}, ""
	}
	n := 0
	for _, f := range failed {
		if f.at.After(settled) {
			n++
		}
	}
	from := newestFailed
	if own, ok := c.lastFenceAt[h.Name]; ok && own.After(from) {
		from = own
	}
	next := from.Add(fenceRetryDelay(n))
	return !c.now().Before(next), next, newestFailedMethod
}

// fenceAuthorityChanged reports whether h, cached as handled (c.fenced), has
// news this coordinator must act on: a newer successful fence on record than
// the one it acted on, or its own failed fence due a retry. The caller then
// drops the cache and takes h down the ordinary path, which re-reads both.
func (c *Coordinator) fenceAuthorityChanged(ctx context.Context, h *corrosion.HostRecord) bool {
	if rec, _, ok := c.recordedFence(ctx, h); ok && rec.ID != c.fencedOn[h.Name] {
		slog.Info("failover: a fence of this host has been recorded since this coordinator handled it; taking it up",
			"host", h.Name, "fence_id", rec.ID, "method", rec.Method, "fenced_at", rec.TS)
		return true
	}
	due, next, _ := c.fenceRetryDue(ctx, h)
	if !due && !next.IsZero() {
		c.noteHold(h.Name, "fence failed; retrying at "+next.UTC().Format(time.RFC3339))
	}
	return due
}

// noteFencedOn records the fence (fencing_log id) this coordinator's recovery
// of host acts on; a successful fence recorded later is news
// (fenceAuthorityChanged).
func (c *Coordinator) noteFencedOn(host, fenceID string) {
	if c.fencedOn == nil {
		c.fencedOn = map[string]string{}
	}
	c.fencedOn[host] = fenceID
}

// noteHold records why the recovery of host is not proceeding, for the stall
// alert. The newest reason wins.
func (c *Coordinator) noteHold(host, reason string) {
	if c.holdReason == nil {
		c.holdReason = map[string]string{}
	}
	c.holdReason[host] = reason
}

// forgetHost drops the per-episode memory kept for host here, once it is back
// in service.
func (c *Coordinator) forgetHost(host string) {
	delete(c.fencedOn, host)
	delete(c.lastFenceAt, host)
	delete(c.holdReason, host)
	delete(c.stallSince, host)
	delete(c.stallAlerted, host)
}

// alertStalledRecoveries raises the stall alert for every fenced or offline
// host that still has recoverable workloads recoveryStallAfter after its
// fence record, at most once per recoveryStallRepeat per host. pending is
// strandedByHost's count, per host.
//
// The stall clock starts at the newest fencing_log row of the host when this
// coordinator first sees it stalled (or now, when there is none), and is held
// in memory, so retried fences do not restart it. A new leader or a restart
// starts it again from the newest row, which only ever delays the alert.
func (c *Coordinator) alertStalledRecoveries(ctx context.Context, pending map[string]int) {
	for host := range c.stallSince {
		if pending[host] == 0 {
			delete(c.stallSince, host)
			delete(c.stallAlerted, host)
		}
	}
	now := c.now()
	for host, n := range pending {
		if n == 0 {
			continue
		}
		if c.stallSince == nil {
			c.stallSince = map[string]time.Time{}
		}
		since, ok := c.stallSince[host]
		if !ok {
			since = now
			if at, found := c.newestFenceRow(ctx, host); found && at.Before(now) {
				since = at
			}
			c.stallSince[host] = since
		}
		if now.Sub(since) < recoveryStallAfter {
			continue
		}
		if last, ok := c.stallAlerted[host]; ok && now.Sub(last) < recoveryStallRepeat {
			continue
		}
		if c.stallAlerted == nil {
			c.stallAlerted = map[string]time.Time{}
		}
		c.stallAlerted[host] = now
		reason := c.holdReason[host]
		if reason == "" {
			reason = "recovery ran and left workloads on the host; see the failover log on " + c.hostName
		}
		slog.Error("failover: recovery of a fenced host has stalled",
			"host", host, "coordinator", c.hostName, "pending", n,
			"since", since.UTC().Format(time.RFC3339), "reason", reason)
		c.publish(EventRecoveryStalled, host, fmt.Sprintf("coordinator=%s pending=%d since=%s reason=%s",
			c.hostName, n, since.UTC().Format(time.RFC3339), reason))
		if c.OnRecoveryStalled != nil {
			c.OnRecoveryStalled(host, c.hostName, reason, n, since)
		}
	}
}

// newestFenceRow is the time of host's newest fencing_log row of any result.
func (c *Coordinator) newestFenceRow(ctx context.Context, host string) (time.Time, bool) {
	rows, err := c.db.Query(ctx, `SELECT timestamp FROM fencing_log WHERE host_name = ?`, host)
	if err != nil {
		return time.Time{}, false
	}
	var best time.Time
	for _, r := range rows {
		if ts, perr := time.Parse(time.RFC3339, r.String("timestamp")); perr == nil && ts.After(best) {
			best = ts
		}
	}
	return best, !best.IsZero()
}
