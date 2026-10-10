package failover

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/notify"
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
	EventRecoveryStalled = notify.KindHostRecoveryStalled

	// retryNotifyEvery bounds how often a failed fence RETRY notifies
	// (fenceNotifies), once its backoff has reached fenceRetryMax.
	retryNotifyEvery = time.Hour
)

// fenceNotifies reports whether the fence fr of host, just run, raises the
// operator's host.fenced notification (OnFence). Every fence does, except a
// failed RETRY of a failed fence: the first failure has notified, and the
// stall alert carries the ongoing state. A failed retry notifies again only
// once its backoff has reached fenceRetryMax, and then at most once per
// retryNotifyEvery per host. The fencing_log row is written either way; the
// backoff caps its rate.
func (c *Coordinator) fenceNotifies(host string, fr fence.Result) bool {
	r := c.retrying
	if r == nil || fr.Success {
		return true
	}
	if fenceRetryDelay(r.Failures+1) < fenceRetryMax {
		return false
	}
	now := c.now()
	if last, ok := c.retryNotified[host]; ok && now.Sub(last) < retryNotifyEvery {
		return false
	}
	if c.retryNotified == nil {
		c.retryNotified = map[string]time.Time{}
	}
	c.retryNotified[host] = now
	return true
}

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

// retryableFenceMethod reports whether a retry running method is worth
// making. A manual fence cannot succeed (the confirmation path owns it), a
// best-effort fence already proceeded on its failure, and a watchdog fence of
// a peer always fails: fence.Execute refuses the watchdog strategy for any
// host but the caller itself, and the coordinator never fences itself.
func retryableFenceMethod(method string) bool {
	switch method {
	case "ipmi", "ssh":
		return true
	}
	return false
}

// retryStrategy is the strategy a retry of a failed `failed` fence of a host
// whose strategy is now `current` runs. The operator's current strategy wins
// when it is one a retry can run — `ipmi` or `ssh`, so configuring working
// BMC credentials after an SSH fence failed is honoured on the next retry.
// Otherwise (best-effort, watchdog, unset) the method that failed is
// repeated: a host switched to best-effort since an IPMI fence failed would
// otherwise "recover" on a failed best-effort fence, which proceeds anyway.
func retryStrategy(current, failed string) string {
	switch s := fence.ResolveStrategy(current); s {
	case "ipmi", "ssh":
		return s
	}
	return failed
}

// fenceRetry is fenceRetryDue's answer for one host.
type fenceRetry struct {
	// Due is true when the host is to be fenced again now.
	Due bool
	// Next is when the retry falls due; zero when no retry applies at all.
	Next time.Time
	// FailedAt is the newest failed attempt the retry repeats.
	FailedAt time.Time
	// Strategy is the strategy the retry runs (retryStrategy).
	Strategy string
	// Failures counts the consecutive failed attempts of this life of the
	// host since its newest success or confirmation, FailedAt's included.
	Failures int
}

// fenceRetryDue reports whether h, left 'offline' by a fence attempt that
// FAILED, is due to be fenced again, when it will be if not yet, and the
// strategy to fence it with (retryStrategy).
//
// It reads fencing_log, so a restart or a new leader keeps the schedule: the
// delay is fenceRetryDelay of the number of consecutive failed attempts since
// the newest successful attempt or operator confirmation — counting only
// attempts of the host's current life (corrosion.HostFenceLife), so failures
// of an earlier outage do not start this one at the cap — from the newest
// failed attempt, or from this coordinator's own last fence of the host if
// that is later on its clock (lastFenceAt). The row is stamped with the clock
// of whoever fenced, and a row from a clock running behind ours must not make
// the retry due at once.
//
// It is not due when the newest row is a successful attempt or a
// confirmation (those resume through recordedFence and the confirmation
// paths), when the failed method cannot succeed on a retry, or when the host's
// strategy is now manual. The caller supplies that h is quorum-down, by
// construction, and checks immediately before the fence that nobody has seen
// it answer since FailedAt (retryStillDown).
func (c *Coordinator) fenceRetryDue(ctx context.Context, h *corrosion.HostRecord) fenceRetry {
	if h == nil || h.State != "offline" || fence.ResolveStrategy(h.FenceStrategy) == "manual" {
		return fenceRetry{}
	}
	rows, err := c.db.Query(ctx,
		`SELECT method, result, timestamp FROM fencing_log WHERE host_name = ?`, h.Name)
	if err != nil {
		slog.Warn("failover: fencing_log read for a fence retry failed", "host", h.Name, "error", err)
		c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
		return fenceRetry{}
	}
	var settled, newestFailed time.Time // newest success/confirmation, newest failure
	var newestFailedMethod string
	var failed []time.Time
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
			failed = append(failed, ts)
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
	// Gate on the strategy the retry would RUN, not the method that failed: a
	// host whose watchdog or manual fence failed and that the operator has
	// since given ipmi or ssh is retried with it.
	strategy := retryStrategy(h.FenceStrategy, newestFailedMethod)
	if newestFailed.IsZero() || newestFailed.Before(settled) || !retryableFenceMethod(strategy) {
		return fenceRetry{}
	}
	life, _, lifeKnown, lerr := corrosion.HostFenceLife(ctx, c.db, h.Name)
	if lerr != nil {
		lifeKnown = false // count every failure: the longer delay, the safe side
	}
	n := 0
	for _, at := range failed {
		if at.After(settled) && (!lifeKnown || !at.Before(life)) {
			n++
		}
	}
	from := newestFailed
	if own, ok := c.lastFenceAt[h.Name]; ok && own.After(from) {
		from = own
	}
	next := from.Add(fenceRetryDelay(n))
	return fenceRetry{
		Due:      !c.now().Before(next),
		Next:     next,
		FailedAt: newestFailed,
		Strategy: strategy,
		Failures: n,
	}
}

// retryStillDown reports whether host may be fenced again for a fence attempt
// that failed at failedAt: nobody has seen it answer since. It is the second
// half of fenceStillStands keyed on the failed attempt, read immediately
// before the retry, under the lease. The candidate set the retry came from
// was read at the top of the cycle, and the moment a retry is most dangerous
// is the moment the outage ends: a partition heals, the observers' rows still
// count failures for a probe interval, and an SSH power-off that failed
// across the partition now succeeds against a host that has just come back.
// A host that answered is never retried; it fails closed on a read error.
func (c *Coordinator) retryStillDown(ctx context.Context, host string, failedAt time.Time) (string, bool) {
	return c.answeredSince(ctx, host, failedAt)
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
	r := c.fenceRetryDue(ctx, h)
	if !r.Due && !r.Next.IsZero() {
		c.noteHold(h.Name, "fence failed; retrying at "+r.Next.UTC().Format(time.RFC3339))
	}
	return r.Due
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

// logRetryRefused logs that a due retry of host was refused because it
// answered since the attempt that failed at failedAt: at Warn on the
// transition — the first refusal for this failed attempt, or a new reason —
// and at Debug while it stays refused for the same one. A one-way partition
// can keep a host a fence candidate with one observer answering for as long
// as it lasts, and the retry is refused on every 5 s poll.
func (c *Coordinator) logRetryRefused(host string, failedAt time.Time, why string) {
	key := failedAt.UTC().Format(time.RFC3339) + "|" + why
	level := slog.LevelWarn
	if c.retryRefusedLogged[host] == key {
		level = slog.LevelDebug
	} else {
		if c.retryRefusedLogged == nil {
			c.retryRefusedLogged = map[string]string{}
		}
		c.retryRefusedLogged[host] = key
	}
	slog.Log(context.Background(), level, "failover: not retrying the fence of a host that answered after the attempt that failed",
		"host", host, "failed_at", failedAt.UTC().Format(time.RFC3339), "reason", why)
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
	delete(c.retryNotified, host)
	delete(c.retryRefusedLogged, host)
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
		switch {
		case reason != "":
		case !c.cycleCandidates[host]:
			reason = "not a fence candidate this cycle: no quorum of observers sees it down (or region-scoped failover declined it); " +
				"if it is down, confirm it off with 'lv host fence-confirm " + host + "'"
		default:
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
