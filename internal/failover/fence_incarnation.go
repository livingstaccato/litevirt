package failover

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// afreshRun is how long a host must have failed since it turned active before
// a failing run that began earlier counts toward its fence: the span of
// offlineThreshold probes, one run's worth, plus fenceSkewMargin, because the
// activation is stamped by the host's clock and the observation by the
// observer's.
const afreshRun = time.Duration(offlineThreshold-1)*health.ProbeInterval + fenceSkewMargin

// countedSinceActive reports whether an observer's failing verdict, n failures
// published at `at`, with last_seen as host_health carries it, counts toward
// the fence of a host recorded active since `since`.
//
// A verdict published before the activation is about the host before it, and
// never counts. One published after it counts once its failing run began after
// the activation — the observers have counted the host down afresh — or once
// the host has been failing for a whole run since (afreshRun).
//
// The second half is the restart case (lab 1, 2026-10-11). An observer does
// not reset its count when its target's state changes, so a host that was
// down, recorded 'upgrading' by its own SIGTERM, comes back with every
// observer's count already past the threshold. Its boot write records it
// 'active' a few seconds before its gRPC server listens, and the first
// unanswered probe in that gap republished the old count with a new
// updated_at: quorum at once, and the host was fenced as soon as its sshd
// answered — node-5 twice and node-2 once, each about 3 s after the boot
// write. Dropping the run outright would never fence a host that turned
// active and then never answered, because the observers' runs never break.
func countedSinceActive(n int, lastSeen string, at, since time.Time) bool {
	return countedSinceActiveWithin(n, lastSeen, at, since, func(time.Time) time.Duration { return afreshRun })
}

// countedSinceActiveWithin is countedSinceActive with the allowance for a run
// that began before the activation chosen by grace, from the run's start.
func countedSinceActiveWithin(n int, lastSeen string, at, since time.Time, grace func(runStart time.Time) time.Duration) bool {
	if at.Before(since) {
		return false
	}
	start := observerRunStart(n, lastSeen, at)
	if !start.Before(since) {
		return true
	}
	return at.Sub(since) >= grace(start)
}

// The inherited-run grace (inheritedRunGraceFrom, over the times
// fenceTimesNeeded reads) is how long a host, recorded active since `since`, must have failed
// since the activation before an observer's run that began at runStart, before
// the activation, counts toward its fence.
//
// It is afreshRun, unless a fence attempt of host is recorded inside that run
// (fencing_log, any result, from runStart less fenceSkewMargin up to the
// activation): then the run has already been acted on, and the host has come
// back since — powered on after its fence (lab 1, 2026-10-14: node-3 recorded
// itself active 16 s before its gRPC server listened, and was SSH-powered off
// again 0.6 s after it did). Such a host gets the allowance a graceful restart
// gets (upgradingTimeout) to answer before it is fenced again on that run. A
// run that begins after the activation is unaffected, and a host that comes
// back and never answers is still fenced, once that allowance has passed.
// An unreadable log keeps afreshRun.

// fenceAttemptTimesIn lists the timestamps of host's fencing_log rows, of any
// result. A read error yields none.
func fenceAttemptTimesIn(ctx context.Context, db *corrosion.Client, host string) []time.Time {
	rows, err := db.Query(ctx, `SELECT timestamp FROM fencing_log WHERE host_name = ?`, host)
	if err != nil {
		slog.Warn("failover: read the fence log of a host that turned active; judging its observers' runs as before",
			"host", host, "error", err)
		return nil
	}
	var out []time.Time
	for _, r := range rows {
		if ts, perr := time.Parse(time.RFC3339, r.String("timestamp")); perr == nil {
			out = append(out, ts)
		}
	}
	return out
}

// turnedActiveThisCycle reports whether target turned active after this cycle
// read when each host last turned active (snapshot), and so after it counted
// target's observers. The fence quorum read the snapshot, then the host's state
// is read again per candidate; a boot write landing between the two showed a
// joining host's quorum, counted while it joined, against a host now active
// (TestFleet_ReaddedHostIsNotFencedWhileItJoins under -race: fenced 23 ms
// after its boot write). Such a host is judged again next cycle, on its
// observations since.
func (c *Coordinator) turnedActiveThisCycle(ctx context.Context, target string, snapshot map[string]time.Time) bool {
	since, ok, err := corrosion.HostActiveSince(ctx, c.db, target)
	if err != nil || !ok {
		return false
	}
	prev, had := snapshot[target]
	return !had || !prev.Equal(since)
}

// fenceRowCutoff is the instant before which a fencing_log row of host is
// about an earlier life of the host: the moment it last turned active
// (corrosion.HostActiveSince), or, for a host recorded 'upgrading', the moment
// it wrote that (upgradingLife). ok=false when there is none to judge by — the
// host is neither, has no membership row, or this node does not read
// host_membership yet — and every row is then judged as before.
//
// recentlyFenced and manualFenceConfirmed used to count any accepted row under
// five minutes old, and so did the proof-grade fence a shared-disk transfer
// binds. A row is a fact about the host as it was when it was written. On the
// kvm003 lab (drill 6) the old node-5 was fence-confirmed, removed with
// `lv host rm --dead` and re-added minutes later; until the window ran out, the
// coordinator would have skipped a failure of the new machine as recently
// fenced, and taken the old machine's confirmation as proof it was off. The
// same holds for one machine that booted again since its fence: it fails anew.
//
// What the window exists for still holds. A row NEWER than the host's last
// activation counts: a fence whose 'fenced' state has not reached this replica
// yet leaves the host recorded active since before the fence. The cutoff is
// truncated to the second, the precision of fencing_log.timestamp, so a row in
// the same second as the activation still counts, erring toward not fencing
// twice.
func (c *Coordinator) fenceRowCutoff(ctx context.Context, host string) (time.Time, bool) {
	since, ok, err := corrosion.HostActiveSince(ctx, c.db, host)
	if err != nil {
		slog.Warn("failover: read when the host last turned active; judging its fence rows as before",
			"host", host, "error", err)
		return time.Time{}, false
	}
	if !ok {
		return c.upgradingLife(ctx, host)
	}
	return since.Truncate(time.Second), true
}

// upgradingLife is fenceRowCutoff for a host recorded 'upgrading': the moment
// it wrote that state. Only the host writes it (its SIGTERM, its boot, an
// upgrade it runs), so a fence row older than the write is about a host that
// was up after it: a boot without a graceful-stop marker records an active
// host 'upgrading' until it serves, and a fence before that boot must not hold
// back, for recentFenceWindow, the fence of a daemon that then never serves
// (upgradingSinceHandled). A row newer than the write still counts.
func (c *Coordinator) upgradingLife(ctx context.Context, host string) (time.Time, bool) {
	h, err := corrosion.GetHost(ctx, c.db, host)
	if err != nil || h == nil || h.State != "upgrading" {
		return time.Time{}, false
	}
	since, ok, err := corrosion.HostStateSince(ctx, c.db, host)
	if err != nil || !ok {
		return time.Time{}, false
	}
	return since.Truncate(time.Second), true
}
