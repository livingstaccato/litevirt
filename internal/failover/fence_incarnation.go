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
	if at.Before(since) {
		return false
	}
	if !observerRunStart(n, lastSeen, at).Before(since) {
		return true
	}
	return at.Sub(since) >= afreshRun
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
// (corrosion.HostActiveSince). ok=false when there is none to judge by — the
// host is not active, has no membership row, or this node does not read
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
		return time.Time{}, false
	}
	return since.Truncate(time.Second), true
}
