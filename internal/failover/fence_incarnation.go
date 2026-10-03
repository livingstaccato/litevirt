package failover

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

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
