package failover

import (
	"context"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// handledMark is when a host's recorded state was last written as this
// coordinator first marked it handled (c.fenced): corrosion.HostStateSince,
// read then. ok=false when it could not be read.
type handledMark struct {
	since time.Time
	ok    bool
}

// markHandled marks host handled for this down-episode (c.fenced), and
// remembers, the first time only, when its recorded state was written then. A
// later mark of the same episode (a resumed recovery) keeps the first one.
func (c *Coordinator) markHandled(ctx context.Context, host string) {
	c.fenced[host] = true
	if c.handledAt == nil {
		c.handledAt = map[string]handledMark{}
	}
	if _, ok := c.handledAt[host]; ok {
		return
	}
	since, ok, err := corrosion.HostStateSince(ctx, c.db, host)
	c.handledAt[host] = handledMark{since: since, ok: err == nil && ok}
}

// unmarkHandled ends host's down-episode in this coordinator.
func (c *Coordinator) unmarkHandled(host string) {
	delete(c.fenced, host)
	delete(c.handledAt, host)
}

// upgradingSinceHandled reports whether host, handled for an outage, has since
// recorded itself 'upgrading': a boot without a graceful-stop marker records an
// active host so until its daemon serves (hostboot), and its replica, which
// stopped at the crash, may still read it active when the coordinator has
// already fenced it. That write starts a new life, as an 'active' boot write
// does (clearRecoveredFromFenced): the cached skip must not hide it, or a host
// whose daemon never serves would never be fenced again. Cleared, it takes the
// ordinary path: skipped for upgradingTimeout from that write, then fenced.
//
// Only a state write strictly newer than the one read when the host was
// handled counts, so a host the coordinator fenced while it was already
// 'upgrading' (past its timeout) stays handled. A host with no mark (handled
// before this build, or by a path that did not mark it) or with an unreadable
// time stays handled, as before.
func (c *Coordinator) upgradingSinceHandled(ctx context.Context, h *corrosion.HostRecord) bool {
	if h.State != "upgrading" {
		return false
	}
	m, ok := c.handledAt[h.Name]
	if !ok || !m.ok {
		return false
	}
	since, ok, err := corrosion.HostStateSince(ctx, c.db, h.Name)
	if err != nil || !ok {
		return false
	}
	return since.After(m.since)
}
