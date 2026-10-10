package failover

// Health-aware relay demotion (colonelpanik/litevirt#175).
//
// Relay election (corrosion.ComputeRelays) must be identical on every node, so
// it may only read replicated state. A host's probe health is each observer's
// own view — until one node turns it into a replicated decision. That node is
// the failover lease holder: it already reads every voter's host_health
// verdicts to decide fences, and there is exactly one of it at a time. It
// writes the decision as a relay_demoted/<host> row (corrosion/relay_health.go)
// that every node's RelayEligibleHosts reads.
//
// A relay set that churns on transient probe failures is worse than one that
// ignores health, so every move has hysteresis:
//
//   - DEMOTE a host when at least a third (minimum one) of the fresh voter
//     observers of it report probe failures, on EVERY evaluation across
//     RelayDemoteWindow, while it is not a fence candidate. One evaluation
//     below the bar restarts the window, so an alternating fail/ok pattern
//     never demotes.
//   - RESTORE it after RelayRestoreWindow with no failing observer (and at
//     least one fresh observer: silence is not health).
//   - At most ONE change per cycle.
//   - Never demote below BaseRelays eligible hosts.
//
// The windows live in this coordinator's memory. A new lease holder, or a gap
// in evaluation longer than RelayEvalGap, starts them again: what happened on
// evaluations nobody made is unknown, and the cost of starting again is only a
// later move, never an earlier one.
//
// Fencing keeps its own rules. A host a quorum sees dead is fenced, not
// demoted; a demotion withholds the relay ROLE only, and the host stays a leaf.

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Tunables. Variables so a test can shorten them; production never changes
// them.
var (
	// RelayDemoteWindow is how long a host's probes must keep failing, on
	// every evaluation, before it is demoted.
	RelayDemoteWindow = 2 * time.Minute
	// RelayRestoreWindow is how long a demoted host must go with no failing
	// observer before it is restored.
	RelayRestoreWindow = 10 * time.Minute
	// RelayEvalGap is the longest gap between two evaluations that still
	// continues a window. Longer — this node lost and regained the lease, or
	// stalled — and every window starts again.
	RelayEvalGap = 30 * time.Second
	// RelayFailingDivisor sets the demotion bar: at least
	// ceil(observers / RelayFailingDivisor) failing observers, minimum one.
	RelayFailingDivisor = 3
)

// relayChangesPerCycle bounds the demotions plus restores one evaluation
// writes: a relay set moves one host at a time.
const relayChangesPerCycle = 1

// relayHealthState is the lease holder's in-memory hysteresis.
type relayHealthState struct {
	lastEval     time.Time
	failingSince map[string]time.Time // non-demoted host → start of its unbroken failing run
	healthySince map[string]time.Time // demoted host → start of its unbroken clean run
}

func (s *relayHealthState) reset() {
	s.failingSince = map[string]time.Time{}
	s.healthySince = map[string]time.Time{}
}

// relayObservation is one host's fresh voter verdicts this evaluation.
type relayObservation struct {
	observers int // fresh voter observers, the target excluded
	failing   int // of those, reporting at least one probe failure
}

// relayFailingBar is the number of failing observers that qualifies a host
// for demotion: a third of its fresh voter observers, minimum one.
func relayFailingBar(observers int) int {
	d := RelayFailingDivisor
	if d < 1 {
		d = 1
	}
	bar := (observers + d - 1) / d
	if bar < 1 {
		bar = 1
	}
	return bar
}

// evaluateRelayHealth runs one evaluation. Called by the lease holder once per
// cycle, after the fence candidates are known and before any is fenced. It
// never fails the cycle: relay duty is an optimisation, fencing is not.
func (c *Coordinator) evaluateRelayHealth(ctx context.Context, voters, fenceCandidates map[string]bool) {
	// Nothing is decided before relay_health_v1 has latched: no row could be
	// written, and windows gathered now would be spent the moment it latches.
	if !c.db.MayWriteRelayDemotion() {
		c.relay.lastEval = time.Time{}
		return
	}
	now := c.now()
	if c.relay.failingSince == nil || c.relay.lastEval.IsZero() || now.Sub(c.relay.lastEval) > RelayEvalGap {
		c.relay.reset()
	}
	c.relay.lastEval = now

	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		slog.Warn("relay health: read hosts", "error", err)
		c.relay.lastEval = time.Time{}
		return
	}
	demoted, err := corrosion.ListRelayDemotions(ctx, c.db)
	if err != nil {
		slog.Warn("relay health: read demotions", "error", err)
		c.relay.lastEval = time.Time{}
		return
	}
	obs, err := c.relayObservations(ctx, voters, now)
	if err != nil {
		slog.Warn("relay health: read host_health", "error", err)
		c.relay.lastEval = time.Time{}
		return
	}

	eligible := 0
	var restore, demote []string
	seen := map[string]bool{}
	for _, h := range hosts {
		seen[h.Name] = true
		o := obs[h.Name]
		if _, isDemoted := demoted[h.Name]; isDemoted {
			delete(c.relay.failingSince, h.Name)
			if o.observers > 0 && o.failing == 0 {
				since, ok := c.relay.healthySince[h.Name]
				if !ok {
					c.relay.healthySince[h.Name] = now
				} else if now.Sub(since) >= RelayRestoreWindow {
					restore = append(restore, h.Name)
				}
			} else {
				delete(c.relay.healthySince, h.Name)
			}
			continue
		}
		delete(c.relay.healthySince, h.Name)
		if h.IsWitness() || h.State != "active" {
			delete(c.relay.failingSince, h.Name)
			continue
		}
		eligible++
		if o.observers > 0 && o.failing >= relayFailingBar(o.observers) && !fenceCandidates[h.Name] {
			since, ok := c.relay.failingSince[h.Name]
			if !ok {
				c.relay.failingSince[h.Name] = now
			} else if now.Sub(since) >= RelayDemoteWindow {
				demote = append(demote, h.Name)
			}
		} else {
			delete(c.relay.failingSince, h.Name)
		}
	}
	for name := range c.relay.failingSince {
		if !seen[name] {
			delete(c.relay.failingSince, name)
		}
	}
	for name := range c.relay.healthySince {
		if !seen[name] {
			delete(c.relay.healthySince, name)
		}
	}

	// One change per cycle. A restore goes first: it only ever adds a relay
	// candidate back.
	sort.Strings(restore)
	sort.Strings(demote)
	changes := 0
	for _, h := range restore {
		if changes >= relayChangesPerCycle {
			return
		}
		d := corrosion.RelayDemotion{
			Demoted: false,
			Since:   now.UTC().Format(time.RFC3339),
			Reason:  fmt.Sprintf("no failing voter observer for %s", RelayRestoreWindow),
		}
		if err := corrosion.SetRelayDemotion(ctx, c.db, h, d, c.hostName); err != nil {
			slog.Warn("relay health: restore", "host", h, "error", err)
			return
		}
		changes++
		eligible++
		delete(c.relay.healthySince, h)
		slog.Info("relay health: host restored to relay eligibility", "host", h, "reason", d.Reason)
	}
	base := c.RelayConfig.BaseRelays
	if base <= 0 {
		base = 3 // corrosion.RelayConfig's default
	}
	for _, h := range demote {
		if changes >= relayChangesPerCycle {
			return
		}
		if eligible-1 < base {
			slog.Info("relay health: not demoting; it would leave fewer eligible hosts than BaseRelays",
				"host", h, "eligible", eligible, "base_relays", base)
			return
		}
		o := obs[h]
		d := corrosion.RelayDemotion{
			Demoted: true,
			Since:   now.UTC().Format(time.RFC3339),
			Reason: fmt.Sprintf("%d of %d fresh voter observers reported probe failures on every evaluation for %s",
				o.failing, o.observers, RelayDemoteWindow),
		}
		if err := corrosion.SetRelayDemotion(ctx, c.db, h, d, c.hostName); err != nil {
			slog.Warn("relay health: demote", "host", h, "error", err)
			return
		}
		changes++
		eligible--
		delete(c.relay.failingSince, h)
		slog.Warn("relay health: host demoted from relay duty (it stays a leaf)", "host", h, "reason", d.Reason)
	}
}

// relayObservations counts, per target, the fresh voter observers and how many
// of them report a probe failure. Fresh is the fence quorum's two-sided
// window (healthFreshness), and a vote counts only from a voter that is not
// the target — the same rules fencing counts by. Like the fence query it
// reads tombstoned rows too: a receiver on the previous release can hold a
// live verdict marked deleted (corrosion/observation_replace.go).
func (c *Coordinator) relayObservations(ctx context.Context, voters map[string]bool, now time.Time) (map[string]relayObservation, error) {
	rows, err := c.db.Query(ctx,
		`SELECT target, observer, consecutive_failures, updated_at FROM host_health`)
	if err != nil {
		return nil, err
	}
	past, future := now.Add(-healthFreshness), now.Add(healthFreshness)
	out := map[string]relayObservation{}
	for _, r := range rows {
		t, o := r.String("target"), r.String("observer")
		if !countsAsVote(voters, o, t) {
			continue
		}
		inst, ok := corrosion.ParseUpdatedAt(r.String("updated_at"))
		if !ok || !inst.After(past) || inst.After(future) {
			continue
		}
		ob := out[t]
		ob.observers++
		if r.Int("consecutive_failures") > 0 {
			ob.failing++
		}
		out[t] = ob
	}
	return out, nil
}
