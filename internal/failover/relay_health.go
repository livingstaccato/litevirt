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
//   - DEMOTE a host when at least a third (minimum one) of its voter
//     observers report probe failures, on EVERY evaluation across
//     RelayDemoteWindow, while it is not a fence candidate. One evaluation
//     below the bar restarts the window, so an alternating fail/ok pattern
//     never demotes.
//   - RESTORE it after RelayRestoreWindow below that bar, with at least one
//     active observer holding a verdict on it (silence is not health). Below the bar, not zero: one
//     flaky observer must not hold a demotion in place for good.
//   - At most ONE change per cycle.
//   - Never demote below R, the relay count the election needs (and never
//     below BaseRelays): a demotion that would only be filled back in by the
//     demoted host itself changes nothing and would misreport.
//   - Never demote a host an operator restored with a hold
//     (`lv cluster relay-restore --hold`) until the hold runs out.
//
// WHAT COUNTS AS AN OBSERVATION. The health checker publishes a verdict when
// it CHANGES, and re-publishes only a failing one (its count climbs every
// probe) — a healthy verdict on an active host is written once and stands
// (health/checker.go, shouldPersistHealth: N·(N−1) refreshes would cost a
// replicated write per pair per heartbeat). So:
//   - the DENOMINATOR is every voter other than the host: a healthy row is
//     the observer's standing verdict whatever its age, and a voter whose
//     verdict has not reached this replica yet is not evidence of failure;
//   - a FAILING observer is one whose failing verdict is FRESH
//     (healthFreshness): a failing row that stopped refreshing is an observer
//     that stopped probing, not evidence.
// Requiring freshness of the denominator too made one failing observer of
// four read as 1/1 in steady state, and made a healed host unrestorable.
//
// An observer whose fresh failing verdicts cover more than half of the hosts
// it observes is DISCOUNTED for the evaluation: a host whose outbound probes
// all time out (conntrack exhaustion, CPU starvation, a broken client
// credential) is the fault, not the hosts it cannot reach, and counting it
// would demote healthy hosts and keep the faulty one a relay.
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
	// RelayRestoreWindow is how long a demoted host must stay below the
	// demotion bar, vouched for by an active observer, before it is restored.
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
	healthySince map[string]time.Time // demoted host → start of its unbroken run below the bar
}

func (s *relayHealthState) reset() {
	s.failingSince = map[string]time.Time{}
	s.healthySince = map[string]time.Time{}
}

// relayObservation is one host's voter verdicts this evaluation.
type relayObservation struct {
	observers int // voters other than the host, discounted observers excluded
	failing   int // of those, with a FRESH failing verdict
	live      int // of those, whose own host is active
}

// relayFailingBar is the number of failing observers that qualifies a host
// for demotion: a third of its voter observers, minimum one.
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

// relayRestoreClean reports whether an evaluation counts toward a demoted
// host's restore window: an active observer vouches for it, and it is below
// the demotion bar.
func relayRestoreClean(o relayObservation) bool {
	return o.live > 0 && o.failing < relayFailingBar(o.observers)
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

	fail := func(what string, err error) {
		slog.Warn("relay health: "+what, "error", err)
		c.relay.lastEval = time.Time{}
	}
	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		fail("read hosts", err)
		return
	}
	rows, err := corrosion.ListRelayRows(ctx, c.db)
	if err != nil {
		fail("read demotions", err)
		return
	}
	active := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		if h.State == "active" {
			active[h.Name] = true
		}
	}
	names := make([]string, 0, len(hosts))
	for _, h := range hosts {
		names = append(names, h.Name)
	}
	obs, err := c.relayObservations(ctx, voters, active, names, now)
	if err != nil {
		fail("read host_health", err)
		return
	}

	eligible := 0
	var restore, demote []string
	seen := map[string]bool{}
	for _, h := range hosts {
		seen[h.Name] = true
		o := obs[h.Name]
		row, hasRow := rows[h.Name]
		if hasRow && row.Demoted {
			delete(c.relay.failingSince, h.Name)
			if relayRestoreClean(o) {
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
		held := hasRow && row.Held(now)
		if !held && o.observers > 0 && o.failing >= relayFailingBar(o.observers) && !fenceCandidates[h.Name] {
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
	// A demotion row for a host that no longer exists is cleared, so a host
	// later added under the name does not start out demoted.
	var gone []string
	for name, row := range rows {
		if row.Demoted && !seen[name] {
			gone = append(gone, name)
		}
	}

	// One change per cycle. A clear or a restore goes first: it only ever
	// adds a relay candidate back.
	sort.Strings(gone)
	sort.Strings(restore)
	sort.Strings(demote)
	changes := 0
	type undo struct{ host, reason string }
	var undos []undo
	for _, h := range gone {
		undos = append(undos, undo{h, "host removed from the cluster"})
	}
	for _, h := range restore {
		undos = append(undos, undo{h, fmt.Sprintf("below the demotion bar for %s", RelayRestoreWindow)})
	}
	for _, u := range undos {
		if changes >= relayChangesPerCycle {
			return
		}
		d := corrosion.RelayDemotion{Demoted: false, Since: now.UTC().Format(time.RFC3339), Reason: u.reason}
		if err := corrosion.SetRelayDemotion(ctx, c.db, u.host, d, c.hostName); err != nil {
			slog.Warn("relay health: restore", "host", u.host, "error", err)
			return
		}
		changes++
		if seen[u.host] {
			eligible++
		}
		delete(c.relay.healthySince, u.host)
		slog.Info("relay health: host restored to relay eligibility", "host", u.host, "reason", d.Reason)
	}
	floor := c.relayFloor()
	for _, h := range demote {
		if changes >= relayChangesPerCycle {
			return
		}
		if eligible-1 < floor {
			slog.Info("relay health: not demoting; the election needs every eligible host as a relay",
				"host", h, "eligible", eligible, "floor", floor)
			return
		}
		o := obs[h]
		d := corrosion.RelayDemotion{
			Demoted: true,
			Since:   now.UTC().Format(time.RFC3339),
			Reason: fmt.Sprintf("%d of %d voter observers reported probe failures on every evaluation for %s",
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

// relayFloor is the fewest eligible hosts a demotion may leave: R for the
// membership the replicator elects over (self included), and never below
// BaseRelays. Below R the election fills the missing relay slots from the
// ineligible hosts in name order — the demoted host among them — so the
// demotion would be written and logged while changing nothing.
func (c *Coordinator) relayFloor() int {
	names := map[string]bool{c.hostName: true}
	for _, m := range c.db.Members() {
		names[m.Name] = true
	}
	floor := c.RelayConfig.RelayCount(len(names))
	base := c.RelayConfig.BaseRelays
	if base <= 0 {
		base = 3 // corrosion.RelayConfig's default
	}
	if floor < base {
		floor = base
	}
	return floor
}

// relayObservations counts, per host in targets: its observers — every voter
// other than itself, minus any discounted observer; how many of them are
// failing it (a FRESH failing verdict); and how many active hosts hold a
// verdict on it at all. Like the fence query it reads tombstoned rows too: a
// receiver on the previous release can hold a live verdict marked deleted
// (corrosion/observation_replace.go).
//
// The denominator is the voter set, not the verdicts this replica happens to
// hold: a voter whose first verdict has not replicated here yet, or that has
// not probed yet, is not evidence of failure, and leaving it out let one
// failing observer of four read as one of three — the bar — on a replica a
// verdict behind. An observer failing more than half of the hosts it holds a
// verdict on is discounted (see the file comment).
func (c *Coordinator) relayObservations(ctx context.Context, voters, active map[string]bool, targets []string, now time.Time) (map[string]relayObservation, error) {
	rows, err := c.db.Query(ctx,
		`SELECT target, observer, consecutive_failures, updated_at FROM host_health`)
	if err != nil {
		return nil, err
	}
	past, future := now.Add(-healthFreshness), now.Add(healthFreshness)
	type verdict struct {
		observer, target string
		fresh, failing   bool
	}
	var vs []verdict
	observed := map[string]int{}  // observer → hosts it holds a verdict on
	failingOf := map[string]int{} // observer → of those, fresh failing
	for _, r := range rows {
		t, o := r.String("target"), r.String("observer")
		if !countsAsVote(voters, o, t) {
			continue
		}
		inst, ok := corrosion.ParseUpdatedAt(r.String("updated_at"))
		if !ok || inst.After(future) {
			continue // unreadable, or stamped by a clock running ahead
		}
		fresh := inst.After(past)
		f := fresh && r.Int("consecutive_failures") > 0
		vs = append(vs, verdict{o, t, fresh, f})
		observed[o]++
		if f {
			failingOf[o]++
		}
	}
	discounted := func(o string) bool { return 2*failingOf[o] > observed[o] }
	out := make(map[string]relayObservation, len(targets))
	for _, v := range vs {
		if discounted(v.observer) {
			continue // this observer is the fault
		}
		ob := out[v.target]
		if v.failing {
			ob.failing++
		}
		if active[v.observer] {
			ob.live++
		}
		out[v.target] = ob
	}
	for _, t := range targets {
		ob := out[t]
		ob.observers = 0
		for v := range voters {
			if v != t && !discounted(v) {
				ob.observers++
			}
		}
		out[t] = ob
	}
	return out, nil
}
