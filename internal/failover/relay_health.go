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
//   - DEMOTE a host when at least the bar (relayFailingBar: a third of the
//     observers, never fewer than 2, a majority of a voter set of 4 or fewer)
//     of its voter observers report probe failures, on EVERY evaluation across
//     RelayDemoteWindow, while it is not a fence candidate. One evaluation
//     below the bar restarts the window, so an alternating fail/ok pattern
//     never demotes.
//   - RESTORE it after RelayRestoreWindow below that bar, with at least one
//     active observer holding a verdict on it (silence is not health). Below
//     the bar, not zero: one flaky observer must not hold a demotion in place
//     for good.
//   - Never count toward the floor an active host the election cannot see
//     (missing from membership).
//   - At most ONE change per cycle.
//   - Never demote below R, the relay count the election needs (and never
//     below BaseRelays): a demotion that would only be filled back in by the
//     demoted host itself changes nothing and would misreport.
//   - Never demote a host an operator restored with a hold
//     (`lv cluster relay-restore --hold`) until the hold runs out, and
//     restore at once a host found demoted under one. The hold is a
//     relay_hold/<host> row of its own, which this evaluator never writes for
//     a host that exists (it only ends a removed host's hold), so
//     its last-writer-wins demotion row cannot erase a hold that reached it a
//     moment late; and the hold is re-read just before a demotion is written.
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
// An observer whose fresh failing verdicts cover more than half of the JUDGED
// hosts it observes (active, non-witness: the ones this evaluator demotes —
// never a host that is down, removed or tombstoned, which every live
// observer fails) is DISCOUNTED for the evaluation: a host whose outbound probes
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
	// ceil(observers / RelayFailingDivisor) failing observers (see
	// relayFailingBar for the floors).
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
	heldLogged   map[string]string    // held host → the hold it was last logged under
}

func (s *relayHealthState) reset() {
	s.failingSince = map[string]time.Time{}
	s.healthySince = map[string]time.Time{}
	if s.heldLogged == nil {
		s.heldLogged = map[string]string{}
	}
}

// relayObservation is one host's voter verdicts this evaluation.
type relayObservation struct {
	observers int // voters other than the host, discounted observers excluded
	failing   int // of those, with a FRESH failing verdict
	live      int // of those, whose own host is active and holds a verdict on it
	bar       int // failing observers that qualify it for demotion (relayFailingBar)
}

// relayFailingBar is the number of failing observers that qualifies a host
// for demotion. One rule for every target, voter or not:
//
//   - a third of n, the observers a voter target has (the counted voters
//     less one) — the spec's bar;
//   - never fewer than 2: one observer's view is never enough;
//   - with 4 or fewer voters (an adopted generation can be that small in a
//     large cluster) a third of the observers is a single one, so the bar is
//     a majority of the voters instead.
func relayFailingBar(n, voters int) int {
	d := RelayFailingDivisor
	if d < 1 {
		d = 1
	}
	bar := (n + d - 1) / d
	if bar < 2 {
		bar = 2
	}
	if voters <= 4 {
		if m := voters/2 + 1; m > bar {
			bar = m
		}
	}
	return bar
}

// relayRestoreClean reports whether an evaluation counts toward a demoted
// host's restore window: an active observer vouches for it, and it is below
// the demotion bar.
func relayRestoreClean(o relayObservation) bool {
	return o.live > 0 && o.failing < o.bar
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
	holds, err := corrosion.ListRelayHolds(ctx, c.db)
	if err != nil {
		fail("read holds", err)
		return
	}
	// judged is the hosts this evaluator would demote or restore: active and
	// not witnesses. Only verdicts about them say anything about an
	// observer's own health (relayObservations).
	active := make(map[string]bool, len(hosts))
	judged := make(map[string]bool, len(hosts))
	names := make([]string, 0, len(hosts))
	for _, h := range hosts {
		names = append(names, h.Name)
		if h.State == "active" {
			active[h.Name] = true
			if !h.IsWitness() {
				judged[h.Name] = true
			}
		}
	}
	obs, err := c.relayObservations(ctx, voters, active, judged, names, now)
	if err != nil {
		fail("read host_health", err)
		return
	}
	members := c.relayMembers()

	eligible := 0
	var restore, demote []string
	seen := map[string]bool{}
	for _, h := range hosts {
		seen[h.Name] = true
		o := obs[h.Name]
		row, hasRow := rows[h.Name]
		held := holds[h.Name].Active(now)
		if hasRow && row.Demoted {
			delete(c.relay.failingSince, h.Name)
			if held {
				// A demotion under an operator's hold is one that raced the
				// hold's replication: the hold wins.
				restore = append(restore, h.Name)
				continue
			}
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
		// Only a host the election can see counts toward the floor: an active
		// host missing from membership is not elected whatever its row says.
		if members[h.Name] {
			eligible++
		}
		qualifies := o.observers > 0 && o.failing >= o.bar && !fenceCandidates[h.Name]
		if qualifies {
			// The window runs under a hold too, so the hold is reported when
			// it actually stops a demotion — after the stable window — not on
			// the first failing evaluation.
			since, ok := c.relay.failingSince[h.Name]
			if !ok {
				c.relay.failingSince[h.Name] = now
			} else if now.Sub(since) >= RelayDemoteWindow {
				if !held {
					demote = append(demote, h.Name)
				} else if c.relay.heldLogged[h.Name] != holds[h.Name].Until {
					c.relay.heldLogged[h.Name] = holds[h.Name].Until
					slog.Warn("relay health: not demoting; an operator hold is in force",
						"host", h.Name, "hold_until", holds[h.Name].Until, "by", holds[h.Name].By,
						"failing", o.failing, "observers", o.observers)
				}
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

	// A removed host's hold ends with it, so a host later added under the
	// name never starts out held. This is the one hold write the lease holder
	// makes, and only for a name no host carries: an operator's hold on a
	// host that exists is never touched.
	for name, h := range holds {
		if seen[name] || !h.Active(now) {
			continue
		}
		end := corrosion.RelayHold{Until: now.UTC().Format(time.RFC3339), Since: h.Since, By: h.By}
		if err := corrosion.SetRelayHold(ctx, c.db, name, end, c.hostName); err != nil {
			slog.Warn("relay health: end a removed host's hold", "host", name, "error", err)
		} else {
			slog.Info("relay health: removed host's relay hold ended", "host", name)
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
		reason := fmt.Sprintf("below the demotion bar for %s", RelayRestoreWindow)
		if holds[h].Active(now) {
			reason = "operator hold until " + holds[h].Until
		}
		undos = append(undos, undo{h, reason})
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
		if members[u.host] {
			eligible++
		}
		delete(c.relay.healthySince, u.host)
		slog.Info("relay health: host restored to relay eligibility", "host", u.host, "reason", d.Reason)
	}
	floor := c.relayFloor(len(members))
	for _, h := range demote {
		if changes >= relayChangesPerCycle {
			return
		}
		if eligible-1 < floor {
			slog.Info("relay health: not demoting; the election needs every eligible host as a relay",
				"host", h, "eligible", eligible, "floor", floor)
			return
		}
		// Re-read the hold just before writing: one an operator set since this
		// cycle's read must not be overtaken by this demotion.
		if hs, err := corrosion.ListRelayHolds(ctx, c.db); err != nil || hs[h].Active(now) {
			continue
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

// relayMembers is the membership the replicator elects over: this node's
// admitted gossip members and itself.
func (c *Coordinator) relayMembers() map[string]bool {
	names := map[string]bool{c.hostName: true}
	for _, m := range c.db.Members() {
		names[m.Name] = true
	}
	return names
}

// relayFloor is the fewest eligible hosts a demotion may leave: R for the
// membership the replicator elects over (n nodes, self included), and never
// below BaseRelays. Below R the election fills the missing relay slots from
// the ineligible hosts in name order — the demoted host among them — so the
// demotion would be written and logged while changing nothing.
func (c *Coordinator) relayFloor(n int) int {
	floor := c.RelayConfig.RelayCount(n)
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
// failing it (a FRESH failing verdict); how many active hosts hold a verdict
// on it at all; and the demotion bar. Like the fence query it reads
// tombstoned rows for the vote: a receiver on the previous release can hold a
// live verdict marked deleted (corrosion/observation_replace.go).
//
// The denominator is the voter set, not the verdicts this replica happens to
// hold: a voter whose first verdict has not replicated here yet, or that has
// not probed yet, is not evidence of failure, and leaving it out let one
// failing observer of four read as one of three on a replica a verdict
// behind.
//
// An observer failing more than half of the JUDGED hosts it holds a verdict
// on — active, non-witness hosts: the ones this evaluator demotes — is
// discounted (see the file comment). Verdicts about a host that is down
// (offline, fenced, in maintenance), removed, or tombstoned say nothing about
// the observer: every live observer fails a powered-off host, and counting
// those discarded exactly the healthy observers during a multi-host incident.
func (c *Coordinator) relayObservations(ctx context.Context, voters, active, judged map[string]bool, targets []string, now time.Time) (map[string]relayObservation, error) {
	rows, err := c.db.Query(ctx,
		`SELECT target, observer, consecutive_failures, updated_at, deleted_at FROM host_health`)
	if err != nil {
		return nil, err
	}
	past, future := now.Add(-healthFreshness), now.Add(healthFreshness)
	type verdict struct {
		observer, target string
		fresh, failing   bool
	}
	var vs []verdict
	observed := map[string]int{}  // observer → judged hosts it holds a live verdict on
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
		if judged[t] && r.String("deleted_at") == "" {
			observed[o]++
			if f {
				failingOf[o]++
			}
		}
	}
	discounted := func(o string) bool { return 2*failingOf[o] > observed[o] }
	counted := 0
	for v := range voters {
		if !discounted(v) {
			counted++
		}
	}
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
	bar := relayFailingBar(counted-1, len(voters))
	for _, t := range targets {
		ob := out[t]
		ob.observers = counted
		if voters[t] && !discounted(t) {
			ob.observers--
		}
		ob.bar = bar
		out[t] = ob
	}
	return out, nil
}
