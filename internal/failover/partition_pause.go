package failover

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
)

// Partition pause, the majority side (docs/design/partition-pause.md §4).
//
// With partition_pause_v1 latched, a host cut off from the voter majority
// suspends its recoverable workloads within T_pause. A coordinator whose
// best-effort fence could not reach such a host — assurance assumed — records
// the fence as self-pause (assurance self_paused) instead, and starts nothing
// for that host until health.PartitionPauseWaitFor has passed since its
// decision, measured on this process's monotonic clock from the later of the
// decision and its own last contact with the host. At the deadline it
// recovers only if the host is still down and cannot hold a voter majority
// (selfPauseStillStands). Unlatched, nothing here runs and failover is
// unchanged.

// pauseWait is one host's pending recovery, held until its deadline.
type pauseWait struct {
	deadline time.Time // monotonic (c.mono)
	fenceAt  time.Time // c.now() at the fence, for fenceStillStands
	wait     time.Duration
}

// mono is the monotonic clock the pause deadline is measured on. It is never
// c.now(): that is a wall (or, in the fleet, virtual) clock and the deadline is
// a duration the minority measures on its own monotonic clock.
func (c *Coordinator) mono() time.Time {
	if c.Mono != nil {
		return c.Mono()
	}
	return time.Now()
}

// relyOnPartitionPause reports whether this coordinator may rely on h pausing
// itself: the predicate (flag && partition_pause_v1 latched) holds, and the
// host has no open partition_pause_failed in this replica. A read error does
// not rely (§4.3).
func (c *Coordinator) relyOnPartitionPause(ctx context.Context, h *corrosion.HostRecord) bool {
	if c.PartitionPauseEnforced == nil || !c.PartitionPauseEnforced(ctx) {
		return false
	}
	// The host's own word, from the latest probe that reached it: the flag
	// changes only with a restart, and the probe reaches each run within a
	// probe interval, which a cached Ping does not (§4.3).
	if c.PeerPausesOnLoss == nil || !c.PeerPausesOnLoss(h.Name) {
		slog.Warn("failover: the host's latest probe answer did not say it pauses on losing the majority; not relying on its pause",
			"host", h.Name)
		return false
	}
	failed, err := corrosion.HostPartitionPauseFailed(ctx, c.db, h.Name)
	if err != nil {
		slog.Warn("failover: could not read whether the host's partition pause failed; not relying on it",
			"host", h.Name, "error", err)
		return false
	}
	if failed {
		slog.Warn("failover: the host reported its partition pause FAILED; recovering on the best-effort fence alone, as without partition pause",
			"host", h.Name)
		return false
	}
	return true
}

// reliesOnPauseIfAssumed is relyOnPartitionPause, decided BEFORE a fence of h
// runs, and only for a host whose fence can come back assumed (the
// best-effort strategy). It is read before the fence for the reason
// fence_state_v1 is: until partition_pause_v1 latches its predicate runs a
// live Ping sweep, and between a successful fence and the write that records
// it, a leader that died or lost its lease in the sweep lost the record of a
// fence that had happened.
func (c *Coordinator) reliesOnPauseIfAssumed(ctx context.Context, h *corrosion.HostRecord) bool {
	return fence.ResolveStrategy(h.FenceStrategy) == "best-effort" && c.relyOnPartitionPause(ctx, h)
}

// asSelfPause rewrites an assumed best-effort fence result as a self-pause
// one when the pause may be relied on (relied, decided before the fence by
// reliesOnPauseIfAssumed). Any other result is returned as is.
func asSelfPause(fr fence.Result, relied bool) fence.Result {
	if !fr.Success || fr.Method != "best-effort-ssh" || !relied {
		return fr
	}
	// The method stays best-effort-ssh, so an older coordinator reads the row
	// as the assumed fence it always was; the reliance rides in the detail.
	fr.Detail = corrosion.FencePauseReliance + fr.Detail
	return fr
}

// partitionPauseWait is W for this cluster: the minority may probe every
// non-maintenance host, and a voter generation mid-change counts at whichever
// size is larger (§4.4). A read error takes the largest count readable.
func (c *Coordinator) partitionPauseWait(ctx context.Context) (time.Duration, int) {
	size := 0
	if hosts, err := corrosion.ListHosts(ctx, c.db); err == nil {
		for _, h := range hosts {
			if h.State != "maintenance" {
				size++
			}
		}
	}
	if adopted, err := corrosion.AdoptedVoterGeneration(ctx, c.db); err == nil {
		if cfgs, err := corrosion.ListVoterConfigs(ctx, c.db); err == nil {
			for _, cfg := range cfgs {
				if cfg != nil && cfg.Generation >= adopted && len(cfg.Members) > size {
					size = len(cfg.Members)
				}
			}
		}
	}
	targets := size - 1
	if targets < 1 {
		targets = 1
	}
	waitFor := health.PartitionPauseWaitFor
	if c.PauseWaitFor != nil {
		waitFor = c.PauseWaitFor
	}
	return waitFor(targets), targets
}

// pauseDeadlinePassed is recoverFenced's gate for a self-pause fence. The
// first call for a host starts its wait and returns false; later calls report
// whether the deadline has passed. The wait is re-checked by retryPauseWait.
func (c *Coordinator) pauseDeadlinePassed(ctx context.Context, h *corrosion.HostRecord) bool {
	if c.pauseWaits == nil {
		c.pauseWaits = map[string]pauseWait{}
	}
	if w, ok := c.pauseWaits[h.Name]; ok {
		return !c.mono().Before(w.deadline)
	}
	now := c.mono()
	anchor := now
	if c.LastContact != nil {
		if lc, ok := c.LastContact(h.Name); ok && lc.After(anchor) {
			anchor = lc
		}
	}
	wait, targets := c.partitionPauseWait(ctx)
	w := pauseWait{deadline: anchor.Add(wait), fenceAt: c.now(), wait: wait}
	c.pauseWaits[h.Name] = w
	slog.Warn("failover: relying on the host's partition pause — starting no replacement until its pause has certainly happened",
		"host", h.Name, "wait", wait, "probe_targets", targets, "assurance", corrosion.FenceSelfPaused)
	c.mAttempt(PhaseSplitBrain, ResultRefused, ErrPartitionPauseWait)
	return wait <= 0
}

// retryPauseWait handles a host whose recovery is waiting out its partition
// pause. It reports whether the host was such a host (the caller then does
// nothing more with it this cycle).
func (c *Coordinator) retryPauseWait(ctx context.Context, host string) bool {
	w, ok := c.pauseWaits[host]
	if !ok {
		return false
	}
	h, err := corrosion.GetHost(ctx, c.db, host)
	if err != nil || h == nil {
		return true // retried next cycle
	}
	if h.State != "fenced" && h.State != "offline" {
		delete(c.pauseWaits, host)
		slog.Info("failover: host is back before its partition-pause deadline; recovering nothing", "host", host, "state", h.State)
		return true
	}
	if c.mono().Before(w.deadline) {
		return true
	}
	delete(c.pauseWaits, host)
	why, only, ok := c.selfPauseStillStands(ctx, h, w.fenceAt)
	if !ok {
		slog.Warn("failover: partition-pause deadline passed, but the host may not have paused or has come back; recovering nothing",
			"host", host, "why", why)
		return true
	}
	slog.Info("failover: partition-pause deadline passed; recovering the host's workloads",
		"host", host, "waited", w.wait, "assurance", corrosion.FenceSelfPaused, "only_reported_paused", only != nil)
	if only != nil {
		if c.recoverOnly == nil {
			c.recoverOnly = map[string]map[string]bool{}
		}
		c.recoverOnly[host] = only
		defer delete(c.recoverOnly, host)
	}
	c.recoverWorkloads(ctx, h)
	return true
}

// selfPauseStillStands is fenceStillStands for a self-pause fence at its
// deadline (docs/design/partition-pause.md §4.2 step 3).
//
// A self-paused host is meant to be up: it is paused, not off. So an observer
// that has seen it answer since the fence does not by itself show that the
// pause failed. A non-voting witness that reaches both halves of a split, and
// the other voters of the host's minority whose verdicts it relays, see it
// answer for as long as the split lasts. But such an answer is also all the
// majority would see of a host that never paused: one that counts its
// majority over a voter set this node does not know (a generation it has not
// adopted, a scope change it has not seen), or one cut off in one direction
// only (§7 F4). Inferring the host's own count cannot tell these apart, so
// the deadline asks the host itself. Once some observer has seen it answer
// since the fence, the majority recovers only on the host's own word that it
// paused: its replicated partition_paused condition, open, and raised during
// this outage, and then only the workloads it lists. A host that never paused
// never raised it. When no observer has seen it answer, this is
// fenceStillStands as before.
//
// On top of that, the host must not hold a voter majority by this node's
// count: the voters whose latest verdict about it is an answer, of any age,
// counting the host itself when it is a voter, are not a majority of any
// voter set it may be counting over (pauseVoterSets). That refuses a host
// that has come back.
//
// Two cases keep fenceStillStands' rule unchanged, where any observer that
// has seen the host answer since the fence refuses:
//
//   - the pause can no longer be relied on (relyOnPartitionPause): the host
//     has reported its pause failed, or no longer says it pauses;
//   - the voter set is derived, or a newer generation is a reset
//     (pauseVoterSets).
func (c *Coordinator) selfPauseStillStands(ctx context.Context, h *corrosion.HostRecord, at time.Time) (why string, only map[string]bool, ok bool) {
	if !c.relyOnPartitionPause(ctx, h) {
		why, ok = c.fenceStillStands(ctx, h.Name, at)
		return why, nil, ok
	}
	sets, explicit, err := c.pauseVoterSets(ctx, h.Name)
	if err != nil {
		slog.Warn("failover: voter set read for a partition-pause deadline failed", "host", h.Name, "error", err)
		c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
		return "voter set unreadable", nil, false
	}
	if !explicit {
		why, ok = c.fenceStillStands(ctx, h.Name, at)
		return why, nil, ok
	}
	if !c.observerStreakSpans(ctx, h.Name, at) {
		return "no observer has watched the host stay down since the fence", nil, false
	}
	if why, ok := c.answeredByAVoterMajority(ctx, h.Name, sets); !ok {
		return why, nil, false
	}
	answered, quiet := c.answeredSince(ctx, h.Name, at)
	if quiet {
		return "", nil, true
	}
	if answered == whyHealthUnreadable {
		return answered, nil, false
	}
	paused, reason, ok := c.hostReportsItsPause(ctx, h.Name, at, sets)
	if !ok {
		return answered + ", and " + reason, nil, false
	}
	return "", paused, true
}

// hostReportsItsPause reads host's own replicated partition_paused
// condition. It holds when the condition is open, lists the workloads the
// host paused (returned as "kind/name" keys, which alone may then be
// recovered: the host's word covers what it paused, nothing more), and was
// raised during the outage the fence at `at` rests on (outageStart). Not
// "after the fence": a minority host pauses T_pause after it loses the
// majority, which can be well before a coordinator decides, as when the lease
// first had to move. It fails closed.
func (c *Coordinator) hostReportsItsPause(ctx context.Context, host string, at time.Time, sets []map[string]bool) (map[string]bool, string, bool) {
	cond, ok, err := corrosion.GetHealthCondition(ctx, c.db, corrosion.PartitionPauseEvaluator,
		corrosion.CondPartitionPaused, "host", host)
	if err != nil {
		slog.Warn("failover: partition_paused read for a partition-pause deadline failed", "host", host, "error", err)
		c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
		return nil, "its partition_paused condition is unreadable", false
	}
	if !ok || cond.Lifecycle == corrosion.ConditionResolved {
		return nil, "the host has not reported pausing anything", false
	}
	var ev struct {
		Paused []string `json:"paused"`
	}
	if err := json.Unmarshal([]byte(cond.Evidence), &ev); err != nil || len(ev.Paused) == 0 {
		return nil, "its partition_paused condition names no paused workload", false
	}
	start, ok := c.outageStart(ctx, host, at, sets)
	if !ok {
		return nil, "too few voters have watched the host fail since before the fence to date the outage", false
	}
	raised, ok := corrosion.ParseUpdatedAt(cond.FirstSeen)
	if !ok || raised.Before(start.Add(-fenceSkewMargin)) {
		return nil, "its partition_paused condition (raised " + cond.FirstSeen + ") predates this outage", false
	}
	paused := make(map[string]bool, len(ev.Paused))
	for _, k := range ev.Paused {
		paused[k] = true
	}
	return paused, "", true
}

// outageStart dates the outage a fence of host at `at` rests on: the moment
// the host can first have lost its majority. Over each voter set in sets, of
// n members with a majority of q, it takes the failing runs of the set's
// voters (not host) that span the fence (observerStreakSpans' rows) and
// returns the (n−q+1)-th earliest start: the host cannot have lost its
// majority before that many voters stopped answering. Voters that are down
// and not observed only make the true moment earlier, and one observer that
// has been failing the host for long, or a non-voter, cannot pull it back.
// With several sets it is the latest of their answers. ok is false when any
// set has fewer such runs than that.
func (c *Coordinator) outageStart(ctx context.Context, host string, at time.Time, sets []map[string]bool) (time.Time, bool) {
	rows, err := c.db.Query(ctx,
		`SELECT observer, consecutive_failures, last_seen, updated_at FROM host_health
		 WHERE target = ? AND status != ?`, host, health.StatusUnready)
	if err != nil {
		return time.Time{}, false
	}
	freshCutoff := c.now().Add(-healthFreshness)
	runs := map[string]time.Time{}
	for _, r := range rows {
		n := r.Int("consecutive_failures")
		if n < offlineThreshold {
			continue
		}
		upd, ok := corrosion.ParseUpdatedAt(r.String("updated_at"))
		if !ok || !upd.After(freshCutoff) {
			continue
		}
		run := observerRunStart(n, r.String("last_seen"), upd)
		if run.After(at.Add(-fenceSkewMargin)) {
			continue
		}
		runs[r.String("observer")] = run
	}
	var latest time.Time
	for _, set := range sets {
		var starts []time.Time
		for v := range set {
			if run, ok := runs[v]; ok && v != host {
				starts = append(starts, run)
			}
		}
		need := len(set) - (len(set)/2 + 1) + 1
		if need < 1 || len(starts) < need {
			return time.Time{}, false
		}
		sort.Slice(starts, func(i, j int) bool { return starts[i].Before(starts[j]) })
		if s := starts[need-1]; s.After(latest) {
			latest = s
		}
	}
	return latest, !latest.IsZero()
}

// answeredByAVoterMajority reports false, and why, when the voters whose
// latest verdict about host is an answer (healthy or unready, the verdicts
// answeredSince reads as one), counting host itself when it is a voter, are
// a majority of any of sets. An empty set, or none, refuses. It fails closed
// on a read error.
func (c *Coordinator) answeredByAVoterMajority(ctx context.Context, host string, sets []map[string]bool) (string, bool) {
	rows, err := c.db.Query(ctx,
		`SELECT observer, status, consecutive_failures FROM host_health WHERE target = ?`, host)
	if err != nil {
		slog.Warn("failover: host_health read for a partition-pause deadline failed", "host", host, "error", err)
		c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
		return whyHealthUnreadable, false
	}
	answered := map[string]bool{}
	for _, r := range rows {
		if r.String("observer") == host {
			continue
		}
		if r.Int("consecutive_failures") == 0 || r.String("status") == health.StatusUnready {
			answered[r.String("observer")] = true
		}
	}
	if len(sets) == 0 {
		return "no voter set to count over", false
	}
	for _, set := range sets {
		if len(set) == 0 {
			return "an empty voter set to count over", false
		}
		var live []string
		for v := range set {
			if v == host || answered[v] {
				live = append(live, v)
			}
		}
		if len(live) >= len(set)/2+1 {
			sort.Strings(live)
			return fmt.Sprintf("voters %s last saw the host answer, %d of %d counting itself: it may hold its majority",
				strings.Join(live, ","), len(live), len(set)), false
		}
	}
	return "", true
}

// pauseVoterSets is every voter set host's pauser may be counting its
// majority over, as far as this node's replica knows: the set this cycle
// decides on (c.scope.voters, host's region's under region scope) and each
// newer generation this node has not adopted yet. explicit is false while
// the voter set is derived, or when a newer generation is a reset (which a
// host that adopted it counts over its own derived set).
func (c *Coordinator) pauseVoterSets(ctx context.Context, host string) (sets []map[string]bool, explicit bool, err error) {
	adopted, err := corrosion.AdoptedVoterConfig(ctx, c.db)
	if err != nil || !adopted.Explicit() {
		return nil, false, err
	}
	cfgs, err := corrosion.ListVoterConfigs(ctx, c.db)
	if err != nil {
		return nil, false, err
	}
	sets = []map[string]bool{c.scope.voters(host)}
	for _, cfg := range cfgs {
		if cfg == nil || cfg.Generation <= adopted.Generation {
			continue
		}
		if !cfg.Explicit() {
			return nil, false, nil
		}
		set := map[string]bool{}
		for _, m := range cfg.Members {
			if !c.scope.region || c.scope.regionOf(m.Name) == c.scope.regionOf(host) {
				set[m.Name] = true
			}
		}
		sets = append(sets, set)
	}
	return sets, true, nil
}

// ── one-way partitions (docs/design/partition-pause.md §7 F4) ──────────────

// oneWayEvidence is partition_one_way's evidence.
type oneWayEvidence struct {
	FailingObservers []string `json:"failing_observers"`
	HealthyInItsView []string `json:"healthy_in_its_view"`
	Detail           string   `json:"detail"`
}

// detectOneWay reports, for a fence candidate target, the quorum observers
// failing it and the voters target itself marked healthy AFTER that voter's
// failure streak against it began, when those make target count a majority
// while a quorum of voters cannot reach it: the one-way case, in which the
// host may never pause. It changes no decision.
func (c *Coordinator) detectOneWay(ctx context.Context, target string) (failing, healthy []string, oneWay bool) {
	voters := c.scope.voters(target)
	rows, err := c.db.Query(ctx,
		`SELECT observer, target, status, consecutive_failures, last_seen, updated_at FROM host_health
		 WHERE (target = ? AND consecutive_failures >= ?) OR (observer = ? AND consecutive_failures = 0)`,
		target, offlineThreshold, target)
	if err != nil {
		return nil, nil, false
	}
	freshCutoff := c.now().Add(-healthFreshness)
	streakStart := map[string]time.Time{}
	lastFailed := map[string]time.Time{}
	type seen struct {
		peer string
		at   time.Time
	}
	var targetSaw []seen
	for _, r := range rows {
		upd, ok := corrosion.ParseUpdatedAt(r.String("updated_at"))
		if !ok {
			continue
		}
		obs, tgt := r.String("observer"), r.String("target")
		if tgt == target && obs != target && countsAsVote(voters, obs, target) && upd.After(freshCutoff) &&
			r.String("status") != health.StatusUnready {
			n := r.Int("consecutive_failures")
			streakStart[obs] = observerRunStart(n, r.String("last_seen"), upd)
			lastFailed[obs] = upd
			continue
		}
		if obs == target && tgt != target && voters[tgt] {
			targetSaw = append(targetSaw, seen{tgt, upd})
		}
	}
	for o := range streakStart {
		failing = append(failing, o)
	}
	sort.Strings(failing)
	if len(failing) < c.scope.quorum(target) {
		return failing, nil, false
	}
	// Both directions at once, not one after the other: target saw the voter
	// healthy after that voter's streak against it began, AND the voter was
	// still failing target after that. A heal produces the first alone — the
	// target's new healthy rows land while the voters' last failing rows are
	// still fresh — and must not read as one-way.
	for _, s := range targetSaw {
		start, ok := streakStart[s.peer]
		if ok && s.at.After(start.Add(fenceSkewMargin)) && lastFailed[s.peer].After(s.at.Add(fenceSkewMargin)) {
			healthy = append(healthy, s.peer)
		}
	}
	sort.Strings(healthy)
	live := len(healthy)
	if voters[target] {
		live++
	}
	return failing, healthy, live >= len(voters)/2+1
}

// resolveOneWayGone resolves partition_one_way for every host it is raised for
// that is not among this cycle's fence candidates.
func (c *Coordinator) resolveOneWayGone(ctx context.Context, candidates []string) {
	if len(c.oneWay) == 0 {
		return
	}
	still := make(map[string]bool, len(candidates))
	for _, cand := range candidates {
		still[cand] = true
	}
	for host, raised := range c.oneWay {
		if raised && !still[host] {
			c.noteOneWay(ctx, host, nil, nil, false)
		}
	}
}

// noteOneWay raises or resolves partition_one_way for target. Written by the
// lease holder, the only coordinator that runs this.
func (c *Coordinator) noteOneWay(ctx context.Context, target string, failing, healthy []string, oneWay bool) {
	if c.oneWay == nil {
		c.oneWay = map[string]bool{}
	}
	if oneWay == c.oneWay[target] {
		return
	}
	ts := c.now().UTC().Format(time.RFC3339)
	row, ok, err := corrosion.GetHealthCondition(ctx, c.db, corrosion.PartitionPauseEvaluator, corrosion.CondPartitionOneWay, "host", target)
	if err != nil {
		return
	}
	if !ok {
		if !oneWay {
			c.oneWay[target] = false
			return
		}
		row = corrosion.HealthCondition{Evaluator: corrosion.PartitionPauseEvaluator, Code: corrosion.CondPartitionOneWay,
			SubjectKind: "host", SubjectID: target, FirstSeen: ts}
	}
	if oneWay {
		if row.Lifecycle == corrosion.ConditionResolved {
			row.FirstSeen, row.ConfirmedAt, row.ObserveCount = ts, "", 0
		}
		row.Lifecycle, row.ResolvedAt, row.CleanCount = corrosion.ConditionConfirmed, "", 0
		if row.ConfirmedAt == "" {
			row.ConfirmedAt = ts
		}
		row.ObserveCount++
		b, _ := json.Marshal(oneWayEvidence{FailingObservers: failing, HealthyInItsView: healthy,
			Detail: fmt.Sprintf("a quorum of voters cannot reach %s while %s still reaches enough of them for a majority: "+
				"a one-way partition, in which it may never pause its workloads", target, target)})
		row.Evidence = string(b)
		slog.Error("failover: ONE-WAY partition — the host counts a majority healthy while a quorum of voters cannot reach it; it may not pause",
			"host", target, "failing_observers", strings.Join(failing, ","), "healthy_in_its_view", strings.Join(healthy, ","))
	} else {
		if row.Lifecycle == corrosion.ConditionResolved {
			c.oneWay[target] = false
			return
		}
		row.Lifecycle, row.ResolvedAt, row.ObserveCount, row.CleanCount = corrosion.ConditionResolved, ts, 0, 1
	}
	row.Severity, row.Hosts, row.LastSeen, row.Reporter = corrosion.SeverityCritical, []string{target}, ts, c.hostName
	if err := corrosion.UpsertHealthCondition(ctx, c.db, row); err != nil {
		slog.Warn("failover: could not record partition_one_way", "host", target, "error", err)
		return
	}
	c.oneWay[target] = oneWay
}
