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
// recovers only if the host is still down and no observer has seen it answer
// since the fence. Unlatched, nothing here runs and failover is unchanged.

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

// asSelfPause rewrites an assumed best-effort fence result as a self-pause
// one when the pause may be relied on. Any other result is returned as is.
func (c *Coordinator) asSelfPause(ctx context.Context, h *corrosion.HostRecord, fr fence.Result) fence.Result {
	if !fr.Success || fr.Method != "best-effort-ssh" || !c.relyOnPartitionPause(ctx, h) {
		return fr
	}
	fr.Method = corrosion.FenceMethodSelfPause
	fr.Detail = "best-effort fence did not reach the host; relying on its partition pause: " + fr.Detail
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
	if why, ok := c.fenceStillStands(ctx, host, w.fenceAt); !ok {
		slog.Warn("failover: partition-pause deadline passed, but the host has answered since the fence; recovering nothing",
			"host", host, "why", why)
		return true
	}
	slog.Info("failover: partition-pause deadline passed; recovering the host's workloads",
		"host", host, "waited", w.wait, "assurance", corrosion.FenceSelfPaused)
	c.recoverWorkloads(ctx, h)
	return true
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
		`SELECT observer, target, status, consecutive_failures, updated_at FROM host_health
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
			streakStart[obs] = upd.Add(-time.Duration(n-1) * health.ProbeInterval)
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
