package failover

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
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
	refused  string // the kind of the deadline's last refusal (pauseVerdict.key), "" before it has
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
// not rely (§4.3). Why it does not rely is logged once per host and reason
// (noteNotRelying), not on every cycle that asks.
func (c *Coordinator) relyOnPartitionPause(ctx context.Context, h *corrosion.HostRecord) bool {
	if c.PartitionPauseEnforced == nil || !c.PartitionPauseEnforced(ctx) {
		return false
	}
	// The host's own word, from the latest probe that reached it: the flag
	// changes only with a restart, and the probe reaches each run within a
	// probe interval, which a cached Ping does not (§4.3).
	if c.PeerPausesOnLoss == nil || !c.PeerPausesOnLoss(h.Name) {
		c.noteNotRelying(h.Name, "no_word", func() {
			slog.Warn("failover: the host's latest probe answer did not say it pauses on losing the majority; not relying on its pause",
				"host", h.Name)
		})
		return false
	}
	failed, err := corrosion.HostPartitionPauseFailed(ctx, c.db, h.Name)
	if err != nil {
		c.noteNotRelying(h.Name, "read_error", func() {
			slog.Warn("failover: could not read whether the host's partition pause failed; not relying on it",
				"host", h.Name, "error", err)
		})
		return false
	}
	if failed {
		c.noteNotRelying(h.Name, "pause_failed", func() {
			slog.Warn("failover: the host reported its partition pause FAILED; recovering on the best-effort fence alone, as without partition pause",
				"host", h.Name)
		})
		return false
	}
	delete(c.notRelying, h.Name)
	return true
}

// noteNotRelying runs log when host's reason for not relying on its pause is
// new: it differs from the last one logged, or the pause was relied on since.
func (c *Coordinator) noteNotRelying(host, reason string, log func()) {
	if c.notRelying == nil {
		c.notRelying = map[string]string{}
	}
	if c.notRelying[host] == reason {
		return
	}
	c.notRelying[host] = reason
	log()
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
// pause. It reports whether it handled the host this cycle (the caller then
// does nothing more with it). A deadline that refuses keeps the wait and
// reports false: the deadline is re-checked on every later cycle, under the
// whole rule each time, and meanwhile an operator confirmation or a new fence
// still reaches the host.
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
	v := c.selfPauseStillStands(ctx, h, w.fenceAt, w.deadline.Add(-w.wait))
	if !v.ok {
		c.refusePauseWait(ctx, h, w, v)
		return false
	}
	only := v.only
	// The deadline went ahead: whatever its limit leaves on the host is named
	// by the stall alert (unpausedHeld), not as a bridged hold.
	c.resolveBridged(ctx, host, "the partition-pause deadline went ahead")
	slog.Info("failover: partition-pause deadline passed; recovering the host's workloads",
		"host", host, "waited", w.wait, "assurance", corrosion.FenceSelfPaused, "only_reported_paused", only != nil)
	// The limit lasts for the down-episode, not this one pass: every later
	// recovery of the host (a claim retry above all) honours it, until the
	// host is back, an operator or a proving fence vouches for it, or a later
	// deadline replaces it with the host's newer list. A later deadline at
	// which nobody has seen the host answer keeps to the host's list while its
	// condition from this outage is readable, and keeps the limit it finds
	// when there is none (pausedThisOutage).
	c.limitRecovery(host, only)
	// A claim retry this recovery leaves owed acts on this wait's start, the
	// moment the fence (or a retry's fresh wait) began it, and no observer
	// may have seen the host answer since (claimRetryOutageOver).
	c.noteRecoveryAt(host, w.fenceAt, w.deadline.Add(-w.wait))
	c.recoverWorkloads(ctx, h)
	return true
}

// refusePauseWait keeps a wait whose deadline refused, so the next cycle
// re-checks it: a read error, or a condition that replicates a moment after
// the deadline, would otherwise leave the paused workloads running nowhere
// until the lease moved. The stall alert names the refusal and its reason. A
// bridged refusal (selfPauseStillStands) also raises ha.recovery.bridged,
// and one that is no longer bridged resolves it, once per change of the
// refusal's kind (pauseVerdict.key) rather than on every re-check.
func (c *Coordinator) refusePauseWait(ctx context.Context, h *corrosion.HostRecord, w pauseWait, v pauseVerdict) {
	host := h.Name
	level := slog.LevelWarn
	switch {
	case w.refused == v.key:
		level = slog.LevelDebug // the same refusal, re-checked every cycle
	case v.bridged:
		c.noteBridgedStall(ctx, h, v.observers, v.why)
	default:
		c.resolveBridged(ctx, host, "the deadline's refusal is no longer a bridge: "+v.why)
	}
	w.refused = v.key
	c.pauseWaits[host] = w
	slog.Log(ctx, level, "failover: partition-pause deadline passed, but the host may not have paused or has come back; recovering nothing, re-checking every cycle",
		"host", host, "why", v.why)
	c.noteHold(host, "recovery refused at the partition-pause deadline ("+v.why+"); re-checked every cycle, "+
		"or 'lv host fence-confirm "+host+"' once it is off")
}

// pauseVerdict is selfPauseStillStands' answer at a self-pause deadline.
type pauseVerdict struct {
	// ok: the deadline goes ahead, recovering only (nil: everything).
	ok   bool
	only map[string]bool
	// why the deadline refused, for the log and the stall alert.
	why string
	// key is the kind of refusal: why without the observers it names, which
	// change with each observer's verdict. A refusal is logged at Warn, and
	// ha.recovery.bridged raised or resolved, only when its key changes.
	key string
	// bridged: the refusal rests only on observers having seen the host
	// answer since the fence, with no voter majority among them; observers
	// names them, sorted.
	bridged   bool
	observers []string
}

// refused is a refusal whose reason names no observer.
func refused(why string) pauseVerdict { return pauseVerdict{why: why, key: why} }

// keyAnswered is the key of a refusal on observers having seen the host
// answer since the fence (whyAnswered), and keyVoterMajority of one on a
// voter majority having seen it answer (answeredByAVoterMajority).
// keyRestarted is the key of a refusal on observers whose failing run began
// after the fence (whyRestarted), and keyContacted of one on this node having
// probed the host healthy since its wait began (whyContacted). Neither is a
// bridge: no observer's latest verdict is an answer.
const (
	keyAnswered      = "observers saw the host answer after the fence"
	keyVoterMajority = "a voter majority last saw the host answer: it may hold its majority"
	keyRestarted     = "observers' failing runs began after the fence"
	keyContacted     = "this node probed the host healthy since the wait began"
)

// whyContacted is the reason a deadline is not quiet when this node has
// probed the host healthy since the wait began (LastContact).
const whyContacted = "this node probed the host healthy since the wait began"

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
// fenceStillStands as before, except that a condition from this outage that
// is still readable keeps the recovery to the workloads it lists, and a limit
// already held for the host stands without one (pausedThisOutage).
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
//
// In both, a limit this coordinator already holds for the host keeps to the
// host's listed workloads as above (quietFallback).
//
// bridged reports a refusal that rests only on observers having seen the host
// answer since the fence, with no voter majority among them: the stall a host
// reaching both halves of a split causes (ha.recovery.bridged). A read error,
// of host_health or of the host's condition, is not one. It changes no
// decision.
//
// host_health about h is read once, and every check here is made over that
// one read.
//
// On the explicit voter set the deadline is quiet only when, besides no
// observer's latest verdict being an answer, no observer's failing run began
// after at (restartedSinceObserversIn) and this node has not probed the host
// healthy since mono, the wait's start on its monotonic clock (LastContact;
// a zero mono skips that). Either is an answer since the fence overwritten or
// unseen by the rows, and the host's own word, dated to this outage, decides.
//
// Neither holds the deadline when enough voters have failed the host without
// a break since before the fence that it cannot have held a majority since
// (noRegainSinceIn): such an answer can only have come from a bridge, and the
// host, with no majority at any moment since, cannot have resumed. On the
// derived voter set the restarted-run rule of quietFallback gives way to the
// same evidence. Answers that are still the latest verdict (a bridge that
// still stands) are not affected.
func (c *Coordinator) selfPauseStillStands(ctx context.Context, h *corrosion.HostRecord, at, mono time.Time) pauseVerdict {
	hr := c.readHostHealth(ctx, h.Name)
	if !c.relyOnPartitionPause(ctx, h) {
		v := c.quietFallback(ctx, hr, h.Name, at, false)
		v.bridged, v.observers = false, nil
		return v
	}
	sets, explicit, err := c.pauseVoterSets(ctx, h.Name)
	if err != nil {
		slog.Warn("failover: voter set read for a partition-pause deadline failed", "host", h.Name, "error", err)
		c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
		return refused("voter set unreadable")
	}
	if !explicit {
		return c.quietFallback(ctx, hr, h.Name, at, c.noRegainSinceIn(ctx, hr, h.Name, at, mono, false))
	}
	if hr.err != nil {
		slog.Warn("failover: host_health read for a partition-pause deadline failed", "host", h.Name, "error", hr.err)
		c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
		return refused(whyHealthUnreadable)
	}
	if !c.streakSpansIn(hr, h.Name, at) {
		return refused(whyNoStreakSpans)
	}
	if why, ok := c.answeredByAVoterMajorityIn(hr, h.Name, sets); !ok {
		v := refused(why)
		if strings.HasPrefix(why, "voters ") {
			v.key = keyVoterMajority
		}
		return v
	}
	answered, observers, quiet := c.answeredSinceIn(hr, h.Name, at)
	key, bridged := keyAnswered, true
	if quiet && !c.noRegainSinceIn(ctx, hr, h.Name, at, mono, true) {
		if r := restartedSinceObserversIn(hr, h.Name, at); len(r) > 0 {
			answered, observers, quiet = whyRestarted(r), nil, false
			key, bridged = keyRestarted, false
		} else if !mono.IsZero() && c.contactedSince(h.Name, mono) {
			answered, observers, quiet = whyContacted, nil, false
			key, bridged = keyContacted, false
		}
	}
	if quiet {
		why, only, ok := c.pausedThisOutageIn(ctx, hr, h.Name, at, sets)
		if !ok {
			return refused(why)
		}
		return pauseVerdict{ok: true, only: only}
	}
	paused, reason, ok := c.hostReportsItsPauseIn(ctx, hr, h.Name, at, sets)
	switch {
	case ok:
		return pauseVerdict{ok: true, only: paused}
	case reason == whyPausedUnreadable:
		// A store error, not a bridge: named on its own.
		return refused(whyPausedUnreadable)
	}
	return pauseVerdict{why: answered + ", and " + reason, key: key + ", and " + reason,
		bridged: bridged, observers: observers}
}

// quietFallback is fenceStillStands, for a deadline that keeps its rule
// (selfPauseStillStands), over host_health rows already read. With noRegain
// (noRegainSinceIn held, on a pause still relied on) a failing run begun
// after the fence does not refuse: only a latest verdict that is an answer
// does. When it holds and this coordinator already limits the host's
// recovery from earlier in the down-episode, the host's own word still
// bounds what moves:
// pausedThisOutage, dating the outage over the voter set this cycle decides
// on. A refusal on observers whose latest verdict is an answer since the
// fence is reported bridged: the form selfPauseStillStands raises on a
// derived voter set. One on failing runs begun after the fence alone, or a
// read error, is not.
func (c *Coordinator) quietFallback(ctx context.Context, hr healthRead, host string, at time.Time, noRegain bool) pauseVerdict {
	var (
		why       string
		observers []string
		ok        bool
	)
	if noRegain {
		// fenceStillStandsIn without its restarted-run rule.
		why = whyNoStreakSpans
		if c.streakSpansIn(hr, host, at) {
			why, observers, ok = c.answeredSinceIn(hr, host, at)
		}
	} else {
		why, observers, ok = c.fenceStillStandsIn(hr, host, at)
	}
	if !ok {
		switch {
		case len(observers) > 0 && len(answeredSinceObserversIn(hr, host, at)) > 0:
			return pauseVerdict{why: why, key: keyAnswered, bridged: true, observers: observers}
		case len(observers) > 0:
			// Failing runs begun after the fence: an answer the rows have
			// overwritten, not a bridge (keyRestarted).
			return pauseVerdict{why: why, key: keyRestarted}
		}
		return refused(why)
	}
	if c.recoverOnly[host] == nil {
		return pauseVerdict{ok: true}
	}
	why, only, ok := c.pausedThisOutageIn(ctx, hr, host, at, []map[string]bool{c.scope.voters(host)})
	if !ok {
		return refused(why)
	}
	return pauseVerdict{ok: true, only: only}
}

// noRegainSinceIn reports whether host cannot have held a voter majority at
// any moment since the fence at `at`, by its own count: over every voter set
// its pauser may be counting over (regainCandidates), enough voters other
// than host have failed it without a break since before the fence that the
// rest, host included, are fewer than a majority. An answer since the fence
// that the rows have overwritten (restartedSinceObserversIn), or this node's
// own probe answer (LastContact), can then only be a bridge's, as the fence
// quorum and the pause wait already assume reachability to be symmetric.
//
// A run counts as spanning only when it began at least fenceSkewMargin plus
// its observer's recorded clock skew from this node (clockSkews) before the
// fence: an observer whose clock runs behind dates its run early. When this
// node has probed the host healthy since mono, its own row is not counted: a
// probe answer can run ahead of the row that records it. Any read error, or a
// voter set it cannot know, reports false.
func (c *Coordinator) noRegainSinceIn(ctx context.Context, hr healthRead, host string, at, mono time.Time, explicit bool) bool {
	if hr.err != nil {
		return false
	}
	if !mono.IsZero() && c.contactedSince(host, mono) {
		rows := make([]corrosion.Row, 0, len(hr.rows))
		for _, r := range hr.rows {
			if r.String("observer") != c.hostName {
				rows = append(rows, r)
			}
		}
		hr = healthRead{rows: rows}
	}
	skews, err := c.clockSkews(ctx)
	if err != nil {
		slog.Warn("failover: clock_skew read for a partition-pause deadline failed", "host", host, "error", err)
		return false
	}
	cands, ok := c.regainCandidates(ctx, hr, host, explicit, skews)
	if !ok || len(cands) == 0 {
		return false
	}
	freshCutoff := c.now().Add(-healthFreshness)
	spanning := map[string]bool{}
	for _, r := range hr.rows {
		obs := r.String("observer")
		if obs == host || r.String("status") == health.StatusUnready {
			continue
		}
		n := r.Int("consecutive_failures")
		if n < offlineThreshold {
			continue
		}
		upd, ok := corrosion.ParseUpdatedAt(r.String("updated_at"))
		if !ok || !upd.After(freshCutoff) {
			continue
		}
		if !observerRunStart(n, r.String("last_seen"), upd).Add(skews[obs]).After(at.Add(-fenceSkewMargin)) {
			spanning[obs] = true
		}
	}
	for _, cand := range cands {
		if len(cand.set) == 0 {
			return false
		}
		need := len(cand.set) - (len(cand.set)/2 + 1) + 1
		have := 0
		for v := range cand.set {
			if v != host && spanning[v] && (cand.countable == nil || cand.countable[v]) {
				have++
			}
		}
		if have < need {
			return false
		}
	}
	return true
}

// regainCandidate is a voter set host's pauser may be counting its majority
// over, for noRegainSinceIn. set is the denominator. countable, when not nil,
// names the members whose spanning run counts: the others may not be in the
// host's set at all, so they are counted only against the claim. A set that
// may hold more or fewer members is checked at its worst: every member that
// may be in it, and only the runs of those that surely are.
type regainCandidate struct {
	set       map[string]bool
	countable map[string]bool
}

// regainCandidates is every voter set host's pauser may be counting over, as
// far as this replica can tell; ok is false when one cannot be known.
//
//   - Explicit (pauseVoterSets: the adopted generation and each newer one):
//     those sets, plus the generation before the adopted one, which a host
//     partitioned before it adopted the current one still counts over. Before
//     the first generation that is the derived set.
//   - Derived: the derived set as the host's replica held it when the outage
//     began (derivedRegainCandidate), plus every explicit generation this
//     node has not adopted.
func (c *Coordinator) regainCandidates(ctx context.Context, hr healthRead, host string, explicit bool, skews map[string]time.Duration) ([]regainCandidate, bool) {
	adopted, err := corrosion.AdoptedVoterConfig(ctx, c.db)
	if err != nil {
		return nil, false
	}
	cfgs, err := corrosion.ListVoterConfigs(ctx, c.db)
	if err != nil {
		return nil, false
	}
	var adoptedGen int64
	if adopted != nil {
		adoptedGen = adopted.Generation
	}
	var cands []regainCandidate
	if explicit {
		sets, ok, err := c.pauseVoterSets(ctx, host)
		if err != nil || !ok {
			return nil, false
		}
		for _, set := range sets {
			cands = append(cands, regainCandidate{set: set})
		}
		var prev *corrosion.VoterConfig
		for _, cfg := range cfgs {
			if cfg != nil && cfg.Generation < adoptedGen {
				prev = cfg
			}
		}
		if prev != nil && prev.Explicit() {
			cands = append(cands, regainCandidate{set: c.regionMembers(prev, host)})
			return cands, true
		}
	} else {
		for _, cfg := range cfgs {
			if cfg != nil && cfg.Generation > adoptedGen && cfg.Explicit() {
				cands = append(cands, regainCandidate{set: c.regionMembers(cfg, host)})
			}
		}
	}
	d, ok := c.derivedRegainCandidate(ctx, hr, host, skews)
	if !ok {
		return nil, false
	}
	return append(cands, d), true
}

// regionMembers is cfg's members, host's region's under region scope.
func (c *Coordinator) regionMembers(cfg *corrosion.VoterConfig, host string) map[string]bool {
	set := map[string]bool{}
	for _, m := range cfg.Members {
		if !c.scope.region || c.scope.regionOf(m.Name) == c.scope.regionOf(host) {
			set[m.Name] = true
		}
	}
	return set
}

// derivedRegainCandidate is the derived voter set host's pauser counts over,
// from the state its replica held when the outage began: host itself, which
// the majority has fenced since, and every host whose voting state may have
// changed since then. The outage began no later than the earliest fresh
// failing run about host, less its observer's skew and fenceSkewMargin. A
// host whose membership is unchanged since then is in the set iff it is
// voting-eligible here, and its run counts. One that changed since, or whose
// change cannot be dated, is in the denominator and its run does not count:
// the host's replica may or may not hold it. ok is false when nothing dates
// the outage.
func (c *Coordinator) derivedRegainCandidate(ctx context.Context, hr healthRead, host string, skews map[string]time.Duration) (regainCandidate, bool) {
	var since time.Time
	for _, r := range hr.rows {
		if r.String("observer") == host || r.String("status") == health.StatusUnready {
			continue
		}
		n := r.Int("consecutive_failures")
		if n <= 0 {
			continue
		}
		upd, ok := corrosion.ParseUpdatedAt(r.String("updated_at"))
		if !ok || !upd.After(c.now().Add(-healthFreshness)) {
			continue
		}
		run := observerRunStart(n, r.String("last_seen"), upd).Add(-skews[r.String("observer")])
		if since.IsZero() || run.Before(since) {
			since = run
		}
	}
	if since.IsZero() {
		return regainCandidate{}, false
	}
	since = since.Add(-fenceSkewMargin)
	stamps, err := corrosion.HostMembershipStamps(ctx, c.db)
	if err != nil {
		return regainCandidate{}, false
	}
	cand := regainCandidate{set: map[string]bool{host: true}, countable: map[string]bool{}}
	for _, st := range stamps {
		if st.Name == host || (c.scope.region && c.scope.regionOf(st.Name) != c.scope.regionOf(host)) {
			continue
		}
		if st.DeletedAt != "" {
			if del, ok := corrosion.ParseUpdatedAt(st.DeletedAt); ok && del.Before(since) {
				continue // deleted before the outage: not in the host's set either
			}
			cand.set[st.Name] = true
			continue
		}
		changed, ok := corrosion.ParseUpdatedAt(st.Changed)
		unchanged := ok && changed.Before(since)
		switch {
		case unchanged && corrosion.VotingEligible(st.State):
			cand.set[st.Name] = true
			cand.countable[st.Name] = true
		case !unchanged:
			cand.set[st.Name] = true
		}
	}
	return cand, true
}

// clockSkews is each peer's recorded clock skew from this node (clock_skew,
// either direction, the larger). Only observers' runs are shifted by it, so
// a skewed host itself dates nothing here (W5c). The checker records a skew only above a second, which
// fenceSkewMargin already covers, so a peer with no row adds nothing.
func (c *Coordinator) clockSkews(ctx context.Context) (map[string]time.Duration, error) {
	rows, err := c.db.Query(ctx,
		`SELECT observer, target, skew_seconds FROM clock_skew WHERE observer = ? OR target = ?`, c.hostName, c.hostName)
	if err != nil {
		return nil, err
	}
	out := map[string]time.Duration{}
	for _, r := range rows {
		peer := r.String("target")
		if peer == c.hostName {
			peer = r.String("observer")
		}
		if peer == c.hostName {
			continue
		}
		d := time.Duration(math.Abs(r.Float("skew_seconds")) * float64(time.Second))
		if d > out[peer] {
			out[peer] = d
		}
	}
	return out, nil
}

// pausedThisOutage is the limit for a deadline at which no observer has seen
// host answer since the fence. When host's own partition_paused condition
// from this outage is readable (hostReportsItsPause), only the workloads it
// lists move: the host may still run the rest, as when it judged one not
// recoverable. With no such condition, a limit this coordinator already
// holds for the host in this down-episode still stands, and with none held
// everything moves, as without a bridge. A read error, of the condition or
// of the voters' runs that date the outage, refuses.
func (c *Coordinator) pausedThisOutage(ctx context.Context, host string, at time.Time, sets []map[string]bool) (string, map[string]bool, bool) {
	return c.pausedThisOutageIn(ctx, c.readHostHealth(ctx, host), host, at, sets)
}

// pausedThisOutageIn is pausedThisOutage over host_health rows already read.
func (c *Coordinator) pausedThisOutageIn(ctx context.Context, hr healthRead, host string, at time.Time, sets []map[string]bool) (string, map[string]bool, bool) {
	paused, reason, ok := c.hostReportsItsPauseIn(ctx, hr, host, at, sets)
	switch {
	case ok:
		return "", paused, true
	case reason == whyPausedUnreadable:
		return reason, nil, false
	default:
		return "", c.recoverOnly[host], true
	}
}

// whyPausedUnreadable is hostReportsItsPause's reason when the condition, or
// the voters' runs that date its outage, cannot be read.
const whyPausedUnreadable = "its partition_paused condition is unreadable"

// hostReportsItsPause reads host's own replicated partition_paused
// condition. It holds when the condition is open, lists the workloads the
// host paused (returned as "kind/name" keys, which alone may then be
// recovered: the host's word covers what it paused, nothing more), and was
// raised during the outage the fence at `at` rests on (outageStart). Not
// "after the fence": a minority host pauses T_pause after it loses the
// majority, which can be well before a coordinator decides, as when the lease
// first had to move. It fails closed.
func (c *Coordinator) hostReportsItsPause(ctx context.Context, host string, at time.Time, sets []map[string]bool) (map[string]bool, string, bool) {
	return c.hostReportsItsPauseIn(ctx, c.readHostHealth(ctx, host), host, at, sets)
}

// hostReportsItsPauseIn is hostReportsItsPause, dating the outage over
// host_health rows already read.
func (c *Coordinator) hostReportsItsPauseIn(ctx context.Context, hr healthRead, host string, at time.Time, sets []map[string]bool) (map[string]bool, string, bool) {
	cond, ok, err := corrosion.GetHealthCondition(ctx, c.db, corrosion.PartitionPauseEvaluator,
		corrosion.CondPartitionPaused, "host", host)
	if err != nil {
		slog.Warn("failover: partition_paused read for a partition-pause deadline failed", "host", host, "error", err)
		c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
		return nil, whyPausedUnreadable, false
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
	start, ok, err := c.outageStartIn(hr, host, at, sets)
	if err != nil {
		slog.Warn("failover: host_health read dating a partition-pause outage failed", "host", host, "error", err)
		c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
		return nil, whyPausedUnreadable, false
	}
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
// set has fewer such runs than that; a read error is returned as err.
func (c *Coordinator) outageStart(ctx context.Context, host string, at time.Time, sets []map[string]bool) (time.Time, bool, error) {
	return c.outageStartIn(c.readHostHealth(ctx, host), host, at, sets)
}

// outageStartIn is outageStart over host_health rows already read.
func (c *Coordinator) outageStartIn(hr healthRead, host string, at time.Time, sets []map[string]bool) (time.Time, bool, error) {
	if hr.err != nil {
		return time.Time{}, false, hr.err
	}
	freshCutoff := c.now().Add(-healthFreshness)
	runs := map[string]time.Time{}
	for _, r := range hr.rows {
		if r.String("status") == health.StatusUnready {
			continue
		}
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
			return time.Time{}, false, nil
		}
		sort.Slice(starts, func(i, j int) bool { return starts[i].Before(starts[j]) })
		if s := starts[need-1]; s.After(latest) {
			latest = s
		}
	}
	return latest, !latest.IsZero(), nil
}

// answeredByAVoterMajority reports false, and why, when the voters whose
// latest verdict about host is an answer (healthy or unready, the verdicts
// answeredSince reads as one), counting host itself when it is a voter, are
// a majority of any of sets. An empty set, or none, refuses. It fails closed
// on a read error.
func (c *Coordinator) answeredByAVoterMajority(ctx context.Context, host string, sets []map[string]bool) (string, bool) {
	return c.answeredByAVoterMajorityIn(c.readHostHealth(ctx, host), host, sets)
}

// answeredByAVoterMajorityIn is answeredByAVoterMajority over host_health
// rows already read.
func (c *Coordinator) answeredByAVoterMajorityIn(hr healthRead, host string, sets []map[string]bool) (string, bool) {
	if hr.err != nil {
		slog.Warn("failover: host_health read for a partition-pause deadline failed", "host", host, "error", hr.err)
		c.mAttempt(PhaseRecovery, ResultError, ErrDBError)
		return whyHealthUnreadable, false
	}
	answered := map[string]bool{}
	for _, r := range hr.rows {
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
