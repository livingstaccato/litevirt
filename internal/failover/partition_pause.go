package failover

import (
	"context"
	"encoding/json"
	"errors"
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
			slog.Warn("failover: the host reported its partition pause FAILED; not relying on it, so a best-effort fence of it recovers nothing until it is confirmed off",
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

// asSelfPause rewrites a best-effort fence that ran ssh and did not confirm
// the power-off (Dialled; or an assumed success, as a fencer on an older
// contract reports it) as a self-pause one when the pause may be relied on
// (relied, decided before the fence by reliesOnPauseIfAssumed). The recovery
// then waits out the pause (pauseDeadlinePassed). Anything else is returned
// as is, and a best-effort fence it does not rewrite is not a fence
// (notAFenceUnlessPaused):
//
//   - a refused or unstarted fence (not Dialled): nothing was attempted;
//   - a host-key mismatch (WrongHost): a different machine answered at the
//     address, so the host may well be elsewhere and still hold the majority,
//     and its pause is no evidence of anything.
//
// A best-effort fence the remote shell confirmed (method ssh) is one more
// fence that proves nothing, and is rewritten the same way, unless the host
// trusts a confirmed SSH power-off (trustedSSH), when it stands as it is.
func asSelfPause(fr fence.Result, relied, trusted bool) fence.Result {
	if relied && fr.Method == "ssh" && fr.Success && !trustedSSH(fr, trusted) {
		fr.Method = "best-effort-ssh"
	} else if fr.Method != "best-effort-ssh" || !relied || fr.WrongHost || (!fr.Success && !fr.Dialled) {
		return fr
	}
	// The method stays best-effort-ssh, so an older coordinator reads the row
	// as the assumed fence it always was; the reliance rides in the detail.
	fr.Detail = corrosion.FencePauseReliance + fr.Detail
	fr.Success, fr.Dialled = true, false
	return fr
}

// notAFenceUnlessPaused is the rule a best-effort fence is judged by: it
// counts only as a self-pause (asSelfPause). One that reports success any
// other way, with no proof the host went down, is a failure; nothing stands
// between it and a second running copy. A successful SSH request (method
// ssh: the remote shell confirmed it was powering the host off) and every
// other strategy's result pass unchanged.
func notAFenceUnlessPaused(fr fence.Result) fence.Result {
	if fr.Method != "best-effort-ssh" || !fr.Success || corrosion.ReliesOnPartitionPause(fr.Method, fr.Detail) {
		return fr
	}
	fr.Success = false
	fr.Detail += "; not counted as a fence: nothing proves the host is off, and its partition pause is not relied on"
	return fr
}

// trustedSSH reports whether fr is an SSH power-off the host's operator has
// chosen to trust (corrosion.LabelTrustSSHPoweroff, trusted): confirmed by
// the remote shell, over the host's pinned key. Nothing else is, whatever the
// setting.
func trustedSSH(fr fence.Result, trusted bool) bool {
	return trusted && fr.Success && fence.ConfirmedOverPin(fr.Method, fr.Detail)
}

// trustsSSHPoweroff reports whether h's operator chose to trust a confirmed
// SSH power-off of it.
func trustsSSHPoweroff(h *corrosion.HostRecord) bool {
	return h != nil && h.Labels[corrosion.LabelTrustSSHPoweroff] == "true"
}

// holdUntrustedSSH stops counting an SSH power-off the remote shell confirmed
// (method ssh) as a fence unless the host trusts one (trustedSSH): a
// confirmed request is not an observed power-off. It is recorded as it ran;
// recoverFenced holds the workloads on it (fr.Unproven) until a hardware
// fence or an operator's fence-confirm.
func holdUntrustedSSH(fr fence.Result, trusted bool) fence.Result {
	if fr.Method != "ssh" || !fr.Success || trustedSSH(fr, trusted) {
		return fr
	}
	fr.Success, fr.Unproven = false, true
	fr.Detail += "; the remote shell confirmed the power-off, but a confirmed SSH power-off is not proof the host is off"
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
	if v.key == keyVoterSetMoved {
		// Counted again next cycle, on the generation it reads: the
		// standing refusal, and its alert, are left as they are.
		c.pauseWaits[host] = w
		slog.Info("failover: partition-pause deadline passed while this node adopted a voter generation; recovering nothing, re-checking next cycle",
			"host", host)
		return
	}
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

// whyPauseNotRelied refuses a self-pause whose pause can no longer be relied
// on, at its deadline and on resume.
const whyPauseNotRelied = "the host's partition pause is no longer relied on (it reported the pause failed, " +
	"or this coordinator does not rely on it), and nothing else proves the host is off; power it off and run " +
	"'lv host fence-confirm', or give it an ipmi or redfish fence strategy"

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

// keyVoterSetMoved is the key, and the reason, of a refusal because this
// node adopted a voter generation after the cycle read its voter set
// (voterSnapshot): the deadline is counted again on the next cycle.
const keyVoterSetMoved = "this node adopted a voter generation since the cycle read its voter set"

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
	if !c.relyOnPartitionPause(ctx, h) {
		// The wait proves nothing without the pause: the host reported its
		// pause failed, or this coordinator cannot rely on it (its own flag
		// off, no probe answer from the host). Nothing else proves the host
		// off, so the deadline refuses, re-checked every cycle, and the
		// stall alert names the way out.
		return refused(whyPauseNotRelied)
	}
	hr := c.readHostHealth(ctx, h.Name)
	sets, explicit, err := c.pauseVoterSets(ctx, h.Name)
	if errors.Is(err, errVoterSetMoved) {
		return refused(keyVoterSetMoved)
	}
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
// any moment since the fence at `at`, by its own count, as far as this node
// can prove it. Over every voter set host's pauser may be counting over
// (regainCandidates), enough voters other than host have failed it without a
// break since before the fence that the rest, host included, are fewer than a
// majority. An answer since the fence that the rows have overwritten
// (restartedSinceObserversIn), or this node's own probe answer
// (LastContact), can then only be a bridge's, as the fence quorum and the
// pause wait already assume reachability to be symmetric.
//
// What it proves rests on two premises, and it reports false whenever it
// cannot read what they need:
//
//   - the voter configuration host may be using is pinned: at most one
//     generation was decided since the outage began, and no reset (on the
//     derived voter set, none at all), and host reported, before the outage
//     began, that it had adopted the oldest generation counted or a later one
//     (hostReportedAdopting);
//   - host's replica held every change of a member's voting state made more
//     than healthFreshness before the outage began.
//
// A run counts as spanning only when it began at least fenceSkewMargin plus
// its observer's clock skew (observerSkews) before the fence: an observer
// whose clock runs behind dates its run early. When this node has probed the
// host healthy since mono, its own row is not counted: a probe answer can run
// ahead of the row that records it.
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
	skew, err := c.observerSkews(ctx, host)
	if err != nil {
		slog.Warn("failover: clock_skew read for a partition-pause deadline failed", "host", host, "error", err)
		return false
	}
	since, ok := c.outageSinceIn(hr, host, skew)
	if !ok {
		return false
	}
	cands, ok := c.regainCandidates(ctx, host, explicit, since, skew)
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
		if !observerRunStart(n, r.String("last_seen"), upd).Add(skew(obs)).After(at.Add(-fenceSkewMargin)) {
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

// outageSinceIn is a moment no later than the outage host is in began: the
// earliest fresh failing run about it, less its observer's skew and
// fenceSkewMargin. ok is false when no such run is read.
func (c *Coordinator) outageSinceIn(hr healthRead, host string, skew func(string) time.Duration) (time.Time, bool) {
	freshCutoff := c.now().Add(-healthFreshness)
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
		if !ok || !upd.After(freshCutoff) {
			continue
		}
		run := observerRunStart(n, r.String("last_seen"), upd).Add(-skew(r.String("observer")))
		if since.IsZero() || run.Before(since) {
			since = run
		}
	}
	if since.IsZero() {
		return time.Time{}, false
	}
	return since.Add(-fenceSkewMargin), true
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

// regainCandidates is every voter set host's pauser may be counting over,
// once the voter configuration is pinned; ok is false when it is not, or a
// set cannot be known.
//
// Pinned: no reset was decided since the outage began, and at most one
// generation was; on the derived voter set none at all. "Since" reaches
// healthFreshness back from `since`, the window membership changes use: a
// generation decided just before the cut may not have reached, or been
// adopted by, the host (its claim round, replication, the adoption tick).
// So the host is at least on the last generation decided before that window,
// which is the adopted one when none was decided since, and the one before
// the adopted one when one was. A generation is dated by the later of its
// proposal and its row (decidedBefore), each moved later by stampSkew, and
// one that cannot be dated was decided since.
//
// The sets, every one of which must be spanned, all from one voterSnapshot
// (ok is false when this node adopted a generation since the cycle read its
// voter set):
//
//   - explicit: the adopted generation and each newer one (pauseVoterSets),
//     and the one before the adopted one, which a host partitioned before it
//     adopted the current one still counts over;
//   - derived: the adopted generation when it is explicit (a newer reset
//     made the set derived) and the one before it, the explicit generation a
//     reset replaced, and each newer explicit generation;
//   - wherever host may be counting over a derived set (the derived branch,
//     a reset, or no generation before the adopted one), the derived set as
//     its replica held it (derivedRegainCandidate).
//
// ok is also false when this node does not hold every generation from the
// oldest counted one to the newest (heldThrough), or a member of a counted
// set reported adopting a generation newer than the newest it holds
// (aVoterReportedNewer): either is a set host may be counting over that this
// node cannot count.
func (c *Coordinator) regainCandidates(ctx context.Context, host string, explicit bool, since time.Time, skew func(string) time.Duration) ([]regainCandidate, bool) {
	adopted, cfgs, err := c.voterSnapshot(ctx)
	if err != nil {
		return nil, false
	}
	stampSkew, ok := c.stampSkew(ctx, skew)
	if !ok {
		return nil, false
	}
	decided := 0
	for _, cfg := range cfgs {
		if cfg == nil {
			continue
		}
		if decidedBefore(cfg, since.Add(-healthFreshness), stampSkew) {
			continue
		}
		if !cfg.Explicit() || !explicit {
			return nil, false
		}
		decided++
	}
	if decided > 1 {
		return nil, false
	}
	before := func(g int64) *corrosion.VoterConfig {
		var prev *corrosion.VoterConfig
		for _, cfg := range cfgs {
			if cfg != nil && cfg.Generation < g {
				prev = cfg
			}
		}
		return prev
	}
	var cands []regainCandidate
	derived := !explicit
	var adoptedGen, newest int64
	if adopted != nil {
		adoptedGen = adopted.Generation
	}
	for _, cfg := range cfgs {
		if cfg != nil {
			newest = max(newest, cfg.Generation)
		}
	}
	// floor is the oldest generation counted: host must have said it adopted
	// that one or a later one. 0 when every generation, and none, is counted.
	floor := adoptedGen
	// counted adds cfg's set; a reset, or none, means the derived set and the
	// explicit generation it replaced.
	counted := func(cfg *corrosion.VoterConfig) {
		for cfg != nil && !cfg.Explicit() {
			derived = true
			cfg = before(cfg.Generation)
		}
		if cfg == nil {
			derived = true
			floor = 0
			return
		}
		floor = min(floor, cfg.Generation)
		cands = append(cands, regainCandidate{set: c.regionMembers(cfg, host)})
	}
	if explicit {
		sets, ok := c.pauseVoterSetsFrom(host, adopted, cfgs)
		if !ok {
			return nil, false
		}
		for _, set := range sets {
			cands = append(cands, regainCandidate{set: set})
		}
		counted(before(adoptedGen))
	} else {
		if adopted != nil {
			counted(adopted)
			if adopted.Explicit() {
				counted(before(adoptedGen))
			}
		}
		for _, cfg := range cfgs {
			if cfg != nil && cfg.Generation > adoptedGen && cfg.Explicit() {
				cands = append(cands, regainCandidate{set: c.regionMembers(cfg, host)})
			}
		}
	}
	if derived {
		d, ok := c.derivedRegainCandidate(ctx, host, since, stampSkew)
		if !ok {
			return nil, false
		}
		cands = append(cands, d)
	}
	if !c.hostReportedAdopting(host, since, floor, newest) {
		return nil, false
	}
	if !heldThrough(cfgs, max(floor, 1), newest) {
		return nil, false
	}
	if c.aVoterReportedNewer(cands, newest) {
		return nil, false
	}
	return cands, true
}

// heldThrough reports whether cfgs holds every generation from `from` to
// `to`. A generation missing from this node's replica in between is one host
// may be counting over that no set counts.
func heldThrough(cfgs []*corrosion.VoterConfig, from, to int64) bool {
	held := map[int64]bool{}
	for _, cfg := range cfgs {
		if cfg != nil {
			held[cfg.Generation] = true
		}
	}
	for g := from; g <= to; g++ {
		if !held[g] {
			return false
		}
	}
	return true
}

// everyReport is the bound under which PeerVoterGeneration returns the
// highest generation a peer reported in any Ping this node received.
var everyReport = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

// aVoterReportedNewer reports whether a member of any of cands' sets said, in
// any Ping this node received, that it had adopted a generation newer than
// newest: one this node does not hold, which no set counts.
func (c *Coordinator) aVoterReportedNewer(cands []regainCandidate, newest int64) bool {
	if c.PeerVoterGeneration == nil {
		return false
	}
	for _, cand := range cands {
		for v := range cand.set {
			if g, ok := c.PeerVoterGeneration(v, everyReport); ok && g > newest {
				return true
			}
		}
	}
	return false
}

// hostReportedAdopting reports whether host said, in a Ping this node
// received before `since`, that it had adopted generation floor or a later
// one this node holds (newest at most). Adoption only moves forward, so host
// counted over that generation or a later one when the outage began; without
// such a report it may be counting over an older generation (its adoption
// stuck behind a sealed-majority import, or an older build that reports
// none). floor 0 needs no report; a report of a generation newer than newest
// names a set this node cannot count.
func (c *Coordinator) hostReportedAdopting(host string, since time.Time, floor, newest int64) bool {
	if c.PeerVoterGeneration == nil {
		return floor == 0
	}
	g, ok := c.PeerVoterGeneration(host, since)
	if !ok {
		return floor == 0
	}
	return g >= floor && g <= newest
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
// from the state its replica held when the outage began (`since`): host
// itself, which the majority has fenced since, and every host whose voting
// state may have changed since then. A host whose membership has not changed
// since healthFreshness before `since` (time for its replica to have it) is
// in the set iff it is voting-eligible here, and its run counts unless its
// state is unknown here. One that changed since then, or whose change cannot
// be dated, is in the denominator and its run does not count: the host's
// replica may or may not hold it. A change is stamped on its writer's clock,
// moved later by stampSkew.
func (c *Coordinator) derivedRegainCandidate(ctx context.Context, host string, since time.Time, stampSkew time.Duration) (regainCandidate, bool) {
	stamps, err := corrosion.HostMembershipStamps(ctx, c.db)
	if err != nil {
		return regainCandidate{}, false
	}
	cutoff := since.Add(-healthFreshness)
	cand := regainCandidate{set: map[string]bool{host: true}, countable: map[string]bool{}}
	for _, st := range stamps {
		if st.Name == host || (c.scope.region && c.scope.regionOf(st.Name) != c.scope.regionOf(host)) {
			continue
		}
		if st.DeletedAt != "" {
			if del, ok := corrosion.ParseUpdatedAt(st.DeletedAt); ok && del.Add(stampSkew).Before(cutoff) {
				continue // deleted before the outage: not in the host's set either
			}
			cand.set[st.Name] = true
			continue
		}
		changed, ok := corrosion.ParseUpdatedAt(st.Changed)
		unchanged := ok && changed.Add(stampSkew).Before(cutoff)
		switch {
		case unchanged && corrosion.VotingEligible(st.State):
			cand.set[st.Name] = true
			if st.State != corrosion.HostStateUnknown {
				cand.countable[st.Name] = true
			}
		case !unchanged:
			cand.set[st.Name] = true
		}
	}
	return cand, true
}

// decidedBefore reports whether cfg was decided, and written, before
// cutoff: both its proposal's stamp (created_at, which a value another
// proposer completed keeps) and its row's (updated_at, the stamp of
// whichever writer's row won the merge, no earlier than that writer's
// write), moved later by stampSkew, precede it. A row stamped before the
// cutoff proves only that some node wrote it then, not that the fenced
// host's replica held it: that is hostReportedAdopting's evidence. A stamp
// that cannot be read dates nothing.
func decidedBefore(cfg *corrosion.VoterConfig, cutoff time.Time, stampSkew time.Duration) bool {
	for _, ts := range []string{cfg.CreatedAt, cfg.UpdatedAt} {
		at, ok := corrosion.ParseUpdatedAt(ts)
		if !ok || !at.Add(stampSkew).Before(cutoff) {
			return false
		}
	}
	return true
}

// stampSkew is how far a cluster stamp (a generation's created_at or
// updated_at, a membership change) may read early: the largest skew of any
// host this node holds a row for, deleted ones and the fenced host included.
// The writer is not named (created_by is "<user> via <host>" or "automatic
// genesis by <host>", the row's updated_at is whichever writer's row won the
// merge, and a membership row records no writer), so any of them may have
// stamped it. ok is false when the hosts cannot be read.
func (c *Coordinator) stampSkew(ctx context.Context, skew func(string) time.Duration) (time.Duration, bool) {
	stamps, err := corrosion.HostMembershipStamps(ctx, c.db)
	if err != nil {
		return 0, false
	}
	var most time.Duration
	for _, st := range stamps {
		most = max(most, skew(st.Name))
	}
	return most, true
}

// unknownSkew is the clock skew assumed for a peer whose skew from this node
// is unknown: not measured by this run (PeerClockSkew) and named in no
// clock_skew row. It is the run-start lead an unmeasured observer needs over
// the fence beyond fenceSkewMargin, and the lead a generation decided by an
// unmeasured host needs over the outage.
const unknownSkew = 30 * time.Second

// observerSkews returns each peer's clock skew from this node, for dating
// its stamps against this node's clock: the largest of this run's own
// measurement (PeerClockSkew) and every clock_skew row naming the peer, as
// observer or target. A row paired with host counts for host alone: a skewed
// host would otherwise shift every observer, but its own skew dates the
// stamps it may have written (stampSkew). A peer measured nowhere is
// unknownSkew; this node is 0.
func (c *Coordinator) observerSkews(ctx context.Context, host string) (func(string) time.Duration, error) {
	rows, err := c.db.Query(ctx, `SELECT observer, target, skew_seconds FROM clock_skew`)
	if err != nil {
		return nil, err
	}
	recorded := map[string]time.Duration{}
	for _, r := range rows {
		o, t := r.String("observer"), r.String("target")
		d := time.Duration(math.Abs(r.Float("skew_seconds")) * float64(time.Second))
		if o == host || t == host {
			recorded[host] = max(recorded[host], d)
			continue
		}
		for _, p := range []string{o, t} {
			if d > recorded[p] {
				recorded[p] = d
			}
		}
	}
	return func(peer string) time.Duration {
		if peer == c.hostName {
			return 0
		}
		d, known := recorded[peer]
		if c.PeerClockSkew != nil {
			if m, ok := c.PeerClockSkew(peer); ok {
				known = true
				if m > d {
					d = m
				}
			}
		}
		if !known {
			return unknownSkew
		}
		return d
	}, nil
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

// errVoterSetMoved is voterSnapshot's error when this node adopted a voter
// generation after the cycle read its voter set (keyVoterSetMoved).
var errVoterSetMoved = errors.New(keyVoterSetMoved)

// voterSnapshot is the voter configurations every voter set a deadline
// counts over is taken from: every generation this node holds, and the one
// it has adopted, which is the generation the cycle read its voter set on
// (c.scope). Adoption runs on its own ticker, so it can land between that
// read and this one; a generation adopted in between would then be counted
// by nobody (neither the cycle's set nor "newer than the adopted one"), and
// errVoterSetMoved holds the deadline for the cycle. The generations are read
// before the adopted one, which only rises: when it still equals the
// cycle's, it was the adopted one throughout, and its row is among them.
func (c *Coordinator) voterSnapshot(ctx context.Context) (adopted *corrosion.VoterConfig, cfgs []*corrosion.VoterConfig, err error) {
	cfgs, err = corrosion.ListVoterConfigs(ctx, c.db)
	if err != nil {
		return nil, nil, err
	}
	adopted, err = corrosion.AdoptedVoterConfig(ctx, c.db)
	if err != nil {
		return nil, nil, err
	}
	var gen int64
	if adopted != nil {
		gen = adopted.Generation
	}
	if gen != c.scope.vr.Generation {
		return nil, nil, errVoterSetMoved
	}
	if adopted != nil {
		held := false
		for _, cfg := range cfgs {
			held = held || (cfg != nil && cfg.Generation == gen)
		}
		if !held {
			return nil, nil, errVoterSetMoved
		}
	}
	return adopted, cfgs, nil
}

// pauseVoterSets is every voter set host's pauser may be counting its
// majority over, as far as this node's replica knows: the set this cycle
// decides on (c.scope.voters, host's region's under region scope, which is
// the adopted generation's: voterSnapshot) and each newer generation this
// node has not adopted yet. explicit is false while the voter set is
// derived, or when a newer generation is a reset (which a host that adopted
// it counts over its own derived set). err is errVoterSetMoved when this
// node adopted a generation since the cycle read its voter set.
func (c *Coordinator) pauseVoterSets(ctx context.Context, host string) (sets []map[string]bool, explicit bool, err error) {
	adopted, cfgs, err := c.voterSnapshot(ctx)
	if err != nil {
		return nil, false, err
	}
	sets, explicit = c.pauseVoterSetsFrom(host, adopted, cfgs)
	return sets, explicit, nil
}

// pauseVoterSetsFrom is pauseVoterSets over one voterSnapshot.
func (c *Coordinator) pauseVoterSetsFrom(host string, adopted *corrosion.VoterConfig, cfgs []*corrosion.VoterConfig) (sets []map[string]bool, explicit bool) {
	if !adopted.Explicit() {
		return nil, false
	}
	sets = []map[string]bool{c.scope.voters(host)}
	for _, cfg := range cfgs {
		if cfg == nil || cfg.Generation <= adopted.Generation {
			continue
		}
		if !cfg.Explicit() {
			return nil, false
		}
		sets = append(sets, c.regionMembers(cfg, host))
	}
	return sets, true
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

// syncOneWay sets which hosts partition_one_way is raised for from the
// replicated rows, whoever raised them. The lease holder resolves a row once
// its case is gone (noteOneWay, resolveOneWayGone), and it must be able to
// resolve one another holder raised: its raiser may have died, restarted or
// lost the lease since, and nothing else ever resolves the row (lab 1,
// 2026-10-16: open and CRITICAL for two and a half hours after its raiser was
// powered off). And a row another holder resolved must read as resolved here,
// so this holder raises it again if the case returns. A read error keeps what
// this process knew.
//
// A row another holder raised counts only once it is older than the lease
// (leaseDuration, by its last_seen). Two coordinators that both believe they
// hold the lease — a handover, a lagging replica — would otherwise flap it
// every cycle, one raising and the other resolving. A raiser still holding
// the lease keeps its row in line itself; one that is gone has had its lease
// run out by then. An unreadable last_seen counts as old.
func (c *Coordinator) syncOneWay(ctx context.Context) {
	open, err := corrosion.ListOpenHealthConditionsByCode(ctx, c.db, corrosion.PartitionPauseEvaluator, corrosion.CondPartitionOneWay)
	if err != nil {
		slog.Warn("failover: could not read partition_one_way conditions; judging them from this process's memory", "error", err)
		return
	}
	raised := make(map[string]bool, len(open))
	for _, row := range open {
		if row.SubjectKind != "host" {
			continue
		}
		if row.Reporter != c.hostName {
			if seen, err := time.Parse(time.RFC3339, row.LastSeen); err == nil && c.now().Sub(seen) < leaseDuration {
				continue
			}
		}
		raised[row.SubjectID] = true
	}
	c.oneWay = raised
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
