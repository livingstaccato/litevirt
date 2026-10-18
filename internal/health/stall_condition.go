package health

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The stall guard as a durable health finding.
//
// A stall makes this node withhold its failure votes and its fence decisions
// for StallGrace. Without a record of it, what an operator sees is failover
// taking longer than usual to fence a host that really died, and a warning in
// the journal of the node nobody is reading. So the heartbeat keeps an
// observer_stalled condition about THIS node: opened when a stall opens the
// grace window, resolved when the window closes.
//
// WHO WRITES: each node, about itself only — one writer per row, the rule
// gossip_isolated and netbox_cluster_name_mismatch follow. It is not an
// ownership condition, so it never refuses admission.
//
// It is confirmed on the first observation, unlike evaluators that need two
// passes: a stall is not an inference from one scan but a measurement of this
// process's own scheduling, and the window it reports is already over by the
// time a second pass could confirm it.
const (
	// StallEvaluator is observer_stalled's evaluator.
	StallEvaluator = "stall"
	stallEvaluator = StallEvaluator
	// CondObserverStalled is the condition code for a node that was not
	// running long enough to have its fence votes withheld.
	CondObserverStalled = "observer_stalled"
)

type stallEvidence struct {
	Detail     string  `json:"detail"`
	GapSeconds float64 `json:"gap_seconds"`
	GraceUntil string  `json:"grace_until"`
	// SilentRuns are this node's failing runs, by target, that are silent
	// through the stall (peerState.silentFrom). Written as each begins, so it
	// may be added after the condition resolved.
	SilentRuns map[string]SilentRun `json:"silent_runs,omitempty"`
}

// SilentRun is a failing run an observer recorded as silent through its
// stall: it began at RunStart, exactly as the run's verdicts publish
// last_seen, and the observer has not seen the target answer since
// SilentSince, the last moment it ran before the stall (its own clock, as
// last_seen is).
type SilentRun struct {
	RunStart    string `json:"run_start"`
	SilentSince string `json:"silent_since"`
}

// SilentSince reads an observer_stalled condition's evidence for target's
// failing run that began at runStart (the verdict's last_seen, as stored):
// since when, by the observer's clock, it has not seen target answer, when it
// recorded that very run as silent through its stall. A run that began after
// an answer has another start and is not found.
func SilentSince(evidence, target, runStart string) (time.Time, bool) {
	if runStart == "" {
		return time.Time{}, false
	}
	var ev stallEvidence
	if json.Unmarshal([]byte(evidence), &ev) != nil {
		return time.Time{}, false
	}
	run, ok := ev.SilentRuns[target]
	if !ok || run.RunStart != runStart {
		return time.Time{}, false
	}
	since, err := time.Parse(time.RFC3339Nano, run.SilentSince)
	if err != nil {
		return time.Time{}, false
	}
	return since, true
}

// noteSilentRun records target's failing run, begun at runStart, as silent
// through the stall that began at silentSince, in this node's observer_stalled
// condition: the open one, or the one in the store once it has resolved (a
// silent run's first counted probe comes at the end of the grace window).
// Reports whether it was written; a run that was not is tried again on its
// next probe. Without the record failover refuses the recovery of a host this
// observer was frozen across the fence of, as it did before the record
// existed (restartedSinceObserversIn).
func (c *Checker) noteSilentRun(ctx context.Context, target string, runStart, silentSince time.Time) bool {
	s := &c.stall
	s.tickMu.Lock()
	defer s.tickMu.Unlock()
	var row corrosion.HealthCondition
	if s.open != nil {
		row = *s.open
	} else {
		stored, ok, err := corrosion.GetHealthCondition(ctx, c.db, stallEvaluator, CondObserverStalled, "host", c.hostName)
		if err != nil || !ok {
			slog.Warn("health checker: no observer_stalled condition to record a run silent through the stall in",
				"target", target, "error", err)
			return false
		}
		row = stored
	}
	var ev stallEvidence
	_ = json.Unmarshal([]byte(row.Evidence), &ev) // an unreadable one is rebuilt with the run
	if ev.SilentRuns == nil {
		ev.SilentRuns = map[string]SilentRun{}
	}
	ev.SilentRuns[target] = SilentRun{
		RunStart:    runStart.UTC().Format(time.RFC3339Nano),
		SilentSince: silentSince.UTC().Format(time.RFC3339Nano),
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return false
	}
	row.Evidence = string(b)
	row.Reporter = c.hostName
	if err := corrosion.UpsertHealthCondition(ctx, c.db, row); err != nil {
		slog.Error("health checker: could not record a run silent through the stall", "target", target, "error", err)
		return false
	}
	if s.open != nil {
		s.open = &row
	}
	return true
}

// stallTick is one heartbeat: beat, then bring the condition in line with it.
// The reporter fields are held under stall.tickMu for the whole tick, so two
// ticks at once report a stall once; it writes only on a transition.
func (c *Checker) stallTick(ctx context.Context) {
	s := &c.stall
	s.tickMu.Lock()
	defer s.tickMu.Unlock()
	now := c.now()
	stallAt, epoch := c.beat(now)

	if !s.loaded {
		row, ok, err := corrosion.GetHealthCondition(ctx, c.db, stallEvaluator, CondObserverStalled, "host", c.hostName)
		if err != nil {
			slog.Warn("health checker: could not read the observer_stalled condition", "error", err)
		} else {
			s.loaded = true
			if ok && row.Lifecycle != corrosion.ConditionResolved {
				s.open = &row // an earlier process's; this process has no stall to match it
			}
		}
	}

	if inGrace(stallAt, now) {
		if s.open != nil && s.reported == epoch {
			return
		}
		s.mu.Lock()
		gap := s.gap
		s.mu.Unlock()
		c.openStallCondition(ctx, now, stallAt, gap, epoch)
		return
	}
	if s.open != nil {
		c.resolveStallCondition(ctx, now)
	}
}

func (c *Checker) openStallCondition(ctx context.Context, now, stallAt time.Time, gap time.Duration, epoch uint64) {
	s := &c.stall
	ts := now.UTC().Format(time.RFC3339)
	row := corrosion.HealthCondition{
		Evaluator: stallEvaluator, Code: CondObserverStalled,
		SubjectKind: "host", SubjectID: c.hostName,
		FirstSeen: ts,
	}
	if s.open != nil && s.open.Lifecycle != corrosion.ConditionResolved {
		row = *s.open // a further stall inside the window: same episode, extended
		// Report the episode's LONGEST pause. A long pause is commonly followed
		// by a short one as the process catches up (8.0s then 2.2s on the lab),
		// and the operator's question is about the first.
		var prev stallEvidence
		if json.Unmarshal([]byte(row.Evidence), &prev) == nil {
			if d := time.Duration(prev.GapSeconds * float64(time.Second)); d > gap {
				gap = d
			}
		}
	}
	row.Lifecycle = corrosion.ConditionConfirmed
	if row.ConfirmedAt == "" {
		row.ConfirmedAt = ts
	}
	row.Severity = corrosion.SeverityWarning
	row.Hosts = []string{c.hostName}
	row.ObserveCount++
	row.CleanCount = 0
	row.LastSeen = ts
	row.ResolvedAt = ""
	row.Reporter = c.hostName
	ev := stallEvidence{
		Detail: "this node was not running (suspended, swapped out or starved of CPU); " +
			"until grace_until it does not count failed probes against peers and does not decide a fence",
		GapSeconds: gap.Round(time.Millisecond).Seconds(),
		GraceUntil: stallAt.Add(StallGrace).UTC().Format(time.RFC3339),
	}
	if b, err := json.Marshal(ev); err == nil {
		row.Evidence = string(b)
	}
	if err := corrosion.UpsertHealthCondition(ctx, c.db, row); err != nil {
		slog.Error("health checker: could not record the observer_stalled condition", "error", err)
		return // retried on the next beat
	}
	s.open, s.reported = &row, epoch
}

func (c *Checker) resolveStallCondition(ctx context.Context, now time.Time) {
	s := &c.stall
	ts := now.UTC().Format(time.RFC3339)
	row := *s.open
	row.Lifecycle = corrosion.ConditionResolved
	row.ResolvedAt = ts
	row.LastSeen = ts
	row.ObserveCount = 0
	row.CleanCount = 1
	row.Reporter = c.hostName
	if err := corrosion.UpsertHealthCondition(ctx, c.db, row); err != nil {
		slog.Error("health checker: could not resolve the observer_stalled condition", "error", err)
		return // stays open in memory; the next beat retries
	}
	s.open = nil
}
