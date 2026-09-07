package grpcapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/notify"
)

// Durable condition lifecycle — the detector's state layer.
//
// The debounce used to live in a per-leader in-memory map, which had exactly
// the failure modes cluster state must not have: a leadership handover re-armed
// the debounce and silently un-confirmed standing findings, a daemon restart
// erased them, and no other consumer could see what the detector knew.
// Findings are now health_conditions ROWS: observation counts, confirmation,
// and resolution survive leader changes and restarts.
//
// Lifecycle:
//
//   - the FIRST positive observation writes an OBSERVED row at the finding's
//     INHERENT severity — critical for the corruption-class codes (vm/ct/vip
//     dual-run, runtime-owner mismatch), warning otherwise. Lifecycle=OBSERVED
//     already tells every reader "not yet confirmed", so the severity column
//     carries the finding's real stakes rather than an artificially softened
//     one: a suspected VM dual-run is a critical-class problem the moment it is
//     first seen, and GetClusterHealth's roll-up promises to surface it as such;
//   - the second CONSECUTIVE positive scan CONFIRMS it. Confirmation, not
//     severity, is what gates PAGING: notify() fires an unconfirmed observation
//     only as a warning-level "observed (unconfirmed)" notice and pages on the
//     confirm transition, unchanged by the severity the row stores;
//   - positive evidence is recorded WITHOUT quorum: refusing to write down
//     corruption because the cluster is degraded would hide exactly the state
//     an operator needs most;
//   - RESOLUTION is stricter than observation: it requires two consecutive
//     clean scans with COMPLETE coverage (no unreachable or partial peer)
//     while the leader's decision gate is valid. An incomplete scan can
//     neither resolve nor reset the observation streak — but it DOES reset the
//     CLEAN streak, because "two consecutive complete clean scans" has to mean
//     consecutive: a blind pass between two clean ones proved nothing and must
//     not be allowed to bridge them;
//   - there is no operator force-clear: operators remove the cause, the
//     evaluator proves the resolution.
//
// One-time rollout caveat (upgrade discontinuity): the debounce this replaced
// was a per-process in-memory map — never durable, never replicated, not even
// to other same-version nodes. So during the single rollout that ships this
// change, a dual-run already CONFIRMED and paging under an old binary has no
// health_conditions row for a new-binary leader to inherit; that leader's first
// pass necessarily writes it as a fresh OBSERVED row and Overall/paging go
// quiet for one detector interval (~60s) even though the split-brain never
// stopped. There is no code-level remedy: the prior state does not exist
// anywhere to migrate from. It is bounded to that one rollout and self-heals on
// the next pass, when the still-present finding re-observes and re-confirms.
// Every subsequent handover is covered, which is the point of the port.

// dualRunEvaluator is this detector's evaluator name in health_conditions /
// health_evaluator_status.
const dualRunEvaluator = "dual_run"

// conditionCleanScans is how many consecutive complete clean scans resolve a
// condition. Two, matching the confirm side: one clean pass can be a probe
// race with a restart; two complete passes apart is a real absence.
const conditionCleanScans = 2

// conditionIdentity maps a notification kind to the condition's durable
// identity (code, subject_kind). The notification Kind strings stay the
// operator-facing contract; the codes are the storage identity.
func conditionIdentity(kind string) (code, subjectKind string) {
	switch kind {
	case kindDualRunVM:
		return "vm_dual_run", "vm"
	case kindDualRunCT:
		return "ct_dual_run", "container"
	case kindDualRunVIP:
		return "vip_dual_run", "vip"
	case kindOwnerMismatch:
		return "runtime_owner_mismatch", "vm"
	case kindLWWUnresolved:
		return "lww_unresolved", "host"
	case kindDualRunCoverage:
		return "coverage_gap", "host"
	default:
		return kind, "cluster"
	}
}

// notifyKindForCondition is the inverse: the stable notification Kind for a
// stored condition.
func notifyKindForCondition(code string) string {
	switch code {
	case "vm_dual_run":
		return kindDualRunVM
	case "ct_dual_run":
		return kindDualRunCT
	case "vip_dual_run":
		return kindDualRunVIP
	case "runtime_owner_mismatch":
		return kindOwnerMismatch
	case "lww_unresolved":
		return kindLWWUnresolved
	case "coverage_gap":
		return kindDualRunCoverage
	default:
		return code
	}
}

// confirmedSeverity is the severity a condition carries once CONFIRMED. The
// corruption-class codes are critical; coverage gaps and unresolved ties are
// degraded-state warnings.
func confirmedSeverity(kind string) string {
	switch kind {
	case kindDualRunVM, kindDualRunCT, kindDualRunVIP, kindOwnerMismatch:
		return corrosion.SeverityCritical
	default:
		return corrosion.SeverityWarning
	}
}

// conditionEvidence is the canonical structured evidence stored per condition.
type conditionEvidence struct {
	Detail string   `json:"detail"`
	Hosts  []string `json:"hosts,omitempty"`
}

func encodeEvidence(detail string, hosts []string) string {
	b, err := json.Marshal(conditionEvidence{Detail: detail, Hosts: hosts})
	if err != nil {
		return `{"detail":"evidence encoding failed"}`
	}
	return string(b)
}

// resolveGateValid reports whether this node's decision gate permits RESOLVING
// conditions. Recording positive evidence never consults it; proving absence
// does — a leader without local quorum cannot promise the rest of the cluster
// is clean. A nil gate (single-node rigs, tests) is valid: there is no quorum
// to lose.
func (s *Server) resolveGateValid(ctx context.Context) bool {
	if s.gate == nil {
		return true
	}
	return s.gate.ExecutionGate(ctx).OK
}

// applyConditionLifecycle advances every dual_run condition against this
// pass's findings and writes the evaluator's scan status. current/details/
// evidenceHosts are this pass's positive findings; coverageComplete says
// whether ABSENCE proved anything this pass.
func (s *Server) applyConditionLifecycle(
	ctx context.Context,
	current map[finding]bool,
	details map[finding]string,
	evidenceHosts map[finding][]string,
	coverageComplete bool,
	coverageDetail string,
	probeFailed []string,
) {
	now := time.Now().UTC().Format(time.RFC3339)

	active, err := corrosion.ListHealthConditions(ctx, s.db, false)
	if err != nil {
		slog.Warn("dual-run detector: list health conditions", "error", err)
		return
	}
	byIdentity := map[finding]corrosion.HealthCondition{}
	for _, h := range active {
		if h.Evaluator != dualRunEvaluator {
			continue
		}
		byIdentity[finding{kind: notifyKindForCondition(h.Code), target: h.SubjectID}] = h
	}

	// Every row this pass touches is collected here and handed to
	// corrosion.UpsertHealthBatch as ONE deferred batch at the end, rather than
	// one write per row. Two reasons: each single write takes the client's
	// EXCLUSIVE lock for its own transaction, so a pass with many findings — the
	// incident storm this detector exists to catch — would otherwise block
	// concurrent readers (GetClusterHealth) N times in a row; and these are
	// periodic-probe writes, the same class as host_health/clock_skew, which use
	// the deferred (no immediate replicator wake) path by convention. The batch
	// is also atomic, so a pass lands completely or not at all instead of
	// leaving a half-applied lifecycle.
	var conditions []corrosion.HealthCondition

	// Positive findings first: observe or confirm. Recorded without quorum.
	for f := range current {
		code, subjectKind := conditionIdentity(f.kind)
		row, exists := byIdentity[f]
		evidence := encodeEvidence(details[f], evidenceHosts[f])
		switch {
		// KNOWN LIMITATION (pre-existing leader-election model, shared with the
		// failover coordinator and the rebalancer): "no local row" is treated as
		// "genuinely new", which a lagging replica cannot distinguish from "the
		// previous leader's confirm has not replicated here yet". A leader that
		// takes the lease with a stale replica can therefore momentarily rewrite
		// an already-CONFIRMED finding as freshly OBSERVED, restarting the
		// debounce. Fixing it properly needs fencing tokens or epochs in
		// leader_election itself, which every lease consumer would have to adopt
		// — out of scope here. The blast radius is bounded: the finding is still
		// present, so the very next pass re-confirms, and positive evidence is
		// never lost, only its confirmation timing.
		case !exists:
			row = corrosion.HealthCondition{
				Evaluator: dualRunEvaluator, Code: code, SubjectKind: subjectKind, SubjectID: f.target,
				// The stored severity is the finding's inherent severity from the
				// first observation — Lifecycle=OBSERVED is what says "unconfirmed",
				// so there is no reason to under-report a corruption-class finding
				// as a warning. Paging is unchanged: it is gated on the confirm
				// transition below, not on this column.
				Lifecycle: corrosion.ConditionObserved, Severity: confirmedSeverity(f.kind),
				Hosts: evidenceHosts[f], Evidence: evidence,
				ObserveCount: 1, CleanCount: 0,
				FirstSeen: now, LastSeen: now, Reporter: s.hostName,
			}
			s.publish("ha.condition.observed", f.kind+":"+f.target, details[f])
			s.notify(ctx, notify.Notification{
				Kind: f.kind, Severity: notify.SevWarn, Subject: f.target,
				Detail: "observed (unconfirmed): " + details[f],
			})
			slog.Info("dual-run detector: condition observed", "kind", f.kind, "target", f.target)
		case row.Lifecycle == corrosion.ConditionObserved:
			row.ObserveCount++
			row.CleanCount = 0
			row.LastSeen = now
			row.Hosts, row.Evidence, row.Reporter = evidenceHosts[f], evidence, s.hostName
			if row.ObserveCount >= dualRunDebounce {
				row.Lifecycle = corrosion.ConditionConfirmed
				row.Severity = confirmedSeverity(f.kind)
				row.ConfirmedAt = now
				s.publish("ha.dualrun", f.kind+":"+f.target, details[f])
				s.notify(ctx, notify.Notification{
					Kind: f.kind, Severity: dualRunSeverity(f.kind), Subject: f.target,
					Detail: details[f],
				})
				slog.Warn("dual-run detector: condition confirmed",
					"kind", f.kind, "target", f.target, "detail", details[f])
			}
		default: // already confirmed — refresh evidence, no re-page (set-transition only)
			row.ObserveCount++
			row.CleanCount = 0
			row.LastSeen = now
			row.Hosts, row.Evidence, row.Reporter = evidenceHosts[f], evidence, s.hostName
		}
		conditions = append(conditions, row)
		byIdentity[f] = row
	}

	// Absent conditions: advance the clean streak — but ONLY under complete
	// coverage and a valid decision gate.
	canResolve := coverageComplete && s.resolveGateValid(ctx)
	for f, row := range byIdentity {
		if current[f] {
			continue
		}
		if !canResolve {
			// This pass could not prove absence, so it BREAKS the clean streak
			// rather than being skipped over: leaving CleanCount intact would let
			// clean → blind → clean resolve a condition on "two consecutive
			// complete clean scans" when the two clean scans were not
			// consecutive. Only write when there is a streak to break — a 0 → 0
			// reset is a no-op, and this loop runs over every tracked condition
			// on every blind pass.
			if row.CleanCount != 0 {
				row.CleanCount = 0
				row.Reporter = s.hostName
				conditions = append(conditions, row)
				byIdentity[f] = row
			}
			continue
		}
		row.CleanCount++
		row.ObserveCount = 0
		row.Reporter = s.hostName
		if row.CleanCount >= conditionCleanScans {
			row.Lifecycle = corrosion.ConditionResolved
			row.ResolvedAt = now
			s.publish("ha.dualrun.cleared", f.kind+":"+f.target, "")
			s.notify(ctx, notify.Notification{
				Kind: f.kind, Severity: notify.SevInfo, Subject: f.target,
				Detail: "resolved: two consecutive complete clean scans",
			})
			slog.Info("dual-run detector: condition resolved", "kind", f.kind, "target", f.target)
		}
		conditions = append(conditions, row)
		byIdentity[f] = row
	}

	// Scan status: when it ran, what it could see.
	coverage := corrosion.CoverageComplete
	if !coverageComplete {
		coverage = corrosion.CoveragePartial
	}
	status := corrosion.HealthEvaluatorStatus{
		Evaluator: dualRunEvaluator, LastScan: now, Coverage: coverage,
		Reporter: s.hostName, Detail: coverageDetail,
	}

	// One transaction for the whole pass. The batch is atomic, so there is no
	// per-row error to report — a failure means nothing landed, and the next
	// pass (60s) recomputes and rewrites the same rows from scratch.
	if err := corrosion.UpsertHealthBatch(ctx, s.db, conditions, &status); err != nil {
		slog.Error("dual-run detector: persist condition pass",
			"evaluator", dualRunEvaluator, "scan", now, "conditions", len(conditions),
			"coverage", coverage, "error", err)
	}

	// Gauges rebuild from the CONFIRMED conditions (the durable state), so a
	// fresh leader's first pass restores the series instead of blanking it.
	confirmedNow := map[finding]bool{}
	for f, row := range byIdentity {
		if row.Lifecycle == corrosion.ConditionConfirmed {
			confirmedNow[f] = true
		}
	}
	s.dualRunMetrics.SetDetected(detectedLabels(confirmedNow))
	sort.Strings(probeFailed)
	s.dualRunMetrics.SetProbeFailed(probeFailed)
}
