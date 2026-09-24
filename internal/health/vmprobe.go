package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The VM healthcheck verdict as durable, replicated state.
//
// A compose `healthcheck:` is probed by the VMChecker on the VM's OWNING host.
// Its results used to live only in that process's memory, so nothing else —
// in particular the depends-on `vm_healthy` wait and the rolling-update health
// wait, which may run on any node — could tell a VM whose probe passes from
// one that is merely running. The owner now publishes its verdict here, and
// EvaluateVMHealth is the one reader every waiter uses.
//
// WHERE: a health_conditions row (evaluator vm_probe, code vm_probe_failing,
// subject vm/<name>). Not vms.state_detail: that column carries stop reasons
// the restart policy and the reconciler decide on (operator-stop above all),
// and a health write racing a stop on another node would replicate over it —
// an operator-stopped VM would then be restarted by policy. A separate row
// cannot touch the VM row at all. The row is a condition in the ordinary
// sense: OPEN (confirmed) while the probe is failing, RESOLVED while it is
// passing or there is no current verdict, and the evidence says which.
//
// Severity is INFO, and the code is not an ownership code: a failing
// application probe is worth seeing in `lv health`, but it is a workload's
// state, not the cluster's — it must neither degrade the cluster roll-up nor
// refuse admission (host_safety only refuses on ownershipConditionCodes).
//
// WHO WRITES: the VM's owner, about the VMs it owns — one writer per row at a
// time, the rule every self-reported condition follows. Ownership moves on
// migration or failover, so the row can have had an earlier writer; the
// verdict's incarnation (below) is what makes that harmless.
//
// WHEN: only on a transition (healthy ↔ unhealthy ↔ unknown, or a verdict for
// a new incarnation), never per probe. The owner compares what it would write
// with the row it holds locally, so a daemon restart, a lost write or a
// 30-day tombstone of the resolved row heals on the next probe without any
// periodic rewrite.
//
// INCARNATION: a verdict is bound to the VM row it was observed against —
// owner host, owner epoch, created_at and the row's updated_at. Recreating the
// VM (new created_at), moving it (new host, epoch bump) and restarting it (the
// running publication rewrites the row) each change that tuple, and so does
// any other write to the VM row; a verdict for an older tuple is read as
// "unknown", never as a pass. That is conservative by construction: an
// unrelated row write can only make a waiter wait for the next probe, it can
// never let a stale pass through.
const (
	VMProbeEvaluator = "vm_probe"
	// CondVMProbeFailing is the condition code of a VM whose healthcheck is
	// failing on the current incarnation.
	CondVMProbeFailing = "vm_probe_failing"

	VerdictHealthy   = "healthy"
	VerdictUnhealthy = "unhealthy"
	VerdictUnknown   = "unknown"
)

// VMIncarnation identifies one incarnation of a VM: the row state a probe
// verdict was observed against. See the package comment above.
type VMIncarnation struct {
	Host       string `json:"host"`
	OwnerEpoch int64  `json:"owner_epoch"`
	CreatedAt  string `json:"created_at"`
	RowTS      string `json:"row_ts"`
}

// IncarnationOf is the incarnation vm is in right now.
func IncarnationOf(vm *corrosion.VMRecord) VMIncarnation {
	return VMIncarnation{
		Host:       vm.HostName,
		OwnerEpoch: vm.OwnerEpoch,
		CreatedAt:  vm.CreatedAt,
		RowTS:      vm.UpdatedAt,
	}
}

// vmProbeEvidence is the evidence JSON of a vm_probe_failing row.
type vmProbeEvidence struct {
	Verdict             string        `json:"verdict"`
	Reason              string        `json:"reason,omitempty"`
	Probe               string        `json:"probe,omitempty"`
	ConsecutiveFailures int           `json:"consecutive_failures,omitempty"`
	Retries             int           `json:"retries,omitempty"`
	ObservedAt          string        `json:"observed_at"`
	Incarnation         VMIncarnation `json:"incarnation"`
}

// VMHealth is what EvaluateVMHealth concluded about one VM.
type VMHealth struct {
	// HasHealthcheck is false when the VM defines no healthcheck. Such a VM
	// keeps the old meaning of vm_healthy: running is healthy.
	HasHealthcheck bool
	// Satisfied reports whether the depends-on vm_healthy condition is met.
	Satisfied bool
	// Verdict is healthy | unhealthy | unknown for a VM with a healthcheck,
	// "" for one without.
	Verdict string
	// Detail says why, in words an operator can act on.
	Detail string
}

// EvaluateVMHealth decides whether vm satisfies vm_healthy, reading only
// replicated state, so every node answers the same question the same way.
//
//   - No healthcheck: running satisfies it (today's meaning, kept).
//   - Healthcheck: only a PASSING verdict for the VM's CURRENT incarnation,
//     published by an owner host that is live, satisfies it. A verdict from a
//     previous incarnation, or from an owner that is offline, fenced or in
//     maintenance, is "unknown": a dead host cannot retract a pass, so its
//     last word must not stand as current.
func EvaluateVMHealth(ctx context.Context, db *corrosion.Client, vm *corrosion.VMRecord) (VMHealth, error) {
	hspec := vmCheckSpec(vm)
	if hspec == nil || hspec.Type == "" {
		if vm.State == "running" {
			return VMHealth{Satisfied: true, Detail: "no healthcheck defined: running counts as healthy"}, nil
		}
		return VMHealth{Detail: fmt.Sprintf("no healthcheck defined, and the VM is %s", vm.State)}, nil
	}
	unknown := func(format string, a ...any) (VMHealth, error) {
		return VMHealth{HasHealthcheck: true, Verdict: VerdictUnknown, Detail: fmt.Sprintf(format, a...)}, nil
	}
	if vm.State != "running" {
		return unknown("the VM is %s", vm.State)
	}
	host, err := corrosion.GetHost(ctx, db, vm.HostName)
	if err != nil {
		return VMHealth{}, fmt.Errorf("read owner host %s: %w", vm.HostName, err)
	}
	if host == nil {
		return unknown("owner host %s is not registered, so nothing can be probing the VM", vm.HostName)
	}
	if !VotingEligible(host.State) {
		return unknown("owner host %s is %s: its last probe verdict cannot be current", vm.HostName, host.State)
	}
	row, ok, err := corrosion.GetHealthCondition(ctx, db, VMProbeEvaluator, CondVMProbeFailing, "vm", vm.Name)
	if err != nil {
		return VMHealth{}, fmt.Errorf("read probe verdict: %w", err)
	}
	if !ok {
		return unknown("no probe verdict published yet (%s probe on %s)", hspec.Type, vm.HostName)
	}
	var ev vmProbeEvidence
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
		return unknown("probe verdict is unreadable: %v", err)
	}
	if ev.Incarnation != IncarnationOf(vm) {
		return unknown("the last verdict (%s) is from a previous incarnation of the VM; no probe of this one has passed yet", ev.Verdict)
	}
	switch ev.Verdict {
	case VerdictHealthy:
		return VMHealth{HasHealthcheck: true, Satisfied: true, Verdict: VerdictHealthy,
			Detail: fmt.Sprintf("%s probe passing since %s", hspec.Type, ev.ObservedAt)}, nil
	case VerdictUnhealthy:
		return VMHealth{HasHealthcheck: true, Verdict: VerdictUnhealthy,
			Detail: fmt.Sprintf("%s probe failing (%d consecutive): %s", hspec.Type, ev.ConsecutiveFailures, ev.Reason)}, nil
	default:
		return unknown("%s", ev.Reason)
	}
}

// probeTrack is the owner's in-memory view of one VM's probe results for one
// incarnation.
type probeTrack struct {
	inc       VMIncarnation
	verdict   string // VerdictHealthy | VerdictUnhealthy | VerdictUnknown
	fails     int    // consecutive failures
	reason    string // last failure reason
	lastProbe time.Time
	inFlight  bool
}

// verdictRow builds the row for ev, carrying the episode fields of prev.
func verdictRow(host, vmName string, ev vmProbeEvidence, prev *corrosion.HealthCondition, now time.Time) corrosion.HealthCondition {
	ts := now.UTC().Format(time.RFC3339)
	row := corrosion.HealthCondition{
		Evaluator: VMProbeEvaluator, Code: CondVMProbeFailing,
		SubjectKind: "vm", SubjectID: vmName,
		Severity: corrosion.SeverityInfo,
		Hosts:    []string{host},
		Reporter: host,
		LastSeen: ts,
	}
	wasOpen := prev != nil && prev.Lifecycle != corrosion.ConditionResolved
	if b, err := json.Marshal(ev); err == nil {
		row.Evidence = string(b)
	}
	if ev.Verdict == VerdictUnhealthy {
		row.Lifecycle = corrosion.ConditionConfirmed
		row.ObserveCount = ev.ConsecutiveFailures
		if wasOpen {
			row.FirstSeen, row.ConfirmedAt = prev.FirstSeen, prev.ConfirmedAt
		} else {
			row.FirstSeen, row.ConfirmedAt = ts, ts
		}
		return row
	}
	row.Lifecycle = corrosion.ConditionResolved
	row.ResolvedAt = ts
	if prev != nil {
		row.FirstSeen, row.ConfirmedAt = prev.FirstSeen, prev.ConfirmedAt
	}
	if row.FirstSeen == "" {
		row.FirstSeen = ts
	}
	return row
}

// decodeVerdict parses a vm_probe row's evidence; ok=false when unreadable.
func decodeVerdict(row corrosion.HealthCondition) (vmProbeEvidence, bool) {
	var ev vmProbeEvidence
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
		return ev, false
	}
	return ev, true
}

// probeIntervalSlack absorbs ticker jitter: an interval equal to the sweep
// period must probe every sweep, not every other one.
const probeIntervalSlack = vmCheckSweepInterval / 10

// probeDue reports whether vm should be probed this sweep, and if so marks the
// probe in flight. The healthcheck's interval is honoured (the sweep period is
// its floor and its default); a probe still running is never doubled; and a
// new incarnation starts a fresh track, probed at once — its predecessor's
// results say nothing about it.
func (v *VMChecker) probeDue(vm corrosion.VMRecord, hspec *pb.HealthCheckSpec, now time.Time) bool {
	inc := IncarnationOf(&vm)
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.tracks == nil {
		v.tracks = make(map[string]*probeTrack)
	}
	tr := v.tracks[vm.Name]
	if tr == nil || tr.inc != inc {
		tr = &probeTrack{inc: inc, verdict: VerdictUnknown}
		v.tracks[vm.Name] = tr
	}
	if tr.inFlight {
		return false
	}
	interval := parseDuration(hspec.Interval, vmCheckSweepInterval)
	if !tr.lastProbe.IsZero() && now.Sub(tr.lastProbe)+probeIntervalSlack < interval {
		return false
	}
	tr.inFlight = true
	tr.lastProbe = now
	return true
}

// recordVerdict folds one probe result into vm's track and publishes the
// verdict when it changed. Docker-style, as far as the schema goes: one pass
// is healthy; `retries` consecutive failures are unhealthy; fewer leave the
// verdict where it was. The schema has no start-period, so none is applied to
// the verdict (the start grace in sweep gates only the healthcheck's action).
//
// A probe that could not be run (out.unknown: no address known for the VM, or
// a target that cannot be interpreted) makes the verdict "unknown" with the
// reason, and resets the failure run: it is not evidence either way.
func (v *VMChecker) recordVerdict(ctx context.Context, vm corrosion.VMRecord, hspec *pb.HealthCheckSpec, out probeOutcome) {
	inc := IncarnationOf(&vm)
	retries := probeRetries(hspec)
	v.mu.Lock()
	if v.tracks == nil {
		v.tracks = make(map[string]*probeTrack)
	}
	tr := v.tracks[vm.Name]
	if tr == nil {
		tr = &probeTrack{inc: inc, verdict: VerdictUnknown}
		v.tracks[vm.Name] = tr
	}
	if tr.inc != inc {
		// The VM was restarted, recreated or moved while this probe ran: the
		// result belongs to an incarnation that no longer exists.
		v.mu.Unlock()
		return
	}
	tr.inFlight = false
	switch {
	case out.unknown:
		tr.fails, tr.reason, tr.verdict = 0, out.reason, VerdictUnknown
	case out.ok:
		tr.fails, tr.reason, tr.verdict = 0, "", VerdictHealthy
	default:
		tr.fails++
		tr.reason = out.reason
		if tr.fails >= retries {
			tr.verdict = VerdictUnhealthy
		}
	}
	ev := vmProbeEvidence{
		Verdict:             tr.verdict,
		Reason:              tr.reason,
		Probe:               strings.TrimSpace(hspec.Type + " " + hspec.Target),
		ConsecutiveFailures: tr.fails,
		Retries:             retries,
		Incarnation:         inc,
	}
	v.mu.Unlock()
	if ev.Verdict == VerdictUnknown && !out.unknown {
		return // no verdict yet for this incarnation: nothing to say
	}
	v.publishVerdict(ctx, vm.Name, ev)
}

// loadVerdicts reads every vm_probe row once per sweep, by VM name. nil on a
// read error: the sweep then settles nothing this pass.
func (v *VMChecker) loadVerdicts(ctx context.Context) map[string]*corrosion.HealthCondition {
	if v.db == nil {
		return nil
	}
	rows, err := corrosion.ListHealthConditions(ctx, v.db, true)
	if err != nil {
		slog.Warn("vmcheck: could not read probe verdicts", "error", err)
		return nil
	}
	out := make(map[string]*corrosion.HealthCondition)
	for i := range rows {
		if rows[i].Evaluator == VMProbeEvaluator && rows[i].Code == CondVMProbeFailing && rows[i].SubjectKind == "vm" {
			out[rows[i].SubjectID] = &rows[i]
		}
	}
	return out
}

// settleIdleVerdict brings the verdict of an owned VM that is not being
// probed — not running, or no healthcheck — to "unknown". A transition, so it
// writes at most once per episode, and never when there is no row.
func (v *VMChecker) settleIdleVerdict(ctx context.Context, vm corrosion.VMRecord, hspec *pb.HealthCheckSpec, prev *corrosion.HealthCondition) {
	v.mu.Lock()
	delete(v.tracks, vm.Name)
	v.mu.Unlock()
	if prev == nil {
		return
	}
	if ev, ok := decodeVerdict(*prev); ok && ev.Verdict == VerdictUnknown {
		return
	}
	reason := fmt.Sprintf("the VM is %s", vm.State)
	if hspec == nil || hspec.Type == "" {
		reason = "the VM defines no healthcheck"
	}
	v.publishVerdict(ctx, vm.Name, vmProbeEvidence{Verdict: VerdictUnknown, Reason: reason, Incarnation: IncarnationOf(&vm)})
}

// settleOrphanVerdicts resolves the OPEN verdicts this host reported for VMs
// it no longer owns: deleted ones, which nobody else will ever write, and
// moved ones, until the new owner publishes its own. Resolved rows are left
// for the 30-day retention GC.
func (v *VMChecker) settleOrphanVerdicts(ctx context.Context, durable map[string]*corrosion.HealthCondition, owned map[string]bool) {
	for name, row := range durable {
		if owned[name] || row.Reporter != v.hostName || row.Lifecycle == corrosion.ConditionResolved {
			continue
		}
		fresh, err := corrosion.GetVM(ctx, v.db, name)
		if err != nil {
			continue
		}
		reason := "the VM was deleted"
		inc := VMIncarnation{}
		if fresh != nil {
			if fresh.HostName == v.hostName {
				continue // ours after all (the list raced a transfer): the next sweep probes it
			}
			reason = "the VM moved to " + fresh.HostName
			inc = IncarnationOf(fresh)
		}
		ev := vmProbeEvidence{Verdict: VerdictUnknown, Reason: reason, Incarnation: inc}
		if err := v.writeVerdict(ctx, name, ev, row); err != nil {
			slog.Warn("vmcheck: could not resolve an orphaned probe verdict", "vm", name, "error", err)
		}
	}
}

// publishVerdict writes ev for an owned VM when it differs from the durable
// row — the transition rule. The VM row is re-read first: a verdict is only
// published against the incarnation it was observed on, by its current owner.
func (v *VMChecker) publishVerdict(ctx context.Context, name string, ev vmProbeEvidence) {
	if v.db == nil {
		return
	}
	prevRow, ok, err := corrosion.GetHealthCondition(ctx, v.db, VMProbeEvaluator, CondVMProbeFailing, "vm", name)
	if err != nil {
		slog.Warn("vmcheck: could not read probe verdict", "vm", name, "error", err)
		return
	}
	var prev *corrosion.HealthCondition
	if ok {
		prev = &prevRow
		// No transition: the same verdict for the same incarnation — and, for
		// "unknown", for the same reason, so a probe that cannot run replaces
		// an older "unknown" with the reason a waiter needs to see. (The idle
		// settle path never gets here with an unknown row: it stops first.)
		if pe, good := decodeVerdict(prevRow); good && pe.Verdict == ev.Verdict &&
			pe.Incarnation == ev.Incarnation &&
			(ev.Verdict != VerdictUnknown || pe.Reason == ev.Reason) {
			return
		}
	}
	fresh, err := corrosion.GetVM(ctx, v.db, name)
	if err != nil || fresh == nil || fresh.HostName != v.hostName {
		return
	}
	if IncarnationOf(fresh) != ev.Incarnation {
		return // superseded while the probe ran; the next sweep probes the new incarnation
	}
	if ev.Verdict != VerdictUnknown && fresh.State != "running" {
		return
	}
	if err := v.writeVerdict(ctx, name, ev, prev); err != nil {
		slog.Warn("vmcheck: could not publish probe verdict", "vm", name, "verdict", ev.Verdict, "error", err)
		return
	}
	slog.Info("vmcheck: probe verdict changed", "vm", name, "verdict", ev.Verdict, "reason", ev.Reason)
	v.publish("vm.health."+ev.Verdict, name, ev.Reason)
}

func (v *VMChecker) writeVerdict(ctx context.Context, name string, ev vmProbeEvidence, prev *corrosion.HealthCondition) error {
	now := time.Now()
	ev.ObservedAt = now.UTC().Format(time.RFC3339)
	return corrosion.UpsertHealthCondition(ctx, v.db, verdictRow(v.hostName, name, ev, prev, now))
}
