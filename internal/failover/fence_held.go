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
)

// ha.fence_held (docs/diagnostics.md): a quorum fails a host, and nothing on it
// needs a fence — no workload a failover would move, and nothing else waiting
// on its fence (fenceNeeds). Fencing it would power off what nobody restarts
// elsewhere, an on_host_failure: none VM included, and buy nothing. So the
// coordinator records it 'offline', not fenced, writes no fencing_log row, and
// raises this condition instead.
//
// 'offline' is what a failed fence already leaves: placement skips the host,
// and nothing reads it as proof that the host is off (corrosion.HostProvedOff
// needs 'fenced' and a proof-grade row), so every flow that needs the host off
// still asks for `lv host fence-confirm` or a verified fence. recoverHosts puts
// the host back 'active' once a quorum sees it healthy again.
//
// The hold is never cached and never read as a decision. While the host stays
// a fence candidate, every cycle judges fenceNeeds afresh, on this coordinator
// or a successor (the open condition is what keeps the terminal-state skip
// from caching it), and the first cycle that finds something needing the fence
// fences it through every guard the fence path has. A workload that becomes
// recoverable after a hold therefore waits at most one cycle, and is never
// recovered without the fence: the hold only ever withholds a fence, so it
// cannot produce a second running copy. An older coordinator taking the lease
// mid-hold reads 'offline' without a fence as terminal and fences nothing,
// which is safe and is the one mixed-version cost: a workload made recoverable
// during that tenure waits for an upgraded leader or an operator.
const CondFenceHeld = "ha.fence_held"

type fenceHeldEvidence struct {
	Detail    string   `json:"detail"`
	Workloads []string `json:"workloads"`
	Remedy    string   `json:"remedy"`
	// ResolvedBy is why a resolved hold ended: heldEndedByFence when the host
	// was fenced after the hold, for as long as it has not been back in
	// service since (heldThisOutage); anything else otherwise.
	ResolvedBy string `json:"resolved_by,omitempty"`
}

// heldEndedByFence marks a hold that ended in a fence of the host.
const heldEndedByFence = "fence"

// fenceNeeds names what on host needs the host fenced before it can proceed,
// sorted: every workload a failover would move off it (recoverableOn), and the
// work recoverableOn leaves out on purpose that still waits on its fence or
// acts on it:
//
//   - a VM stopped by intent on shared storage, which failover moves to a
//     live host still stopped (stoppedVMRekeyable);
//   - a VM or container recorded on host mid-transfer (pending, starting,
//     migrating, relocating): its guest may run on either end, and only the
//     fence path settles which;
//   - a container carrying a relocate-restore marker
//     (resolvePendingRelocations acts on it independent of the fence);
//   - a pending recovery proof (prepared or in progress) for a workload
//     recorded on host, or whose destination is host.
//
// An error is returned rather than a partial answer: the caller fences on it.
func (c *Coordinator) fenceNeeds(ctx context.Context, host string) ([]string, error) {
	need, err := c.recoverableOn(ctx, host)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(need))
	for _, n := range need {
		seen[n] = true
	}
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			need = append(need, name)
		}
	}
	onHost := map[string]bool{}
	vms, err := corrosion.ListVMs(ctx, c.db, "", host)
	if err != nil {
		return nil, err
	}
	for _, vm := range vms {
		onHost["vm/"+vm.Name] = true
		if transferStates[vm.State] {
			add("vm/" + vm.Name)
		}
		// A VM stopped by intent on shared storage is moved to a live host,
		// still stopped, behind the fence (stoppedVMRekeyable); the fence
		// that move may need is not this decision's to judge.
		if corrosion.VMStoppedForFailover(vm) && c.vmWasCandidate(ctx, vm) && !vmUsesFirmwareState(vm) {
			disks, err := corrosion.GetVMDisks(ctx, c.db, vm.Name)
			if err != nil {
				return nil, err
			}
			if !corrosion.VMHasHostLocalDisk(disks) {
				add("vm/" + vm.Name)
			}
		}
	}
	cts, err := corrosion.ListContainers(ctx, c.db, host)
	if err != nil {
		return nil, err
	}
	for _, ct := range cts {
		onHost["container/"+ct.Name] = true
		if transferStates[ct.State] {
			add("ct/" + ct.Name)
		}
		if _, _, ok := corrosion.RelocateRestoreMarker(ct.State, ct.StateDetail); ok {
			add("ct/" + ct.Name)
		}
	}
	rows, err := c.db.Query(ctx, `SELECT target_kind, target_name, dest_host FROM runtime_action_proofs
		WHERE deleted_at IS NULL AND status IN (?, ?)`, corrosion.ProofPrepared, corrosion.ProofInProgress)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		kind, name := r.String("target_kind"), r.String("target_name")
		if r.String("dest_host") == host || onHost[kind+"/"+name] {
			add("proof:" + kind + "/" + name)
		}
	}
	sort.Strings(need)
	return need, nil
}

// transferStates are workload row states in which the recorded host is
// mid-move, so the row alone does not say where the guest runs.
var transferStates = map[string]bool{"pending": true, "starting": true, "migrating": true, "relocating": true}

// holdUnneededFence decides, immediately before a fence of h, whether the
// fence is needed at all. It reports true when the fence is held: nothing on
// h needs it (fenceNeeds), so h is recorded 'offline' and ha.fence_held is
// raised instead. It reports false when the fence must run: something needs
// it, or that cannot be read (fail closed, the fence as before).
//
// The decision is re-checked after the 'offline' write. A workload recorded on
// h before that write landed is seen by the re-check, and h is fenced in this
// cycle; one recorded after it was placed by a node that had not seen the
// write yet, and the next cycle's decision, never cached, finds it.
func (c *Coordinator) holdUnneededFence(ctx context.Context, h *corrosion.HostRecord) bool {
	need, err := c.fenceNeeds(ctx, h.Name)
	if err != nil {
		slog.Warn("failover: cannot tell whether anything on the host needs its fence; fencing it", "host", h.Name, "error", err)
		c.mAttempt(PhaseSkip, ResultError, ErrDBError)
		return false
	}
	if len(need) > 0 {
		// An open hold stays open until the fence is recorded
		// (resolveFenceHeldSettled): a fence this cycle does not reach — the
		// lease lost first, HA disarmed — must leave the host re-checked, not
		// cached as a terminal 'offline'.
		return false
	}
	if c.fenceHeldDecided != nil {
		c.fenceHeldDecided(h.Name)
	}
	// The condition first: it is what keeps an 'offline' host with no fence
	// on record out of the terminal-state skip, so a host recorded offline
	// without it would be cached as handled and never re-checked.
	if !c.raiseFenceHeld(ctx, h) {
		c.mAttempt(PhaseSkip, ResultError, ErrDBError)
		return true // not fenced, not recorded offline: the next cycle decides again
	}
	if h.State != "offline" {
		applied, err := corrosion.UpdateHostStateFrom(ctx, c.db, h.Name, h.State, "offline")
		if err != nil {
			// No fence ran, and the next cycle judges again.
			slog.Error("failover: record a host offline whose fence is held", "host", h.Name, "error", err)
			c.mAttempt(PhaseSkip, ResultError, ErrDBError)
			return true
		}
		if !applied {
			// Its state moved since this cycle read it (a fence, an undrain, a
			// boot): the next cycle decides from the new state.
			return true
		}
	}
	// After the 'offline' write: anything recorded on h before it landed is
	// visible now.
	if need, err := c.fenceNeeds(ctx, h.Name); err != nil || len(need) > 0 {
		slog.Warn("failover: something recorded on the host while its fence was being held needs it; fencing it",
			"host", h.Name, "needs", strings.Join(capList(need), ","), "error", err)
		return false
	}
	c.mAttempt(PhaseSkip, ResultSkipped, ErrNothingRecoverable)
	return true
}

// SetFenceHeldDecidedForTest installs a hook run when holdUnneededFence has
// found nothing needing a fence, before it records the host offline: a test
// writes there what a placement racing the decision would.
func (c *Coordinator) SetFenceHeldDecidedForTest(f func(host string)) { c.fenceHeldDecided = f }

// fenceHeld reports whether host's ha.fence_held is open.
func (c *Coordinator) fenceHeld(ctx context.Context, host string) (bool, error) {
	row, ok, err := corrosion.GetHealthCondition(ctx, c.db, RefenceEvaluator, CondFenceHeld, "host", host)
	if err != nil {
		return false, err
	}
	return ok && row.Lifecycle != corrosion.ConditionResolved, nil
}

// fenceHeldOpen is fenceHeld with a read error reported as not open.
func (c *Coordinator) fenceHeldOpen(ctx context.Context, host string) bool {
	open, err := c.fenceHeld(ctx, host)
	return err == nil && open
}

// raiseFenceHeld writes ha.fence_held for h, naming the workloads left running
// on it and their policies. It reports whether the condition is recorded.
func (c *Coordinator) raiseFenceHeld(ctx context.Context, h *corrosion.HostRecord) bool {
	ts := c.now().UTC().Format(time.RFC3339)
	row, ok, err := corrosion.GetHealthCondition(ctx, c.db, RefenceEvaluator, CondFenceHeld, "host", h.Name)
	if err != nil {
		slog.Warn("failover: could not read "+CondFenceHeld, "host", h.Name, "error", err)
		return false
	}
	fresh := !ok || row.Lifecycle == corrosion.ConditionResolved
	if fresh {
		row = corrosion.HealthCondition{Evaluator: RefenceEvaluator, Code: CondFenceHeld,
			SubjectKind: "host", SubjectID: h.Name, FirstSeen: ts, ConfirmedAt: ts}
	}
	var left []string
	if vms, err := corrosion.ListVMs(ctx, c.db, "", h.Name); err == nil {
		for _, vm := range vms {
			p := vmFailurePolicy(vm)
			if p == "" {
				p = "none"
			}
			left = append(left, fmt.Sprintf("vm/%s (%s, on_host_failure %s)", vm.Name, vm.State, p))
		}
	}
	if cts, err := corrosion.ListContainers(ctx, c.db, h.Name); err == nil {
		for _, ct := range cts {
			p := ct.OnHostFailure
			if p == "" {
				p = "none"
			}
			left = append(left, fmt.Sprintf("ct/%s (%s, on_host_failure %s)", ct.Name, ct.State, p))
		}
	}
	sort.Strings(left)
	detail := fmt.Sprintf("a quorum of voters fails %s, and nothing on it needs a fence: no workload a failover would move, "+
		"no transfer, relocation or recovery proof waiting on it. It is recorded offline, not fenced, and no fence is "+
		"recorded; whatever runs there keeps running. Each cycle re-checks, and %s is fenced as soon as something "+
		"recoverable is recorded on it", h.Name, h.Name)
	remedy := fmt.Sprintf("bring %s's daemon back: it returns to active once a quorum sees it healthy. A move off it "+
		"still needs it proven off: once it is powered off, `lv host fence-confirm %s`", h.Name, h.Name)
	b, _ := json.Marshal(fenceHeldEvidence{Detail: detail, Workloads: capList(left), Remedy: remedy})
	if !fresh && row.Evidence == string(b) && row.Severity == corrosion.SeverityWarning {
		// Open and unchanged: a hold can last days, and rewriting the
		// replicated row every cycle would only move its counters.
		return true
	}
	row.Lifecycle, row.ResolvedAt, row.CleanCount = corrosion.ConditionConfirmed, "", 0
	row.ObserveCount++
	row.Evidence = string(b)
	row.Severity, row.Hosts, row.LastSeen, row.Reporter = corrosion.SeverityWarning, []string{h.Name}, ts, c.hostName
	if err := corrosion.UpsertHealthCondition(ctx, c.db, row); err != nil {
		slog.Warn("failover: could not record "+CondFenceHeld, "host", h.Name, "error", err)
		return false
	}
	if fresh {
		slog.Warn("failover: quorum reached, but nothing on the host needs a fence; recorded offline, not fenced",
			"host", h.Name, "left_running", strings.Join(capList(left), ","))
	}
	return true
}

// resolveFenceHeld resolves host's ha.fence_held, when open, recording by
// what it ended (fenceHeldEvidence.ResolvedBy).
func (c *Coordinator) resolveFenceHeld(ctx context.Context, host, by, why string) {
	row, ok, err := corrosion.GetHealthCondition(ctx, c.db, RefenceEvaluator, CondFenceHeld, "host", host)
	if err != nil || !ok || row.Lifecycle == corrosion.ConditionResolved {
		return
	}
	var ev fenceHeldEvidence
	_ = json.Unmarshal([]byte(row.Evidence), &ev)
	ev.ResolvedBy = by
	if b, err := json.Marshal(ev); err == nil {
		row.Evidence = string(b)
	}
	ts := c.now().UTC().Format(time.RFC3339)
	row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, ts, ts, c.hostName
	row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
	if err := corrosion.UpsertHealthCondition(ctx, c.db, row); err != nil {
		slog.Warn("failover: could not resolve "+CondFenceHeld, "host", host, "error", err)
		return
	}
	slog.Info("failover: "+CondFenceHeld+" resolved", "host", host, "reason", why)
}

// resolveFenceHeldSettled resolves each open ha.fence_held whose host is no
// longer held: removed, out of 'offline' (back in service, fenced, in
// maintenance), or fenced by anyone since the hold was raised.
func (c *Coordinator) resolveFenceHeldSettled(ctx context.Context) {
	rows, err := c.db.Query(ctx, `SELECT subject_id, first_seen FROM health_conditions
		WHERE evaluator = ? AND code = ? AND subject_kind = 'host' AND lifecycle != ? AND deleted_at IS NULL`,
		RefenceEvaluator, CondFenceHeld, corrosion.ConditionResolved)
	if err != nil {
		return
	}
	for _, r := range rows {
		host := r.String("subject_id")
		h, err := corrosion.GetHost(ctx, c.db, host)
		if err != nil {
			continue
		}
		switch {
		case h == nil:
			c.resolveFenceHeld(ctx, host, "removed", "removed")
		case h.State == "fenced":
			c.resolveFenceHeld(ctx, host, heldEndedByFence, "host is fenced")
		case h.State != "offline":
			c.resolveFenceHeld(ctx, host, h.State, "host is "+h.State)
		default:
			since, ok := corrosion.ParseUpdatedAt(r.String("first_seen"))
			if _, at, found := c.newestFenceAttempt(ctx, host); ok && found && !at.Before(since) {
				c.resolveFenceHeld(ctx, host, heldEndedByFence, "a fence was recorded since")
			}
		}
	}
	// A hold that ended in a fence stops counting once its host is back in
	// service: its next outage is a new one (heldThisOutage).
	rows, err = c.db.Query(ctx, `SELECT subject_id, evidence FROM health_conditions
		WHERE evaluator = ? AND code = ? AND subject_kind = 'host' AND lifecycle = ? AND deleted_at IS NULL`,
		RefenceEvaluator, CondFenceHeld, corrosion.ConditionResolved)
	if err != nil {
		return
	}
	for _, r := range rows {
		var ev fenceHeldEvidence
		if json.Unmarshal([]byte(r.String("evidence")), &ev) != nil || ev.ResolvedBy != heldEndedByFence {
			continue
		}
		host := r.String("subject_id")
		h, err := corrosion.GetHost(ctx, c.db, host)
		if err != nil || (h != nil && h.State != "active") {
			continue
		}
		row, ok, err := corrosion.GetHealthCondition(ctx, c.db, RefenceEvaluator, CondFenceHeld, "host", host)
		if err != nil || !ok || row.Lifecycle != corrosion.ConditionResolved {
			continue
		}
		ev.ResolvedBy = "active"
		if b, err := json.Marshal(ev); err == nil {
			row.Evidence = string(b)
			if err := corrosion.UpsertHealthCondition(ctx, c.db, row); err != nil {
				slog.Warn("failover: could not record the end of a held fence's outage", "host", host, "error", err)
			}
		}
	}
}

// heldThisOutage reports whether host's fence was held (ha.fence_held) during
// its current outage: the condition is open, or it ended in a fence of the
// host that has not been back in service since. Unreadable, it reports true.
//
// A fence that ends a hold is not covered by the host's partition pause. The
// pause covers what the host itself found recoverable when it lost the
// majority, and a hold means nothing was: whatever is recovered now became
// recoverable during the hold, a change a partitioned host never saw, so it
// was never paused and may still run there. recoverFenced therefore recovers
// nothing on an assumed best-effort fence of such a host (one that did not
// reach it) until an operator confirms it off.
func (c *Coordinator) heldThisOutage(ctx context.Context, host string) bool {
	row, ok, err := corrosion.GetHealthCondition(ctx, c.db, RefenceEvaluator, CondFenceHeld, "host", host)
	if err != nil {
		return true
	}
	if !ok {
		return false
	}
	if row.Lifecycle != corrosion.ConditionResolved {
		return true
	}
	var ev fenceHeldEvidence
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
		return true
	}
	return ev.ResolvedBy == heldEndedByFence
}
