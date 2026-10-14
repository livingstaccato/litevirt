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
	"github.com/litevirt/litevirt/internal/health"
)

// ha.recovery.bridged (docs/diagnostics.md): a host's workloads stay paused,
// and nothing recovers them, because observers outside the voter majority
// still see the host answer — typically a host that reaches both halves of a
// split of the voters relays the minority's view to the majority. It has two
// forms:
//
//   - at a self-pause fence's deadline the coordinator recovered nothing,
//     because observers saw the host answer since the fence and that is not
//     evidence enough here that the host paused (selfPauseStillStands);
//   - before any fence: the host has kept its partition_paused open for longer
//     than the pause wait, yet is no fence candidate, because the observers
//     that see it answer leave too few voters failing it for a quorum (a
//     witness bridge on a derived voter set, where the witness votes).
//
// Visibility only. Written by the lease holder; a successor reads it back
// from the replica and resolves it.
const CondRecoveryBridged = "ha.recovery.bridged"

// bridgedListLimit caps the workloads and observers named in the evidence.
const bridgedListLimit = 20

type bridgedEvidence struct {
	Detail          string   `json:"detail"`
	Workloads       []string `json:"workloads"`
	Observers       []string `json:"observers"`
	DerivedVoterSet bool     `json:"derived_voter_set"`
	Remedy          string   `json:"remedy"`
}

// noteBridgedStall raises ha.recovery.bridged for h, whose recovery at the
// deadline of a self-pause fence at `at` was refused for why (refusePauseWait,
// on each change of reason; retryPauseWait resolves it once the deadline goes
// ahead). A host with no
// recoverable workload on it holds nothing back, and raises nothing.
func (c *Coordinator) noteBridgedStall(ctx context.Context, h *corrosion.HostRecord, at time.Time, why string) {
	derived := c.derivedVoterSet(ctx)
	set := "an adopted voter generation"
	if derived {
		set = "a derived voter set (no voter generation adopted), on which any observer that sees a self-paused host answer holds its recovery"
	}
	c.raiseBridged(ctx, h.Name, c.answeredSinceObservers(ctx, h.Name, at), derived,
		fmt.Sprintf("the partition-pause deadline of %s passed and its workloads were not recovered: %s. "+
			"Observers outside the majority still see it answer, as a host reaching both halves of a split relays; "+
			"the cluster is on %s. Nothing ran twice; the workloads stay paused on %s, and the deadline is re-checked every cycle",
			h.Name, why, set, h.Name))
}

// noteBridgedBeforeFence raises ha.recovery.bridged for each host held before
// any fence (bridgedBeforeFence), and returns the hosts it found held. Run by
// the lease holder once per cycle, after the fence loop.
func (c *Coordinator) noteBridgedBeforeFence(ctx context.Context) map[string]bool {
	held := map[string]bool{}
	rows, err := c.db.Query(ctx, `SELECT subject_id, first_seen FROM health_conditions
		WHERE evaluator = ? AND code = ? AND subject_kind = 'host' AND lifecycle != ? AND deleted_at IS NULL`,
		corrosion.PartitionPauseEvaluator, corrosion.CondPartitionPaused, corrosion.ConditionResolved)
	if err != nil || len(rows) == 0 {
		return held
	}
	wait, _ := c.partitionPauseWait(ctx)
	for _, r := range rows {
		host := r.String("subject_id")
		since, ok := corrosion.ParseUpdatedAt(r.String("first_seen"))
		if !ok || c.now().Sub(since) <= wait {
			continue
		}
		failing, answering, ok := c.bridgedBeforeFence(ctx, host)
		if !ok {
			continue
		}
		held[host] = true
		if row, found, err := corrosion.GetHealthCondition(ctx, c.db, RefenceEvaluator, CondRecoveryBridged, "host", host); err != nil ||
			(found && row.Lifecycle != corrosion.ConditionResolved) {
			continue // raised already (by either form), or unreadable
		}
		derived := c.derivedVoterSet(ctx)
		c.raiseBridged(ctx, host, answering, derived,
			fmt.Sprintf("%s has kept its workloads paused since %s, longer than the partition-pause wait (%v), and is no fence "+
				"candidate: voters %s see it down, but observers %s still see it answer, so too few voters fail it for a quorum. "+
				"Nothing is fenced or recovered; the workloads stay paused on %s",
				host, since.UTC().Format(time.RFC3339), wait, strings.Join(failing, ","), strings.Join(answering, ","), host))
	}
	return held
}

// bridgedBeforeFence reports whether host, a host with an open
// partition_paused, is held before any fence: in service (not fenced,
// offline or in maintenance, whose holds the deadline form and the operator
// own), not a fence candidate this cycle, some voter's fresh verdict sees it
// down, and the voters whose latest verdict, of any age, sees it answer are
// no quorum (a quorum answering is a host coming back, about to resume). It
// returns the failing voters and the answering observers, sorted.
func (c *Coordinator) bridgedBeforeFence(ctx context.Context, host string) (failing, answering []string, ok bool) {
	if c.cycleCandidates[host] {
		return nil, nil, false
	}
	h, err := corrosion.GetHost(ctx, c.db, host)
	if err != nil || h == nil {
		return nil, nil, false
	}
	switch h.State {
	case "fenced", "offline", "maintenance":
		return nil, nil, false
	}
	rows, err := c.db.Query(ctx,
		`SELECT observer, status, consecutive_failures, updated_at FROM host_health WHERE target = ?`, host)
	if err != nil {
		return nil, nil, false
	}
	voters := c.scope.voters(host)
	freshCutoff := c.now().Add(-healthFreshness)
	votersAnswering := 0
	for _, r := range rows {
		o := r.String("observer")
		if o == host {
			continue
		}
		if r.Int("consecutive_failures") == 0 || r.String("status") == health.StatusUnready {
			// Any age: a checker does not re-stamp a steadily healthy edge,
			// so a bridge that never lost the host has no fresh row.
			answering = append(answering, o)
			if voters[o] {
				votersAnswering++
			}
			continue
		}
		if upd, ok := corrosion.ParseUpdatedAt(r.String("updated_at")); ok && upd.After(freshCutoff) && voters[o] {
			failing = append(failing, o)
		}
	}
	if len(failing) == 0 || len(answering) == 0 || votersAnswering >= c.scope.quorum(host) {
		return nil, nil, false
	}
	sort.Strings(failing)
	sort.Strings(answering)
	return failing, answering, true
}

// raiseBridged writes ha.recovery.bridged for host. A host with no
// recoverable workload on it holds nothing back, and raises nothing.
func (c *Coordinator) raiseBridged(ctx context.Context, host string, observers []string, derived bool, detail string) {
	workloads, err := c.recoverableOn(ctx, host)
	if err != nil || len(workloads) == 0 {
		return
	}
	ts := c.now().UTC().Format(time.RFC3339)
	row, ok, err := corrosion.GetHealthCondition(ctx, c.db, RefenceEvaluator, CondRecoveryBridged, "host", host)
	if err != nil {
		slog.Warn("failover: could not read "+CondRecoveryBridged, "host", host, "error", err)
		return
	}
	if !ok || row.Lifecycle == corrosion.ConditionResolved {
		row = corrosion.HealthCondition{Evaluator: RefenceEvaluator, Code: CondRecoveryBridged,
			SubjectKind: "host", SubjectID: host, FirstSeen: ts, ConfirmedAt: ts}
	}
	remedy := fmt.Sprintf("heal the partition: %s comes back and resumes its paused workloads; or, once %s is powered off, "+
		"`lv host fence-confirm %s`, and the coordinator recovers its workloads", host, host, host)
	if derived {
		remedy += ". To keep the next split from stalling, complete voter genesis once every host is back " +
			"(clear what ha.voter.genesis_pending names, or `lv cluster voter init --members <hosts>`)"
	}
	b, _ := json.Marshal(bridgedEvidence{Detail: detail, Workloads: capList(workloads), Observers: capList(observers),
		DerivedVoterSet: derived, Remedy: remedy})
	row.Lifecycle, row.ResolvedAt, row.CleanCount = corrosion.ConditionConfirmed, "", 0
	row.ObserveCount++
	row.Evidence = string(b)
	row.Severity, row.Hosts, row.LastSeen, row.Reporter = corrosion.SeverityCritical, []string{host}, ts, c.hostName
	if err := corrosion.UpsertHealthCondition(ctx, c.db, row); err != nil {
		slog.Warn("failover: could not record "+CondRecoveryBridged, "host", host, "error", err)
		return
	}
	slog.Error("failover: a paused host's workloads are held while observers outside the majority see it answer",
		"host", host, "workloads", strings.Join(capList(workloads), ","), "observers", strings.Join(observers, ","),
		"derived_voter_set", derived, "detail", detail, "remedy", remedy)
}

// derivedVoterSet reports whether this node has adopted no voter generation
// with members. A read error reports false.
func (c *Coordinator) derivedVoterSet(ctx context.Context) bool {
	cfg, err := corrosion.AdoptedVoterConfig(ctx, c.db)
	return err == nil && !cfg.Explicit()
}

// resolveBridgedSettled resolves each raised ha.recovery.bridged whose host no
// longer holds anything back. A fenced or offline host (the deadline form)
// settles once it has no recoverable workload left (recovered); any other
// host once it is not held before a fence this cycle (held, from
// noteBridgedBeforeFence): back in service, its pause over, or fenced at
// last. A removed host settles at once. pending is strandedByHost's count,
// per host.
func (c *Coordinator) resolveBridgedSettled(ctx context.Context, pending map[string]int, held map[string]bool) {
	rows, err := c.db.Query(ctx, `SELECT subject_id FROM health_conditions
		WHERE evaluator = ? AND code = ? AND subject_kind = 'host' AND lifecycle != ? AND deleted_at IS NULL`,
		RefenceEvaluator, CondRecoveryBridged, corrosion.ConditionResolved)
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
			c.resolveBridged(ctx, host, "removed")
		case h.State == "fenced" || h.State == "offline":
			if pending[host] == 0 {
				c.resolveBridged(ctx, host, "no recoverable workload left on it")
			}
		case !held[host]:
			c.resolveBridged(ctx, host, "no longer held: back in service")
		}
	}
}

// resolveBridged resolves host's ha.recovery.bridged, when raised.
func (c *Coordinator) resolveBridged(ctx context.Context, host, why string) {
	row, ok, err := corrosion.GetHealthCondition(ctx, c.db, RefenceEvaluator, CondRecoveryBridged, "host", host)
	if err != nil || !ok || row.Lifecycle == corrosion.ConditionResolved {
		return
	}
	ts := c.now().UTC().Format(time.RFC3339)
	row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, ts, ts, c.hostName
	row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
	if err := corrosion.UpsertHealthCondition(ctx, c.db, row); err != nil {
		slog.Warn("failover: could not resolve "+CondRecoveryBridged, "host", host, "error", err)
		return
	}
	slog.Info("failover: "+CondRecoveryBridged+" resolved", "host", host, "reason", why)
}

// answeredSinceObservers is every observer answeredSince would name: those
// whose latest verdict about host, healthy or unready, is newer than `at`
// less fenceSkewMargin. Sorted; nil on a read error.
func (c *Coordinator) answeredSinceObservers(ctx context.Context, host string, at time.Time) []string {
	rows, err := c.db.Query(ctx,
		`SELECT observer, status, consecutive_failures, updated_at FROM host_health WHERE target = ?`, host)
	if err != nil {
		return nil
	}
	var out []string
	for _, r := range rows {
		if r.String("observer") == host {
			continue
		}
		if r.Int("consecutive_failures") != 0 && r.String("status") != health.StatusUnready {
			continue
		}
		if upd, ok := corrosion.ParseUpdatedAt(r.String("updated_at")); ok && upd.After(at.Add(-fenceSkewMargin)) {
			out = append(out, r.String("observer"))
		}
	}
	sort.Strings(out)
	return out
}

// recoverableOn names the workloads on host a failover would move
// (vm/<name>, ct/<name>), by strandedByHost's rules, sorted.
func (c *Coordinator) recoverableOn(ctx context.Context, host string) ([]string, error) {
	enrolled, err := c.autoPromoteEnrolled(ctx)
	if err != nil {
		return nil, err
	}
	vms, err := corrosion.ListVMs(ctx, c.db, "", host)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, vm := range vms {
		would, err := c.wouldRecoverVM(ctx, vm, enrolled)
		if err != nil {
			return nil, err
		}
		if would {
			out = append(out, "vm/"+vm.Name)
		}
	}
	cts, err := corrosion.ListContainers(ctx, c.db, host)
	if err != nil {
		return nil, err
	}
	for _, ct := range cts {
		if containerNeedsFailover(ct) {
			out = append(out, "ct/"+ct.Name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// wouldRecoverVM reports whether a failover would move vm off its host, by
// strandedByHost's rules: a failover candidate (vmNeedsFailover), and not a
// stopped VM on a host-local disk, which stays by design. enrolled is
// autoPromoteEnrolled.
func (c *Coordinator) wouldRecoverVM(ctx context.Context, vm corrosion.VMRecord, enrolled map[string]bool) (bool, error) {
	if !vmNeedsFailover(vm, enrolled[vm.Name]) {
		return false, nil
	}
	if vm.State == "stopped" {
		disks, err := corrosion.GetVMDisks(ctx, c.db, vm.Name)
		if err != nil {
			return false, err
		}
		if corrosion.VMHasHostLocalDisk(disks) {
			return false, nil
		}
	}
	return true, nil
}

func capList(in []string) []string {
	if len(in) <= bridgedListLimit {
		return in
	}
	out := append([]string(nil), in[:bridgedListLimit]...)
	return append(out, fmt.Sprintf("… and %d more", len(in)-bridgedListLimit))
}
