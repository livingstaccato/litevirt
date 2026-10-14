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

// ha.recovery.bridged (docs/diagnostics.md): at a self-pause fence's deadline
// the coordinator recovered nothing because observers saw the host answer
// since the fence, and that is not evidence enough here that the host paused
// (selfPauseStillStands). Typically a host that reaches both halves of a split
// of the voters, a witness or a host in maintenance, relays the minority's
// view to the majority. Nothing re-checks the host afterwards, so the
// workloads stay paused where they are until the partition heals or an
// operator confirms the host off. Written by the lease holder; a successor
// reads it back from the replica and resolves it.
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
// deadline of a self-pause fence at `at` was refused for why. A host with no
// recoverable workload on it holds nothing back, and raises nothing.
func (c *Coordinator) noteBridgedStall(ctx context.Context, h *corrosion.HostRecord, at time.Time, why string) {
	workloads, err := c.recoverableOn(ctx, h.Name)
	if err != nil || len(workloads) == 0 {
		return
	}
	observers := c.answeredSinceObservers(ctx, h.Name, at)
	cfg, err := corrosion.AdoptedVoterConfig(ctx, c.db)
	derived := err == nil && !cfg.Explicit()
	ts := c.now().UTC().Format(time.RFC3339)
	row, ok, err := corrosion.GetHealthCondition(ctx, c.db, RefenceEvaluator, CondRecoveryBridged, "host", h.Name)
	if err != nil {
		slog.Warn("failover: could not read "+CondRecoveryBridged, "host", h.Name, "error", err)
		return
	}
	if !ok || row.Lifecycle == corrosion.ConditionResolved {
		row = corrosion.HealthCondition{Evaluator: RefenceEvaluator, Code: CondRecoveryBridged,
			SubjectKind: "host", SubjectID: h.Name, FirstSeen: ts, ConfirmedAt: ts}
	}
	set := "an adopted voter generation"
	if derived {
		set = "a derived voter set (no voter generation adopted), on which any observer that sees a self-paused host answer holds its recovery"
	}
	remedy := fmt.Sprintf("heal the partition: %s comes back and resumes its paused workloads; or, once %s is powered off, "+
		"`lv host fence-confirm %s`, and the recovery resumes from it", h.Name, h.Name, h.Name)
	if derived {
		remedy += ". To keep the next split from stalling, complete voter genesis once every host is back " +
			"(clear what ha.voter.genesis_pending names, or `lv cluster voter init --members <hosts>`)"
	}
	b, _ := json.Marshal(bridgedEvidence{
		Detail: fmt.Sprintf("the partition-pause deadline of %s passed and its workloads were not recovered: %s. "+
			"Observers outside the majority still see it answer, as a host reaching both halves of a split relays; "+
			"the cluster is on %s. Nothing ran twice; the workloads stay paused on %s",
			h.Name, why, set, h.Name),
		Workloads: capList(workloads), Observers: capList(observers), DerivedVoterSet: derived, Remedy: remedy})
	row.Lifecycle, row.ResolvedAt, row.CleanCount = corrosion.ConditionConfirmed, "", 0
	row.ObserveCount++
	row.Evidence = string(b)
	row.Severity, row.Hosts, row.LastSeen, row.Reporter = corrosion.SeverityCritical, []string{h.Name}, ts, c.hostName
	if err := corrosion.UpsertHealthCondition(ctx, c.db, row); err != nil {
		slog.Warn("failover: could not record "+CondRecoveryBridged, "host", h.Name, "error", err)
		return
	}
	slog.Error("failover: recovery of a self-paused host is held while observers outside the majority see it answer",
		"host", h.Name, "workloads", strings.Join(capList(workloads), ","), "observers", strings.Join(observers, ","),
		"derived_voter_set", derived, "remedy", remedy)
}

// resolveBridgedSettled resolves each raised ha.recovery.bridged whose host no
// longer holds anything back: removed, no longer fenced or offline (the
// partition healed), or with no recoverable workload left on it (recovered).
// pending is strandedByHost's count, per host.
func (c *Coordinator) resolveBridgedSettled(ctx context.Context, pending map[string]int) {
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
		case h.State != "fenced" && h.State != "offline":
			c.resolveBridged(ctx, host, "back in service")
		case pending[host] == 0:
			c.resolveBridged(ctx, host, "no recoverable workload left on it")
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
// (vm/<name>, ct/<name>), sorted.
func (c *Coordinator) recoverableOn(ctx context.Context, host string) ([]string, error) {
	vms, err := corrosion.ListVMs(ctx, c.db, "", host)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, vm := range vms {
		if !vmNeedsFailover(vm, false) {
			continue
		}
		// As strandedByHost: a stopped VM on a host-local disk stays by design.
		if vm.State == "stopped" {
			disks, err := corrosion.GetVMDisks(ctx, c.db, vm.Name)
			if err != nil {
				return nil, err
			}
			if corrosion.VMHasHostLocalDisk(disks) {
				continue
			}
		}
		out = append(out, "vm/"+vm.Name)
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

func capList(in []string) []string {
	if len(in) <= bridgedListLimit {
		return in
	}
	out := append([]string(nil), in[:bridgedListLimit]...)
	return append(out, fmt.Sprintf("… and %d more", len(in)-bridgedListLimit))
}
