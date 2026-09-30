package health

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// Orphaned runtimes: a workload litevirt created that is still present on this
// host while its row is gone.
//
// selfFence and the owner-assert decide from a workload's row. A domain with
// no live row gives them nothing to decide from, so both skip it, and so do
// the container sweep and re-key. That is right for a domain an operator made
// by hand. It was wrong on the kvm003-f3 lab, 2026-09-30: a stale delete
// tombstoned claimvm on every replica while the VM kept running on node-4,
// and nothing reported the VM left running with no record.
//
// WHAT IS RECOGNISED. Only a runtime carrying litevirt's own stamp, never one
// guessed from a name:
//   - a domain whose <metadata> holds litevirt's owner-epoch element
//     (https://litevirt.dev/xmlns/owner-epoch/1). The executor writes it when a
//     VM is published running, and it lives and dies with the domain. A domain
//     whose metadata is corrupt, or that predates the marker, is not
//     recognised, so a hand-made domain can never be reported — even one that
//     reuses a deleted VM's name;
//   - a container with an owner-epoch marker under the daemon's containers
//     root (<data_dir>/containers/<name>/owner_epoch). LXC's own store keeps
//     no litevirt stamp, and that marker is the one litevirt writes for every
//     container it owns.
//
// WHEN. A recognised runtime whose name has no live row anywhere — missing
// entirely, or tombstoned — seen on two consecutive passes. A single sighting
// is not reported, because a delete in flight tombstones the row a moment
// before (or after) it removes the runtime. Nothing is reported, and nothing
// is resolved, while this node's replica has not caught up: a replica that
// missed the row's creation looks exactly like one whose row is gone.
//
// WHAT HAPPENS. A condition (evaluator orphan_runtime, code vm_orphan_runtime
// or ct_orphan_runtime, subject <name>@<host>) and the litevirt_orphan_runtime
// gauge. Nothing else. No path destroys the runtime.
//
// Why not reap automatically: the only tombstone that could prove a running
// runtime is unwanted is one naming THIS host and THIS runtime's owner epoch.
// The delete paths remove the runtime before they write that tombstone, so
// such a pair appears only after a crash or an LWW anomaly — exactly when an
// automatic destroy is least trustworthy. The lab's tombstone named another
// host at an older epoch: it was decided against a runtime that no longer
// existed, and destroying node-4's VM on its strength would have acted on a
// stale decision. docs/diagnostics.md has the reap procedure.
//
// ONE WRITER PER ROW. Each host reports only its own runtimes, and the subject
// carries the host, so two hosts holding a same-named orphan never write the
// same row.

// OrphanRuntimeEvaluator is the evaluator every orphan-runtime condition is
// filed under.
const OrphanRuntimeEvaluator = "orphan_runtime"

// Condition codes.
const (
	CondVMOrphanRuntime = "vm_orphan_runtime"
	CondCTOrphanRuntime = "ct_orphan_runtime"
)

// Orphan row classification.
const (
	OrphanRowMissing    = "missing"
	OrphanRowTombstoned = "tombstoned"
)

// orphanSightingsToReport is how many consecutive passes must see an orphan
// before it is reported.
const orphanSightingsToReport = 2

// OrphanRuntime is one recognised runtime with no live row.
type OrphanRuntime struct {
	Kind         string // "vm" | "ct"
	Name         string
	Host         string // the host running it: always the reporter
	Row          string // OrphanRowMissing | OrphanRowTombstoned
	RuntimeState string
	MarkerEpoch  int64
	// The row it last had, when Row is OrphanRowTombstoned.
	RowHost       string
	RowOwnerEpoch int64
	RowDeletedAt  string
}

type orphanEvidence struct {
	Detail        string `json:"detail"`
	Name          string `json:"name"`
	Host          string `json:"host"`
	RuntimeState  string `json:"runtime_state"`
	MarkerEpoch   int64  `json:"marker_epoch"`
	Row           string `json:"row"`
	RowHost       string `json:"row_host,omitempty"`
	RowOwnerEpoch int64  `json:"row_owner_epoch,omitempty"`
	RowDeletedAt  string `json:"row_deleted_at,omitempty"`
}

// orphanReporter keeps the consecutive-sighting counts between passes. The
// durable state is the condition rows themselves.
type orphanReporter struct {
	mu        sync.Mutex
	sightings map[string]int // kind/name → consecutive passes seen
}

func orphanCode(kind string) string {
	if kind == "ct" {
		return CondCTOrphanRuntime
	}
	return CondVMOrphanRuntime
}

func orphanSubjectKind(kind string) string {
	if kind == "ct" {
		return "container"
	}
	return "vm"
}

func orphanSubjectID(name, host string) string { return name + "@" + host }

func orphanRowOf(trace *corrosion.WorkloadRowTrace) (row, host string, epoch int64, deletedAt string) {
	if trace == nil {
		return OrphanRowMissing, "", 0, ""
	}
	return OrphanRowTombstoned, trace.HostName, trace.OwnerEpoch, trace.DeletedAt
}

// pass brings this host's orphan conditions of one kind in line with found,
// the COMPLETE set of orphans a trusted scan saw this pass. It returns the
// orphans that are reported (seen on enough consecutive passes).
func (o *orphanReporter) pass(ctx context.Context, db *corrosion.Client, host, kind string, found []OrphanRuntime, now time.Time) []OrphanRuntime {
	o.mu.Lock()
	if o.sightings == nil {
		o.sightings = map[string]int{}
	}
	seen := make(map[string]bool, len(found))
	var reported []OrphanRuntime
	for _, f := range found {
		key := kind + "/" + f.Name
		seen[key] = true
		o.sightings[key]++
		if o.sightings[key] >= orphanSightingsToReport {
			reported = append(reported, f)
		}
	}
	for key := range o.sightings {
		if strings.HasPrefix(key, kind+"/") && !seen[key] {
			delete(o.sightings, key)
		}
	}
	o.mu.Unlock()

	existing, err := corrosion.ListHealthConditions(ctx, db, false)
	if err != nil {
		slog.Warn("orphan-runtime: cannot read health conditions; reporting deferred", "error", err)
		return reported
	}
	code := orphanCode(kind)
	suffix := "@" + host
	open := map[string]corrosion.HealthCondition{}
	for _, c := range existing {
		if c.Evaluator == OrphanRuntimeEvaluator && c.Code == code && strings.HasSuffix(c.SubjectID, suffix) {
			open[c.SubjectID] = c
		}
	}

	ts := now.UTC().Format(time.RFC3339)
	for _, f := range reported {
		subject := orphanSubjectID(f.Name, host)
		ev := orphanEvidence{
			Detail: "a runtime litevirt created is present on this host with no live record; " +
				"nothing reaps it automatically — see docs/diagnostics.md, orphaned runtimes",
			Name: f.Name, Host: host, RuntimeState: f.RuntimeState, MarkerEpoch: f.MarkerEpoch,
			Row: f.Row, RowHost: f.RowHost, RowOwnerEpoch: f.RowOwnerEpoch, RowDeletedAt: f.RowDeletedAt,
		}
		b, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		severity := corrosion.SeverityInfo
		if f.RuntimeState == "running" {
			severity = corrosion.SeverityWarning
		}
		row, had := open[subject]
		if had && row.Evidence == string(b) && row.Severity == severity {
			continue // unchanged: write on transitions only
		}
		if !had {
			row = corrosion.HealthCondition{
				Evaluator: OrphanRuntimeEvaluator, Code: code,
				SubjectKind: orphanSubjectKind(kind), SubjectID: subject,
				FirstSeen: ts, ConfirmedAt: ts,
			}
			slog.Warn("orphan-runtime: a litevirt runtime has no live record on any replica — reported, NOT reaped",
				"kind", kind, "name", f.Name, "host", host, "row", f.Row, "row_host", f.RowHost,
				"row_owner_epoch", f.RowOwnerEpoch, "marker_epoch", f.MarkerEpoch, "runtime_state", f.RuntimeState)
		}
		row.Lifecycle = corrosion.ConditionConfirmed
		row.Severity = severity
		row.Hosts = []string{host}
		row.Evidence = string(b)
		row.ObserveCount++
		row.CleanCount = 0
		row.LastSeen = ts
		row.ResolvedAt = ""
		row.Reporter = host
		if err := corrosion.UpsertHealthCondition(ctx, db, row); err != nil {
			slog.Error("orphan-runtime: could not record the condition", "name", f.Name, "error", err)
		}
	}

	for subject, row := range open {
		name := strings.TrimSuffix(subject, suffix)
		if seen[kind+"/"+name] {
			continue // still there (a first sighting after a restart keeps its episode)
		}
		row.Lifecycle = corrosion.ConditionResolved
		row.ResolvedAt = ts
		row.LastSeen = ts
		row.ObserveCount = 0
		row.CleanCount = 1
		row.Reporter = host
		if err := corrosion.UpsertHealthCondition(ctx, db, row); err != nil {
			slog.Error("orphan-runtime: could not resolve the condition", "subject", subject, "error", err)
			continue
		}
		slog.Info("orphan-runtime: resolved — the runtime is gone or has a live record again",
			"kind", kind, "name", name, "host", host)
	}
	sort.Slice(reported, func(i, j int) bool { return reported[i].Name < reported[j].Name })
	return reported
}

// SetOrphanRuntimeObserver wires the observer told, after every trusted
// orphan-runtime pass, of the complete set of orphaned VMs this host reports
// (kind "vm"). The daemon feeds it to litevirt_orphan_runtime. nil-safe.
func (r *Reconciler) SetOrphanRuntimeObserver(fn func(kind string, orphans []OrphanRuntime)) {
	r.onOrphans = fn
}

// reportOrphanRuntimes finds this host's litevirt domains with no live row and
// reports them. Report-only: see the file comment.
func (r *Reconciler) reportOrphanRuntimes(ctx context.Context) {
	if r.virt == nil {
		return
	}
	if ok, why := r.replicaTrusted(ctx); !ok {
		slog.Debug("orphan-runtime: replica not caught up; not scanning", "cause", why)
		return
	}
	domains, err := r.virt.ListDomains()
	if err != nil {
		return
	}
	var found []OrphanRuntime
	for _, name := range domains {
		vm, err := corrosion.GetVM(ctx, r.db, name)
		if err != nil {
			return // an incomplete scan proves nothing, in either direction
		}
		if vm != nil {
			continue
		}
		epoch, marked, merr := r.virt.GetDomainOwnerEpoch(name)
		if merr != nil || !marked {
			continue // not stamped by litevirt: an operator's domain, never reported
		}
		trace, err := corrosion.LookupVMRowAnyState(ctx, r.db, name)
		if err != nil {
			return
		}
		state, _ := r.virt.DomainState(name)
		row, rowHost, rowEpoch, deletedAt := orphanRowOf(trace)
		found = append(found, OrphanRuntime{
			Kind: "vm", Name: name, Host: r.hostName, Row: row, RuntimeState: state, MarkerEpoch: epoch,
			RowHost: rowHost, RowOwnerEpoch: rowEpoch, RowDeletedAt: deletedAt,
		})
	}
	reported := r.orphans.pass(ctx, r.db, r.hostName, "vm", found, r.now())
	if r.onOrphans != nil {
		r.onOrphans("vm", reported)
	}
}

// SetOrphanRuntimeObserver is the container twin of the Reconciler's (kind
// "ct").
func (c *ContainerChecker) SetOrphanRuntimeObserver(fn func(kind string, orphans []OrphanRuntime)) {
	c.onOrphans = fn
}

// SetReplicaFreshness wires the replica catch-up signal the orphan report
// waits for. nil (unwired) is trusted, for tests that do not exercise it.
func (c *ContainerChecker) SetReplicaFreshness(fn func() (bool, string)) { c.replicaCaughtUp = fn }

// reportOrphanContainers is reportOrphanRuntimes for containers.
func (c *ContainerChecker) reportOrphanContainers(ctx context.Context) {
	if c.runtime == nil || c.containersRoot == "" {
		return
	}
	if ok, why := corrosion.ReplicaTrusted(ctx, c.db, c.hostName, c.replicaCaughtUp); !ok {
		slog.Debug("orphan-runtime: replica not caught up; not scanning containers", "cause", why)
		return
	}
	names, err := c.runtime.List(ctx)
	if err != nil {
		return
	}
	var found []OrphanRuntime
	for _, name := range names {
		traces, err := corrosion.LookupContainerRowsAnyState(ctx, c.db, name)
		if err != nil {
			return
		}
		live := false
		for _, t := range traces {
			if t.DeletedAt == "" {
				live = true
				break
			}
		}
		if live {
			continue // a live row anywhere: the sweep or the re-key owns it
		}
		epoch, marked, merr := ReadContainerOwnerEpochMarker(c.containersRoot, name)
		if merr != nil || !marked {
			continue // not litevirt's container: never reported
		}
		var trace *corrosion.WorkloadRowTrace
		if len(traces) > 0 {
			trace = &traces[0]
		}
		st, _ := c.runtime.State(ctx, name)
		state := "stopped"
		if st == lxc.StateRunning {
			state = "running"
		}
		row, rowHost, rowEpoch, deletedAt := orphanRowOf(trace)
		found = append(found, OrphanRuntime{
			Kind: "ct", Name: name, Host: c.hostName, Row: row, RuntimeState: state, MarkerEpoch: epoch,
			RowHost: rowHost, RowOwnerEpoch: rowEpoch, RowDeletedAt: deletedAt,
		})
	}
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	reported := c.orphans.pass(ctx, c.db, c.hostName, "ct", found, now)
	if c.onOrphans != nil {
		c.onOrphans("ct", reported)
	}
}
