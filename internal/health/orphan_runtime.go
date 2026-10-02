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
//     VM is published running, and it lives and dies with the domain;
//   - a domain whose <metadata> holds litevirt's managed stamp
//     (https://litevirt.dev/xmlns/managed/1, internal/libvirt/managed_stamp.go);
//   - a container with an owner-epoch marker under the daemon's containers
//     root (<data_dir>/containers/<name>/owner_epoch);
//   - a container carrying the managed stamp inside its own LXC directory
//     (<lxcpath>/<name>/litevirt-managed, internal/lxc/managed_stamp.go).
//
// A domain whose metadata is corrupt, or that carries none of these, is not
// recognised, so a hand-made domain can never be reported — even one that
// reuses a deleted VM's name and litevirt's disk paths.
//
// WHY A SECOND STAMP. The owner-epoch markers cover too little on their own.
// The domain element is written only for a running VM whose row holds a real
// generation, so a VM created before stamping whose row is still at the
// pre-epoch 0 (enforcement.owner_epoch off, the default), and every shut-off
// VM, carries none; the container marker is written only on a relocation.
// Nothing older litevirt wrote into a domain proves more: the generator never
// emitted metadata, a title or a description, and a name or a disk path under
// <data_dir>/disks is a string anyone can reuse. So the reconciler and the
// container sweep ADOPT every runtime this host has a live row for into the
// managed stamp (adoptManagedDomains, adoptManagedContainers). A live row
// naming this host is the proof: it is what litevirt already manages the
// runtime by. The stamp then outlives the row, which is when the report needs
// it. It carries no generation and gates nothing, so writing it cannot bend
// any owner-epoch rule. A runtime that never had a live row here is never
// stamped, and one whose row was already gone before this release ran on the
// host stays unrecognised: the price of never guessing.
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

// How an orphan was recognised as litevirt's (evidence recognised_by).
const (
	OrphanRecognisedByOwnerEpoch   = "owner_epoch"
	OrphanRecognisedByManagedStamp = "managed_stamp"
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
	MarkerEpoch  int64  // 0 when recognised by the managed stamp alone
	RecognisedBy string // OrphanRecognisedByOwnerEpoch | OrphanRecognisedByManagedStamp
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
	RecognisedBy  string `json:"recognised_by"`
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
			Name: f.Name, Host: host, RuntimeState: f.RuntimeState, MarkerEpoch: f.MarkerEpoch, RecognisedBy: f.RecognisedBy,
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
		epoch, by := r.recogniseDomain(name)
		if by == "" {
			continue // not stamped by litevirt: an operator's domain, never reported
		}
		trace, err := corrosion.LookupVMRowAnyState(ctx, r.db, name)
		if err != nil {
			return
		}
		state, _ := r.virt.DomainState(name)
		row, rowHost, rowEpoch, deletedAt := orphanRowOf(trace)
		found = append(found, OrphanRuntime{
			Kind: "vm", Name: name, Host: r.hostName, Row: row, RuntimeState: state, MarkerEpoch: epoch, RecognisedBy: by,
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
		epoch, by := c.recogniseContainer(name)
		if by == "" {
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
			Kind: "ct", Name: name, Host: c.hostName, Row: row, RuntimeState: state, MarkerEpoch: epoch, RecognisedBy: by,
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

// recogniseDomain says how a domain is known to be litevirt's: by its
// owner-epoch element (with that epoch), by the managed stamp, or not at all
// (""). A metadata read that errors proves nothing and recognises nothing.
func (r *Reconciler) recogniseDomain(name string) (int64, string) {
	if epoch, marked, err := r.virt.GetDomainOwnerEpoch(name); err == nil && marked {
		return epoch, OrphanRecognisedByOwnerEpoch
	}
	if stamped, err := r.virt.GetDomainManaged(name); err == nil && stamped {
		return 0, OrphanRecognisedByManagedStamp
	}
	return 0, ""
}

// recogniseContainer is recogniseDomain for containers. The managed stamp is
// read only from a runtime that implements lxc.ManagedStamper.
func (c *ContainerChecker) recogniseContainer(name string) (int64, string) {
	if epoch, marked, err := ReadContainerOwnerEpochMarker(c.containersRoot, name); err == nil && marked {
		return epoch, OrphanRecognisedByOwnerEpoch
	}
	if st, ok := c.runtime.(lxc.ManagedStamper); ok {
		if stamped, err := st.IsManaged(name); err == nil && stamped {
			return 0, OrphanRecognisedByManagedStamp
		}
	}
	return 0, ""
}

// adoptManagedDomains writes the managed stamp on every local domain whose
// live row names this host and that does not carry it yet. See the file
// comment, WHY A SECOND STAMP. It touches nothing else, and a domain with no
// live row here (a hand-made one, or one whose row names another host) is
// never stamped.
//
// It waits for a trusted replica, like the report: a replica that has not
// caught up can still hold a live row for a VM deleted while this node was
// away, and a same-named domain made by hand since must not be adopted on its
// strength.
func (r *Reconciler) adoptManagedDomains(ctx context.Context) {
	if r.virt == nil {
		return
	}
	if ok, why := r.replicaTrusted(ctx); !ok {
		slog.Debug("orphan-runtime: replica not caught up; not adopting domains", "cause", why)
		return
	}
	domains, err := r.virt.ListDomains()
	if err != nil {
		return
	}
	for _, name := range domains {
		if inc, ok, err := r.virt.GetDomainManagedIncarnation(name); err == nil && ok && inc != "" {
			continue
		}
		vm, err := corrosion.GetVM(ctx, r.db, name)
		if err != nil {
			return
		}
		if vm == nil || vm.HostName != r.hostName {
			continue // no live row here: not proof that litevirt made it
		}
		state, _ := r.virt.DomainState(name)
		active := state == RuntimeRunning || state == "paused"
		// The stamp carries the incarnation of the row it was adopted from, so
		// a later settle (settle.go) knows which incarnation this domain is
		// without trusting a row that may since have moved. A domain stamped
		// before the attribute existed is re-stamped with it here, once.
		if err := r.virt.SetDomainManagedIncarnation(name, corrosion.IncarnationOf(vm.CreatedAt), active); err != nil {
			slog.Warn("orphan-runtime: could not write the managed stamp (retried next pass)",
				"vm", name, "error", err)
			continue
		}
		slog.Info("orphan-runtime: adopted a litevirt domain into the managed stamp", "vm", name)
	}
}

// adoptManagedContainers is adoptManagedDomains for containers: every local
// container with a live row in rows, which the sweep reads for this host only
// (container rows are keyed by host and name, so another host's same-named row
// is never among them). A runtime without lxc.ManagedStamper adopts nothing.
func (c *ContainerChecker) adoptManagedContainers(ctx context.Context, rows []corrosion.ContainerRecord) {
	st, ok := c.runtime.(lxc.ManagedStamper)
	if !ok {
		return
	}
	if ok, why := corrosion.ReplicaTrusted(ctx, c.db, c.hostName, c.replicaCaughtUp); !ok {
		slog.Debug("orphan-runtime: replica not caught up; not adopting containers", "cause", why)
		return
	}
	names, err := c.runtime.List(ctx)
	if err != nil {
		return
	}
	local := make(map[string]bool, len(names))
	for _, n := range names {
		local[n] = true
	}
	for _, ct := range rows {
		if !local[ct.Name] {
			continue
		}
		if stamped, err := st.IsManaged(ct.Name); err == nil && stamped {
			continue
		}
		if err := st.StampManaged(ct.Name); err != nil {
			slog.Warn("orphan-runtime: could not write the container managed stamp (retried next sweep)",
				"container", ct.Name, "error", err)
			continue
		}
		slog.Info("orphan-runtime: adopted a litevirt container into the managed stamp", "container", ct.Name)
	}
}
