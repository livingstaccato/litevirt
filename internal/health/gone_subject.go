package health

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Conditions whose subject is gone.
//
// Most evaluators resolve a condition when a pass no longer sees its cause.
// A pass over workloads or hosts never looks at one that was deleted, and a
// host-local evaluator stops running when its host is removed, so a
// condition naming either stayed open for good: lab 1 accumulated about 80.
//
// So each reconciler pass resolves every open condition whose subject is
// gone, on positive proof from a replica that has caught up:
//
//   - a vm or container subject ("<name>" or "<name>@<host>") whose workload
//     has a tombstoned row and no live one (a container on any host: a
//     relocation tombstones one host's row and leaves another live);
//   - any subject naming a host ("<host>", "<pool>@<host>", "<name>@<host>",
//     "<host>/<detail>") whose hosts row is tombstoned and not live again.
//
// A name with no row at all is not proof: the row may not have replicated
// here yet, or this replica was reseeded without the tombstone. The evaluators
// and codes in goneSubjectKeepEvaluators and goneSubjectKeepCodes outlive their subject by design and are never resolved
// here. The write is the evaluators' own full-row upsert of an open row, so
// a resolved row is never rewritten, and one an older node raises again is
// resolved again, once, on the next pass.

// goneSubjectKeepEvaluators are evaluators none of whose conditions this
// sweep resolves, with why.
var goneSubjectKeepEvaluators = map[string]string{
	// Ownership evidence. Its detector re-derives every finding from runtime
	// probes each pass and resolves only after complete clean scans; a deleted
	// row whose runtimes still run is exactly what it reports.
	"dual_run": "the dual-run detector resolves its own on complete clean scans",
	// The subject has no live row by definition: a deleted VM whose runtime
	// is still defined is what it reports.
	OrphanRuntimeEvaluator: "an orphan runtime's workload has no live row by definition",
	// Security evidence: revocation_owed is about removed hosts by design
	// (their certificate must still reach every CRL), and the rest record
	// tampering or unsafe keys that a removal does not undo.
	"certificate": "certificate revocation and key safety outlive the host",
	// The audit chain's hold is evidence about the log, not the host.
	"audit": "audit evidence",
	// Inputs to failover recovery (refence_failed, ha.recovery.bridged).
	"failover": "read by failover recovery; resolving it changes when a host's workloads recover",
}

// goneSubjectKeepCodes are single codes this sweep never resolves, with why.
var goneSubjectKeepCodes = map[string]string{
	// Each holds set-aside disk copies and has its evaluator's own rule for a
	// deleted VM (deleted_vm_residue.go, start_cancelled.go, stranded_disk.go).
	CondVMDiskStranded:   "the residue evaluator decides a deleted VM's disks",
	CondVMFailoverHeld:   "the residue evaluator decides a deleted VM's disks",
	CondVMStartCancelled: "the residue evaluator decides a deleted VM's disks",
	// The rootfs outlives the container; nothing removes it.
	CondCTRootfsStranded: "the stranded rootfs outlives the container",
	// The deputy raises and resolves it for a removed host by design.
	"reservation_stale": "the deputy reports a removed host's reservations",
	// Read by failover recovery to time a host's recovery.
	corrosion.CondPartitionPaused:      "read by failover recovery; resolving it changes when a host's workloads recover",
	corrosion.CondPartitionPauseFailed: "read by failover recovery; resolving it changes when a host's workloads recover",
	corrosion.CondPartitionOneWay:      "read by failover recovery; resolving it changes when a host's workloads recover",
	// LUN holds guard shared storage, which a removal does not release.
	"iscsi_lun_hold_standing":   "a LUN hold guards shared storage beyond the host",
	"iscsi_lun_hold_unreadable": "a LUN hold guards shared storage beyond the host",
	// Each names images left in a shared Ceph pool, which the removal neither
	// releases nor purges; the removed host's own record of them is gone with
	// it, and a trash entry held open may be a running VM's disk.
	"ceph_image_leftover": "names images left in shared Ceph storage beyond the host",
	"ceph_trash_leftover": "names images left in shared Ceph storage beyond the host",
}

// goneSubjectKept reports whether c outlives its subject by design.
func goneSubjectKept(c corrosion.HealthCondition) bool {
	if _, ok := goneSubjectKeepEvaluators[c.Evaluator]; ok {
		return true
	}
	_, ok := goneSubjectKeepCodes[c.Code]
	return ok
}

// conditionSubject splits a condition's subject into the workload it names
// (vm and container subjects) and the host it names, either "" when it
// names none. Names never contain '@' or '/' (safename).
func conditionSubject(kind, id string) (workload, host string) {
	switch kind {
	case "vm", "container":
		workload, host, _ = strings.Cut(id, "@")
	case "host":
		switch {
		case strings.Contains(id, "@"):
			host = id[strings.LastIndex(id, "@")+1:]
		case strings.Contains(id, "/"):
			host, _, _ = strings.Cut(id, "/")
		default:
			host = id
		}
	}
	return workload, host
}

// goneLookup answers "is this subject gone" once per name per pass.
type goneLookup struct {
	ctx   context.Context
	db    *corrosion.Client
	cache map[string]bool
}

// tombstonedOnly reports whether a workload table holds at least one
// tombstoned row where col = name and no live one. An unreadable table proves nothing.
func (g *goneLookup) tombstonedOnly(table, col, name string) bool {
	key := table + "\x00" + name
	if v, ok := g.cache[key]; ok {
		return v
	}
	rows, err := g.db.Query(g.ctx, `SELECT deleted_at FROM `+table+` WHERE `+col+` = ?`, name)
	gone := err == nil && len(rows) > 0
	for _, r := range rows {
		if r.String("deleted_at") == "" {
			gone = false
		}
	}
	if err == nil {
		g.cache[key] = gone
	}
	return gone
}

// hostRemoved is corrosion.HostRemoved, once per host per pass. An
// unreadable table proves nothing.
func (g *goneLookup) hostRemoved(host string) bool {
	key := "hosts\x00" + host
	if v, ok := g.cache[key]; ok {
		return v
	}
	removed, err := corrosion.HostRemoved(g.ctx, g.db, host)
	if err != nil {
		return false
	}
	g.cache[key] = removed
	return removed
}

// why reports why c's subject is gone, or "" when it is not proven gone.
func (g *goneLookup) why(c corrosion.HealthCondition) string {
	workload, host := conditionSubject(c.SubjectKind, c.SubjectID)
	switch {
	case workload != "" && c.SubjectKind == "vm" && g.tombstonedOnly("vms", "name", workload):
		return "the VM was deleted"
	case workload != "" && c.SubjectKind == "container" && g.tombstonedOnly("containers", "name", workload):
		return "the container was deleted"
	case host != "" && g.hostRemoved(host):
		return "the host was removed"
	}
	return ""
}

// resolveGoneSubjects resolves every open condition whose subject is gone
// (see the top of this file).
func (r *Reconciler) resolveGoneSubjects(ctx context.Context) {
	if ok, _ := r.replicaTrusted(ctx); !ok {
		return
	}
	open, err := corrosion.ListHealthConditions(ctx, r.db, false)
	if err != nil {
		slog.Warn("reconciler: cannot read health conditions; conditions of deleted subjects resolve on a later pass", "error", err)
		return
	}
	g := &goneLookup{ctx: ctx, db: r.db, cache: map[string]bool{}}
	for _, c := range open {
		if goneSubjectKept(c) {
			continue
		}
		why := g.why(c)
		if why == "" {
			continue
		}
		ts := r.now().UTC().Format(time.RFC3339)
		c.Lifecycle, c.ResolvedAt, c.LastSeen = corrosion.ConditionResolved, ts, ts
		c.ObserveCount, c.CleanCount, c.Reporter = 0, 1, r.hostName
		if err := corrosion.UpsertHealthCondition(ctx, r.db, c); err != nil {
			slog.Warn("reconciler: could not resolve a condition whose subject is gone",
				"evaluator", c.Evaluator, "code", c.Code, "subject", c.SubjectKind+"/"+c.SubjectID, "error", err)
			continue
		}
		slog.Info("reconciler: resolved a condition whose subject is gone — "+why,
			"evaluator", c.Evaluator, "code", c.Code, "subject", c.SubjectKind+"/"+c.SubjectID)
	}
}
