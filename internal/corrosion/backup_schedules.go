package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// BackupScheduleRecord is one row of the backup_schedules table. A schedule
// targets one of five scopes (Scope): "vm" (back up VMName), "pool" (every VM
// whose disks live on PoolName), "cluster" (every VM), "project" (every VM
// in ProjectName), or "container" (replication only: one container, see
// ContainerScheduleKey). The scheduler fans the non-vm scopes out per host at tick
// time. VMName always holds the row's identity key — for non-vm scopes it is a
// sentinel (see ScheduleKey) so several scopes can share one repo under the
// (vm_name, repo) primary key.
type BackupScheduleRecord struct {
	VMName      string
	PoolName    string // set when Scope == "pool"
	ProjectName string // set when Scope == "project"
	Scope       string // "vm" | "pool" | "cluster" | "project" | "container"; "" treated as "vm"
	Repo        string
	Cron        string
	KeepLast    int
	KeepDaily   int
	KeepWeekly  int
	KeepMonthly int
	KeepYearly  int
	Enabled     bool
	LastRunAt   string // RFC3339 UTC; "" = never run
	LastRunErr  string // empty = success

	// Replication (v17). Type "" / "backup" is a backup schedule; "replication"
	// replicates the VM's disks to TargetPool (on TargetHost, or a shared pool,
	// or an auto-selected healthy peer). KeepReplicas caps retained copies.
	// Replication rows store the destination pool in Repo (so the (vm_name,repo)
	// PK stays unique and meaningful).
	Type         string
	TargetPool   string
	TargetHost   string
	KeepReplicas int

	// Origin is the vm_name of the schedule ROW a fan-out run came from (its
	// sentinel), set by the scheduler when it expands a pool/project/cluster
	// schedule into per-VM runs. Not a column: it lets the replication runner
	// tell two schedules replicating one VM into one pool apart, so one never
	// prunes the other's replicas. Empty for a vm-scoped row (VMName is the row).
	Origin string

	// Replication follow-ups (v18). Incremental transfers only dirty extents
	// into raw replicas (full-copy fallback when unavailable). AutoPromote lets
	// failover bring up the freshest replica on host loss. LastCheckpoint is the
	// per-schedule dirty-bitmap chain anchor advanced after each incremental run.
	Incremental    bool
	AutoPromote    bool
	LastCheckpoint string
}

// ScheduleKey returns the value stored in backup_schedules.vm_name for a
// schedule of the given scope. For "vm" scope it is the VM name; for the other
// scopes it is a sentinel so multiple scopes can coexist on one repo under the
// (vm_name, repo) primary key.
func ScheduleKey(scope, vmName, poolName, projectName string) string {
	switch scope {
	case "pool":
		return "@pool:" + poolName
	case "project":
		return "@project:" + projectName
	case "cluster":
		return "@cluster"
	case "container":
		return ContainerScheduleKey(projectName, vmName)
	default:
		return vmName
	}
}

// containerScheduleKeyPrefix keeps a container schedule's identity apart from a
// VM of the same name under the (vm_name, repo) primary key, and keeps a
// previous-release scheduler (which looks the key up among VMs and finds none)
// from running it as a VM replication.
const containerScheduleKeyPrefix = "@ct:"

// ContainerScheduleKey is the vm_name a container-scoped replication schedule is
// stored under: "@ct:<project>/<name>". The project is part of the identity
// because a container name is unique per project, not cluster-wide: keyed by
// name alone, one project's schedule add would replace another project's
// schedule of the same name into the same repo. Neither a project nor a
// container name can contain "/".
func ContainerScheduleKey(project, name string) string {
	return containerScheduleKeyPrefix + normalizeProject(project) + "/" + name
}

// ContainerScheduleName is the container a container-scoped schedule key names.
// project is "" for the earlier "@ct:<name>" form, whose row records its project
// only in project_name (ContainerScheduleIs reads both forms). ok is false for
// any other key.
func ContainerScheduleName(key string) (project, name string, ok bool) {
	rest, found := strings.CutPrefix(key, containerScheduleKeyPrefix)
	if !found || rest == "" {
		return "", "", false
	}
	if p, n, qualified := strings.Cut(rest, "/"); qualified {
		if p == "" || n == "" {
			return "", "", false
		}
		return p, n, true
	}
	return "", rest, true
}

// ContainerScheduleIs reports whether r is a container-scoped schedule of the
// container name in project, in either key form.
func ContainerScheduleIs(r BackupScheduleRecord, project, name string) bool {
	if r.Scope != "container" {
		return false
	}
	p, n, ok := ContainerScheduleName(r.VMName)
	if !ok || n != name {
		return false
	}
	if p == "" {
		p = r.ProjectName
	}
	return normalizeProject(p) == normalizeProject(project)
}

// ContainerScheduleProject is the project of a container-scoped schedule row,
// from its key when the key names one and from project_name otherwise.
func ContainerScheduleProject(r BackupScheduleRecord) string {
	if p, _, ok := ContainerScheduleName(r.VMName); ok && p != "" {
		return p
	}
	return normalizeProject(r.ProjectName)
}

// UpsertContainerReplicationSchedule creates or replaces a container's
// replication schedule: release feature container_replication's data, which a
// host on an earlier build would skip without a word or take for a VM's. It
// writes only with a grant from that feature's gate, which has put this node's
// used record on its stream ahead of the row.
func UpsertContainerReplicationSchedule(ctx context.Context, c *Client, g capabilities.FeatureGrant, s BackupScheduleRecord) error {
	if err := g.Check(capabilities.FeatureContainerReplication); err != nil {
		return err
	}
	if _, _, ok := ContainerScheduleName(s.VMName); !ok || s.Scope != "container" || s.Type != "replication" {
		return fmt.Errorf("schedule %q (scope %q, type %q) is not a container replication schedule", s.VMName, s.Scope, s.Type)
	}
	return upsertBackupSchedule(ctx, c, s)
}

// UpsertBackupSchedule creates or replaces a schedule by (vm_name, repo).
// A container's replication schedule (a key ContainerScheduleName reads) is
// refused: it is written only by UpsertContainerReplicationSchedule, behind
// its release feature's gate. No other schedule's key has that form (a VM
// name cannot contain '@' or ':').
// PoolName is stored alongside but is not part of the primary key —
// callers wanting a pool-level row leave VMName empty and set PoolName.
// The PRIMARY KEY is still (vm_name, repo), with the convention that
// an empty vm_name + non-empty pool_name maps to a single pool row
// per repo.
func UpsertBackupSchedule(ctx context.Context, c *Client, s BackupScheduleRecord) error {
	if _, _, ok := ContainerScheduleName(s.VMName); ok {
		return fmt.Errorf("schedule %q is a container replication schedule, written only behind release feature %s",
			s.VMName, capabilities.FeatureContainerReplication)
	}
	return upsertBackupSchedule(ctx, c, s)
}

func upsertBackupSchedule(ctx context.Context, c *Client, s BackupScheduleRecord) error {
	now := c.NowTS()
	scope := s.Scope
	if scope == "" {
		scope = "vm"
	}
	typ := s.Type
	if typ == "" {
		typ = "backup"
	}
	return c.Execute(ctx,
		`INSERT INTO backup_schedules
		   (vm_name, pool_name, project_name, scope, repo, cron, keep_last, keep_daily, keep_weekly, keep_monthly, keep_yearly, enabled, type, target_pool, target_host, keep_replicas, incremental, auto_promote, last_checkpoint, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(vm_name, repo) DO UPDATE SET
		   pool_name = excluded.pool_name,
		   project_name = excluded.project_name,
		   scope = excluded.scope,
		   cron = excluded.cron,
		   keep_last = excluded.keep_last,
		   keep_daily = excluded.keep_daily,
		   keep_weekly = excluded.keep_weekly,
		   keep_monthly = excluded.keep_monthly,
		   keep_yearly = excluded.keep_yearly,
		   enabled = excluded.enabled,
		   type = excluded.type,
		   target_pool = excluded.target_pool,
		   target_host = excluded.target_host,
		   keep_replicas = excluded.keep_replicas,
		   incremental = excluded.incremental,
		   auto_promote = excluded.auto_promote,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`,
		s.VMName, nullableString(s.PoolName), nullableString(s.ProjectName), scope, s.Repo, s.Cron,
		s.KeepLast, s.KeepDaily, s.KeepWeekly, s.KeepMonthly, s.KeepYearly,
		s.Enabled, typ, nullableString(s.TargetPool), nullableString(s.TargetHost), s.KeepReplicas,
		boolToInt(s.Incremental), boolToInt(s.AutoPromote), nullableString(s.LastCheckpoint), now,
	)
}

// nullableString maps "" → SQL NULL so we don't carry an empty-string
// pool_name on per-VM rows. SQLite treats "" and NULL distinctly in
// some predicates; keep them aligned.
func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// CountActiveSchedulesUsingPool counts ENABLED, non-deleted schedules that target
// (host, poolName) — the schedule half of the pool-delete reference guard
// (disabled schedules don't block). Three matches, per the host-scoping nuance:
//   - a pool-scoped backup schedule (scope='pool', pool_name=poolName);
//   - a replication schedule targeting poolName with NO target_host set — ambiguous
//     across same-named pools on other hosts, so blocked CONSERVATIVELY (any pool
//     of that name) unless --force;
//   - a replication schedule targeting (poolName, host) explicitly.
func CountActiveSchedulesUsingPool(ctx context.Context, c *Client, host, poolName string) (int, error) {
	rows, err := c.Query(ctx,
		`SELECT COUNT(*) AS n FROM backup_schedules
		 WHERE deleted_at IS NULL AND enabled = 1 AND (
		     (scope = 'pool' AND pool_name = ?)
		  OR (target_pool = ? AND COALESCE(target_host, '') = '')
		  OR (target_pool = ? AND target_host = ?)
		 )`,
		poolName, poolName, poolName, host)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return rows[0].Int("n"), nil
}

// ListBackupSchedules returns every non-deleted schedule.
func ListBackupSchedules(ctx context.Context, c *Client) ([]BackupScheduleRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT vm_name, pool_name, project_name, scope, repo, cron, keep_last, keep_daily, keep_weekly, keep_monthly, keep_yearly,
		        enabled, last_run_at, last_run_err, type, target_pool, target_host, keep_replicas, incremental, auto_promote, last_checkpoint
		 FROM backup_schedules
		 WHERE deleted_at IS NULL
		 ORDER BY scope, vm_name, repo`)
	if err != nil {
		return nil, fmt.Errorf("list backup_schedules: %w", err)
	}
	out := make([]BackupScheduleRecord, 0, len(rows))
	for _, r := range rows {
		scope := r.String("scope")
		if scope == "" {
			scope = "vm"
		}
		typ := r.String("type")
		if typ == "" {
			typ = "backup"
		}
		out = append(out, BackupScheduleRecord{
			VMName:         r.String("vm_name"),
			PoolName:       r.String("pool_name"),
			ProjectName:    r.String("project_name"),
			Scope:          scope,
			Repo:           r.String("repo"),
			Cron:           r.String("cron"),
			KeepLast:       r.Int("keep_last"),
			KeepDaily:      r.Int("keep_daily"),
			KeepWeekly:     r.Int("keep_weekly"),
			KeepMonthly:    r.Int("keep_monthly"),
			KeepYearly:     r.Int("keep_yearly"),
			Enabled:        r.Int("enabled") != 0,
			LastRunAt:      r.String("last_run_at"),
			LastRunErr:     r.String("last_run_err"),
			Type:           typ,
			TargetPool:     r.String("target_pool"),
			TargetHost:     r.String("target_host"),
			KeepReplicas:   r.Int("keep_replicas"),
			Incremental:    r.Int("incremental") != 0,
			AutoPromote:    r.Int("auto_promote") != 0,
			LastCheckpoint: r.String("last_checkpoint"),
		})
	}
	return out, nil
}

// VMsOnPool returns the VM names whose disks live on the given
// storage pool. Used by the snapshot scheduler to expand a
// pool-level backup_schedules row at tick time.
func VMsOnPool(ctx context.Context, c *Client, hostName, poolName string) ([]string, error) {
	rows, err := c.Query(ctx,
		`SELECT DISTINCT vms.name
		 FROM vms
		 JOIN vm_disks ON vm_disks.vm_name = vms.name
		 WHERE vms.host_name = ?
		   AND vms.deleted_at IS NULL
		   AND vm_disks.deleted_at IS NULL
		   AND vm_disks.storage_volume = ?
		 ORDER BY vms.name`, hostName, poolName)
	if err != nil {
		return nil, fmt.Errorf("vms_on_pool: %w", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.String("name"))
	}
	return out, nil
}

// VMsOnHost returns every VM owned by the given host. Used by the snapshot
// scheduler to expand a cluster-scoped backup_schedules row at tick time.
func VMsOnHost(ctx context.Context, c *Client, hostName string) ([]string, error) {
	rows, err := c.Query(ctx,
		`SELECT name FROM vms
		 WHERE host_name = ? AND deleted_at IS NULL
		 ORDER BY name`, hostName)
	if err != nil {
		return nil, fmt.Errorf("vms_on_host: %w", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.String("name"))
	}
	return out, nil
}

// VMsInProject returns the host's VMs that belong to the given tenancy
// project. Used by the snapshot scheduler to expand a project-scoped
// backup_schedules row at tick time.
func VMsInProject(ctx context.Context, c *Client, hostName, project string) ([]string, error) {
	rows, err := c.Query(ctx,
		`SELECT name FROM vms
		 WHERE host_name = ? AND project = ? AND deleted_at IS NULL
		 ORDER BY name`, hostName, project)
	if err != nil {
		return nil, fmt.Errorf("vms_in_project: %w", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.String("name"))
	}
	return out, nil
}

// DeleteBackupSchedule marks the (vm_name, repo) schedule deleted.
func DeleteBackupSchedule(ctx context.Context, c *Client, vmName, repo string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE backup_schedules
		 SET deleted_at = ?, updated_at = ?
		 WHERE vm_name = ? AND repo = ?`,
		nowRFC3339(), now, vmName, repo)
}

// MarkBackupScheduleRun records the outcome of a scheduled run; runErr
// "" means success. runAt is the timestamp to persist as last_run_at —
// callers driving virtual time pass their injected clock here so the
// "already ran this minute" guard in the scheduler is reproducible.
func MarkBackupScheduleRun(ctx context.Context, c *Client, vmName, repo, runErr string, runAt time.Time) error {
	ts := runAt.UTC().Format(time.RFC3339) // last_run_at = the actual run time
	return c.Execute(ctx,
		`UPDATE backup_schedules
		 SET last_run_at = ?, last_run_err = ?, updated_at = ?
		 WHERE vm_name = ? AND repo = ?`,
		ts, runErr, c.NowTS(), vmName, repo)
}

// SetReplicationCheckpoint advances the per-schedule dirty-bitmap chain anchor
// after a successful incremental replication run. An empty checkpoint resets
// the chain (next run is a full push). Separate from the schedule upsert so an
// operator edit can't accidentally rewind the chain.
// Keyed by the REAL vm + repo in the dedicated replication_checkpoints table
// (NOT backup_schedules.last_checkpoint, which is the schedule-row sentinel for
// fan-out scopes — writing there missed every fanned-out VM). An empty
// checkpoint resets the chain. Upsert so per-VM and fan-out both persist.
func SetReplicationCheckpoint(ctx context.Context, c *Client, vmName, repo, checkpoint string) error {
	now := c.NowTS()
	if checkpoint == "" {
		// Reset: tombstone the row so the next run re-bases (parent = "").
		return c.Execute(ctx,
			`UPDATE replication_checkpoints SET deleted_at = ?, updated_at = ?
			 WHERE vm_name = ? AND repo = ?`, nowRFC3339(), now, vmName, repo)
	}
	return c.Execute(ctx,
		`INSERT INTO replication_checkpoints (vm_name, repo, checkpoint, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, NULL)
		 ON CONFLICT(vm_name, repo) DO UPDATE SET checkpoint = excluded.checkpoint,
		   updated_at = excluded.updated_at, deleted_at = NULL`,
		vmName, repo, checkpoint, now)
}

// GetReplicationCheckpoint returns the recorded incremental-replication anchor
// for (vmName, repo), or "" if none (chain not yet established / was reset).
func GetReplicationCheckpoint(ctx context.Context, c *Client, vmName, repo string) (string, error) {
	rows, err := c.Query(ctx,
		`SELECT checkpoint FROM replication_checkpoints
		 WHERE vm_name = ? AND repo = ? AND deleted_at IS NULL`, vmName, repo)
	if err != nil || len(rows) == 0 {
		return "", err
	}
	return rows[0].String("checkpoint"), nil
}

// ScheduleOrphanGrace is how long a workload's schedule is kept after the
// workload's tombstone before the orphan sweep may remove it.
const ScheduleOrphanGrace = 24 * time.Hour

// OrphanedStackSchedules returns the live schedules of a workload of a
// torn-down stack: a vm-scoped schedule (backup or replication) whose vms row
// is a tombstone of a VM of a stack whose record is a tombstone, or a
// container-scoped schedule whose container has no live row and whose newest
// tombstone carries the label of such a stack. The tombstone's deletion must be
// at least grace before now, and the schedule last written no later than that
// tombstone (LWW order; an equal stamp is an orphan: a re-create's schedule is
// written only after its create revived the row). Only VMName and Repo (and
// Scope) are set.
//
// Nothing else is an orphan. A schedule of a VM or container that is not a
// stack's, or of a stack still recorded live, stays dormant as it always has
// (the scheduler skips a workload with no live row) and resumes when the name
// comes back: a failed rebuild or re-create, or a blue-green cutover's blue,
// leaves exactly that. A schedule of a name with no row at all — one
// replicated ahead of its workload — is never one.
//
// A run that finished after the delete stamped the row later
// (MarkBackupScheduleRun bumps updated_at), so that schedule reads as newer
// than the tombstone; it is swept once nothing has written it for a full grace
// (orphanTombstone). A redeploy of the stack is never touched: its stack row
// and its workloads' rows are live again before the compose hook writes a
// schedule. The one residual risk is a sweeper whose replica is more than a
// grace behind the origin of a re-created stack's rows, which is not a state
// a failover lease holder is in.
func OrphanedStackSchedules(ctx context.Context, c *Client, now time.Time, grace time.Duration) ([]BackupScheduleRecord, error) {
	out, err := orphanedStackVMSchedules(ctx, c, now, grace)
	if err != nil {
		return nil, err
	}
	cts, err := orphanedStackContainerSchedules(ctx, c, now, grace)
	if err != nil {
		return nil, err
	}
	return append(out, cts...), nil
}

// orphanTombstone reports whether a tombstone (its deleted_at and LWW key)
// makes a schedule last written at scheduleAt an orphan at now.
func orphanTombstone(deletedAt, tombAt, scheduleAt string, now time.Time, grace time.Duration) bool {
	deleted, ok := ParseUpdatedAt(deletedAt)
	if !ok || now.Sub(deleted) < grace {
		return false
	}
	if lwwOrder(scheduleAt, tombAt) <= 0 {
		return true
	}
	// Written after the tombstone, but not for a full grace since. Every
	// config write needs a live workload, so with none since, that write was a
	// run in flight at the delete (MarkBackupScheduleRun), not a schedule for a
	// new incarnation; one for a new incarnation replicates with its revival
	// well inside the grace.
	written, ok := ParseUpdatedAt(scheduleAt)
	return ok && now.Sub(written) >= grace
}

func orphanedStackVMSchedules(ctx context.Context, c *Client, now time.Time, grace time.Duration) ([]BackupScheduleRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT s.vm_name, s.repo, s.updated_at AS schedule_at, v.updated_at AS vm_at, v.deleted_at AS vm_deleted
		 FROM backup_schedules s JOIN vms v ON v.name = s.vm_name
		 WHERE s.deleted_at IS NULL AND v.deleted_at IS NOT NULL
		   AND COALESCE(s.scope, 'vm') IN ('vm', '')
		   AND COALESCE(v.stack_name, '') != ''
		   AND EXISTS (SELECT 1 FROM stacks st WHERE st.name = v.stack_name AND st.deleted_at IS NOT NULL)`)
	if err != nil {
		return nil, fmt.Errorf("orphaned vm schedules: %w", err)
	}
	var out []BackupScheduleRecord
	for _, r := range rows {
		if orphanTombstone(r.String("vm_deleted"), r.String("vm_at"), r.String("schedule_at"), now, grace) {
			out = append(out, BackupScheduleRecord{VMName: r.String("vm_name"), Repo: r.String("repo"), Scope: "vm"})
		}
	}
	return out, nil
}

func orphanedStackContainerSchedules(ctx context.Context, c *Client, now time.Time, grace time.Duration) ([]BackupScheduleRecord, error) {
	scheds, err := c.Query(ctx,
		`SELECT vm_name, repo, project_name, updated_at FROM backup_schedules
		 WHERE deleted_at IS NULL AND scope = 'container'`)
	if err != nil {
		return nil, fmt.Errorf("orphaned container schedules: %w", err)
	}
	var out []BackupScheduleRecord
	for _, sr := range scheds {
		rec := BackupScheduleRecord{VMName: sr.String("vm_name"), Repo: sr.String("repo"), ProjectName: sr.String("project_name"), Scope: "container"}
		_, name, ok := ContainerScheduleName(rec.VMName)
		if !ok {
			continue
		}
		project := ContainerScheduleProject(rec)
		rows, err := c.Query(ctx,
			`SELECT COALESCE(project, '_default') AS project, COALESCE(labels, '') AS labels,
			        updated_at, COALESCE(deleted_at, '') AS deleted_at
			 FROM containers WHERE name = ?`, name)
		if err != nil {
			return nil, fmt.Errorf("orphaned container schedules: %w", err)
		}
		live := false
		var newest map[string]string
		for _, r := range rows {
			if normalizeProject(r.String("project")) != project {
				continue
			}
			if r.String("deleted_at") == "" {
				live = true
				break
			}
			if newest == nil || lwwOrder(newest["at"], r.String("updated_at")) < 0 {
				newest = map[string]string{"at": r.String("updated_at"), "deleted": r.String("deleted_at"), "labels": r.String("labels")}
			}
		}
		if live || newest == nil {
			continue
		}
		var labels map[string]string
		if json.Unmarshal([]byte(newest["labels"]), &labels) != nil || labels[LabelStack] == "" {
			continue
		}
		torn, err := c.Query(ctx, `SELECT 1 FROM stacks WHERE name = ? AND deleted_at IS NOT NULL`, labels[LabelStack])
		if err != nil {
			return nil, fmt.Errorf("orphaned container schedules: %w", err)
		}
		if len(torn) == 0 {
			continue
		}
		if orphanTombstone(newest["deleted"], newest["at"], sr.String("updated_at"), now, grace) {
			out = append(out, BackupScheduleRecord{VMName: rec.VMName, Repo: rec.Repo, Scope: "container"})
		}
	}
	return out, nil
}
