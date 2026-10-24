// Snapshot/backup scheduler.
//
// Each daemon runs its own scheduler. Per tick (default 60 s), it
// pulls every non-deleted backup_schedules row whose VM is hosted
// locally and whose cron expression matches the current minute, then
// invokes the SnapshotRunner. There is no cluster-wide leader gate:
// a VM is owned by exactly one host at a time, so each backup_schedules
// row has exactly one candidate executor and double-firing is
// impossible by construction. The `same-minute` dedup guard prevents
// a fast-poll within a minute from re-firing the same row.
//
// Why not leader-gated: in the original design the leader iterated
// all schedules and skipped non-local VMs (returning nil). That
// silently dropped backups for every VM whose host wasn't currently
// holding the snapshot-scheduler lease — a real correctness bug.
// The per-host model has no such failure mode.

package scheduler

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// SnapshotRunner is what the scheduler calls when a cron fires. The
// production implementation lives in internal/grpcapi (lockVM +
// pbsstore.PushFile + retention); tests pass a stub that records calls.
//
// The runAt argument is the scheduler's view of "now" — runners MUST
// use it as the manifest timestamp instead of consulting time.Now()
// directly. Two backups in the same wall-clock second from different
// schedulers (or fast virtual-time test ticks) would otherwise collide
// on the manifest filename and silently overwrite each other.
type SnapshotRunner interface {
	RunBackup(ctx context.Context, sched corrosion.BackupScheduleRecord, runAt time.Time) error
}

// ReplicationRunner is called for schedules with type='replication' (the
// production impl lives in internal/grpcapi: ReplicateVolume + keep_replicas
// pruning). Optional — nil means replication rows are skipped.
type ReplicationRunner interface {
	RunReplication(ctx context.Context, sched corrosion.BackupScheduleRecord, runAt time.Time) error
}

// PointInTimeRetrier is optionally implemented by a ReplicationRunner whose
// copies can fall short of point-in-time. A run it says is due is dispatched
// at this tick even when the schedule's cron does not match, so a
// not-point-in-time replica is followed by a point-in-time attempt a minute
// later, not a full interval later.
type PointInTimeRetrier interface {
	// AnyPointInTimeRetryDue is the cheap check made first.
	AnyPointInTimeRetryDue() bool
	// PointInTimeRetryDue reports whether sched (a fan-out row's per-VM
	// run included) is owed a retry.
	PointInTimeRetryDue(sched corrosion.BackupScheduleRecord) bool
}

// SnapshotScheduler is a per-host minute-tick scheduler. Each daemon
// runs its own instance; ownership is decided at tick time by reading
// `vms.host_name`. There is no cluster-wide lease.
type SnapshotScheduler struct {
	DB           *corrosion.Client
	HostName     string
	Runner       SnapshotRunner
	ReplRunner   ReplicationRunner // optional; handles type='replication' rows
	PollInterval time.Duration     // default 60s
	Now          func() time.Time
	// RunHoldBound is how long one run holds the pass that dispatched it
	// (default DefaultRunHoldBound). See runHeld.
	RunHoldBound time.Duration

	stopOnce sync.Once
	stopCh   chan struct{}

	// running holds each run that has not returned, by runKey, with when
	// it started: one is never started again until it has (runHeld).
	runningMu sync.Mutex
	running   map[string]time.Time
}

// DefaultRunHoldBound is how long a run holds the pass that dispatched it
// before the pass goes on without it. Runs are made one after another, so a
// copy whose target stopped answering mid-write (an NFS server that died;
// the write waits in the kernel for as long as the server is gone) held
// every other schedule of the host for the whole outage. A run past the
// bound goes on in its own goroutine and records its outcome when it
// returns; until then it is never started a second time.
const DefaultRunHoldBound = 5 * time.Minute

func (s *SnapshotScheduler) runHoldBound() time.Duration {
	if s.RunHoldBound > 0 {
		return s.RunHoldBound
	}
	return DefaultRunHoldBound
}

// runKey names one run of a schedule: the row it came from (a fan-out's
// Origin), the VM it is for, its repo or pool, and its type.
func runKey(sched corrosion.BackupScheduleRecord) string {
	return sched.Type + "\x00" + sched.Origin + "\x00" + sched.VMName + "\x00" + sched.Repo
}

// runHeld runs fn, the run of sched dispatched at runAt, unless the same
// run (runKey) has not returned yet, in which case it is not started and
// false is returned. The caller waits for fn at most the hold bound; past
// it, fn goes on in its own goroutine and the run stays marked running until
// fn has returned, its outcome recorded by fn itself, so it is neither
// started twice nor recorded twice.
func (s *SnapshotScheduler) runHeld(sched corrosion.BackupScheduleRecord, runAt time.Time, fn func()) bool {
	key := runKey(sched)
	s.runningMu.Lock()
	if since, busy := s.running[key]; busy {
		s.runningMu.Unlock()
		slog.Warn("snapshot scheduler: run not started, because its previous run has not returned",
			"type", sched.Type, "vm", sched.VMName, "repo", sched.Repo, "previous_started", since.UTC().Format(time.RFC3339))
		return false
	}
	if s.running == nil {
		s.running = map[string]time.Time{}
	}
	started := time.Now()
	s.running[key] = started
	s.runningMu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			s.runningMu.Lock()
			delete(s.running, key)
			s.runningMu.Unlock()
		}()
		fn()
	}()
	bound := s.runHoldBound()
	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		slog.Warn("snapshot scheduler: run has not returned within its hold; it goes on, and the other schedules no longer wait for it",
			"type", sched.Type, "vm", sched.VMName, "repo", sched.Repo, "run_at", runAt.UTC().Format(time.RFC3339), "held", bound)
	}
	return true
}

// NewSnapshotScheduler returns a configured scheduler with sensible defaults.
func NewSnapshotScheduler(db *corrosion.Client, hostName string, runner SnapshotRunner) *SnapshotScheduler {
	return &SnapshotScheduler{
		DB:           db,
		HostName:     hostName,
		Runner:       runner,
		PollInterval: 60 * time.Second,
		Now:          func() time.Time { return time.Now().UTC() },
		stopCh:       make(chan struct{}),
	}
}

// Run blocks until ctx is cancelled or Stop is called, ticking every
// PollInterval. The first tick fires immediately so a freshly-started
// daemon can pick up overdue schedules before the next minute boundary.
func (s *SnapshotScheduler) Run(ctx context.Context) {
	if s.PollInterval <= 0 {
		s.PollInterval = 60 * time.Second
	}
	if s.Now == nil {
		s.Now = func() time.Time { return time.Now().UTC() }
	}
	ticker := time.NewTicker(s.PollInterval)
	defer ticker.Stop()
	s.Tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.Tick(ctx)
		}
	}
}

// Stop interrupts a running scheduler. Idempotent.
func (s *SnapshotScheduler) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// Tick runs one scheduling pass. Exposed for tests so virtual-time
// runs can drive minute boundaries directly without sleeping.
func (s *SnapshotScheduler) Tick(ctx context.Context) {
	now := s.Now()
	schedules, err := corrosion.ListBackupSchedules(ctx, s.DB)
	if err != nil {
		slog.Warn("snapshot scheduler: list schedules", "error", err)
		return
	}
	for _, sched := range schedules {
		if !sched.Enabled {
			continue
		}
		cron, err := ParseCron(sched.Cron)
		if err != nil {
			slog.Warn("snapshot scheduler: bad cron",
				"vm", sched.VMName, "pool", sched.PoolName, "repo", sched.Repo,
				"cron", sched.Cron, "error", err)
			continue
		}
		if !cron.Matches(now) {
			s.dispatchPointInTimeRetries(ctx, sched, now)
			continue
		}
		if alreadyRanThisMinute(sched.LastRunAt, now) {
			continue
		}

		// Fan-out scopes (pool / cluster / project): expand to every
		// matching VM owned by THIS host and fire one backup each.
		// Per-VM scope: the single-host-owner gate below.
		if fanoutVMs, isFanout := s.expandScope(ctx, sched); isFanout {
			if len(fanoutVMs) == 0 {
				// No matching VMs on this host's slice — nothing to do.
				// Don't mark the row run; other hosts may own matches.
				continue
			}
			for _, vmName := range fanoutVMs {
				fanout := sched
				fanout.Origin = sched.VMName
				fanout.VMName = vmName
				fanout.Scope = "vm"
				fanout.PoolName = ""
				fanout.ProjectName = ""
				s.dispatch(ctx, fanout, now)
			}
			// Record one last_run_at on the scope row per minute, keyed
			// by the row's identity (sentinel vm_name for non-vm scopes).
			_ = corrosion.MarkBackupScheduleRun(ctx, s.DB, sched.VMName, sched.Repo, "", now)
			continue
		}

		// A container-scoped replication schedule routes by the container's
		// host, not a VM's.
		if sched.Scope == "container" {
			if project, name, isCT := corrosion.ContainerScheduleName(sched.VMName); isCT {
				if project == "" {
					project = sched.ProjectName // the earlier name-only key
				}
				if owner, ok := s.containerOwner(ctx, name, project); ok && owner == s.HostName {
					s.dispatch(ctx, sched, now)
				}
			}
			continue
		}

		// Per-VM mode: route only when this host owns the VM.
		owner, ok := s.vmOwner(ctx, sched.VMName)
		if !ok || owner != s.HostName {
			continue
		}
		s.dispatch(ctx, sched, now)
	}
}

type pitRetryCtxKey struct{}

// WithPointInTimeRetry marks ctx as a point-in-time retry's: the runner makes
// a point-in-time copy or none.
func WithPointInTimeRetry(ctx context.Context) context.Context {
	return context.WithValue(ctx, pitRetryCtxKey{}, true)
}

// IsPointInTimeRetry reports whether ctx is a point-in-time retry's.
func IsPointInTimeRetry(ctx context.Context) bool {
	v, _ := ctx.Value(pitRetryCtxKey{}).(bool)
	return v
}

// dispatchPointInTimeRetries runs, outside its cron, each of a replication
// schedule's per-VM runs the runner says is owed a point-in-time retry
// (PointInTimeRetrier). A fan-out row's last_run_at is left alone: the retry
// is one VM's run, not the row's.
func (s *SnapshotScheduler) dispatchPointInTimeRetries(ctx context.Context, sched corrosion.BackupScheduleRecord, now time.Time) {
	if sched.Type != "replication" || s.ReplRunner == nil {
		return
	}
	r, ok := s.ReplRunner.(PointInTimeRetrier)
	if !ok || !r.AnyPointInTimeRetryDue() {
		return
	}
	ctx = WithPointInTimeRetry(ctx)
	if fanoutVMs, isFanout := s.expandScope(ctx, sched); isFanout {
		for _, vmName := range fanoutVMs {
			fanout := sched
			fanout.Origin = sched.VMName
			fanout.VMName = vmName
			fanout.Scope = "vm"
			fanout.PoolName = ""
			fanout.ProjectName = ""
			if r.PointInTimeRetryDue(fanout) {
				s.runHeld(fanout, now, func() {
					if err := s.ReplRunner.RunReplication(ctx, fanout, now); errors.Is(err, ErrRunSkipped) {
						slog.Info("snapshot scheduler: point-in-time retry skipped", "vm", vmName, "repo", sched.Repo, "reason", err)
					} else if err != nil {
						slog.Warn("snapshot scheduler: point-in-time retry failed", "vm", vmName, "repo", sched.Repo, "error", err)
					}
				})
			}
		}
		return
	}
	if !r.PointInTimeRetryDue(sched) || alreadyRanThisMinute(sched.LastRunAt, now) {
		return
	}
	if owner, ok := s.vmOwner(ctx, sched.VMName); !ok || owner != s.HostName {
		return
	}
	s.dispatch(ctx, sched, now)
}

// expandScope resolves a fan-out schedule to the VMs on this host it should
// back up. It returns (vmNames, true) for pool/cluster/project scopes and
// (nil, false) for the per-VM scope. A legacy pool row (pool_name set with no
// explicit scope) is still treated as a pool fan-out.
func (s *SnapshotScheduler) expandScope(ctx context.Context, sched corrosion.BackupScheduleRecord) ([]string, bool) {
	switch {
	case sched.Scope == "cluster":
		vms, err := corrosion.VMsOnHost(ctx, s.DB, s.HostName)
		if err != nil {
			slog.Warn("snapshot scheduler: list cluster vms", "error", err)
			return nil, true
		}
		return vms, true
	case sched.Scope == "project":
		vms, err := corrosion.VMsInProject(ctx, s.DB, s.HostName, sched.ProjectName)
		if err != nil {
			slog.Warn("snapshot scheduler: list project vms", "project", sched.ProjectName, "error", err)
			return nil, true
		}
		return vms, true
	case sched.Scope == "pool" || sched.PoolName != "":
		vms, err := corrosion.VMsOnPool(ctx, s.DB, s.HostName, sched.PoolName)
		if err != nil {
			slog.Warn("snapshot scheduler: list pool vms", "pool", sched.PoolName, "error", err)
			return nil, true
		}
		return vms, true
	default:
		return nil, false
	}
}

// vmOwner returns the host_name column of the VM and a not-found flag.
// Schedules whose VM has been deleted return ok=false so dispatch
// silently skips the row rather than logging an error every tick.
func (s *SnapshotScheduler) vmOwner(ctx context.Context, vmName string) (string, bool) {
	rows, err := s.DB.Query(ctx,
		`SELECT host_name FROM vms WHERE name = ? AND deleted_at IS NULL`, vmName)
	if err != nil || len(rows) == 0 {
		return "", false
	}
	return rows[0].String("host_name"), true
}

// containerOwner returns the host holding the live container name of project
// (the default project when empty). ok is false when there is none, or when
// more than one host holds one: a container name is unique per host, not
// cluster-wide, so an ambiguous schedule runs nowhere rather than on a guess.
func (s *SnapshotScheduler) containerOwner(ctx context.Context, name, project string) (string, bool) {
	if project == "" {
		project = corrosion.DefaultProject
	}
	rows, err := s.DB.Query(ctx,
		`SELECT host_name FROM containers WHERE name = ? AND project = ? AND deleted_at IS NULL`, name, project)
	if err != nil || len(rows) != 1 {
		return "", false
	}
	return rows[0].String("host_name"), true
}

// dispatch fires one backup and records the outcome. The runAt
// timestamp is the scheduler's view of "now" so virtual-time tests are
// reproducible.
//
// The run holds the pass at most the hold bound (runHeld): one that does not
// return goes on by itself and records its outcome when it does.
func (s *SnapshotScheduler) dispatch(ctx context.Context, sched corrosion.BackupScheduleRecord, runAt time.Time) {
	s.runHeld(sched, runAt, func() { s.runAndRecord(ctx, sched, runAt) })
}

// runAndRecord makes one run and records its outcome on the schedule row.
func (s *SnapshotScheduler) runAndRecord(ctx context.Context, sched corrosion.BackupScheduleRecord, runAt time.Time) {
	var err error
	if sched.Type == "replication" {
		if s.ReplRunner == nil {
			slog.Warn("snapshot scheduler: nil replication runner, skipping", "vm", sched.VMName)
			return
		}
		err = s.ReplRunner.RunReplication(ctx, sched, runAt)
	} else {
		if s.Runner == nil {
			slog.Warn("snapshot scheduler: nil runner, skipping", "vm", sched.VMName)
			return
		}
		err = s.Runner.RunBackup(ctx, sched, runAt)
	}
	if errors.Is(err, ErrRunSkipped) {
		// Not this host's run: nothing is recorded on the schedule row,
		// which the owner's runs keep.
		slog.Info("snapshot scheduler: schedule run skipped", "type", sched.Type, "vm", sched.VMName, "repo", sched.Repo, "reason", err)
		return
	}
	runErr := ""
	if err != nil {
		runErr = err.Error()
		slog.Error("snapshot scheduler: schedule run failed", "type", sched.Type, "vm", sched.VMName, "repo", sched.Repo, "error", err)
	} else {
		slog.Info("snapshot scheduler: schedule run ok", "type", sched.Type, "vm", sched.VMName, "repo", sched.Repo)
	}
	if mErr := corrosion.MarkBackupScheduleRun(ctx, s.DB, sched.VMName, sched.Repo, runErr, runAt); mErr != nil {
		slog.Warn("snapshot scheduler: mark run", "vm", sched.VMName, "error", mErr)
	}
}

// alreadyRanThisMinute returns true if last_run_at falls in the same
// UTC minute as now — prevents a fast-poll loop from double-firing.
func alreadyRanThisMinute(lastRunAt string, now time.Time) bool {
	if lastRunAt == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, lastRunAt)
	if err != nil {
		return false
	}
	return t.UTC().Truncate(time.Minute).Equal(now.UTC().Truncate(time.Minute))
}

// ErrRunSkipped is wrapped by a runner's error for a run this host does not
// make because it may not act as the workload's owner now: it is coming back
// from a fence or a partition (warmup), or its view of the workload is behind,
// and the workload may have moved. The scheduler logs it at info and records
// nothing on the schedule row; it is not a failure of the schedule.
var ErrRunSkipped = errors.New("schedule run skipped")

// ErrNoRepoConfigured is returned by RunnerWithRepoResolver when a
// schedule references a logical repo name not present in the daemon
// config. The dispatcher logs and records it but continues — a
// misconfigured row should not stall the whole scheduler.
var ErrNoRepoConfigured = errors.New("no backup_repos entry resolves the repo name")
