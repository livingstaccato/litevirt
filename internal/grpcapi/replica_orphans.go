package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// Replicas and checkpoints a removed schedule or a deleted VM leaves.
//
// A replication schedule's replicas sit in its target pool's replica area,
// on whichever host holds the pool, each with a record naming the schedule
// that wrote it (replica_records.go); its incremental chain is anchored in a
// replication_checkpoints row keyed by the VM and the target pool. Removing
// the schedule, or deleting the VM, stopped the runs and left both behind.
//
// Now:
//   - a schedule's removal retires the checkpoint rows no live schedule still
//     uses, and a plain VM delete retires the VM's (retire*Checkpoints);
//   - every host sweeps the replica areas of its own pools
//     (sweepOrphanReplicas): a replica whose schedule row, or whose VM row,
//     is a tombstone older than corrosion.ScheduleOrphanGrace is removed,
//     record first, as a prune removes one. A re-create, or a schedule added
//     again, within the grace keeps them;
//   - the failover lease holder retires checkpoint rows no live schedule uses
//     that have not advanced for the grace, and those of a VM deleted that
//     long ago (sweepOrphanCheckpoints): the ones an older build left.
//
// Nothing else is removed. A replica a VM disk references (a --no-localize
// promotion's base) or a set-aside disk copy backs on stays, as from a prune;
// a file with no record, or a record that does not match its directory, is
// never touched; another schedule's replicas of the same VM are its own.

// replicaOrphanSweepInterval is how often each host sweeps.
const replicaOrphanSweepInterval = time.Hour

// RunReplicaOrphanSweep runs the replica and checkpoint orphan sweeps until
// ctx ends: the first a few minutes after start, then hourly.
func (s *Server) RunReplicaOrphanSweep(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Minute):
	}
	t := time.NewTicker(replicaOrphanSweepInterval)
	defer t.Stop()
	for {
		now := time.Now()
		s.sweepOrphanReplicas(ctx, now)
		s.sweepOrphanCheckpoints(ctx, now)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// SweepReplicaOrphansForTest runs one pass of both sweeps at now and returns
// the replicas it removed.
func (s *Server) SweepReplicaOrphansForTest(ctx context.Context, now time.Time) int {
	n := s.sweepOrphanReplicas(ctx, now)
	s.sweepOrphanCheckpoints(ctx, now)
	return n
}

// isFanOutSchedule reports whether a schedule row replicates every VM of a
// pool, project or the cluster. Only the scope decides: a vm-scoped row's
// pool_name is not a fan-out target.
func isFanOutSchedule(r corrosion.BackupScheduleRecord) bool {
	switch r.Scope {
	case "pool", "project", "cluster":
		return true
	}
	return false
}

// checkpointInUse reports whether a live replication schedule may still run
// (vm, repo)'s chain: one of the VM's own, or a fan-out into repo.
func checkpointInUse(live []corrosion.BackupScheduleRecord, vm, repo string) bool {
	for _, r := range live {
		if r.Type != "replication" || r.Repo != repo || r.Scope == "container" {
			continue
		}
		if isFanOutSchedule(r) || r.VMName == vm {
			return true
		}
	}
	return false
}

// retireCheckpoint tombstones (vm, repo)'s checkpoint row and, when the VM is
// on this host, drops its bitmap (best effort: a bitmap left costs space, not
// correctness).
func (s *Server) retireCheckpoint(ctx context.Context, row corrosion.ReplicationCheckpointRow, why string) {
	if err := corrosion.SetReplicationCheckpoint(ctx, s.db, row.VMName, row.Repo, ""); err != nil {
		slog.Warn("replication: could not retire a checkpoint row", "vm", row.VMName, "repo", row.Repo, "error", err)
		return
	}
	slog.Info("replication: retired a checkpoint row", "vm", row.VMName, "repo", row.Repo, "checkpoint", row.Checkpoint, "why", why)
	if row.Checkpoint == "" || s.backupSource == nil {
		return
	}
	if vm, err := corrosion.GetVM(ctx, s.db, row.VMName); err == nil && vm != nil && vm.HostName == s.hostName {
		if err := s.backupSource.DeleteCheckpoint(row.VMName, row.Checkpoint); err != nil {
			slog.Debug("replication: dropping a retired checkpoint's bitmap failed", "vm", row.VMName, "checkpoint", row.Checkpoint, "error", err)
		}
	}
}

// retireScheduleCheckpoints retires the checkpoint rows of the replication
// schedule row just removed that no live schedule still uses: a VM's own
// schedule's row, or each row of a fan-out's target pool.
func (s *Server) retireScheduleCheckpoints(ctx context.Context, removed corrosion.BackupScheduleRecord) {
	if removed.Type != "replication" || removed.Scope == "container" {
		return
	}
	live, err := corrosion.ListBackupSchedules(ctx, s.db)
	if err != nil {
		slog.Warn("replication: could not read the schedules; checkpoint rows of the removed schedule are kept", "schedule", removed.VMName, "repo", removed.Repo, "error", err)
		return
	}
	vm := ""
	if !isFanOutSchedule(removed) {
		vm = removed.VMName
	}
	rows, err := corrosion.LiveReplicationCheckpoints(ctx, s.db, vm)
	if err != nil {
		slog.Warn("replication: could not read the checkpoint rows of the removed schedule", "schedule", removed.VMName, "repo", removed.Repo, "error", err)
		return
	}
	for _, row := range rows {
		if row.Repo != removed.Repo || checkpointInUse(live, row.VMName, row.Repo) {
			continue
		}
		s.retireCheckpoint(ctx, row, "its schedule was removed")
	}
}

// retireVMCheckpoints retires every checkpoint row of a VM a plain delete
// removed.
func (s *Server) retireVMCheckpoints(ctx context.Context, vmName string) {
	rows, err := corrosion.LiveReplicationCheckpoints(ctx, s.db, vmName)
	if err != nil {
		slog.Warn("delete: could not read the deleted VM's checkpoint rows", "vm", vmName, "error", err)
		return
	}
	for _, row := range rows {
		s.retireCheckpoint(ctx, row, "its VM was deleted")
	}
}

// sweepOrphanCheckpoints is the checkpoint orphan sweep, on the failover
// lease holder: a live row whose VM was deleted at least the grace ago, or
// that no live schedule uses and that was last written at least the grace
// ago, is retired.
func (s *Server) sweepOrphanCheckpoints(ctx context.Context, now time.Time) {
	held, err := corrosion.IsLeaseHolder(ctx, s.db, corrosion.LeaseKeyFailover, s.hostName, time.Now())
	if err != nil || !held {
		return
	}
	live, err := corrosion.ListBackupSchedules(ctx, s.db)
	if err != nil {
		slog.Warn("checkpoint sweep: could not read the schedules", "error", err)
		return
	}
	rows, err := corrosion.LiveReplicationCheckpoints(ctx, s.db, "")
	if err != nil {
		slog.Warn("checkpoint sweep: could not read the checkpoint rows", "error", err)
		return
	}
	grace := corrosion.ScheduleOrphanGrace
	for _, row := range rows {
		if gone, err := corrosion.VMGoneFor(ctx, s.db, row.VMName, now, grace); err == nil && gone {
			s.retireCheckpoint(ctx, row, "its VM was deleted")
			continue
		}
		if checkpointInUse(live, row.VMName, row.Repo) {
			continue
		}
		if at, ok := corrosion.ParseUpdatedAt(row.UpdatedAt); ok && now.Sub(at) >= grace {
			s.retireCheckpoint(ctx, row, "no schedule uses it")
		}
	}
}

// sweepOrphanReplicas is the replica orphan sweep of this host's file-based
// pools. It returns the replicas removed.
func (s *Server) sweepOrphanReplicas(ctx context.Context, now time.Time) int {
	pools, err := corrosion.ListStoragePoolsForHost(ctx, s.db, s.hostName)
	if err != nil {
		slog.Warn("replica sweep: could not read this host's pools", "error", err)
		return 0
	}
	removed := 0
	for _, p := range pools {
		if !isFileBasedDriver(p.Driver) {
			continue
		}
		dir, err := s.replicaPoolDir(ctx, p.Name)
		if err != nil {
			continue // refused, unmounted or not answering: nothing is judged
		}
		removed += s.sweepPoolReplicas(ctx, p.Name, dir, now)
	}
	return removed
}

// orphanReplica says why a replica is an orphan at now, or "".
func (s *Server) orphanReplica(ctx context.Context, r replicaRecord, now time.Time) string {
	grace := corrosion.ScheduleOrphanGrace
	if gone, err := corrosion.VMGoneFor(ctx, s.db, r.VM, now, grace); err == nil && gone {
		return "its VM was deleted"
	}
	i := strings.LastIndex(r.Schedule, "/")
	if i <= 0 || i == len(r.Schedule)-1 {
		return ""
	}
	if gone, err := corrosion.ScheduleGoneFor(ctx, s.db, r.Schedule[:i], r.Schedule[i+1:], now, grace); err == nil && gone {
		return "its schedule was removed"
	}
	return ""
}

// sweepPoolReplicas sweeps one pool's replica area.
func (s *Server) sweepPoolReplicas(ctx context.Context, pool, poolDir string, now time.Time) int {
	area := filepath.Join(poolDir, replicaAreaDir)
	owners, err := storage.Bounded("list the replica area", area, func() ([]os.DirEntry, error) { return os.ReadDir(area) })
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("replica sweep: could not list a pool's replica area", "pool", pool, "error", err)
		}
		return 0
	}
	var backing backingSet
	backingRead := false
	removed := 0
	for _, o := range owners {
		if !o.IsDir() {
			continue
		}
		dir := filepath.Join(area, o.Name())
		ents, err := storage.Bounded("list a replica directory", dir, func() ([]os.DirEntry, error) { return os.ReadDir(dir) })
		if err != nil {
			continue
		}
		for _, e := range ents {
			name := e.Name()
			if !e.Type().IsRegular() || !strings.HasSuffix(name, ".json") {
				continue
			}
			data, err := storage.ReadPoolFile(filepath.Join(dir, name))
			if err != nil {
				continue
			}
			var r replicaRecord
			if json.Unmarshal(data, &r) != nil || r.validate() != nil || name != r.File+".json" ||
				replicaOwnerDir(poolDir, r.Project, r.VM) != dir {
				continue
			}
			why := s.orphanReplica(ctx, r, now)
			if why == "" {
				continue
			}
			path := filepath.Join(dir, r.File)
			if !backingRead {
				if backing, err = s.supersededBacking(ctx); err != nil {
					slog.Warn("replica sweep: could not read the set-aside disk copies; nothing is removed", "error", err)
					return removed
				}
				backingRead = true
			}
			if backing.has(path) {
				continue
			}
			if owners, oerr := s.diskReferencesAnyHost(ctx, path); oerr != nil || len(owners) > 0 {
				continue
			}
			if err := os.Remove(path + ".json"); err != nil && !errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				slog.Warn("replica sweep: removed a replica's record but not its file", "pool", pool, "file", path, "error", err)
				continue
			}
			removed++
			slog.Info("replica sweep: removed a replica", "pool", pool, "project", r.Project, "vm", r.VM,
				"disk", r.Disk, "schedule", r.Schedule, "taken", r.Taken, "why", why)
		}
	}
	return removed
}

// PlaceReplicaForTest writes a recorded replica of (project, vm, disk) taken
// at taken by schedule into poolDir's replica area, as a run does, and
// returns its path.
func PlaceReplicaForTest(ctx context.Context, poolDir, project, vm, disk, schedule, taken string, data []byte) (string, error) {
	return publishRecordedReplica(ctx, poolDir, newReplicaRecord(project, vm, disk, schedule, taken, "qcow2"),
		func(tmp string) error { return os.WriteFile(tmp, data, 0o600) })
}
