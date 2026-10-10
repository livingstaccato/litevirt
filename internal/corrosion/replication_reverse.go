package corrosion

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

// ReplicationReversal is one replication schedule ReverseReplicationOnMove
// re-pointed, or, with Skipped set, one it found in need of re-pointing and could
// not.
type ReplicationReversal struct {
	Kind     string // "vm" | "container"
	Workload string
	// FromHost is the host the schedule replicated TO, which the workload has now
	// moved onto; ToHost is the host it replicates to now: the one the workload
	// left. Repo is the pool (VM) or backup repo (container) on ToHost.
	FromHost, ToHost, Repo string
	// Skipped is why the schedule was left as it was, which leaves the workload
	// replicating onto its own host (a replica that protects nothing). Empty when
	// the schedule was re-pointed.
	Skipped string
}

// ReverseReplicationOnMove switches the direction of a workload's replication
// after it moved from oldHost to newHost: a schedule that replicated TO newHost
// (so the workload now runs on its own replica target) replicates to oldHost
// instead, so the old source becomes the target. It is how a promotion by
// failover, a planned migrate, and a move back (failback) all end up with the
// replica on the host the workload is not on.
//
// It touches only per-workload schedules with an EXPLICIT target host equal to
// newHost. A schedule with no target host (a shared pool, or an auto-selected
// peer) already replicates away from wherever the workload runs, and a pool,
// project or cluster schedule is shared by many workloads, so none of those is
// re-pointed for one of them.
//
// The switch touches target_host and nothing else. With opts.TargetOnly it is
// one compare-and-set statement (RepointReplicationTarget), so an operator's
// concurrent edit of the same row on another node (enabled, cron, keep) is not
// reverted by last-writer-wins. That statement is a shape a previous-release
// peer does not know, and an unknown shape back-pressures the sender's whole
// stream, so a caller sets TargetOnly only once every host is known to run a
// build that has it (the container_replication release feature). Without it the
// row is re-read immediately before the write and re-upserted from that read,
// under the same compare: a change that landed here first is kept.
//
// It also drops the workload's incremental checkpoint, which belongs to the old
// direction: the dirty-bitmap anchor lives on the OLD source's disk, and the new
// source has none, so the first reversed run of an incremental VM schedule is a
// full push, or an incremental one only from a base the target holds for that
// very checkpoint (replicateIncremental). Nothing on oldHost is read, written or
// removed here, and replicas are only ever added there as new files, so the copy
// it holds is never replaced by the reversal.
//
// project is the container's project (ignored for a VM).
func ReverseReplicationOnMove(ctx context.Context, c *Client, kind, name, project, oldHost, newHost string, opts ReverseOptions) ([]ReplicationReversal, error) {
	if oldHost == "" || newHost == "" || oldHost == newHost {
		return nil, nil
	}
	rows, err := ListBackupSchedules(ctx, c)
	if err != nil {
		return nil, err
	}
	var out []ReplicationReversal
	for _, r := range rows {
		if r.Type != "replication" || r.TargetHost != newHost {
			continue
		}
		switch kind {
		case "vm":
			if (r.Scope != "vm" && r.Scope != "") || r.VMName != name {
				continue
			}
		case "container":
			if !ContainerScheduleIs(r, project, name) {
				continue
			}
		default:
			return nil, fmt.Errorf("unknown workload kind %q", kind)
		}
		rev := ReplicationReversal{Kind: kind, Workload: name, FromHost: newHost, ToHost: oldHost, Repo: r.TargetPool}
		if reason := reversalBlocker(ctx, c, kind, oldHost, r); reason != "" {
			rev.Skipped = reason
			out = append(out, rev)
			continue
		}
		if reverseBeforeWrite != nil {
			reverseBeforeWrite()
		}
		applied, err := repointSchedule(ctx, c, r.VMName, r.Repo, newHost, oldHost, opts.TargetOnly)
		if err != nil {
			return out, fmt.Errorf("re-point replication schedule of %q: %w", name, err)
		}
		if !applied {
			continue // re-pointed or re-targeted meanwhile; nothing of ours to do
		}
		if kind == "vm" {
			if err := SetReplicationCheckpoint(ctx, c, name, r.Repo, ""); err != nil {
				return out, fmt.Errorf("reset replication checkpoint of %q: %w", name, err)
			}
		}
		out = append(out, rev)
	}
	return out, nil
}

// ReverseOptions tunes ReverseReplicationOnMove.
type ReverseOptions struct {
	// TargetOnly writes the switch as a compare-and-set of target_host alone
	// (RepointReplicationTarget). Set only when every host knows that statement.
	TargetOnly bool
}

// reverseBeforeWrite runs between the read and the write of each switch (tests
// only: a concurrent edit lands there).
var reverseBeforeWrite func()

// repointSchedule moves the (vmName, repo) schedule's target from from to to,
// only while it still targets from. applied is false when it no longer does.
func repointSchedule(ctx context.Context, c *Client, vmName, repo, from, to string, targetOnly bool) (bool, error) {
	if targetOnly {
		return RepointReplicationTarget(ctx, c, vmName, repo, from, to)
	}
	rows, err := ListBackupSchedules(ctx, c)
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		if r.VMName != vmName || r.Repo != repo {
			continue
		}
		if r.TargetHost != from {
			return false, nil
		}
		r.TargetHost = to
		return true, UpsertBackupSchedule(ctx, c, r)
	}
	return false, nil
}

// RepointReplicationTarget sets a replication schedule's target_host to to
// while it is from, and changes nothing else in the row: a compare-and-set, so
// a concurrent edit of any other column on another node survives it. applied
// is false when the row does not target from (any more).
func RepointReplicationTarget(ctx context.Context, c *Client, vmName, repo, from, to string) (bool, error) {
	n, err := c.ExecuteRowsStrict(ctx,
		`UPDATE backup_schedules SET target_host = ?, updated_at = ?
		 WHERE vm_name = ? AND repo = ? AND target_host = ? AND deleted_at IS NULL`,
		to, c.NowTS(), vmName, repo, from)
	if errors.Is(err, ErrNoRowsAffected) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// reversalBlocker says why oldHost cannot be a schedule's new target, or "".
// Everything it reads is replicated state, so it works with oldHost down: a
// promotion after a host loss is the case this exists for, and the schedule then
// reports the missing replica on every run until the host is back.
func reversalBlocker(ctx context.Context, c *Client, kind, oldHost string, r BackupScheduleRecord) string {
	h, err := GetHost(ctx, c, oldHost)
	if err != nil {
		return fmt.Sprintf("cannot read host %q: %v", oldHost, err)
	}
	if h == nil || h.State == "removed" {
		return fmt.Sprintf("host %q is no longer in the cluster", oldHost)
	}
	switch kind {
	case "container":
		if !HostRunsContainers(*h) {
			return fmt.Sprintf("host %q cannot run containers, so a replica there could never be promoted", oldHost)
		}
	default:
		if _, ok, err := GetStoragePool(ctx, c, oldHost, r.TargetPool); err != nil {
			return fmt.Sprintf("cannot read pool %q on %q: %v", r.TargetPool, oldHost, err)
		} else if !ok {
			return fmt.Sprintf("pool %q does not exist on host %q; add a schedule for a pool it has", r.TargetPool, oldHost)
		}
	}
	return ""
}

// ReverseReplicationAudited is ReverseReplicationOnMove for a mover with no
// notification path of its own (the failover coordinator, the health checker,
// the owner reconciler): each switch, and each refusal, is handed to audit, the
// caller's own (signed) audit writer, as a replication.reverse row. A schedule
// left targeting the workload's own host is then reported by its runs
// (suspended, never a success), so nothing is silent. It never fails the move.
func ReverseReplicationAudited(ctx context.Context, c *Client, kind, name, project, oldHost, newHost string, audit func(detail, result string)) {
	revs, err := ReverseReplicationOnMove(ctx, c, kind, name, project, oldHost, newHost, ReverseOptions{})
	if err != nil {
		slog.Warn("replication: could not switch direction after a move", "kind", kind, "workload", name, "from", oldHost, "to", newHost, "error", err)
	}
	for _, r := range revs {
		if r.Skipped != "" {
			audit(fmt.Sprintf("%s %s moved %s -> %s onto its own replica target; could not switch replication back: %s", kind, name, oldHost, newHost, r.Skipped), "skipped")
			continue
		}
		audit(fmt.Sprintf("%s %s moved %s -> %s: replication now runs %s -> %s (%s)", kind, name, oldHost, newHost, newHost, r.ToHost, r.Repo), "ok")
	}
}
