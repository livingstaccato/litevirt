package corrosion

import (
	"context"
	"fmt"
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
// It writes the schedule through UpsertBackupSchedule and drops the workload's
// incremental checkpoint, which belongs to the old direction: the dirty-bitmap
// anchor lives on the OLD source's disk, and the new source has none, so the first
// reversed run of an incremental VM schedule is a full push and later ones are
// incremental again. (A container needs no such step: its transport only sends
// chunks the target lacks.) Nothing on oldHost is read, written or removed here,
// and replicas are only ever added there as new files, so the copy it holds is
// never replaced by the reversal.
//
// project is the container's project (ignored for a VM).
func ReverseReplicationOnMove(ctx context.Context, c *Client, kind, name, project, oldHost, newHost string) ([]ReplicationReversal, error) {
	if oldHost == "" || newHost == "" || oldHost == newHost {
		return nil, nil
	}
	rows, err := ListBackupSchedules(ctx, c)
	if err != nil {
		return nil, err
	}
	norm := func(p string) string {
		if p == "" {
			return DefaultProject
		}
		return p
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
			if r.Scope != "container" || r.VMName != ContainerScheduleKey(name) || norm(r.ProjectName) != norm(project) {
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
		r.TargetHost = oldHost
		if err := UpsertBackupSchedule(ctx, c, r); err != nil {
			return out, fmt.Errorf("re-point replication schedule of %q: %w", name, err)
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
