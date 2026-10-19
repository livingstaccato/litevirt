package corrosion

import (
	"context"
	"fmt"
	"time"
)

// ScheduleGoneFor reports whether the schedule row (vmName, repo) was removed
// at least grace before now and not written since: its row is a tombstone
// deleted that long ago. A live row, a tombstone younger than the grace, and
// no row at all (a replica that has not seen the schedule yet) are not gone.
func ScheduleGoneFor(ctx context.Context, c *Client, vmName, repo string, now time.Time, grace time.Duration) (bool, error) {
	rows, err := c.Query(ctx,
		`SELECT deleted_at FROM backup_schedules WHERE vm_name = ? AND repo = ?`, vmName, repo)
	if err != nil {
		return false, fmt.Errorf("read schedule %s/%s: %w", vmName, repo, err)
	}
	if len(rows) == 0 {
		return false, nil
	}
	return deletedLongAgo(rows[0].String("deleted_at"), now, grace), nil
}

// VMGoneFor reports whether the VM name was deleted at least grace before
// now: its row is a tombstone deleted that long ago. A live row, a younger
// tombstone (a re-create in flight), and no row at all are not gone.
func VMGoneFor(ctx context.Context, c *Client, name string, now time.Time, grace time.Duration) (bool, error) {
	rows, err := c.Query(ctx, `SELECT deleted_at FROM vms WHERE name = ?`, name)
	if err != nil {
		return false, fmt.Errorf("read vm %s: %w", name, err)
	}
	if len(rows) == 0 {
		return false, nil
	}
	return deletedLongAgo(rows[0].String("deleted_at"), now, grace), nil
}

func deletedLongAgo(deletedAt string, now time.Time, grace time.Duration) bool {
	if deletedAt == "" {
		return false
	}
	t, ok := ParseUpdatedAt(deletedAt)
	return ok && now.Sub(t) >= grace
}

// ReplicationCheckpointRow is one live replication_checkpoints row.
type ReplicationCheckpointRow struct {
	VMName     string
	Repo       string
	Checkpoint string
	UpdatedAt  string
}

// LiveReplicationCheckpoints returns every live replication checkpoint row;
// vmName, when set, only that VM's.
func LiveReplicationCheckpoints(ctx context.Context, c *Client, vmName string) ([]ReplicationCheckpointRow, error) {
	q := `SELECT vm_name, repo, checkpoint, updated_at FROM replication_checkpoints WHERE deleted_at IS NULL`
	var args []any
	if vmName != "" {
		q += ` AND vm_name = ?`
		args = append(args, vmName)
	}
	rows, err := c.Query(ctx, q+` ORDER BY vm_name, repo`, args...)
	if err != nil {
		return nil, fmt.Errorf("list replication checkpoints: %w", err)
	}
	out := make([]ReplicationCheckpointRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, ReplicationCheckpointRow{VMName: r.String("vm_name"), Repo: r.String("repo"), Checkpoint: r.String("checkpoint"), UpdatedAt: r.String("updated_at")})
	}
	return out, nil
}

// GetBackupScheduleRow returns the live schedule row (vmName, repo), or nil.
func GetBackupScheduleRow(ctx context.Context, c *Client, vmName, repo string) (*BackupScheduleRecord, error) {
	all, err := ListBackupSchedules(ctx, c)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].VMName == vmName && all[i].Repo == repo {
			return &all[i], nil
		}
	}
	return nil, nil
}
