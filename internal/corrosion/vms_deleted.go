package corrosion

import "context"

// ListDeletedVMs returns every tombstoned vms row (name, host, project): VMs
// deleted whose artifacts — disks kept with them, replicas in a pool's replica
// area — are still theirs, so their project can find and remove them. A name
// that has a live row again is not listed (the live row replaced the
// tombstone).
func ListDeletedVMs(ctx context.Context, c *Client) ([]VMRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, host_name, COALESCE(project, '_default') AS project
		 FROM vms WHERE deleted_at IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	out := make([]VMRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, VMRecord{Name: r.String("name"), HostName: r.String("host_name"), Project: r.String("project")})
	}
	return out, nil
}
