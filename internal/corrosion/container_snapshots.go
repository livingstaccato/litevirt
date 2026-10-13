package corrosion

import (
	"context"
)

// ContainerSnapshotRecord is one container snapshot's cluster-state row —
// the container analogue of SnapshotRecord. A snapshot is a host-local
// point-in-time copy of the container's on-disk dir (type='tar' → a tar at
// `Path`; COW variants may be added later).
type ContainerSnapshotRecord struct {
	ID        string
	CtName    string
	HostName  string
	Name      string
	State     string
	SizeBytes int64
	Type      string // 'tar' (default); future: 'cow-btrfs' / 'cow-zfs'
	Path      string // host-local snapshot path (for type='tar')
	CreatedAt string
}

// InsertContainerSnapshot records a new container snapshot. Idempotent on the
// (host,container,name) unique key via INSERT OR REPLACE. A snapshot
// re-created under a deleted one's name takes its id back and is un-deleted,
// as InsertSnapshot does and for the same reason.
func InsertContainerSnapshot(ctx context.Context, c *Client, s ContainerSnapshotRecord) error {
	if s.Type == "" {
		s.Type = "tar"
	}
	return insertNaturalKeyRow(ctx, c,
		`SELECT id, deleted_at FROM container_snapshots WHERE host_name = ? AND ct_name = ? AND name = ?`,
		[]interface{}{s.HostName, s.CtName, s.Name}, s.ID,
		func(id string) []Statement {
			return []Statement{{SQL: insertContainerSnapshotSQL, Params: []interface{}{
				id, s.CtName, s.HostName, s.Name, s.State, s.SizeBytes, s.Type, s.Path, nowRFC3339(), c.NowTS(),
			}}}
		},
		func() Statement {
			return Statement{SQL: deleteContainerSnapshotSQL, Params: []interface{}{nil, c.NowTS(), s.HostName, s.CtName, s.Name}}
		})
}

const insertContainerSnapshotSQL = `INSERT OR REPLACE INTO container_snapshots
		   (id, ct_name, host_name, name, state, size_bytes, type, path, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

const deleteContainerSnapshotSQL = `UPDATE container_snapshots SET deleted_at = ?, updated_at = ?
		 WHERE host_name = ? AND ct_name = ? AND name = ?`

// ListContainerSnapshots returns a container's snapshots (oldest first).
func ListContainerSnapshots(ctx context.Context, c *Client, hostName, ctName string) ([]ContainerSnapshotRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT id, ct_name, host_name, name, state, size_bytes, type, COALESCE(path,'') AS path, created_at
		 FROM container_snapshots
		 WHERE host_name = ? AND ct_name = ? AND deleted_at IS NULL
		 ORDER BY created_at`,
		hostName, ctName)
	if err != nil {
		return nil, err
	}
	out := make([]ContainerSnapshotRecord, len(rows))
	for i, r := range rows {
		out[i] = scanContainerSnapshot(r)
	}
	return out, nil
}

// GetContainerSnapshot returns one snapshot by (host, container, name) or nil.
func GetContainerSnapshot(ctx context.Context, c *Client, hostName, ctName, name string) (*ContainerSnapshotRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT id, ct_name, host_name, name, state, size_bytes, type, COALESCE(path,'') AS path, created_at
		 FROM container_snapshots
		 WHERE host_name = ? AND ct_name = ? AND name = ? AND deleted_at IS NULL LIMIT 1`,
		hostName, ctName, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	s := scanContainerSnapshot(rows[0])
	return &s, nil
}

// DeleteContainerSnapshot tombstones a snapshot record.
func DeleteContainerSnapshot(ctx context.Context, c *Client, hostName, ctName, name string) error {
	now := c.NowTS()
	return c.Execute(ctx, deleteContainerSnapshotSQL, nowRFC3339(), now, hostName, ctName, name)
}

func scanContainerSnapshot(r Row) ContainerSnapshotRecord {
	return ContainerSnapshotRecord{
		ID:        r.String("id"),
		CtName:    r.String("ct_name"),
		HostName:  r.String("host_name"),
		Name:      r.String("name"),
		State:     r.String("state"),
		SizeBytes: r.Int64("size_bytes"),
		Type:      r.String("type"),
		Path:      r.String("path"),
		CreatedAt: r.String("created_at"),
	}
}
