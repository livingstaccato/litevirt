package corrosion

import (
	"context"

	"github.com/google/uuid"
)

// SnapshotRecord represents a stored snapshot.
type SnapshotRecord struct {
	ID        string
	VMName    string
	HostName  string
	Name      string
	State     string
	SizeBytes int64
	CreatedAt string

	// Live/RAM snapshots (#3). Type is "disk" (external disk-only, default) or
	// "memory" (also captured guest RAM). VMStatePath/VMStateBytes describe the
	// saved RAM image for memory snapshots.
	Type         string
	VMStatePath  string
	VMStateBytes int64
}

// InsertSnapshot records a new snapshot.
//
// A snapshot re-created under the name of a deleted one takes the deleted
// row's id back and is un-deleted in the same entry (reuseNaturalKeyRow). A
// delete is a soft delete, so every peer still holds the tombstone under the
// (vm_name, name) natural key; a freshly minted id met that tombstone on every
// peer, failed UNIQUE(vm_name, name), and stopped this node's whole push
// stream behind it (lab 2, F-2).
func InsertSnapshot(ctx context.Context, c *Client, s SnapshotRecord) error {
	if s.Type == "" {
		s.Type = "disk"
	}
	id, undelete, err := reuseNaturalKeyRow(ctx, c,
		`SELECT id, deleted_at FROM snapshots WHERE vm_name = ? AND name = ?`, s.ID, s.VMName, s.Name)
	if err != nil {
		return err
	}
	s.ID = id
	stmts := []Statement{{SQL: insertSnapshotSQL, Params: []interface{}{
		s.ID, s.VMName, s.HostName, s.Name, s.State, s.SizeBytes, s.Type, s.VMStatePath, s.VMStateBytes, nowRFC3339(), c.NowTS(),
	}}}
	if undelete {
		// The registered tombstone shape with a NULL deleted_at, stamped after
		// the insert. The insert alone does not clear a peer's tombstone: a
		// receiver applies a replicated INSERT as a column-preserving upsert,
		// and deleted_at is not among its columns. This shape is one every
		// released receiver already applies (per-row LWW by natural key).
		stmts = append(stmts, Statement{SQL: deleteSnapshotSQL, Params: []interface{}{
			nil, c.NowTS(), s.VMName, s.Name,
		}})
	}
	return c.ExecuteBatch(ctx, stmts)
}

const insertSnapshotSQL = `INSERT OR REPLACE INTO snapshots (id, vm_name, host_name, name, state, size_bytes, type, vmstate_path, vmstate_size_bytes, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

const deleteSnapshotSQL = `UPDATE snapshots SET deleted_at = ?, updated_at = ? WHERE vm_name = ? AND name = ?`

// reuseNaturalKeyRow picks the id a natural-key identity table's insert
// writes under: the caller's id when it names one, else the id of the row this
// node already holds under the same natural key (live or deleted), else a
// fresh one. undelete reports that the reused row is a tombstone, which the
// caller must clear explicitly.
//
// Reusing the id is what makes delete-then-recreate replicate: the new row is
// the same primary key every peer already holds, so it applies under ordinary
// LWW instead of colliding with the tombstone on the natural key.
func reuseNaturalKeyRow(ctx context.Context, c *Client, query, id string, natural ...interface{}) (string, bool, error) {
	rows, err := c.Query(ctx, query, natural...)
	if err != nil {
		return "", false, err
	}
	if len(rows) == 0 {
		if id == "" {
			id = uuid.New().String()
		}
		return id, false, nil
	}
	prior := rows[0].String("id")
	if id == "" || id == prior {
		return prior, rows[0].String("deleted_at") != "", nil
	}
	return id, false, nil
}

// ListSnapshots returns all snapshots for a VM.
func ListSnapshots(ctx context.Context, c *Client, vmName string) ([]SnapshotRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT id, vm_name, host_name, name, state, size_bytes, type, vmstate_path, vmstate_size_bytes, created_at
		 FROM snapshots WHERE vm_name = ? AND deleted_at IS NULL ORDER BY created_at`,
		vmName)
	if err != nil {
		return nil, err
	}

	snaps := make([]SnapshotRecord, len(rows))
	for i, r := range rows {
		snaps[i] = scanSnapshot(r)
	}
	return snaps, nil
}

// GetSnapshot returns one snapshot by (vm, name), or (nil, nil) if absent.
// Used by restore/delete so they can branch on snapshot type and reach the
// recorded vmstate path.
func GetSnapshot(ctx context.Context, c *Client, vmName, snapshotName string) (*SnapshotRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT id, vm_name, host_name, name, state, size_bytes, type, vmstate_path, vmstate_size_bytes, created_at
		 FROM snapshots WHERE vm_name = ? AND name = ? AND deleted_at IS NULL LIMIT 1`,
		vmName, snapshotName)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	s := scanSnapshot(rows[0])
	return &s, nil
}

func scanSnapshot(r Row) SnapshotRecord {
	typ := r.String("type")
	if typ == "" {
		typ = "disk"
	}
	return SnapshotRecord{
		ID:           r.String("id"),
		VMName:       r.String("vm_name"),
		HostName:     r.String("host_name"),
		Name:         r.String("name"),
		State:        r.String("state"),
		SizeBytes:    r.Int64("size_bytes"),
		Type:         typ,
		VMStatePath:  r.String("vmstate_path"),
		VMStateBytes: r.Int64("vmstate_size_bytes"),
		CreatedAt:    r.String("created_at"),
	}
}

// DeleteSnapshot tombstones a snapshot record.
func DeleteSnapshot(ctx context.Context, c *Client, vmName, snapshotName string) error {
	now := c.NowTS()
	return c.Execute(ctx, deleteSnapshotSQL, nowRFC3339(), now, vmName, snapshotName)
}
