package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

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
	return insertNaturalKeyRow(ctx, c,
		`SELECT id, deleted_at FROM snapshots WHERE vm_name = ? AND name = ?`,
		[]interface{}{s.VMName, s.Name}, s.ID,
		func(id string) []Statement {
			stmts := []Statement{{SQL: insertSnapshotSQL, Params: []interface{}{
				id, s.VMName, s.HostName, s.Name, s.State, s.SizeBytes, s.Type, s.VMStatePath, s.VMStateBytes, nowRFC3339(), c.NowTS(),
			}}}
			return stmts
		},
		// The registered tombstone shape with a NULL deleted_at, stamped after
		// the insert. The insert alone does not clear a peer's tombstone: a
		// receiver applies a replicated INSERT as a column-preserving upsert,
		// and deleted_at is not among its columns. Every released receiver
		// already applies this shape (per-row LWW by natural key).
		func() Statement {
			return Statement{SQL: deleteSnapshotSQL, Params: []interface{}{nil, c.NowTS(), s.VMName, s.Name}}
		})
}

const insertSnapshotSQL = `INSERT OR REPLACE INTO snapshots (id, vm_name, host_name, name, state, size_bytes, type, vmstate_path, vmstate_size_bytes, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

const deleteSnapshotSQL = `UPDATE snapshots SET deleted_at = ?, updated_at = ? WHERE vm_name = ? AND name = ?`

// insertNaturalKeyRow writes a natural-key identity table's row under the id
// of the row this node already holds for that natural key, live or deleted,
// and un-deletes it when it is a tombstone (undelete, appended after the
// insert). Only when no row holds the name does it use callerID, or mint one.
//
// Re-using the id is what makes delete-then-recreate replicate: the new row is
// the same primary key every peer already holds, so it applies under ordinary
// LWW instead of colliding with the tombstone on the natural key. A caller's
// id is not honoured over an existing row for the same reason — a different id
// over a tombstone is exactly the write an older peer can never apply.
//
// The lookup and the write are one transaction: the write's guard re-reads the
// natural key and declines if another writer changed it in between, and the
// decision is made again (at most a few times) from what it then finds.
func insertNaturalKeyRow(ctx context.Context, c *Client, lookup string, natural []interface{}, callerID string,
	build func(id string) []Statement, undelete func() Statement) error {
	for attempt := 0; attempt < 3; attempt++ {
		prior, deleted, found, err := naturalKeyRow(ctx, c, lookup, natural)
		if err != nil {
			return err
		}
		id := prior
		if !found {
			id = callerID
			if id == "" {
				id = uuid.New().String()
			}
		}
		stmts := build(id)
		if found && deleted {
			stmts = append(stmts, undelete())
		}
		applied, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
			var gotID, gotDeleted sql.NullString
			err := tx.QueryRow(lookup, natural...).Scan(&gotID, &gotDeleted)
			if errors.Is(err, sql.ErrNoRows) {
				return !found, nil
			}
			if err != nil {
				return false, err
			}
			return found && gotID.String == prior && (gotDeleted.Valid && gotDeleted.String != "") == deleted, nil
		}, stmts)
		if err != nil || applied {
			return err
		}
	}
	return fmt.Errorf("record %v: the name kept changing under a concurrent writer", natural)
}

// naturalKeyRow reads the id and tombstone state of the row lookup finds.
func naturalKeyRow(ctx context.Context, c *Client, lookup string, natural []interface{}) (id string, deleted, found bool, err error) {
	rows, err := c.Query(ctx, lookup, natural...)
	if err != nil || len(rows) == 0 {
		return "", false, false, err
	}
	return rows[0].String("id"), rows[0].String("deleted_at") != "", true, nil
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
