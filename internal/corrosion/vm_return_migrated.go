package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ReturnMigratedVM moves a VM whose live firmware move committed to fromHost
// (the move's target) back to toHost (its source), with its disk rows, in one
// guarded transaction: the operator's `lv doctor firmware-move --accept-source`
// after the commit (spec §17 D-5, the return writer).
//
// It reuses the commit's own statements with from and to swapped
// (vmHostStateSQL, vmDiskHostMoveSQL, placementGenStmts), so it adds no
// replicated statement shape. Its guard mirrors CommitMigrationOwnership's,
// against the commit it undoes:
//   - the VM row names fromHost, for the move's incarnation (the spec's uuid
//     and the row's created_at);
//   - every disk row in expected (read after the commit) still has its
//     placement — host, path, storage type, volume — and no disk row was
//     added or removed.
//
// RepointMigratedVM is not this: it requires `migrating` on the source and
// moves the VM row alone.
//
// state must be "stopped": the guest runs on neither host when the source's
// copy is accepted. It is a parameter only so scripts/ci/runningcheck polices
// the call site like every other ownership writer's. committed=false (no
// error) when the guard declines.
func ReturnMigratedVM(ctx context.Context, c *Client, vmName, fromHost, toHost, uuid, createdAt, state string, expected []DiskRecord) (bool, error) {
	if state != "stopped" {
		return false, fmt.Errorf("ReturnMigratedVM returns a stopped VM; asked for state %q", state)
	}
	if uuid == "" || createdAt == "" {
		return false, errors.New("ReturnMigratedVM needs the move's uuid and created_at")
	}
	now := c.NowTS()
	stmts := []Statement{{
		SQL:    vmHostStateSQL,
		Params: []interface{}{toHost, state, now, vmName},
	}}
	for _, d := range expected {
		if keep, _ := SharedRowKeepsOwner(ctx, c, d, fromHost, toHost); keep {
			continue // its unproven owner keeps the row (review I1); the guard accepts it unchanged
		}
		stmts = append(stmts, Statement{
			SQL:    vmDiskHostMoveSQL,
			Params: []interface{}{toHost, now, vmName, d.DiskName},
		})
	}
	stmts = append(stmts, placementGenStmts(ctx, c, vmName)...)
	guard := func(tx *sql.Tx) (bool, error) {
		var host, spec, created string
		switch err := tx.QueryRowContext(ctx,
			`SELECT host_name, spec, created_at FROM vms WHERE name = ? AND deleted_at IS NULL`, vmName).
			Scan(&host, &spec, &created); {
		case errors.Is(err, sql.ErrNoRows):
			return false, nil
		case err != nil:
			return false, err
		}
		var s struct {
			UUID string `json:"uuid"`
		}
		_ = json.Unmarshal([]byte(spec), &s)
		if host != fromHost || created != createdAt || !strings.EqualFold(s.UUID, uuid) {
			return false, nil // not the commit this undoes
		}
		for _, d := range expected {
			var dh, path, stype, svol string
			switch err := tx.QueryRowContext(ctx,
				`SELECT host_name, path, storage_type, storage_volume FROM vm_disks
				 WHERE vm_name = ? AND disk_name = ? AND deleted_at IS NULL`, vmName, d.DiskName).
				Scan(&dh, &path, &stype, &svol); {
			case errors.Is(err, sql.ErrNoRows):
				return false, nil
			case err != nil:
				return false, err
			}
			if dh != d.HostName || path != d.Path || stype != d.StorageType || svol != d.StorageVolume {
				return false, nil // changed since the commit
			}
		}
		var live int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM vm_disks WHERE vm_name = ? AND deleted_at IS NULL`, vmName).Scan(&live); err != nil {
			return false, err
		}
		return live == len(expected), nil
	}
	ok, err := c.ExecuteBatchGuarded(ctx, guard, stmts)
	if ok && err == nil {
		SpendDrainOrigin(ctx, c, vmName)
	}
	return ok, err
}
