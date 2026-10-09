package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// StoppedRekeyDetailPrefix starts the state_detail of a VM the failover
// coordinator re-keyed, stopped, off a failed host (RekeyStoppedVM): the
// prefix, then the host it left. It is a stop by intent everywhere — the
// VM was stopped by intent when it was re-keyed — and it tells the new host's
// reconciler to define the VM's domain there, shut off, so `lv start` works
// on it as on any stopped VM. The reconciler replaces it with "operator-stop"
// once the domain is defined.
const StoppedRekeyDetailPrefix = "failover-rekey-stopped:"

// StoppedRekeyDetail is the state_detail RekeyStoppedVM records for a VM it
// moved off from.
func StoppedRekeyDetail(from string) string { return StoppedRekeyDetailPrefix + from }

// IsStoppedRekeyDetail reports whether detail is RekeyStoppedVM's marker.
func IsStoppedRekeyDetail(detail string) bool {
	return strings.HasPrefix(detail, StoppedRekeyDetailPrefix)
}

// RekeyStoppedVM moves a VM stopped by intent off the failed host fromHost to
// destHost, still stopped, with its disk rows: the failover coordinator's move
// for a stopped VM whose disks are all on shared storage, with recovery claims
// off, so it gets off a dead host on its real disks and is never started. Its
// state_detail becomes StoppedRekeyDetail(fromHost).
//
// One guarded transaction (rekeyStoppedGuard). The statements replicate
// without an epoch predicate — the reschedule's host/state write and the
// plain state write — so two coordinators that both re-key the VM converge,
// by last-writer-wins, on one host for the VM and all its disks. An
// epoch-bound transfer would not: each side's row would have moved past the
// generation the other's statement names. Like the claims-off reschedule, it
// does not advance the ownership generation; with claims on,
// RekeyStoppedVMClaimed does. The marker is written at its own, later,
// timestamp: at the move's, a receiver applying the move first meets an
// exact tie and keeps its own detail, and the destination would learn the
// marker only from anti-entropy.
//
// state must be "stopped": it is a parameter only so scripts/ci/runningcheck
// polices the call site like every other ownership writer's (a literal
// "stopped" there is provably not a running publish).
func RekeyStoppedVM(ctx context.Context, c *Client, name, fromHost, destHost, state string, expectedEpoch int64) error {
	if state != "stopped" {
		return fmt.Errorf("RekeyStoppedVM moves a stopped VM; asked for state %q", state)
	}
	disks, err := GetVMDisks(ctx, c, name)
	if err != nil {
		return err
	}
	now := c.NowTS()
	stmts := []Statement{{SQL: vmHostStateSQL, Params: []interface{}{destHost, state, now, name}}}
	for _, d := range disks {
		if d.HostName == destHost {
			continue
		}
		stmts = append(stmts, Statement{SQL: vmDiskHostMoveSQL, Params: []interface{}{destHost, now, name, d.DiskName}})
	}
	stmts = append(stmts, Statement{SQL: vmStateUpdateSQL, Params: []interface{}{state, StoppedRekeyDetail(fromHost), c.NowTS(), name}})
	applied, err := c.ExecuteBatchGuarded(ctx, rekeyStoppedGuard(ctx, name, fromHost, expectedEpoch), stmts)
	if err != nil {
		return err
	}
	if !applied {
		return ErrNoRowsAffected
	}
	return nil
}

// RekeyStoppedVMClaimed is RekeyStoppedVM for a re-key decided under a
// recovery claim, at expectedEpoch. It advances the ownership generation, as
// every claimed transfer does when it completes: the claim is keyed on the
// generation, and a key left at the generation it decided would hand the
// VM's NEXT failover this re-key's decided value — a destination that is
// now the failed host — and strand it. Every coordinator learns the same
// decided destination, so the epoch-bound transfer cannot leave two replicas
// on two hosts.
func RekeyStoppedVMClaimed(ctx context.Context, c *Client, name, fromHost, destHost, state string, expectedEpoch int64) error {
	if state != "stopped" {
		return fmt.Errorf("RekeyStoppedVMClaimed moves a stopped VM; asked for state %q", state)
	}
	disks, err := GetVMDisks(ctx, c, name)
	if err != nil {
		return err
	}
	now := c.NowTS()
	stmts := []Statement{{
		SQL: `UPDATE vms
		      SET host_name = ?, state = ?, state_detail = '',
		          vm_owner_epoch = vm_owner_epoch + 1, updated_at = ?
		      WHERE name = ? AND deleted_at IS NULL AND vm_owner_epoch = ?`,
		Params: []interface{}{destHost, state, now, name, expectedEpoch},
	}}
	for _, d := range disks {
		if d.HostName == destHost {
			continue
		}
		stmts = append(stmts, Statement{SQL: vmDiskHostMoveSQL, Params: []interface{}{destHost, now, name, d.DiskName}})
	}
	stmts = append(stmts, Statement{SQL: vmStateAtEpochSQL,
		Params: []interface{}{state, StoppedRekeyDetail(fromHost), c.NowTS(), name, expectedEpoch + 1}})
	applied, err := c.ExecuteBatchGuarded(ctx, rekeyStoppedGuard(ctx, name, fromHost, expectedEpoch), stmts)
	if err != nil {
		return err
	}
	if !applied {
		return ErrNoRowsAffected
	}
	return nil
}

// rekeyStoppedGuard is a re-key's transaction precondition: the row is still
// on fromHost at expectedEpoch, still stopped by intent
// (VMStoppedForFailover), and still has no host-local disk
// (VMHasHostLocalDisk). The checks are local preconditions.
func rekeyStoppedGuard(ctx context.Context, name, fromHost string, expectedEpoch int64) func(tx *sql.Tx) (bool, error) {
	return func(tx *sql.Tx) (bool, error) {
		var host string
		var epoch int64
		var stopped bool
		err := tx.QueryRowContext(ctx,
			`SELECT host_name, vm_owner_epoch, `+vmStoppedByIntentSQL+` FROM vms WHERE name = ? AND deleted_at IS NULL`,
			append(vmStoppedByIntentArgs(), name)...).Scan(&host, &epoch, &stopped)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if host != fromHost || epoch != expectedEpoch || !stopped {
			return false, nil
		}
		rows, err := tx.QueryContext(ctx,
			`SELECT COALESCE(storage_type, '') FROM vm_disks WHERE vm_name = ? AND deleted_at IS NULL`, name)
		if err != nil {
			return false, err
		}
		defer rows.Close()
		var now []DiskRecord
		for rows.Next() {
			var d DiskRecord
			if err := rows.Scan(&d.StorageType); err != nil {
				return false, err
			}
			now = append(now, d)
		}
		if err := rows.Err(); err != nil {
			return false, err
		}
		return !VMHasHostLocalDisk(now), nil
	}
}
