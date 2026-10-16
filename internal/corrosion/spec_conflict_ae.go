package corrosion

import (
	"context"
	"database/sql"
	"errors"
)

// Resolving two versions of a VM's spec at one generation in an anti-entropy
// merge, once spec_conflict_v1 is active (spec_conflict.go explains the
// conflict). The order is the WAL's (spec_conflict_apply.go), so both lanes
// keep the same version:
//
//  1. the higher owner epoch — workloadParentAuthorityDecision's own rule,
//     unchanged; this only records the version it drops;
//  2. an operation's barrier: a row whose operation is in flight is never
//     overwritten by an out-of-band edit at its generation, and a row carrying
//     an in-flight operation's claim replaces an out-of-band edit. An
//     operation counts as finished once either side records a terminal step
//     for it; the row without the barrier is then its completion, and the
//     clocks decide as before;
//  3. the clocks, by updated_at, through the ordinary merge — and its tie
//     resolver, which leaves a differing spec at one instant unresolved.
//
// Two versions with the same spec drop nothing and change nothing here.

// finishedOperationsInPayload is every operation an anti-entropy payload
// records a terminal step for.
func finishedOperationsInPayload(payload *syncPayload) map[string]bool {
	out := map[string]bool{}
	for _, table := range payload.Tables {
		if table.Name != "operation_steps" {
			continue
		}
		idIdx, stepIdx := indexOf(table.Columns, "operation_id"), indexOf(table.Columns, "step_name")
		if idIdx < 0 || stepIdx < 0 {
			continue
		}
		for _, row := range table.Rows {
			if len(row) != len(table.Columns) {
				continue
			}
			if opTerminalStates[coerceString(row[stepIdx])] {
				out[coerceString(row[idIdx])] = true
			}
		}
	}
	return out
}

// specConflictAEDecision decides a live incoming VM row against the live local
// row at the same generation. decided=false leaves it to the ordinary rules.
func (c *Client) specConflictAEDecision(tx *sql.Tx, incoming workloadMergeAuthority, localOwner int64, localActiveOp string) (mergeAuthorityDecision, bool, error) {
	var localSpec, localUpdated, localHost string
	err := tx.QueryRow(`SELECT COALESCE(spec, ''), COALESCE(updated_at, ''), COALESCE(host_name, '')
		FROM vms WHERE name = ?`, incoming.name).Scan(&localSpec, &localUpdated, &localHost)
	if errors.Is(err, sql.ErrNoRows) {
		return mergeAuthorityNormal, false, nil
	}
	if err != nil {
		return mergeAuthorityKeepLocal, true, err
	}
	if localSpec == incoming.spec {
		return mergeAuthorityNormal, false, nil
	}
	dropLocal := specEditDrop{vm: incoming.name, host: incoming.host, epoch: incoming.ownerEpoch, gen: incoming.generation,
		path: pathAE, keptAt: incoming.updatedAt, droppedAt: localUpdated, droppedSpec: localSpec}
	dropIncoming := specEditDrop{vm: incoming.name, host: localHost, epoch: localOwner, gen: incoming.generation,
		path: pathAE, keptAt: localUpdated, droppedAt: incoming.updatedAt, droppedSpec: incoming.spec}

	switch {
	case incoming.ownerEpoch > localOwner:
		dropLocal.reason = specDropStaleEpoch
		c.noteSpecEditDropped(tx, dropLocal)
		return mergeAuthorityApplyIncoming, true, nil
	case incoming.ownerEpoch < localOwner:
		dropIncoming.reason = specDropStaleEpoch
		c.noteSpecEditDropped(tx, dropIncoming)
		return mergeAuthorityKeepLocal, true, nil
	}

	finished := func(op string) (bool, error) {
		if incoming.finishedOps[op] {
			return true, nil
		}
		return operationFinished(context.Background(), tx, op)
	}
	switch {
	case localActiveOp != "" && incoming.activeOperationID == "":
		done, ferr := finished(localActiveOp)
		if ferr != nil {
			return mergeAuthorityKeepLocal, true, ferr
		}
		if !done {
			dropIncoming.reason = specDropOperation
			c.noteSpecEditDropped(tx, dropIncoming)
			return mergeAuthorityKeepLocal, true, nil
		}
	case localActiveOp == "" && incoming.activeOperationID != "":
		done, ferr := finished(incoming.activeOperationID)
		if ferr != nil {
			return mergeAuthorityKeepLocal, true, ferr
		}
		if !done {
			dropLocal.reason = specDropOperation
			c.noteSpecEditDropped(tx, dropLocal)
			return mergeAuthorityApplyIncoming, true, nil
		}
	}
	// The clocks decide, through the ordinary merge; record what it drops.
	switch ord := lwwOrder(localUpdated, incoming.updatedAt); {
	case ord < 0:
		dropLocal.reason = specDropLaterEdit
		c.noteSpecEditDropped(tx, dropLocal)
	case ord > 0:
		dropIncoming.reason = specDropLaterEdit
		c.noteSpecEditDropped(tx, dropIncoming)
	default:
		dropIncoming.reason = specDropTie
		c.noteSpecEditDropped(tx, dropIncoming)
	}
	return mergeAuthorityNormal, false, nil
}
