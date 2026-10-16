package corrosion

import (
	"context"
	"database/sql"
	"errors"
)

// Resolving two versions of a VM's spec in an anti-entropy merge once
// spec_conflict_v1 is active (spec_conflict.go explains the conflict). It
// runs after workloadParentAuthorityDecision, which still decides by owner
// epoch and generation; this adds what the WAL lane does
// (spec_conflict_apply.go), so both lanes keep the same version:
//
//   - at one owner epoch and generation, the version specOrder keeps — an
//     unfinished operation's barrier, then the later edit stamp, then the
//     greater content hash — and NOT the row with the later clock, which
//     unrelated writes move. The winner's spec and barrier are made the
//     local row's and the incoming row's both, and the ordinary merge then
//     settles the row's other columns by their clock as before;
//   - the version a higher epoch or generation replaces, and the incoming
//     version a lower one loses to, are recorded when the lineage shows it
//     did not survive into the version kept.
//
// An operation counts as finished once either side records a terminal step
// for it: the row without its barrier is then its completion.

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

// specVersionWrite makes the local row hold the winning version's spec and
// barrier, leaving its clock and every other column to the ordinary merge.
// Local only, inside the merge's transaction; the merge itself is what the
// peer sends.
const specVersionWriteSQL = `UPDATE vms SET spec = ?, active_operation_id = ? WHERE name = ?`

// specConflictAE adjusts decision for a live incoming VM row against the live
// local row. row is the incoming row; when the local version wins at one
// generation its spec and barrier cells are replaced with the local ones.
func (c *Client) specConflictAE(tx *sql.Tx, table syncTable, row []interface{}, incoming workloadMergeAuthority, decision mergeAuthorityDecision) (mergeAuthorityDecision, error) {
	if incoming.deleted || !incoming.valid {
		return decision, nil
	}
	ctx := context.Background()
	local, found, err := readSpecRow(ctx, tx, incoming.name)
	if err != nil {
		return mergeAuthorityKeepLocal, err
	}
	if !found || local.deleted {
		return decision, nil
	}
	inHash, localHash := specContentHash(incoming.spec), specContentHash(local.spec)
	dropLocal := specEditDrop{vm: incoming.name, host: incoming.host, gen: local.gen, path: pathAE,
		droppedSpec: local.spec, keptSpec: incoming.spec}
	dropIncoming := specEditDrop{vm: incoming.name, host: local.host, gen: incoming.generation, path: pathAE,
		droppedSpec: incoming.spec, keptSpec: local.spec}

	switch {
	case incoming.generation > local.gen:
		if decision == mergeAuthorityApplyIncoming || decision == mergeAuthorityApplyIncomingAndSweep {
			if is, known := specAncestorAt(incoming.spec, incoming.generation-local.gen, localHash); known && !is && inHash != localHash {
				dropLocal.reason = specDropNewerGen
				c.noteSpecEditDropped(tx, dropLocal)
			}
		}
		return decision, nil
	case incoming.generation < local.gen:
		if decision == mergeAuthorityKeepLocal {
			if is, known := specAncestorAt(local.spec, local.gen-incoming.generation, inHash); known && !is && inHash != localHash {
				dropIncoming.reason = specDropNewerGen
				c.noteSpecEditDropped(tx, dropIncoming)
			}
		}
		return decision, nil
	}

	// One generation.
	if incoming.ownerEpoch != local.epoch {
		// The authority rule carries the newer owner's whole row.
		if inHash != localHash {
			if incoming.ownerEpoch > local.epoch && decision != mergeAuthorityKeepLocal {
				dropLocal.reason = specDropStaleEpoch
				c.noteSpecEditDropped(tx, dropLocal)
			} else if incoming.ownerEpoch < local.epoch && decision == mergeAuthorityKeepLocal {
				dropIncoming.reason = specDropStaleEpoch
				c.noteSpecEditDropped(tx, dropIncoming)
			}
		}
		return decision, nil
	}
	if decision != mergeAuthorityNormal {
		return decision, nil
	}
	var ferr error
	localFinished := finishedHere(ctx, tx, &ferr)
	finished := func(op string) bool { return incoming.finishedOps[op] || localFinished(op) }
	inWins, reason := specOrder(
		specVersion{epoch: local.epoch, op: local.activeOp, spec: local.spec},
		specVersion{epoch: incoming.ownerEpoch, op: incoming.activeOperationID, spec: incoming.spec}, finished)
	if ferr != nil {
		return mergeAuthorityKeepLocal, ferr
	}
	winSpec, winOp := local.spec, local.activeOp
	if inWins {
		winSpec, winOp = incoming.spec, incoming.activeOperationID
	}
	if winOp != "" && finished(winOp) {
		winOp = "" // a finished operation leaves no barrier behind
	}
	if ferr != nil {
		return mergeAuthorityKeepLocal, ferr
	}
	if winSpec != local.spec || winOp != local.activeOp {
		if _, err := tx.Exec(specVersionWriteSQL, winSpec, winOp, incoming.name); err != nil {
			return mergeAuthorityKeepLocal, err
		}
	}
	specIdx, opIdx := indexOf(table.Columns, "spec"), indexOf(table.Columns, "active_operation_id")
	if specIdx < 0 || opIdx < 0 {
		return mergeAuthorityKeepLocal, errors.New("vms dump without spec or active_operation_id")
	}
	row[specIdx], row[opIdx] = winSpec, winOp
	if reason != "" {
		if inWins {
			dropLocal.reason = reason
			c.noteSpecEditDropped(tx, dropLocal)
		} else {
			dropIncoming.reason = reason
			c.noteSpecEditDropped(tx, dropIncoming)
		}
	}
	return mergeAuthorityNormal, nil
}
