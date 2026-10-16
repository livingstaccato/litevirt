package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Resolving a desired-spec edit that meets another at its generation, on the
// WAL lane (spec_conflict.go explains the conflict).
//
// A received edit E→E+1 whose row here is already at E+1 meets a sibling: an
// edit made from the same generation somewhere else. Before spec_conflict_v1
// its compare-and-swap missed and it applied as a zero-row no-op, so each
// replica kept whichever sibling reached it first. Now it is resolved the way
// anti-entropy resolves the two rows (workloadParentAuthorityDecision), so the
// WAL converges every replica on the version anti-entropy would keep:
//
//  1. the higher owner epoch. An edit made under a superseded owner loses. An
//     edit from a newer owner than this replica knows is left to anti-entropy,
//     which carries the newer owner's whole row; the statement alone cannot.
//  2. an operation's barrier. An out-of-band edit never overwrites a row whose
//     operation is in flight, and an operation's claim overwrites an
//     out-of-band edit at its generation. A claim whose operation has already
//     finished here changes nothing: the row is past it.
//  3. the later edit, by updated_at. An exact tie keeps the local version, as
//     the tie resolver does for a differing spec (an unresolved tie).
//
// The losing edit is recorded (noteSpecEditDropped). Everything else — an edit
// that meets its own generation, a row ahead by more than one, a tombstone, a
// row that has not arrived — applies exactly as DispLiveRowUpdate does.

var (
	fpSpecMutateAtEpoch = mustFingerprint(vmSpecMutateAtEpochSQL)
	fpOperationBegin    = mustFingerprint(vmOperationBeginSQL)
)

func mustFingerprint(sql string) string {
	fp, err := FingerprintSQL(sql)
	if err != nil {
		panic("spec edit SQL does not parse: " + sql + ": " + err.Error())
	}
	return fp
}

// The forms a receiver applies when the received edit wins against a sibling:
// the edit's own assignments without the generation bump, guarded on the
// sibling's generation. Local only — never logged or relayed; the received
// statement is what travels on.
const (
	specSiblingTakeEditSQL = `UPDATE vms SET spec = ?, updated_at = ?
		WHERE name = ? AND vm_owner_epoch = ? AND spec_generation = ? AND active_operation_id = '' AND deleted_at IS NULL`
	specSiblingTakeClaimSQL = `UPDATE vms SET spec = ?, active_operation_id = ?, updated_at = ?
		WHERE name = ? AND vm_owner_epoch = ? AND spec_generation = ? AND active_operation_id = '' AND deleted_at IS NULL`
)

// specEdit is a received desired-spec edit.
type specEdit struct {
	name      string
	epoch     int64 // the owner epoch it was made at
	fromGen   int64 // the generation it was made from; it writes fromGen+1
	spec      string
	updatedAt string
	opID      string // the operation claiming the barrier; "" for an out-of-band edit
}

// specRow is the local row an edit meets.
type specRow struct {
	epoch, gen      int64
	activeOp        string
	spec, updatedAt string
	host            string
	deleted         bool
}

type specVerdict uint8

const (
	// specApplyAsBefore: no sibling to resolve; apply as DispLiveRowUpdate.
	specApplyAsBefore specVerdict = iota
	// specKeepLocal: the local version stands; the received edit changes nothing.
	specKeepLocal
	// specTakeEdit: the received edit replaces the local sibling.
	specTakeEdit
)

// Why an edit was dropped. Bounded: they label a metric.
const (
	specDropStaleEpoch = "stale_owner_epoch"
	specDropOperation  = "operation_in_progress"
	specDropLaterEdit  = "later_edit"
	specDropTie        = "unresolved_tie"
)

type specDecision struct {
	verdict specVerdict
	// reason is set when an edit is dropped: the received one under
	// specKeepLocal, the local one under specTakeEdit.
	reason string
}

// resolveSpecEdit decides a received edit against the live local row.
// opFinished reports whether the received claim's operation has already
// finished here; it is consulted only for a claim.
func resolveSpecEdit(local specRow, in specEdit, opFinished bool) specDecision {
	keep := func(reason string) specDecision {
		if local.spec == in.spec {
			reason = "" // nothing of the edit is lost
		}
		return specDecision{verdict: specKeepLocal, reason: reason}
	}
	take := func(reason string) specDecision {
		if local.spec == in.spec {
			reason = ""
		}
		return specDecision{verdict: specTakeEdit, reason: reason}
	}
	switch {
	case local.gen == in.fromGen:
		// No sibling. An edit from a superseded owner still applies nowhere:
		// its epoch guard misses, as anti-entropy keeps the newer owner's row.
		if in.epoch < local.epoch {
			return keep(specDropStaleEpoch)
		}
		return specDecision{verdict: specApplyAsBefore}
	case local.gen != in.fromGen+1:
		return specDecision{verdict: specApplyAsBefore}
	}
	// A sibling at the generation the edit writes.
	if local.spec == in.spec && local.updatedAt == in.updatedAt && local.activeOp == in.opID {
		return specDecision{verdict: specKeepLocal} // this very edit, already here
	}
	switch {
	case in.epoch < local.epoch:
		return keep(specDropStaleEpoch)
	case in.epoch > local.epoch:
		// The edit's owner is newer than this replica knows. Its whole row —
		// owner, host and all — comes by anti-entropy, which applies it over
		// the local sibling (and records the drop); this statement cannot.
		return specDecision{verdict: specApplyAsBefore}
	}
	if in.opID != "" {
		switch {
		case local.activeOp == in.opID:
			return specDecision{verdict: specKeepLocal}
		case local.activeOp != "":
			return keep(specDropOperation)
		case opFinished:
			// The operation already finished here: the row is past its claim.
			return specDecision{verdict: specKeepLocal}
		default:
			return take(specDropOperation)
		}
	}
	if local.activeOp != "" {
		return keep(specDropOperation)
	}
	switch ord := lwwOrder(local.updatedAt, in.updatedAt); {
	case ord < 0:
		return take(specDropLaterEdit)
	case ord > 0:
		return keep(specDropLaterEdit)
	default:
		return keep(specDropTie)
	}
}

// specEditFrom reads a DispSpecGeneration statement's edit from its params.
// The fingerprint fixes the parameter order.
func specEditFrom(s Statement, sh StmtShape) (specEdit, bool) {
	str := func(i int) string { return coerceString(s.Params[i]) }
	num := func(i int) (int64, bool) { return coerceInt64OK(s.Params[i]) }
	switch stmtFingerprint(sh) {
	case fpSpecMutateAtEpoch: // spec, updated_at, name, epoch, generation
		if len(s.Params) != 5 {
			return specEdit{}, false
		}
		e, ok1 := num(3)
		g, ok2 := num(4)
		return specEdit{spec: str(0), updatedAt: str(1), name: str(2), epoch: e, fromGen: g}, ok1 && ok2
	case fpOperationBegin: // spec, operation, updated_at, name, epoch, generation
		if len(s.Params) != 6 {
			return specEdit{}, false
		}
		e, ok1 := num(4)
		g, ok2 := num(5)
		in := specEdit{spec: str(0), opID: str(1), updatedAt: str(2), name: str(3), epoch: e, fromGen: g}
		return in, ok1 && ok2 && in.opID != ""
	}
	return specEdit{}, false
}

func readSpecRow(ctx context.Context, tx *sql.Tx, name string) (specRow, bool, error) {
	var r specRow
	var deleted sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT vm_owner_epoch, spec_generation, active_operation_id,
		COALESCE(spec, ''), COALESCE(updated_at, ''), COALESCE(host_name, ''), deleted_at
		FROM vms WHERE name = ?`, name).Scan(&r.epoch, &r.gen, &r.activeOp, &r.spec, &r.updatedAt, &r.host, &deleted)
	if errors.Is(err, sql.ErrNoRows) {
		return specRow{}, false, nil
	}
	if err != nil {
		return specRow{}, false, err
	}
	r.deleted = deleted.Valid && deleted.String != ""
	return r, true, nil
}

// operationFinished reports whether operation id has recorded a terminal step
// here. A reaped operation's tombstoned steps still count: it finished.
func operationFinished(ctx context.Context, tx *sql.Tx, id string) (bool, error) {
	var one int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM operation_steps
		WHERE operation_id = ? AND step_name IN (?, ?, ?, ?) LIMIT 1`,
		id, OpStepCompleted, OpStepFailed, OpStepCancelled, OpStepSuperseded).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// applySpecGeneration applies a DispSpecGeneration statement.
func (r *Replicator) applySpecGeneration(ctx context.Context, tx *sql.Tx, s Statement, sh StmtShape, tableName string, pkCols []string, incomingHLC string) error {
	asBefore := func() error {
		if err := r.applyLWWGated(ctx, tx, appliedForm(s), sh, tableName, pkCols, incomingHLC); err != nil {
			return err
		}
		if park := r.client.parkIfRowAbsent(ctx, tx, s, incomingHLC); park != nil {
			r.client.deferAfterCommit(tx, park)
		}
		return nil
	}
	in, ok := specEditFrom(s, sh)
	if !ok {
		return invalidf("spec edit statement carries unreadable parameters")
	}
	local, found, err := readSpecRow(ctx, tx, in.name)
	if err != nil {
		return err
	}
	if !found || local.deleted {
		return asBefore()
	}
	finished := false
	if in.opID != "" && local.gen == in.fromGen+1 && local.activeOp == "" {
		if finished, err = operationFinished(ctx, tx, in.opID); err != nil {
			return err
		}
	}
	d := resolveSpecEdit(local, in, finished)
	switch d.verdict {
	case specApplyAsBefore:
		return asBefore()
	case specKeepLocal:
		if d.reason != "" {
			r.client.noteSpecEditDropped(tx, specEditDrop{
				vm: in.name, host: local.host, epoch: local.epoch, gen: local.gen, reason: d.reason, path: pathWAL,
				keptAt: local.updatedAt, droppedAt: in.updatedAt, droppedSpec: in.spec,
			})
		}
		return nil
	}
	// specTakeEdit: the received edit replaces the local sibling — unless its
	// clock is quarantined as future-skewed, which every other apply refuses.
	if r.client.skewQuarantinesIncoming(r.client.hlcSkewGuardOn(), local.updatedAt, in.updatedAt, time.Now()) {
		return nil
	}
	changed, err := takeSiblingSpecEdit(ctx, tx, in, local)
	if err != nil {
		return err
	}
	if changed && d.reason != "" {
		r.client.noteSpecEditDropped(tx, specEditDrop{
			vm: in.name, host: local.host, epoch: local.epoch, gen: local.gen, reason: d.reason, path: pathWAL,
			keptAt: in.updatedAt, droppedAt: local.updatedAt, droppedSpec: local.spec,
		})
	}
	return nil
}

// takeSiblingSpecEdit applies a received edit over the local sibling at its
// generation, carrying the edit's own updated_at as every WAL apply does, so
// the row is the one its origin holds. It reports whether the row changed.
func takeSiblingSpecEdit(ctx context.Context, tx *sql.Tx, in specEdit, local specRow) (bool, error) {
	var res sql.Result
	var err error
	if in.opID != "" {
		res, err = tx.ExecContext(ctx, specSiblingTakeClaimSQL, in.spec, in.opID, in.updatedAt, in.name, local.epoch, local.gen)
	} else {
		res, err = tx.ExecContext(ctx, specSiblingTakeEditSQL, in.spec, in.updatedAt, in.name, local.epoch, local.gen)
	}
	if err != nil {
		return false, err
	}
	return rowsChanged(res), nil
}
