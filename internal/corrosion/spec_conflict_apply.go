package corrosion

import (
	"context"
	"database/sql"
	"errors"
)

// Resolving desired-spec edits on the WAL lane once spec_conflict_v1 is
// active (spec_conflict.go explains the conflict, spec_stamp.go the stamp).
//
// The generation is the order of spec edits, so an edit, an operation's claim
// and its clear apply by their generation guard, not by the row's clock: an
// unrelated state write that reached the row first no longer makes a replica
// skip an edit every other replica applied. A received edit E→E+1 whose row
// is already at E+1 meets a sibling, and the two are ordered as anti-entropy
// orders them (specOrder), so every replica keeps the same version whatever
// order it hears them in:
//
//  1. the higher owner epoch. An edit from an owner newer than this replica
//     knows is left to anti-entropy, which carries that owner's whole row;
//  2. an operation's barrier, while the operation has not finished: it is
//     never overwritten by an out-of-band edit, and a claim replaces one;
//  3. the later edit stamp (when the spec was edited — never the row clock);
//  4. the greater content hash, so no two versions are left unresolved.
//
// An edit that loses is recorded (noteSpecEditDropped), and so is an edit
// that disappears because the other side's line of edits reached a later
// generation: an edit arriving behind the row, and the version an edit from
// another lineage replaces (both judged from the stamp's lineage).

var (
	fpSpecMutateAtEpoch = mustFingerprint(vmSpecMutateAtEpochSQL)
	fpOperationBegin    = mustFingerprint(vmOperationBeginSQL)
	fpOperationClear    = mustFingerprint(vmOperationClearSQL)
)

func mustFingerprint(sql string) string {
	fp, err := FingerprintSQL(sql)
	if err != nil {
		panic("spec edit SQL does not parse: " + sql + ": " + err.Error())
	}
	return fp
}

// specSiblingTakeSQL is what a receiver applies when the received edit wins
// against the local sibling at its generation: the edit's spec, the barrier
// it leaves, and the later of the two row clocks, guarded on the sibling it
// replaces. Local only — never logged or relayed; the received statement is
// what travels on.
const specSiblingTakeSQL = `UPDATE vms SET spec = ?, active_operation_id = ?, updated_at = ?
	WHERE name = ? AND vm_owner_epoch = ? AND spec_generation = ? AND active_operation_id = ? AND deleted_at IS NULL`

// specEdit is a received desired-spec edit.
type specEdit struct {
	name      string
	epoch     int64 // the owner epoch it was made at
	fromGen   int64 // the generation it was made from; it writes fromGen+1
	spec      string
	updatedAt string // the statement's row clock; only ever clamped, never compared
	opID      string // the operation claiming the barrier; "" for an out-of-band edit
}

// specRow is the local row an edit meets.
type specRow struct {
	name            string
	epoch, gen      int64
	activeOp        string
	spec, updatedAt string
	host            string
	deleted         bool
}

// specVersion is one version of a spec at a generation, as specOrder sees it.
type specVersion struct {
	epoch int64
	op    string // its barrier, "" for none
	spec  string
}

// Why an edit was dropped. Bounded: they label a log line and an event.
const (
	specDropStaleEpoch   = "stale_owner_epoch"
	specDropOperation    = "operation_in_progress"
	specDropLaterEdit    = "later_edit"
	specDropContentOrder = "content_order"
	specDropNewerGen     = "newer_generation"
)

// specOrder orders two versions of a spec at one generation, the same way on
// both lanes: inWins reports whether in is kept over local, and reason why
// the other is dropped — "" when nothing of it is lost (the same content).
// finished reports whether an operation has finished; a finished
// operation's barrier no longer stands.
func specOrder(local, in specVersion, finished func(op string) bool) (inWins bool, reason string) {
	same := specContentHash(local.spec) == specContentHash(in.spec)
	why := func(r string) string {
		if same {
			return ""
		}
		return r
	}
	switch {
	case in.epoch > local.epoch:
		return true, why(specDropStaleEpoch)
	case in.epoch < local.epoch:
		return false, why(specDropStaleEpoch)
	}
	// An unfinished operation's barrier. Two claims at one epoch and
	// generation need two hosts that each think they own the VM (an
	// ownership split brain): they fall through to the stamp, and the
	// losing host's completion then misses — as main's clock merge let the
	// later claim win — and its resize recovery, which keeps no journal,
	// re-drives the winner's resize on its own copy.
	localBarrier := local.op != "" && !finished(local.op)
	inBarrier := in.op != "" && !finished(in.op)
	switch {
	case localBarrier && !inBarrier:
		return false, why(specDropOperation)
	case inBarrier && !localBarrier:
		return true, why(specDropOperation)
	}
	switch ord := specStampOrder(local.spec, in.spec); {
	case ord < 0:
		return true, why(specDropLaterEdit)
	case ord > 0:
		return false, why(specDropLaterEdit)
	}
	if !same {
		return specContentHash(in.spec) > specContentHash(local.spec), specDropContentOrder
	}
	// The same content at the same stamp, written differently: still one
	// agreed version, so every replica holds the same bytes.
	return in.spec > local.spec, ""
}

type specVerdict uint8

const (
	// specApplyByGeneration: apply the statement under its own guard,
	// clamping the row clock; record reason (the local version) if it lands.
	specApplyByGeneration specVerdict = iota
	// specKeepLocal: the local version stands; record reason (the received
	// edit) if set.
	specKeepLocal
	// specTakeEdit: the received edit replaces the local sibling; record
	// reason (the local version) if set.
	specTakeEdit
)

type specDecision struct {
	verdict specVerdict
	reason  string
}

// resolveSpecEdit decides a received edit against the live local row.
func resolveSpecEdit(local specRow, in specEdit, finished func(op string) bool) specDecision {
	inHash, localHash := specContentHash(in.spec), specContentHash(local.spec)
	switch {
	case local.gen == in.fromGen:
		if in.epoch < local.epoch {
			// Its epoch guard misses, as anti-entropy keeps the newer owner's row.
			if inHash == localHash {
				return specDecision{verdict: specKeepLocal}
			}
			return specDecision{verdict: specKeepLocal, reason: specDropStaleEpoch}
		}
		// The edit replaces the local version. If it was made from another
		// version, the local one is gone with it.
		if is, known := specAncestorAt(in.spec, 1, localHash); known && !is && inHash != localHash {
			return specDecision{verdict: specApplyByGeneration, reason: specDropNewerGen}
		}
		return specDecision{verdict: specApplyByGeneration}
	case local.gen > in.fromGen+1:
		// The row is past this edit. It survives only if the local line of
		// edits descends from it.
		if is, known := specAncestorAt(local.spec, local.gen-in.fromGen-1, inHash); known && !is && inHash != localHash {
			return specDecision{verdict: specKeepLocal, reason: specDropNewerGen}
		}
		return specDecision{verdict: specKeepLocal}
	case local.gen != in.fromGen+1:
		// The row is behind: the edits between have not arrived.
		return specDecision{verdict: specApplyByGeneration}
	}
	// A sibling at the generation the edit writes.
	if inHash == localHash && specMetaOf(in.spec).At == specMetaOf(local.spec).At && local.activeOp == in.opID {
		return specDecision{verdict: specKeepLocal} // this very edit, already here
	}
	if in.epoch > local.epoch {
		// The edit's owner is newer than this replica knows. Its whole row —
		// owner, host and all — comes by anti-entropy, which applies it over
		// the local sibling and records the drop; this statement cannot.
		return specDecision{verdict: specApplyByGeneration}
	}
	inWins, reason := specOrder(
		specVersion{epoch: local.epoch, op: local.activeOp, spec: local.spec},
		specVersion{epoch: in.epoch, op: in.opID, spec: in.spec}, finished)
	if inWins {
		return specDecision{verdict: specTakeEdit, reason: reason}
	}
	return specDecision{verdict: specKeepLocal, reason: reason}
}

// specEditFrom reads a DispSpecGeneration edit's parameters. The fingerprint
// fixes their order.
func specEditFrom(s Statement, fp string) (specEdit, bool) {
	str := func(i int) string { return coerceString(s.Params[i]) }
	num := func(i int) (int64, bool) { return coerceInt64OK(s.Params[i]) }
	switch fp {
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
	r.name = name
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

// finishedHere is operationFinished as a predicate, remembering the first
// read error for the caller.
func finishedHere(ctx context.Context, tx *sql.Tx, errp *error) func(string) bool {
	return func(op string) bool {
		done, err := operationFinished(ctx, tx, op)
		if err != nil && *errp == nil {
			*errp = err
		}
		return done
	}
}

// laterClock is the later of two row clocks: an edit applied by its
// generation never moves the row's clock back.
func laterClock(a, b string) string {
	if a == "" || (b != "" && lwwOrder(a, b) < 0) {
		return b
	}
	return a
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
	// byGeneration applies the statement under its own guard, with the
	// row's clock kept at the later of the two.
	byGeneration := func() (bool, error) {
		clamped, err := retainSemanticMaxUpdatedAt(ctx, tx, appliedForm(s), sh, tableName, pkCols)
		if err != nil {
			return false, err
		}
		res, err := tx.ExecContext(ctx, clamped.SQL, clamped.Params...)
		if err != nil {
			return false, err
		}
		return rowsChanged(res), nil
	}
	fp := stmtFingerprint(sh)
	if fp == fpOperationClear {
		// The clear's guard — this operation's barrier at its epoch and
		// generation — is its order, as the claim's is.
		pk, ok := pkValuesFromShape(sh, s)
		if !ok || len(pk) != 1 {
			return invalidf("operation clear without its VM")
		}
		local, found, err := readSpecRow(ctx, tx, coerceString(pk[0]))
		if err != nil {
			return err
		}
		if !found || local.deleted {
			return asBefore()
		}
		changed, err := byGeneration()
		if err != nil || changed {
			return err
		}
		return keepClock(ctx, tx, local, clearClock(s))
	}
	in, ok := specEditFrom(s, fp)
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
	var ferr error
	finished := finishedHere(ctx, tx, &ferr)
	d := resolveSpecEdit(local, in, finished)
	if ferr != nil {
		return ferr
	}
	dropIncoming := specEditDrop{vm: in.name, host: local.host, gen: in.fromGen + 1, reason: d.reason, path: pathWAL,
		droppedSpec: in.spec, keptSpec: local.spec}
	dropLocal := specEditDrop{vm: in.name, host: local.host, gen: local.gen, reason: d.reason, path: pathWAL,
		droppedSpec: local.spec, keptSpec: in.spec}
	switch d.verdict {
	case specKeepLocal:
		if d.reason != "" {
			r.client.noteSpecEditDropped(tx, dropIncoming)
		}
		return keepClock(ctx, tx, local, in.updatedAt)
	case specApplyByGeneration:
		changed, err := byGeneration()
		if err != nil {
			return err
		}
		if !changed {
			return keepClock(ctx, tx, local, in.updatedAt)
		}
		if d.reason != "" {
			r.client.noteSpecEditDropped(tx, dropLocal)
		}
		return nil
	}
	// specTakeEdit. A claim whose operation has already finished here leaves
	// no barrier behind.
	op := in.opID
	if op != "" && finished(op) {
		op = ""
	}
	if ferr != nil {
		return ferr
	}
	changed, err := takeSiblingSpecEdit(ctx, tx, in, op, local)
	if err != nil {
		return err
	}
	if !changed {
		return keepClock(ctx, tx, local, in.updatedAt)
	}
	if d.reason != "" {
		r.client.noteSpecEditDropped(tx, dropLocal)
	}
	return nil
}

// clearClock is an operation clear's row clock (its first parameter).
func clearClock(s Statement) string {
	if len(s.Params) == 0 {
		return ""
	}
	return coerceString(s.Params[0])
}

// keepClock advances the live row's clock to the later of its own and a
// received edit's that changed nothing here. Every replica's row clock is
// then the latest of every write to the row, whichever ones each kept, so
// replicas that keep the same version converge on the same clock. The clock
// orders no spec — the stamp does (spec_stamp.go). It is still the row's LWW
// clock for its other columns: a non-spec write from a third host whose
// clock falls between the kept edit's and the dropped one's is skipped on a
// replica that advanced past it, while one that saw it first applied it —
// the same partial-column class any replica that saw the dropped edit first
// already had; anti-entropy settles the columns by the tie resolver.
func keepClock(ctx context.Context, tx *sql.Tx, local specRow, incoming string) error {
	later := laterClock(local.updatedAt, incoming)
	if later == local.updatedAt {
		return nil
	}
	_, err := tx.ExecContext(ctx, `UPDATE vms SET updated_at = ? WHERE name = ? AND deleted_at IS NULL`, later, local.name)
	return err
}

// takeSiblingSpecEdit applies a received edit over the local sibling at its
// generation, leaving barrier op. The row's clock is the later of the edit's
// and the row's, as every generation-ordered apply keeps it — the edit's own
// stamp, stamped by NowTS on its origin, is inside the spec. It reports
// whether the row changed.
func takeSiblingSpecEdit(ctx context.Context, tx *sql.Tx, in specEdit, op string, local specRow) (bool, error) {
	res, err := tx.ExecContext(ctx, specSiblingTakeSQL, in.spec, op, laterClock(local.updatedAt, in.updatedAt),
		in.name, local.epoch, local.gen, local.activeOp)
	if err != nil {
		return false, err
	}
	return rowsChanged(res), nil
}
