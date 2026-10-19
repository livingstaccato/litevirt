package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// A deleted account stays deleted (user_incarnation_v1).
//
// A users row's created_at is its INCARNATION: the account that one create
// made. Without it, ordering is by the row clock alone, and a password change
// made on a node that had not yet seen the account's delete is newer than the
// delete. That node then skips the tombstone and keeps the account live, and
// anti-entropy's newer-wins carries the live row back to every node that
// deleted it, with the lagging node's password.
//
// Once user_incarnation_v1 has latched:
//
//   - a re-create of a deleted name (InsertUser over a tombstone, the admin
//     floor's reinstatement) stamps a fresh created_at
//     (usersReactivateIncarnationSQL);
//   - a delete names the incarnation it ends (usersTombstoneIncarnationSQL);
//   - a receiver applies the delete to that incarnation whatever later write
//     it holds, keeping the later clock, and applies a re-create over the
//     tombstone of an older incarnation whatever the clocks say
//     (applyUserIncarnation);
//   - anti-entropy never lets a live row beat a tombstone of its own
//     incarnation, and lets a newer incarnation, live or deleted, beat an
//     older one (userIncarnationDecision).
//
// Before the latch every writer emits the previous release's statements, and
// both kinds are accepted: a node only emits the new ones once every host it
// replicates to runs a build that decodes them.

// usersReactivateIncarnationSQL re-creates a deleted name as a NEW incarnation.
// usersReactivateSQL without the new created_at is the previous release's.
const usersReactivateIncarnationSQL = `UPDATE users SET role = ?, password_hash = ?, deleted_at = NULL, created_at = ?, updated_at = ? WHERE username = ?`

// usersTombstoneIncarnationSQL deletes one incarnation of a name, and nothing
// a later re-create made of it.
const usersTombstoneIncarnationSQL = `UPDATE users SET deleted_at = ?, updated_at = ? WHERE username = ? AND created_at = ?`

// usersTombstoneSQL is the previous release's delete: the row, whichever
// incarnation it holds.
const usersTombstoneSQL = `UPDATE users SET deleted_at = ?, updated_at = ? WHERE username = ?`

var (
	fpUsersReactivateIncarnation = mustFingerprint(usersReactivateIncarnationSQL)
	fpUsersTombstoneIncarnation  = mustFingerprint(usersTombstoneIncarnationSQL)
)

// SetUserIncarnationGate injects the predicate that says user_incarnation_v1
// has DURABLY latched. Nil-safe; unset reads false, the previous release's
// statements and merge.
func (c *Client) SetUserIncarnationGate(fn func() bool) {
	if fn == nil {
		c.userIncarnationGate.Store(nil)
		return
	}
	c.userIncarnationGate.Store(&fn)
}

// UserIncarnationOn reports whether this node writes and merges users rows by
// incarnation.
func (c *Client) UserIncarnationOn() bool {
	fn := c.userIncarnationGate.Load()
	return fn != nil && (*fn)()
}

// nextIncarnation is a created_at for a re-create of a name whose last
// incarnation is prev: now, at nanosecond precision, and strictly after prev
// whatever the two clocks say, so every node orders the re-create after the
// incarnation it replaces.
func nextIncarnation(prev string) string {
	now := time.Now().UTC()
	if p, err := time.Parse(time.RFC3339Nano, prev); err == nil && !now.After(p) {
		now = p.Add(time.Nanosecond)
	}
	return now.Format(time.RFC3339Nano)
}

// applyUserIncarnation applies one of the two incarnation-bearing users
// statements on the WAL lane.
func (r *Replicator) applyUserIncarnation(ctx context.Context, tx *sql.Tx, s Statement, sh StmtShape, tableName string, pkCols []string, incomingHLC string) error {
	if tableName != "users" || len(s.Params) != 5 && len(s.Params) != 4 {
		return invalidf("user incarnation statement on %s with %d params", tableName, len(s.Params))
	}
	fp := stmtFingerprint(sh)
	var username string
	switch fp {
	case fpUsersTombstoneIncarnation:
		username = coerceString(s.Params[2])
	case fpUsersReactivateIncarnation:
		username = coerceString(s.Params[4])
	default:
		return invalidf("unknown user incarnation statement")
	}
	var localCreated string
	var localDeleted sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT created_at, deleted_at FROM users WHERE username = ?`, username).
		Scan(&localCreated, &localDeleted)
	if errors.Is(err, sql.ErrNoRows) {
		// No row to end or revive here; anti-entropy brings the row and
		// decides it by incarnation.
		return nil
	}
	if err != nil {
		return err
	}
	if fp == fpUsersReactivateIncarnation {
		incoming := coerceString(s.Params[2])
		switch {
		case incoming == localCreated:
			// This incarnation again (a re-delivery): its row clock decides.
			return r.applyLWWGated(ctx, tx, s, sh, tableName, pkCols, incomingHLC)
		case !localDeleted.Valid || !incarnationAfter(incoming, localCreated):
			// An older incarnation, or a live row of an older one here whose
			// delete has not arrived yet: kept. The delete ends it, and
			// anti-entropy then brings the re-create.
			r.client.observeMergeRejected("users", "wal", "older_incarnation")
			return nil
		}
	}
	// The tombstone's WHERE names its incarnation; a re-create of a newer one
	// replaces the tombstone of an older one. Either way the row keeps the
	// later clock, so a lagging write cannot win it back.
	s, err = retainSemanticMaxUpdatedAt(ctx, tx, s, sh, tableName, pkCols)
	if err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, s.SQL, s.Params...)
	if err == nil && rowsChanged(res) {
		r.client.deferAfterCommit(tx, func() { r.client.clearUnresolvedFromShape(sh, s) })
	}
	return err
}

// userIncarnationDecision decides an anti-entropy merge of a users row from
// incarnation identity (created_at), once user_incarnation_v1 is on. It
// decides only a live row against a tombstone, and a newer incarnation against
// an older one; everything else is left to the ordinary merge.
func userIncarnationDecision(tx *sql.Tx, table syncTable, row []interface{}) (mergeAuthorityDecision, error) {
	idx := columnIndexMap(table.Columns)
	nameIdx, okN := idx["username"]
	createdIdx, okC := idx["created_at"]
	deletedIdx, okD := idx["deleted_at"]
	if !okN || !okC || !okD {
		return mergeAuthorityNormal, nil
	}
	incomingCreated := coerceString(row[createdIdx])
	incomingDeleted := row[deletedIdx] != nil && coerceString(row[deletedIdx]) != ""
	var localCreated string
	var localDeleted sql.NullString
	err := tx.QueryRow(`SELECT created_at, deleted_at FROM users WHERE username = ?`, coerceString(row[nameIdx])).
		Scan(&localCreated, &localDeleted)
	if errors.Is(err, sql.ErrNoRows) {
		return mergeAuthorityNormal, nil
	}
	if err != nil {
		return mergeAuthorityKeepLocal, err
	}
	if localCreated == "" || incomingCreated == "" {
		return mergeAuthorityNormal, nil
	}
	localIsDeleted := localDeleted.Valid && localDeleted.String != ""
	switch {
	case incarnationAfter(incomingCreated, localCreated):
		// A newer incarnation, live or deleted, replaces an older one.
		return mergeAuthorityApplyIncoming, nil
	case incarnationAfter(localCreated, incomingCreated):
		return mergeAuthorityKeepLocal, nil
	case localCreated != incomingCreated:
		// Different stamps neither of which orders: not evidence of anything.
		return mergeAuthorityNormal, nil
	case localIsDeleted && !incomingDeleted:
		// A live copy of the incarnation this tombstone ended: whatever its
		// clock, it was written by a node that had not seen the delete.
		return mergeAuthorityKeepLocal, nil
	case !localIsDeleted && incomingDeleted:
		return mergeAuthorityApplyIncoming, nil
	default:
		return mergeAuthorityNormal, nil
	}
}
