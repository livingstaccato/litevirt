package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"strings"
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
	if fp == fpUsersReactivateIncarnation {
		// What this node holds under the name besides the users row is the
		// older incarnation's: its credential, factors, codes, bindings and
		// cut-offs, some maybe written here after it was deleted elsewhere
		// (a lagging password change, or a delete's cascade). None of it is the
		// new account's, and a newer clock on it must not keep what the new
		// account's own writes bring from landing: it goes, here only.
		if err := retireOlderIncarnationRows(ctx, tx, username); err != nil {
			return err
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
func (c *Client) userIncarnationDecision(tx *sql.Tx, table syncTable, row []interface{}) (mergeAuthorityDecision, error) {
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
		// The peer holds an older account of the name. Its credential row,
		// on this exchange's sensitive pull, is that account's too: refused
		// unless it is the one this node holds, as for a re-minted account
		// (users_admin_guard.go).
		username := coerceString(row[nameIdx])
		if pwIdx, ok := idx["password_hash"]; ok {
			c.remints.note(username, coerceString(row[pwIdx]))
		}
		table.remints.noteUnknown(username)
		table.remints.noteOlderIncarnation(username)
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

// Writes that name an account by username alone — a password change and its
// credential row, and a delete's cascade over the account's second factors,
// recovery codes, role bindings, enrollment code, directory bindings and
// session cut-offs — reach whatever account holds the name on a receiver. A
// lagging node's write to an account that has since been deleted and the
// name re-created would land on the NEW account: the old holder's password
// would log into it, and the old account's delete would strip the new one's
// factors and bindings.
//
// Once user_incarnation_v1 has latched each such statement carries a
// user_incarnation_v1 mutation guard naming the account's incarnation, and a
// receiver applies it only while its users row is that incarnation
// (userIncarnationGuardMatches). The SQL is unchanged, so no shape is added.
// Revocations by session or token id are not guarded: an id names one
// credential of one account, and revoking it is right whatever the name
// holds now.

// userIncarnationGuardV1 binds a statement to one incarnation of an account.
// ResourceID is the username, Incarnation its created_at. ResourceKind
// userGuardLive also requires the account live (a password change);
// userGuardAny accepts it deleted (a delete's cascade, after its tombstone).
const (
	userIncarnationGuardV1 = "user_incarnation_v1"
	userGuardLive          = "user_live"
	userGuardAny           = "user"
)

// userIncarnationGuard is the guard for username's incarnation as this node
// holds it, or nil when the gate is closed or the account has no row here.
func userIncarnationGuard(ctx context.Context, c *Client, username string, live bool) (*MutationGuard, error) {
	if !c.UserIncarnationOn() {
		return nil, nil
	}
	rows, err := c.Query(ctx, `SELECT created_at FROM users WHERE username = ?`, username)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	kind := userGuardAny
	if live {
		kind = userGuardLive
	}
	return &MutationGuard{Protocol: userIncarnationGuardV1, ResourceKind: kind,
		ResourceID: username, Incarnation: rows[0].String("created_at")}, nil
}

// withUserIncarnationGuard sets g on every statement of stmts (nil leaves
// them unguarded, the previous release's wire form).
func withUserIncarnationGuard(stmts []Statement, g *MutationGuard) []Statement {
	if g == nil {
		return stmts
	}
	out := make([]Statement, len(stmts))
	for i, s := range stmts {
		guard := *g
		s.Guard = &guard
		out[i] = s
	}
	return out
}

// userIncarnationGuardMatches: the receiver's users row for the name is the
// guard's incarnation (and live, for userGuardLive).
func userIncarnationGuardMatches(ctx context.Context, tx *sql.Tx, g *MutationGuard) (bool, error) {
	if g.ResourceID == "" || g.Incarnation == "" || g.ResourceKind != userGuardLive && g.ResourceKind != userGuardAny {
		return false, invalidf("invalid user incarnation guard")
	}
	var created string
	var deleted sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT created_at, deleted_at FROM users WHERE username = ?`, g.ResourceID).
		Scan(&created, &deleted)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if created != g.Incarnation {
		return false, nil
	}
	return g.ResourceKind == userGuardAny || !deleted.Valid || deleted.String == "", nil
}

// userGuardedShapes is every statement a user_incarnation_v1 guard may bind,
// with how it names the account: the guard binds exactly the account the
// statement writes.
var userGuardedShapes = map[string]func(p []interface{}, user string) bool{
	mustFingerprint(usersUpdatePasswordSQL):       paramIs(2),
	mustFingerprint(userCredentialUpsertSQL):      paramIs(0),
	mustFingerprint(usersTombstoneIncarnationSQL): paramIs(2),
	mustFingerprint(`UPDATE user_2fa SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`):           paramIs(2),
	mustFingerprint(`UPDATE user_2fa_sets SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`):      paramIs(2),
	mustFingerprint(`UPDATE recovery_codes SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`):     paramIs(2),
	mustFingerprint(`UPDATE recovery_code_sets SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`): paramIs(2),
	mustFingerprint(userRoleBindingsRevokeSQL): func(p []interface{}, user string) bool {
		return len(p) == 4 && coerceString(p[2]) == "user:"+user && coerceString(p[3]) == "user:"+user+"@local"
	},
	mustFingerprint(enrollmentCodeTombstoneSQL): paramIs(2),
	mustFingerprint(identityBindingClearSQL):    paramIs(2),
	mustFingerprint(userLifecycleUpsertSQL):     paramIs(0),
}

func paramIs(i int) func(p []interface{}, user string) bool {
	return func(p []interface{}, user string) bool { return len(p) > i && coerceString(p[i]) == user }
}

// validateUserIncarnationEntry checks an entry whose statements carry
// user_incarnation_v1 guards: one guard identity, each guarded statement one
// of userGuardedShapes and binding the guard's account. Unguarded statements
// (a revocation by id) are left to their own rules.
func validateUserIncarnationEntry(stmts []Statement) error {
	var base *MutationGuard
	for _, s := range stmts {
		if s.Guard == nil {
			continue
		}
		g := s.Guard
		if g.Protocol != userIncarnationGuardV1 {
			return invalidf("user incarnation entry mixes mutation guard protocols")
		}
		if base == nil {
			base = g
		} else if *g != *base {
			return invalidf("user incarnation entry mixes guard identities")
		}
		if g.ResourceID == "" || g.Incarnation == "" || g.ResourceKind != userGuardLive && g.ResourceKind != userGuardAny {
			return invalidf("invalid user incarnation guard")
		}
		sh, _, err := parseResolved(s.SQL)
		if err != nil {
			return err
		}
		binds, ok := userGuardedShapes[stmtFingerprint(sh)]
		if !ok || !binds(s.Params, g.ResourceID) {
			return invalidf("user incarnation guard on a statement it does not bind (table %s)", sh.Table)
		}
	}
	return nil
}

// retireOlderIncarnationRows drops, on this node only, every row keyed by
// username that an older incarnation of the name left here
// (applyUserIncarnation). Each statement is on one line for the hard-delete
// tripwire (hard_delete_guard_test.go).
func retireOlderIncarnationRows(ctx context.Context, tx *sql.Tx, username string) error {
	for _, q := range []string{
		`DELETE FROM user_credentials WHERE username = ? -- full-state-delete-ok: an older incarnation's, replaced by a re-create`,
		`DELETE FROM user_2fa WHERE username = ? -- full-state-delete-ok: an older incarnation's, replaced by a re-create`,
		`DELETE FROM user_2fa_sets WHERE username = ? -- full-state-delete-ok: an older incarnation's, replaced by a re-create`,
		`DELETE FROM recovery_codes WHERE username = ? -- full-state-delete-ok: an older incarnation's, replaced by a re-create`,
		`DELETE FROM recovery_code_sets WHERE username = ? -- full-state-delete-ok: an older incarnation's, replaced by a re-create`,
		`DELETE FROM user_enrollment_codes WHERE username = ? -- full-state-delete-ok: an older incarnation's, replaced by a re-create`,
		`DELETE FROM user_identity_bindings WHERE username = ? -- full-state-delete-ok: an older incarnation's, replaced by a re-create`,
		`DELETE FROM user_lifecycle WHERE username = ? -- full-state-delete-ok: an older incarnation's, replaced by a re-create`,
	} {
		if _, err := tx.ExecContext(ctx, q, username); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx,
		`DELETE FROM role_bindings WHERE principal IN (?, ?) -- full-state-delete-ok: an older incarnation's, replaced by a re-create`,
		"user:"+username, "user:"+username+"@local")
	return err
}

// userKeyedTables are the public tables whose rows name an account by
// username alone (role_bindings by its principal). An anti-entropy row from a
// sender holding an older incarnation of the name than this node is that
// account's, not this node's, and is refused (userKeyedRowDecision). The
// sender's incarnation is in the same payload's users rows (the manifest).
var userKeyedTables = map[string]bool{
	"user_lifecycle": true, "user_enrollment_codes": true, "user_identity_bindings": true, "role_bindings": true,
}

// sensitiveUserKeyedTables are the peer-only tables of the same kind. Their
// rows travel apart from the users rows, so the public pull of the same
// exchange marks the names the sender holds an older account of
// (remintScope.older), and those rows are refused.
var sensitiveUserKeyedTables = map[string]bool{
	"user_2fa": true, "user_2fa_sets": true, "recovery_codes": true, "recovery_code_sets": true, "user_credentials": true,
}

func (c *Client) userKeyedRowDecision(tx *sql.Tx, table syncTable, row []interface{}) (mergeAuthorityDecision, error) {
	if table.authority == nil {
		return mergeAuthorityNormal, nil
	}
	idx := columnIndexMap(table.Columns)
	username := cellStr(row, idx, "username")
	if table.Name == "role_bindings" {
		p := cellStr(row, idx, "principal")
		username = strings.TrimSuffix(strings.TrimPrefix(p, "user:"), "@local")
		if !strings.HasPrefix(p, "user:") {
			return mergeAuthorityNormal, nil
		}
	}
	sender, ok := table.authority.users[username]
	if !ok || username == "" {
		return mergeAuthorityNormal, nil
	}
	var local string
	err := tx.QueryRow(`SELECT created_at FROM users WHERE username = ?`, username).Scan(&local)
	if errors.Is(err, sql.ErrNoRows) {
		return mergeAuthorityNormal, nil
	}
	if err != nil {
		return mergeAuthorityKeepLocal, err
	}
	if incarnationAfter(local, sender) {
		return mergeAuthorityKeepLocal, nil
	}
	return mergeAuthorityNormal, nil
}
