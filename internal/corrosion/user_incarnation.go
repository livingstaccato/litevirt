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
		switch userRecreateVerdictOf(coerceString(s.Params[2]), localCreated, localDeleted) {
		case userRecreateSame:
			// This incarnation again (a re-delivery): its row clock decides.
			return r.applyLWWGated(ctx, tx, s, sh, tableName, pkCols, incomingHLC)
		case userRecreateKept:
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
		if err := retireOlderIncarnationRows(ctx, tx, username, coerceString(s.Params[2])); err != nil {
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

// userRecreateVerdict is what a receiver does with a re-create of a name
// whose row it holds (applyUserIncarnation).
type userRecreateVerdict int

const (
	userRecreateApply userRecreateVerdict = iota // over the tombstone of an older incarnation
	userRecreateSame                             // this incarnation again: its row clock decides
	userRecreateKept                             // an older incarnation, or a live older row: refused
)

func userRecreateVerdictOf(incoming, localCreated string, localDeleted sql.NullString) userRecreateVerdict {
	switch {
	case incoming == localCreated:
		return userRecreateSame
	case !localDeleted.Valid || !incarnationAfter(incoming, localCreated):
		return userRecreateKept
	}
	return userRecreateApply
}

// userRecreateRefused reports whether s is an incarnation re-create this
// receiver keeps off (userRecreateKept). The WAL apply loop asks before it
// applies the statement, so a refused re-create takes nothing of its entry
// with it: its credential is bound to the new incarnation, and the
// unlatched-origin absorb skips it (replicator.go).
func userRecreateRefused(ctx context.Context, tx *sql.Tx, s Statement) (bool, error) {
	if len(s.Params) != 5 || !strings.Contains(s.SQL, "created_at") {
		return false, nil
	}
	sh, _, err := parseResolved(s.SQL)
	if err != nil || stmtFingerprint(sh) != fpUsersReactivateIncarnation {
		return false, nil
	}
	var localCreated string
	var localDeleted sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT created_at, deleted_at FROM users WHERE username = ?`, coerceString(s.Params[4])).
		Scan(&localCreated, &localDeleted)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return userRecreateVerdictOf(coerceString(s.Params[2]), localCreated, localDeleted) == userRecreateKept, nil
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
		// A newer incarnation, live or deleted, replaces an older one, and
		// once it has landed the older one's rows under the name are retired
		// here as a WAL re-create retires them (retireOlderIncarnationRows):
		// a node that learns the re-create this way first must not keep a
		// write it made to the deleted account, with a later clock than the
		// new account's own, for anti-entropy to carry to every node.
		return mergeAuthorityApplyIncomingAndRetire, nil
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
// credential row, a delete's cascade over the account's second factors,
// recovery codes, role bindings, enrollment code, directory bindings and
// session cut-offs, and every grant made to it (a token, a session, a role
// binding, a directory binding, an enrollment code, recovery codes, a factor
// change, a lifecycle change) — reach whatever account holds the name on a
// receiver. A lagging node's write to an account that has since been deleted
// and the name re-created would land on the NEW account: the old holder's
// password or token would log into it, and the old account's delete would
// strip the new one's factors and bindings.
//
// Once user_incarnation_v1 has latched each such statement carries a
// user_incarnation_v1 mutation guard naming the account's incarnation, and a
// receiver applies it only while its users row is that incarnation
// (userIncarnationGuardMatches). The SQL is unchanged, so no shape is added.
// A writer may set the guard itself (a password change, a delete's cascade);
// every other such statement is stamped on the local write path with the
// incarnation its users row holds just before the statement runs, inside the
// write's own transaction (stampUserIncarnation), and an explicit guard is
// checked there too, so a delete and re-create that land between a writer's
// read and its batch fail the write instead of shipping it. Revocations by
// session or token id are not guarded: an id names one credential of one
// account, and revoking it is right whatever the name holds now.

// userIncarnationGuardV1 binds a statement to one incarnation of an account.
// ResourceID is the username, Incarnation its created_at. ResourceKind
// userGuardLive also requires the account live (a password change, a grant);
// userGuardDeleted requires it deleted (a write made to a deleted name, such
// as a re-create's lifecycle reset, which must not reach a live account of
// that incarnation on a node the delete has not reached); userGuardAny
// accepts either (a delete's cascade, after its tombstone).
const (
	userIncarnationGuardV1 = "user_incarnation_v1"
	userGuardLive          = "user_live"
	userGuardDeleted       = "user_deleted"
	userGuardAny           = "user"
)

// ErrUserAccountChanged is a local write's refusal when the account it names
// was deleted or re-created between the writer's read and its write: the
// write was prepared for an account the name no longer holds. Nothing was
// changed; the caller may read again and retry.
var ErrUserAccountChanged = errors.New("the account was deleted or re-created while this write was prepared; nothing was changed")

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

func validUserGuardKind(k string) bool {
	return k == userGuardLive || k == userGuardDeleted || k == userGuardAny
}

// userIncarnationGuardMatches: the receiver's users row for the name is the
// guard's incarnation (and live, or deleted, as the kind requires).
func userIncarnationGuardMatches(ctx context.Context, tx *sql.Tx, g *MutationGuard) (bool, error) {
	if g.ResourceID == "" || g.Incarnation == "" || !validUserGuardKind(g.ResourceKind) {
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
	isDeleted := deleted.Valid && deleted.String != ""
	switch g.ResourceKind {
	case userGuardLive:
		return !isDeleted, nil
	case userGuardDeleted:
		return isDeleted, nil
	}
	return true, nil
}

// userGuardedShapes is every statement a user_incarnation_v1 guard may bind,
// with the account it names: the guard binds exactly that account.
var userGuardedShapes = map[string]func(p []interface{}) string{
	mustFingerprint(usersUpdatePasswordSQL):       paramAt(2),
	mustFingerprint(userCredentialUpsertSQL):      paramAt(0),
	mustFingerprint(usersTombstoneIncarnationSQL): paramAt(2),
	mustFingerprint(`UPDATE user_2fa SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`):           paramAt(2),
	mustFingerprint(`UPDATE user_2fa_sets SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`):      paramAt(2),
	mustFingerprint(`UPDATE recovery_codes SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`):     paramAt(2),
	mustFingerprint(`UPDATE recovery_code_sets SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`): paramAt(2),
	mustFingerprint(userRoleBindingsRevokeSQL): func(p []interface{}) string {
		if len(p) != 4 {
			return ""
		}
		user := strings.TrimPrefix(coerceString(p[2]), "user:")
		if user == "" || coerceString(p[2]) != "user:"+user || coerceString(p[3]) != "user:"+user+"@local" {
			return ""
		}
		return user
	},
	mustFingerprint(enrollmentCodeTombstoneSQL): paramAt(2),
	mustFingerprint(identityBindingClearSQL):    paramAt(2),
	mustFingerprint(userLifecycleUpsertSQL):     paramAt(0),
	// Grants, and the changes that lift a restriction.
	mustFingerprint(tokensInsertSQL):           paramAt(1),
	mustFingerprint(sessionsInsertSQL):         paramAt(1),
	mustFingerprint(identityBindingUpsertSQL):  paramAt(0),
	mustFingerprint(enrollmentCodeUpsertSQL):   paramAt(0),
	mustFingerprint(roleBindingInsertSQL):      roleBindingAccount,
	mustFingerprint(user2FASetUpsertSQL):       paramAt(0),
	mustFingerprint(user2FAUpsertSQL):          paramAt(0),
	mustFingerprint(user2FATombstoneSQL):       paramAt(2),
	mustFingerprint(user2FASetRetireSQL):       paramAt(2),
	mustFingerprint(recoveryCodeSetUpsertSQL):  paramAt(0),
	mustFingerprint(recoveryCodesSupersedeSQL): paramAt(2),
	mustFingerprint(recoveryCodeUpsertSQL):     paramAt(0),
}

func paramAt(i int) func(p []interface{}) string {
	return func(p []interface{}) string {
		if len(p) <= i {
			return ""
		}
		return coerceString(p[i])
	}
}

// roleBindingAccount is the local account a role binding insert binds:
// principal "user:U" or "user:U@local", as a delete revokes them. Any other
// principal (a group, a directory realm) is left unguarded.
func roleBindingAccount(p []interface{}) string {
	if len(p) != 6 {
		return ""
	}
	principal := coerceString(p[3])
	if !strings.HasPrefix(principal, "user:") {
		return ""
	}
	user := strings.TrimPrefix(principal, "user:")
	if local := strings.TrimSuffix(user, "@local"); local != user {
		return local
	}
	if strings.Contains(user, "@") {
		return ""
	}
	return user
}

// userStampedShapes are the userGuardedShapes a local write stamps: the
// writes that GRANT the account something, or lift a restriction on it. A
// restriction (a disable, a cut-off, a cleared binding, a voided code) is left
// unguarded, so it reaches whatever account holds the name — fail-closed —
// and a new account's restriction that reaches a node ahead of its re-create
// still lands there (retireOlderIncarnationRows keeps it). A delete's cascade
// carries its own guard (DeleteUserCounted).
var userStampedShapes = map[string]bool{
	mustFingerprint(usersUpdatePasswordSQL):   true,
	mustFingerprint(userCredentialUpsertSQL):  true,
	mustFingerprint(tokensInsertSQL):          true,
	mustFingerprint(sessionsInsertSQL):        true,
	mustFingerprint(identityBindingUpsertSQL): true,
	mustFingerprint(enrollmentCodeUpsertSQL):  true,
	mustFingerprint(roleBindingInsertSQL):     true,
	mustFingerprint(user2FASetUpsertSQL):      true,
	mustFingerprint(user2FAUpsertSQL):         true,
	mustFingerprint(user2FATombstoneSQL):      true,
	mustFingerprint(user2FASetRetireSQL):      true,
	mustFingerprint(`UPDATE user_2fa SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`):           true,
	mustFingerprint(`UPDATE user_2fa_sets SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`):      true,
	mustFingerprint(`UPDATE recovery_codes SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`):     true,
	mustFingerprint(`UPDATE recovery_code_sets SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`): true,
	mustFingerprint(recoveryCodeSetUpsertSQL):  true,
	mustFingerprint(recoveryCodesSupersedeSQL): true,
	mustFingerprint(recoveryCodeUpsertSQL):     true,
	mustFingerprint(userLifecycleUpsertSQL):    true, // a lift only (lifecycleLift)
}

var fpUserLifecycleUpsert = mustFingerprint(userLifecycleUpsertSQL)

// lifecycleLift reports whether a user_lifecycle upsert lifts a restriction:
// an enable, or any expiry change (an extension, or none). A disable and a
// session or token cut-off restrict.
func lifecycleLift(p []interface{}) bool {
	if len(p) < 3 {
		return false
	}
	switch coerceString(p[1]) {
	case UserAttrDisabled:
		return coerceString(p[2]) != "true"
	case UserAttrExpiresAt:
		return true
	}
	return false
}

// userStatementAccount is the account s names when a local write stamps it
// (userStampedShapes), or "".
func userStatementAccount(s Statement) string {
	if !strings.Contains(s.SQL, "user") && !strings.Contains(s.SQL, "recovery_code") &&
		!strings.Contains(s.SQL, "tokens") && !strings.Contains(s.SQL, "sessions") && !strings.Contains(s.SQL, "role_bindings") {
		return ""
	}
	sh, _, err := parseResolved(s.SQL)
	if err != nil {
		return ""
	}
	fp := stmtFingerprint(sh)
	if !userStampedShapes[fp] || fp == fpUserLifecycleUpsert && !lifecycleLift(s.Params) {
		return ""
	}
	return userGuardedShapes[fp](s.Params)
}

// userStampPlan decides whether a local write's unguarded user-keyed
// statements are stamped (stampUserIncarnation): only once the gate is on,
// and only when every user-keyed statement of the entry names ONE account and
// nothing in it carries another protocol's guard — a receiver refuses an entry
// that mixes them (validateUserIncarnationEntry), and a write that names two
// accounts (clearing several accounts' directory bindings) keeps the previous
// release's form.
func (c *Client) userStampPlan(stmts []Statement) bool {
	if !c.UserIncarnationOn() {
		return false
	}
	account, unguarded := "", false
	for _, s := range stmts {
		u := ""
		if s.Guard != nil {
			if s.Guard.Protocol != userIncarnationGuardV1 {
				return false
			}
			u = s.Guard.ResourceID
		} else if u = userStatementAccount(s); u == "" {
			continue
		} else {
			unguarded = true
		}
		if account != "" && u != account {
			return false
		}
		account = u
	}
	return unguarded
}

// stampUserIncarnation sets, on an unguarded user-keyed statement of a write
// userStampPlan admitted, the guard for the account's incarnation as the
// users row stands just before the statement runs (live or deleted). A name
// with no row here is left unguarded.
func stampUserIncarnation(ctx context.Context, tx *sql.Tx, s *Statement) error {
	if s.Guard != nil {
		return nil
	}
	user := userStatementAccount(*s)
	if user == "" {
		return nil
	}
	var created string
	var deleted sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT created_at, deleted_at FROM users WHERE username = ?`, user).Scan(&created, &deleted)
	if errors.Is(err, sql.ErrNoRows) || err == nil && created == "" {
		return nil
	}
	if err != nil {
		return err
	}
	kind := userGuardLive
	if deleted.Valid && deleted.String != "" {
		kind = userGuardDeleted
	}
	s.Guard = &MutationGuard{Protocol: userIncarnationGuardV1, ResourceKind: kind, ResourceID: user, Incarnation: created}
	return nil
}

// checkOwnUserGuard is the local write path's check of a statement's
// user_incarnation_v1 guard against the row as it stands in the write's own
// transaction: a guard that no longer matches here is ErrUserAccountChanged.
// Receivers skip such a statement, but this node would apply it, and its
// newer clock would then carry it to every node by anti-entropy.
func checkOwnUserGuard(ctx context.Context, tx *sql.Tx, s Statement) error {
	if s.Guard == nil || s.Guard.Protocol != userIncarnationGuardV1 {
		return nil
	}
	ok, err := userIncarnationGuardMatches(ctx, tx, s.Guard)
	if err != nil {
		return err
	}
	if !ok {
		return ErrUserAccountChanged
	}
	return nil
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
		if g.ResourceID == "" || g.Incarnation == "" || !validUserGuardKind(g.ResourceKind) {
			return invalidf("invalid user incarnation guard")
		}
		sh, _, err := parseResolved(s.SQL)
		if err != nil {
			return err
		}
		binds, ok := userGuardedShapes[stmtFingerprint(sh)]
		if !ok || binds(s.Params) != g.ResourceID {
			return invalidf("user incarnation guard on a statement it does not bind (table %s)", sh.Table)
		}
	}
	return nil
}

// retireOlderIncarnationRows drops, on this node only, the rows under the
// name an older incarnation left here that could keep the new account's own
// writes from landing (applyUserIncarnation). It never drops a row whose loss
// could GRANT access: a row the new account's writes put here first, from
// another origin ahead of the re-create, is indistinguishable from an older
// incarnation's, so only the side whose loss is fail-closed goes:
//
//   - a row that grants (a credential, a recovery code or its active set, an
//     enrollment code, a directory binding, a role binding — bindings are
//     union-only, so losing one never widens access — an API token, a
//     session) goes only while LIVE.
//     Its tombstone stays: dropped, an older live row of the same key could
//     land under it and grant again (a consumed code, an unbound identity);
//   - a row that restricts (a second factor or its active set, a lifecycle
//     attribute: disabled, expiry, session and token cut-offs) goes only as a
//     TOMBSTONE. A live one stays: dropped, a disabled account would read as
//     enabled, or a factor would stop being asked for, until anti-entropy
//     brought it back.
//
// What this costs is fail-closed: an older incarnation's live restriction (a
// lagging delete's cut-off) or tombstoned grant of the same key (its cleared
// directory binding, its consumed enrollment code) can still reach the new
// account, which then logs in again, binds again or is issued a new code.
//
// It runs wherever this node takes a newer incarnation in place of an older
// one: a WAL re-create (applyUserIncarnation) and an anti-entropy merge
// (userIncarnationDecision, mergeAuthorityApplyIncomingAndRetire).
// Each statement is on one line for the hard-delete tripwire
// (hard_delete_guard_test.go).
func retireOlderIncarnationRows(ctx context.Context, tx *sql.Tx, username, incarnation string) error {
	for _, q := range []string{
		// Grants: live rows only.
		`DELETE FROM user_credentials WHERE username = ? AND deleted_at IS NULL -- full-state-delete-ok: an older incarnation's live grant, replaced by a re-create`,
		`DELETE FROM recovery_codes WHERE username = ? AND deleted_at IS NULL -- full-state-delete-ok: an older incarnation's live grant, replaced by a re-create`,
		`DELETE FROM recovery_code_sets WHERE username = ? AND deleted_at IS NULL -- full-state-delete-ok: an older incarnation's live grant, replaced by a re-create`,
		`DELETE FROM user_enrollment_codes WHERE username = ? AND deleted_at IS NULL -- full-state-delete-ok: an older incarnation's live grant, replaced by a re-create`,
		`DELETE FROM user_identity_bindings WHERE username = ? AND deleted_at IS NULL -- full-state-delete-ok: an older incarnation's live grant, replaced by a re-create`,
		`DELETE FROM tokens WHERE username = ? AND deleted_at IS NULL -- full-state-delete-ok: an older incarnation's live grant, replaced by a re-create`,
		`DELETE FROM sessions WHERE username = ? AND revoked_at IS NULL -- full-state-delete-ok: an older incarnation's live grant, replaced by a re-create`,
		// Restrictions: tombstones only.
		`DELETE FROM user_2fa WHERE username = ? AND deleted_at IS NOT NULL -- full-state-delete-ok: an older incarnation's lifted restriction, replaced by a re-create`,
		`DELETE FROM user_2fa_sets WHERE username = ? AND deleted_at IS NOT NULL -- full-state-delete-ok: an older incarnation's lifted restriction, replaced by a re-create`,
		`DELETE FROM user_lifecycle WHERE username = ? AND deleted_at IS NOT NULL -- full-state-delete-ok: an older incarnation's lifted restriction, replaced by a re-create`,
	} {
		if _, err := tx.ExecContext(ctx, q, username); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM role_bindings WHERE principal IN (?, ?) AND deleted_at IS NULL -- full-state-delete-ok: an older incarnation's live grant, replaced by a re-create`,
		"user:"+username, "user:"+username+"@local"); err != nil {
		return err
	}
	return retireLaggingLifts(ctx, tx, username, incarnation)
}

// retireLaggingLifts drops the live rows under the name that LIFT a
// restriction (an enable, an expiry change, a second factor or its active
// set) and were written after the new incarnation was made. The new
// account's own such writes are bound to it (userStampedShapes), so none can
// be here before its re-create: a row like that is a lagging node's write to
// the deleted account, whose later clock would otherwise beat the new
// account's own restriction (a disable, an earlier expiry, its factor) here,
// and then on every node by anti-entropy. One written before the re-create
// stays: the new account's own writes come after it and win by clock.
func retireLaggingLifts(ctx context.Context, tx *sql.Tx, username, incarnation string) error {
	if incarnation == "" {
		return nil
	}
	type lift struct{ table, key, ts string }
	var lifts []lift
	for _, q := range []struct{ table, sql string }{
		{"user_lifecycle", `SELECT attribute, updated_at FROM user_lifecycle WHERE username = ? AND deleted_at IS NULL AND (attribute = 'disabled' AND value <> 'true' OR attribute = 'expires_at')`},
		{"user_2fa", `SELECT method || char(31) || COALESCE(label, ''), updated_at FROM user_2fa WHERE username = ? AND deleted_at IS NULL`},
		{"user_2fa_sets", `SELECT '', updated_at FROM user_2fa_sets WHERE username = ? AND deleted_at IS NULL`},
	} {
		rows, err := tx.QueryContext(ctx, q.sql, username)
		if err != nil {
			return err
		}
		for rows.Next() {
			var key, ts string
			if err := rows.Scan(&key, &ts); err != nil {
				rows.Close()
				return err
			}
			if lwwOrder(incarnation, ts) < 0 {
				lifts = append(lifts, lift{q.table, key, ts})
			}
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	for _, l := range lifts {
		var err error
		switch l.table {
		case "user_lifecycle":
			_, err = tx.ExecContext(ctx, `DELETE FROM user_lifecycle WHERE username = ? AND attribute = ? AND updated_at = ? -- full-state-delete-ok: a deleted account's lagging lift, replaced by a re-create`, username, l.key, l.ts)
		case "user_2fa":
			_, err = tx.ExecContext(ctx, `DELETE FROM user_2fa WHERE username = ? AND method || char(31) || COALESCE(label, '') = ? AND updated_at = ? -- full-state-delete-ok: a deleted account's lagging lift, replaced by a re-create`, username, l.key, l.ts)
		case "user_2fa_sets":
			_, err = tx.ExecContext(ctx, `DELETE FROM user_2fa_sets WHERE username = ? AND updated_at = ? -- full-state-delete-ok: a deleted account's lagging lift, replaced by a re-create`, username, l.ts)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// userKeyedTables are the public tables whose rows name an account by
// username alone (role_bindings by its principal). An anti-entropy row from a
// sender holding an older incarnation of the name than this node is that
// account's, not this node's, and is refused (userKeyedRowDecision). The
// sender's incarnation is in the same payload's users rows (the manifest).
var userKeyedTables = map[string]bool{
	"user_lifecycle": true, "user_enrollment_codes": true, "user_identity_bindings": true, "role_bindings": true,
	"tokens": true,
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
