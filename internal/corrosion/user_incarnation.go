package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/hlc"
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
	return incarnationAfterAll(time.Now().UTC(), prev)
}

// newIncarnation is nextIncarnation floored at this node's hybrid clock too,
// which has seen every write that reached it: a create on a node whose wall
// clock runs behind a peer's still orders after any incarnation of the name
// this node could have heard of. prev is "" for a first create.
func (c *Client) newIncarnation(prev string) string {
	now := time.Now().UTC()
	if t, ok := tsInstant(c.NowTS()); ok && t.After(now) {
		now = t.UTC()
	}
	return incarnationAfterAll(now, prev)
}

func incarnationAfterAll(now time.Time, prev string) string {
	if p, err := time.Parse(time.RFC3339Nano, prev); err == nil && !now.After(p) {
		now = p.Add(time.Nanosecond)
	}
	// Never a whole second: a fractional second is what marks an incarnation
	// made after the latch (latchedIncarnation, token_incarnation.go).
	if now.Nanosecond() == 0 {
		now = now.Add(time.Nanosecond)
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
	// userGuardTighten binds a write that TIGHTENS the account (a second
	// factor or its active set, a disable, an earlier expiry, a later
	// cut-off). It applies wherever the name does not hold a newer
	// incarnation, ahead of its own included, and is never dropped for the
	// one it names (user_holds.go).
	userGuardTighten = "user_tighten"
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
	return k == userGuardLive || k == userGuardDeleted || k == userGuardAny || k == userGuardTighten
}

// userIncarnationGuardMatches: the receiver applies the guarded statement
// now — its users row is the guard's incarnation (live, or deleted, as the
// kind requires), or the statement tightens and the guard is not behind it
// (userGuardVerdictOf, user_holds.go).
func (c *Client) userIncarnationGuardMatches(ctx context.Context, tx *sql.Tx, g *MutationGuard) (bool, error) {
	v, err := c.userGuardVerdictOf(ctx, tx, g)
	if err != nil {
		return false, err
	}
	return v == userVerdictApply || v == userVerdictAhead && g.ResourceKind == userGuardTighten, nil
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
	mustFingerprint(tokensInsertSQL):            paramAt(1),
	mustFingerprint(tokensInsertIncarnationSQL): paramAt(1),
	mustFingerprint(sessionsInsertSQL):          paramAt(1),
	mustFingerprint(identityBindingUpsertSQL):   paramAt(0),
	mustFingerprint(enrollmentCodeUpsertSQL):    paramAt(0),
	mustFingerprint(roleBindingInsertSQL):       roleBindingAccount,
	mustFingerprint(user2FASetUpsertSQL):        paramAt(0),
	mustFingerprint(user2FAUpsertSQL):           paramAt(0),
	mustFingerprint(user2FATombstoneSQL):        paramAt(2),
	mustFingerprint(user2FASetRetireSQL):        paramAt(2),
	mustFingerprint(recoveryCodeSetUpsertSQL):   paramAt(0),
	mustFingerprint(recoveryCodesSupersedeSQL):  paramAt(2),
	mustFingerprint(recoveryCodeUpsertSQL):      paramAt(0),
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
	mustFingerprint(usersUpdatePasswordSQL):     true,
	mustFingerprint(userCredentialUpsertSQL):    true,
	mustFingerprint(tokensInsertSQL):            true,
	mustFingerprint(tokensInsertIncarnationSQL): true,
	mustFingerprint(sessionsInsertSQL):          true,
	mustFingerprint(identityBindingUpsertSQL):   true,
	mustFingerprint(enrollmentCodeUpsertSQL):    true,
	mustFingerprint(roleBindingInsertSQL):       true,
	mustFingerprint(user2FASetUpsertSQL):        true,
	mustFingerprint(user2FAUpsertSQL):           true,
	mustFingerprint(user2FATombstoneSQL):        true,
	mustFingerprint(user2FASetRetireSQL):        true,
	mustFingerprint(`UPDATE user_2fa SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`):           true,
	mustFingerprint(`UPDATE user_2fa_sets SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`):      true,
	mustFingerprint(`UPDATE recovery_codes SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`):     true,
	mustFingerprint(`UPDATE recovery_code_sets SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`): true,
	mustFingerprint(recoveryCodeSetUpsertSQL):  true,
	mustFingerprint(recoveryCodesSupersedeSQL): true,
	mustFingerprint(recoveryCodeUpsertSQL):     true,
	mustFingerprint(userLifecycleUpsertSQL):    true,
}

// userTighteningShapes are the userStampedShapes that only ever tighten:
// enrolling a second factor, and the active set it is enrolled under. A
// user_lifecycle write is judged by its value (lifecycleTightens).
var userTighteningShapes = map[string]bool{
	mustFingerprint(user2FASetUpsertSQL): true,
	mustFingerprint(user2FAUpsertSQL):    true,
}

var fpUserLifecycleUpsert = mustFingerprint(userLifecycleUpsertSQL)

// noAccessBindingInsert reports whether a statement of shape fp inserts a
// NoAccess binding. It grants nothing; it only keeps its principal bound, so
// it never falls back to its legacy role. That tightens the account, so a
// project delete that leaves one for each of several accounts in one entry
// is not a multi-account grant (ErrUserMultiAccountGrant).
func noAccessBindingInsert(fp string, p []interface{}) bool {
	return fp == fpRoleBindingInsert && len(p) == 6 && coerceString(p[2]) == SentinelRole
}

// lifecycleTightens reports whether a user_lifecycle upsert tightens the
// account against the value this node holds (cur, "" for none): a disable, an
// expiry set or brought earlier, a cut-off moved later (an unchanged value
// loosens nothing, and counts as tightening). An enable, an expiry cleared or
// extended and a cut-off set back loosen it.
func lifecycleTightens(p []interface{}, cur string) bool {
	if len(p) < 3 {
		return false
	}
	val := coerceString(p[2])
	switch coerceString(p[1]) {
	case UserAttrDisabled:
		return val == "true"
	case UserAttrExpiresAt:
		if val == "" {
			return false
		}
		if cur == "" {
			return true
		}
		return lwwOrder(cur, val) >= 0
	case UserAttrSessionsNotBefore, UserAttrTokensNotBefore:
		return cur == "" || lwwOrder(cur, val) <= 0
	}
	return true
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
	if !userStampedShapes[fp] {
		return ""
	}
	return userGuardedShapes[fp](s.Params)
}

// userStampPlan decides whether a local write's unguarded user-keyed
// statements are stamped (stampUserIncarnation): only once the gate is on,
// and only when every user-keyed statement of the entry names ONE account and
// nothing in it carries another protocol's guard, because a receiver refuses
// an entry that mixes them (validateUserIncarnationEntry). A write that names
// two accounts stays unstamped only if all it does is tighten (clearing
// several accounts' directory bindings, with their cut-offs): a grant or lift
// left unguarded would reach a re-created account, so such a write is
// refused (ErrUserMultiAccountGrant) rather than sent.
func (c *Client) userStampPlan(stmts []Statement) (bool, error) {
	if !c.UserIncarnationOn() {
		return false, nil
	}
	account, unguarded, mixed, loosens := "", false, false, false
	for _, s := range stmts {
		u := ""
		if s.Guard != nil {
			if s.Guard.Protocol != userIncarnationGuardV1 {
				return false, nil
			}
			u = s.Guard.ResourceID
		} else if u = userStatementAccount(s); u == "" {
			continue
		} else {
			unguarded = true
			if !statementOnlyTightens(s) {
				loosens = true
			}
		}
		if account != "" && u != account {
			mixed = true
		}
		account = u
	}
	if mixed {
		if loosens {
			return false, ErrUserMultiAccountGrant
		}
		return false, nil
	}
	return unguarded, nil
}

// ErrUserMultiAccountGrant refuses a local write that grants, or lifts a
// restriction on, more than one account in one entry: its statements could
// not each be bound to their account's incarnation.
var ErrUserMultiAccountGrant = errors.New("a write that grants or loosens more than one account in one entry cannot be bound to their incarnations")

// statementOnlyTightens reports, without reading any row, whether s can only
// tighten: a factor enrolment, or a lifecycle write that is a disable or a
// cut-off (judged against no current value; an expiry change may loosen).
func statementOnlyTightens(s Statement) bool {
	sh, _, err := parseResolved(s.SQL)
	if err != nil {
		return false
	}
	fp := stmtFingerprint(sh)
	if userTighteningShapes[fp] || noAccessBindingInsert(fp, s.Params) {
		return true
	}
	if fp == fpUserLifecycleUpsert && len(s.Params) >= 3 {
		switch coerceString(s.Params[1]) {
		case UserAttrDisabled:
			return coerceString(s.Params[2]) == "true"
		case UserAttrSessionsNotBefore, UserAttrTokensNotBefore:
			return true
		}
	}
	return false
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
	tightens, err := statementTightensHere(ctx, tx, *s)
	if err != nil {
		return err
	}
	if tightens {
		kind = userGuardTighten
	}
	s.Guard = &MutationGuard{Protocol: userIncarnationGuardV1, ResourceKind: kind, ResourceID: user, Incarnation: created}
	return nil
}

// statementTightensHere reports whether s tightens its account against the
// row this node holds (userGuardTighten).
func statementTightensHere(ctx context.Context, tx *sql.Tx, s Statement) (bool, error) {
	sh, _, err := parseResolved(s.SQL)
	if err != nil {
		return false, nil
	}
	fp := stmtFingerprint(sh)
	if userTighteningShapes[fp] || noAccessBindingInsert(fp, s.Params) {
		return true, nil
	}
	if fp != fpUserLifecycleUpsert || len(s.Params) < 3 {
		return false, nil
	}
	var cur string
	err = tx.QueryRowContext(ctx, `SELECT value FROM user_lifecycle WHERE username = ? AND attribute = ? AND deleted_at IS NULL`,
		coerceString(s.Params[0]), coerceString(s.Params[1])).Scan(&cur)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	return lifecycleTightens(s.Params, cur), nil
}

// checkOwnUserGuard is the local write path's check of a statement's
// user_incarnation_v1 guard against the row as it stands in the write's own
// transaction: a guard that no longer matches here is ErrUserAccountChanged.
// Receivers skip such a statement, but this node would apply it, and its
// newer clock would then carry it to every node by anti-entropy.
//
// The writer holds the account it writes, so anything but "apply" means the
// name moved: deleted or re-created here, or — known from a write for a newer
// incarnation that reached this node first — re-created elsewhere. A write
// to an account that is gone is refused rather than overwrite what the new
// account's write put here first.
func (c *Client) checkOwnUserGuard(ctx context.Context, tx *sql.Tx, s Statement) error {
	if s.Guard == nil || s.Guard.Protocol != userIncarnationGuardV1 {
		return nil
	}
	v, err := c.userGuardVerdictOf(ctx, tx, s.Guard)
	if err != nil {
		return err
	}
	if v != userVerdictApply || c.userHolds.newerKnown(s.Guard.ResourceID, s.Guard.Incarnation) {
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
		} else if g.ResourceID != base.ResourceID || g.Incarnation != base.Incarnation {
			// One account, one incarnation; each statement's kind is its own.
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
//     session) goes only while LIVE. An API token stamped with the new
//     incarnation is the new account's own, and stays.
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
	// A token says which incarnation it was issued to (token_incarnation.go):
	// one stamped with the new incarnation is the new account's own, heard
	// before its re-create, and stays. An unstamped one goes, as every token
	// did before.
	for _, q := range []string{
		`DELETE FROM token_credentials WHERE token_id IN (SELECT id FROM tokens WHERE username = ? AND deleted_at IS NULL AND user_created_at IS NOT ?) -- full-state-delete-ok: an older incarnation's live grant, replaced by a re-create`,
		`DELETE FROM tokens WHERE username = ? AND deleted_at IS NULL AND user_created_at IS NOT ? -- full-state-delete-ok: an older incarnation's live grant, replaced by a re-create`,
	} {
		if _, err := tx.ExecContext(ctx, q, username, incarnation); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM role_bindings WHERE principal IN (?, ?) AND deleted_at IS NULL -- full-state-delete-ok: an older incarnation's live grant, replaced by a re-create`,
		"user:"+username, "user:"+username+"@local"); err != nil {
		return err
	}
	return retireLaggingLifts(ctx, tx, username, incarnation, true)
}

// retireLaggingLifts drops, durably, what a deleted account's lagging writes
// left under the name once this node holds the newer incarnation inc. It
// runs only when the name's incarnation changes here (a re-create, or the
// name's first row: settleUserName, retireOlderIncarnationRows), never on an
// ordinary write to the users row. It reads only the rows themselves, so a
// restart or a long partition does not change its answer:
//
//   - a second factor or its active set whose epoch is tagged with an older
//     incarnation (userEpochTag): a lagging re-enrolment of the deleted
//     account. The new account's own factor carries its own incarnation, so
//     one that reached this node first — over the WAL or the sensitive lane —
//     is kept. An untagged epoch (written before the latch, or by a node
//     that had not latched) is never dropped: a clock cannot tell it from
//     the account's own, and dropping a live factor would leave a
//     password-only login. When hold is set — this node held an OLDER
//     incarnation of the name, not merely no row — an untagged active set is
//     held instead (holdUntaggedFactorSet): kept, never accepted, and the
//     account fails closed until an admin removes it;
//   - an enable or an expiry change tagged as written to an older incarnation
//     while it was live, after inc was made (userLifecycleTag): a lagging
//     lift, whose later clock would beat the new account's own disable or
//     expiry. One written before inc stays: it is the state a deleted account
//     hands on (DeleteUser keeps the lifecycle; t1-auth-review m3), and the
//     new account's own writes come after it. A row written to the deleted
//     name (a re-create's reset) is the successor's, and stays;
//   - an untagged enable or no-expiry written after inc, which reads as no
//     restriction at all (the fallback for a row from before the latch).
//
// A restriction — a disable, a cut-off — is never dropped here: whoever it
// was written for, losing it would loosen the account.
func retireLaggingLifts(ctx context.Context, tx *sql.Tx, username, inc string, hold bool) error {
	if inc == "" {
		return nil
	}
	if hold {
		if err := holdUntaggedFactorSet(ctx, tx, username); err != nil {
			return err
		}
	}
	after := func(ts string) bool { return lwwOrder(inc, ts) < 0 }
	older := func(tag string) bool { return tag != inc && !incarnationAfter(tag, inc) }
	type row struct{ a, b, c, ts string }
	collect := func(q string, keep func(r row) bool) ([]row, error) {
		rows, err := tx.QueryContext(ctx, q, username)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.a, &r.b, &r.c, &r.ts); err != nil {
				return nil, err
			}
			if !keep(r) {
				out = append(out, r)
			}
		}
		return out, rows.Err()
	}
	epochKeeps := func(epoch string) bool {
		if _, held := heldEpochBase(epoch); held {
			return true
		}
		tag, ok := userEpochTag(epoch)
		return !ok || !older(tag)
	}
	factors, err := collect(`SELECT method, COALESCE(label, ''), epoch, updated_at FROM user_2fa WHERE username = ? AND deleted_at IS NULL`,
		func(r row) bool { return epochKeeps(r.c) })
	if err != nil {
		return err
	}
	sets, err := collect(`SELECT '', '', active_epoch, updated_at FROM user_2fa_sets WHERE username = ? AND deleted_at IS NULL`,
		func(r row) bool { return epochKeeps(r.c) })
	if err != nil {
		return err
	}
	lifts, err := collect(`SELECT attribute, value, set_by, updated_at FROM user_lifecycle WHERE username = ? AND deleted_at IS NULL AND (attribute = 'disabled' AND value <> 'true' OR attribute = 'expires_at')`,
		func(r row) bool {
			if !after(r.ts) {
				return true
			}
			if kind, tag, ok := userLifecycleTag(r.c); ok {
				return kind != userTagLive || !older(tag)
			}
			// Untagged: only a lift that reads as no restriction at all.
			return !(r.a == UserAttrDisabled || r.b == "")
		})
	if err != nil {
		return err
	}
	for _, r := range factors {
		if _, err := tx.ExecContext(ctx, `DELETE FROM user_2fa WHERE username = ? AND method = ? AND COALESCE(label, '') = ? AND updated_at = ? -- full-state-delete-ok: a deleted account's lagging factor, replaced by a re-create`, username, r.a, r.b, r.ts); err != nil {
			return err
		}
	}
	for _, r := range sets {
		if _, err := tx.ExecContext(ctx, `DELETE FROM user_2fa_sets WHERE username = ? AND updated_at = ? -- full-state-delete-ok: a deleted account's lagging factor set, replaced by a re-create`, username, r.ts); err != nil {
			return err
		}
	}
	for _, r := range lifts {
		if _, err := tx.ExecContext(ctx, `DELETE FROM user_lifecycle WHERE username = ? AND attribute = ? AND updated_at = ? -- full-state-delete-ok: a deleted account's lagging lift, replaced by a re-create`, username, r.a, r.ts); err != nil {
			return err
		}
	}
	return nil
}

// A second factor's epoch, and a lifecycle row's set_by, carry the
// incarnation they were written for once user_incarnation_v1 has latched. It
// rides in values every build already stores and only ever compares for
// equality (the epoch) or never reads (set_by), so it needs no new column and
// no new statement shape, and survives a restart and anti-entropy with the
// row (retireLaggingLifts).
const (
	userEpochTagSep     = "~"
	userLifecycleTagSep = "\x1f"
	userTagLive         = "inc"
	userTagDeleted      = "after"
)

// userEpochTag is the incarnation an epoch was minted for, if it carries one.
func userEpochTag(epoch string) (string, bool) {
	_, tag, ok := strings.Cut(epoch, userEpochTagSep)
	return tag, ok && tag != ""
}

// userEpochHeldSuffix marks a factor set as held: its active_epoch is the
// untagged epoch of its factors with this suffix, so no factor joins the
// active set (ListUser2FA, VerifyTOTP, WebAuthn), and none is deleted.
const userEpochHeldSuffix = userEpochTagSep + "held"

// heldEpochBase is the epoch of the factors a held set holds.
func heldEpochBase(epoch string) (string, bool) {
	base, ok := strings.CutSuffix(epoch, userEpochHeldSuffix)
	return base, ok && base != "" && !strings.Contains(base, userEpochTagSep)
}

// holdUntaggedFactorSet holds, on this node, the name's live factor set when
// its epoch carries no incarnation and this node has just replaced an older
// incarnation of the name with a newer one. Such a set may be the deleted
// account's, enrolled by a node that had not latched user_incarnation_v1, and
// a clock cannot tell it from the new account's own: dropped, a legitimate
// factor goes (a password-only login); left active, the deleted holder's
// device passes the new account's second factor. Held, it is kept, never
// accepted, and the account counts as having a second factor, so it fails
// closed (HeldUser2FA, the held_second_factor condition).
//
// The hold is this node's own write, stamped just after the set it holds, so
// anti-entropy carries it over that same set everywhere, while a set written
// later — the new account's own enrolment — still wins over it.
func holdUntaggedFactorSet(ctx context.Context, tx *sql.Tx, username string) error {
	var epoch, ts string
	err := tx.QueryRowContext(ctx, `SELECT active_epoch, updated_at FROM user_2fa_sets WHERE username = ? AND deleted_at IS NULL`, username).Scan(&epoch, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if epoch == "" || strings.Contains(epoch, userEpochTagSep) {
		return nil // tagged, or held already
	}
	at, ok := justAfterTS(ts)
	if !ok {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_2fa_sets SET active_epoch = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL AND active_epoch = ?`,
		epoch+userEpochHeldSuffix, at, username, epoch); err != nil {
		return err
	}
	var held []User2FARecord
	rows, err := tx.QueryContext(ctx, `SELECT method, COALESCE(label, '') FROM user_2fa WHERE username = ? AND deleted_at IS NULL AND epoch = ?`, username, epoch)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var f User2FARecord
		if err := rows.Scan(&f.Method, &f.Label); err != nil {
			return err
		}
		held = append(held, f)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	slog.Warn("held the second factors of an account re-created under the same name: they may be the deleted account's, "+
		"and none is accepted until an admin removes them",
		"user", username, "recovery", HeldSecondFactorRecovery(username, held))
	return nil
}

// HeldSecondFactorRecovery is what an admin runs for an account whose second
// factors are held: a disable of each, by its own method and label, then an
// enrollment code. With none given it names the form.
func HeldSecondFactorRecovery(username string, held []User2FARecord) string {
	if len(held) == 0 {
		return fmt.Sprintf("lv 2fa disable --user %s --method <method> --label <label> for each held factor "+
			"(lv 2fa ls --user %s lists them), then lv 2fa enroll-code %s", username, username, username)
	}
	disables := make([]string, 0, len(held))
	for _, f := range held {
		disables = append(disables, fmt.Sprintf("lv 2fa disable --user %s --method %s --label %s", username, f.Method, f.Label))
	}
	return strings.Join(disables, ", ") + ", then lv 2fa enroll-code " + username
}

// justAfterTS is the LWW key that orders immediately after ts: one logical
// tick for an HLC key, one nanosecond for an RFC3339 one.
func justAfterTS(ts string) (string, bool) {
	if t, ok := hlc.Parse(ts); ok {
		if t.Logical >= 9999 { // four digits on the wire
			t.PhysicalMS++
			t.Logical = 0
		} else {
			t.Logical++
		}
		return t.String(), true
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return "", false
	}
	return t.Add(time.Nanosecond).UTC().Format(time.RFC3339Nano), true
}

// userLifecycleTag is how a lifecycle row was written: to the incarnation
// while it was live (userTagLive), or to it deleted (userTagDeleted, as a
// re-create's reset is), if its set_by carries one.
func userLifecycleTag(setBy string) (kind, inc string, ok bool) {
	i := strings.LastIndex(setBy, userLifecycleTagSep)
	if i < 0 {
		return "", "", false
	}
	kind, inc, ok = strings.Cut(setBy[i+len(userLifecycleTagSep):], ":")
	return kind, inc, ok && inc != "" && (kind == userTagLive || kind == userTagDeleted)
}

// tagUserLifecycle tags, on the local write path, a lifecycle upsert's
// set_by with the account's incarnation as its users row stands just before
// the statement runs (userLifecycleTag). A name with no row is left as it is.
func tagUserLifecycle(ctx context.Context, tx *sql.Tx, s *Statement) error {
	if len(s.Params) < 5 || !strings.Contains(s.SQL, "user_lifecycle") {
		return nil
	}
	sh, _, err := parseResolved(s.SQL)
	if err != nil || stmtFingerprint(sh) != fpUserLifecycleUpsert {
		return nil
	}
	setBy := coerceString(s.Params[3])
	var created string
	var deleted sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT created_at, deleted_at FROM users WHERE username = ?`, coerceString(s.Params[0])).Scan(&created, &deleted)
	if errors.Is(err, sql.ErrNoRows) || err == nil && created == "" {
		return nil
	}
	if err != nil {
		return err
	}
	kind := userTagLive
	if deleted.Valid && deleted.String != "" {
		kind = userTagDeleted
	}
	tag := userLifecycleTagSep + kind + ":" + created
	if strings.HasSuffix(setBy, tag) && strings.Count(setBy, userLifecycleTagSep) == 1 {
		return nil // tagged already, as this write would be (a retried statement)
	}
	// The tag is this node's alone: whatever set_by carried that looks like
	// one does not decide how the row is judged (retireLaggingLifts).
	params := append([]interface{}(nil), s.Params...)
	params[3] = strings.ReplaceAll(setBy, userLifecycleTagSep, "") + tag
	s.Params = params
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
