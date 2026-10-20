package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// An API token belongs to one account incarnation (users-L2).
//
// user_incarnation_v1 binds the WAL writes that grant an account something to
// its incarnation, the users row's created_at. A token row that reached a
// node some other way was still judged by the users row alone: a node that
// had not latched took a deleted account's token by plain anti-entropy, or
// applied an unguarded insert from a writer that had not latched, and once
// it latched served that token as the re-created account's.
//
// tokens.user_created_at (schemaVersionTokenUserIncarnation) names the
// incarnation the token was issued to, so the row itself says whose it is,
// and every node judges it the same way whatever its own latch says:
//
//   - authentication (ValidateToken, TokenLive) opens a token only while its
//     account holds that incarnation (tokenIncarnationHolds);
//   - the WAL skips, with its credential, a token insert for an incarnation
//     the name has left (staleTokenInsert), anti-entropy does not take such
//     a row (tokenRowDecision), and a node whose users row takes a new
//     incarnation drops the live tokens that do not hold for it
//     (retireStaleTokens).
//
// An unstamped token ("") was issued by a writer that could not stamp it: a
// previous release, or this build before user_incarnation_v1 latched, for an
// account made before the latch. It holds only while the account's
// incarnation is one made before the latch (latchedIncarnation false). That
// keeps every existing account's tokens working across the roll, and an
// account re-created after the latch never takes one: a writer stamps every
// token of an account a latched writer made, latched or not.
//
// No capability token of its own: the guarantee is enforced where a token is
// USED, on the serving node, from the row alone. The writer emits the
// stamped insert only where every receiver decodes it: once it has latched
// user_incarnation_v1 (mandatory, ReplicationGated, so every host it
// replicates to advertises it, which only builds with this column do), or for
// an account whose incarnation a latched writer made, which proves the same
// of the cluster.

// tokensInsertIncarnationSQL is InsertToken's insert with the incarnation;
// tokensInsertSQL is the previous release's.
const tokensInsertIncarnationSQL = `INSERT INTO tokens (id, username, name, token_hash, expires_at, scope_paths, created_at, updated_at, user_created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

var fpTokensInsertIncarnation = mustFingerprint(tokensInsertIncarnationSQL)

// latchedIncarnation reports whether created is an incarnation a writer that
// had latched user_incarnation_v1 made (newIncarnation): it always carries a
// fractional second (incarnationAfterAll), and no earlier writer of
// users.created_at ever wrote one (nowRFC3339, bare seconds).
func latchedIncarnation(created string) bool {
	t, err := time.Parse(time.RFC3339Nano, created)
	return err == nil && t.Nanosecond() != 0
}

// tokenIncarnationHolds reports whether a token stamped stamp ("" for none)
// may authenticate the account whose users row holds incarnation current.
func tokenIncarnationHolds(stamp, current string) bool {
	if current == "" {
		return false
	}
	if stamp != "" {
		return stamp == current
	}
	return !latchedIncarnation(current)
}

// tokenIncarnationStale reports whether a token stamped stamp was issued to
// an incarnation the name has LEFT for current: an older one, or, unstamped,
// any before a latched writer's. A token for an incarnation this node has
// not reached yet is not stale; it does not authenticate until it does.
func tokenIncarnationStale(stamp, current string) bool {
	if current == "" {
		return false
	}
	if stamp == "" {
		return latchedIncarnation(current)
	}
	return stamp != current && incarnationAfter(current, stamp)
}

// tokenStampFor is the incarnation a new token of username is stamped with,
// or "" for the previous release's insert (see the file comment).
func (c *Client) tokenStampFor(ctx context.Context, username string) (string, error) {
	rows, err := c.Query(ctx, `SELECT created_at FROM users WHERE username = ?`, username)
	if err != nil || len(rows) == 0 {
		return "", err
	}
	created := rows[0].String("created_at")
	if created != "" && (c.UserIncarnationOn() || latchedIncarnation(created)) {
		return created, nil
	}
	return "", nil
}

// staleTokenInsert reports whether s is a replicated token insert for an
// incarnation the name has left here. A name with no users row here is not
// judged: the row arrives later, and settles the token then.
func staleTokenInsert(ctx context.Context, tx *sql.Tx, s Statement) (bool, error) {
	if !strings.Contains(s.SQL, "INTO tokens") {
		return false, nil
	}
	sh, _, err := parseResolved(s.SQL)
	if err != nil {
		return false, nil
	}
	var stamp string
	switch stmtFingerprint(sh) {
	case fpTokensInsert:
		if len(s.Params) < 2 {
			return false, nil
		}
	case fpTokensInsertIncarnation:
		if len(s.Params) < 9 {
			return false, nil
		}
		stamp = coerceString(s.Params[8])
	default:
		return false, nil
	}
	current, err := userIncarnationHeld(ctx, tx, coerceString(s.Params[1]))
	if err != nil {
		return false, err
	}
	return tokenIncarnationStale(stamp, current), nil
}

// tokenRowDecision is anti-entropy's rule for a tokens row: a token for an
// incarnation the name has left here is not taken (this node never holds
// one live: retireStaleTokens).
func tokenRowDecision(tx *sql.Tx, table syncTable, row []interface{}) (mergeAuthorityDecision, error) {
	idx := columnIndexMap(table.Columns)
	var current string
	err := tx.QueryRow(`SELECT created_at FROM users WHERE username = ?`, cellStr(row, idx, "username")).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return mergeAuthorityNormal, nil
	}
	if err != nil {
		return mergeAuthorityKeepLocal, err
	}
	if tokenIncarnationStale(cellStr(row, idx, "user_created_at"), current) {
		return mergeAuthorityKeepLocal, nil
	}
	return mergeAuthorityNormal, nil
}

// retireStaleTokens drops, on this node only, the live tokens of name (and
// their credentials) that were issued to an incarnation the name has left:
// they could never authenticate again. It runs whenever the name's users row takes another incarnation
// here, latched or not (settleUserName). Each statement is on one line for
// the hard-delete tripwire (hard_delete_guard_test.go).
func retireStaleTokens(ctx context.Context, tx *sql.Tx, name, current string) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, user_created_at FROM tokens WHERE username = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return err
	}
	var stale []string
	for rows.Next() {
		var id, stamp string
		if err := rows.Scan(&id, &stamp); err != nil {
			rows.Close()
			return err
		}
		if tokenIncarnationStale(stamp, current) {
			stale = append(stale, id)
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range stale {
		if _, err := tx.ExecContext(ctx, `DELETE FROM token_credentials WHERE token_id = ? -- full-state-delete-ok: a live token of an incarnation the name has left`, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM tokens WHERE id = ? AND deleted_at IS NULL -- full-state-delete-ok: a live token of an incarnation the name has left`, id); err != nil {
			return err
		}
	}
	return nil
}
