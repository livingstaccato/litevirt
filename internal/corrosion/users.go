package corrosion

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// userWriteInterleaveHook is a test seam: it runs between an account write's
// read and its guarded batch (InsertUser's re-create, the admin floor), where
// a peer's write can replicate in. Nil in production.
var userWriteInterleaveHook func(username string)

// UserRecord represents a litevirt user.
type UserRecord struct {
	Username     string
	Role         string
	PasswordHash string
	// Realm names the authority this row belongs to. users is keyed on username
	// ALONE, so one name exists once across every realm — which makes this the
	// only thing that can tell a local account from an external one that happens
	// to share its name. A caller that shadows an external subject must consult
	// it; see auth.EnsureUserShadow.
	Realm     string
	CreatedAt string
	// ScopePaths is non-nil only when ValidateToken populates it from the
	// matched API token. Empty slice = no scoping (inherit user's full
	// perms). A scoped token may only operate on paths that are under one
	// of these prefixes.
	ScopePaths []string
	// TokenID is the matched API token's id, set only by ValidateToken, so an
	// open stream authenticated by it can be re-checked without a bcrypt sweep.
	TokenID string
	// TokenCreatedAt is the matched token's created_at (ValidateToken only),
	// checked against the account's tokens_not_before.
	TokenCreatedAt string
}

// TokenRecord represents an API token.
type TokenRecord struct {
	automationAuthentication *AutomationAccountAuthentication
	ID                       string
	Username                 string
	Name                     string
	TokenHash                string
	ExpiresAt                string
	CreatedAt                string
	ScopePaths               []string // empty/nil = no scoping
}

// usersReactivateSQL is InsertUser's reactivation shape, also reused by
// ReinstateAdminIfNoneRemain so that path adds no shape of its own.
const usersReactivateSQL = `UPDATE users SET role = ?, password_hash = ?, deleted_at = NULL, updated_at = ? WHERE username = ?`

// InsertUser creates a new user. If the username was previously soft-deleted,
// it reactivates the row with the new role and password.
//
// Once credentials_split_v1 has latched the hash is written to user_credentials
// as well, in the same batch and under the same updated_at; users.password_hash
// keeps it for a previous-release reader until credentials_clear_v1 latches,
// and is empty after (oldColumnValue; see credentials_split.go).
func InsertUser(ctx context.Context, c *Client, username, role, passwordHash string) error {
	now := c.NowTS()
	split := c.MayWriteCredentialTables()
	// Try reactivating a soft-deleted user first.
	rows, err := c.Query(ctx,
		`SELECT u.username, u.created_at, u.updated_at, k.updated_at AS cred_ts
		   FROM users u LEFT JOIN user_credentials k ON k.username = u.username
		  WHERE u.username = ? AND u.deleted_at IS NOT NULL`, username)
	if err == nil && len(rows) > 0 {
		// Whatever this node recorded about the name describes the row before
		// this write (re-review 3, R1).
		c.forgetExternalShadow(username)
		ts := now
		if passwordHash == "" {
			ts = shadowReactivationTS(rows[0].String("updated_at"), rows[0].String("cred_ts"), now)
		}
		// Once user_incarnation_v1 has latched the re-created account is a
		// new incarnation, which replaces the tombstone on every node
		// (user_incarnation.go).
		created := rows[0].String("created_at")
		prev := created
		oldColumn := passwordHash
		if split {
			oldColumn = c.oldColumnValue(passwordHash)
		}
		reactivate := Statement{SQL: usersReactivateSQL, Params: []interface{}{role, oldColumn, ts, username}}
		if c.UserIncarnationOn() {
			created = c.newIncarnation(created)
			reactivate = Statement{SQL: usersReactivateIncarnationSQL, Params: []interface{}{role, oldColumn, created, ts, username}}
		}
		// The re-create replaces the tombstone this node read, and nothing a
		// peer wrote under the name since: another account of the name that
		// replicated in between is left as it is, and the caller told to
		// retry. The credential is bound to the NEW incarnation once
		// user_incarnation_v1 has latched (stampUserIncarnation), so a
		// receiver that keeps this re-create off — it still holds the old
		// account live — takes none of it.
		still := func(tx *sql.Tx) (bool, error) {
			var cur string
			err := tx.QueryRowContext(ctx, `SELECT created_at FROM users WHERE username = ? AND deleted_at IS NOT NULL`, username).Scan(&cur)
			if errors.Is(err, sql.ErrNoRows) {
				return false, nil
			}
			return err == nil && cur == prev, err
		}
		if userWriteInterleaveHook != nil {
			userWriteInterleaveHook(username)
		}
		var applied bool
		if split {
			applied, err = c.executeGuardedLifecycleBatch(ctx, still, []Statement{
				reactivate,
				{SQL: userCredentialUpsertSQL, Params: []interface{}{username, passwordHash, ts}},
			}, "principal", username, "birth")
		} else {
			applied, err = c.executeGuardedLifecycleBatch(ctx, still, []Statement{reactivate}, "principal", username, "birth")
		}
		if err != nil {
			return err
		}
		if !applied {
			return ErrUserAccountChanged
		}
		if split {
			return nil
		}
		if passwordHash == "" {
			c.noteExternalShadow(userIdentity{Username: username, CreatedAt: created, UpdatedAt: ts})
		}
		return nil
	}
	created := nowRFC3339()
	if c.UserIncarnationOn() {
		// An incarnation at nanosecond precision, so two creates of one name
		// on partitioned nodes in the same second are two incarnations.
		created = c.newIncarnation("")
	}
	if passwordHash != "" {
		// A local account under this name: any record that this node made
		// an external shadow of it is about an earlier incarnation.
		c.forgetExternalShadow(username)
	}
	if split {
		return c.executeLifecycleBatch(ctx, []Statement{
			{SQL: usersInsertSQL, Params: []interface{}{username, role, c.oldColumnValue(passwordHash), created, now}},
			{SQL: userCredentialUpsertSQL, Params: []interface{}{username, passwordHash, now}},
		}, "principal", username, "birth")
	}
	if err := c.executeLifecycleBatch(ctx, []Statement{{SQL: usersInsertSQL, Params: []interface{}{username, role, passwordHash, created, now}}}, "principal", username, "birth"); err != nil {
		return err
	}
	if passwordHash == "" {
		// An external-realm shadow made where no credential row can be
		// written yet: positive evidence, bound to this row's identity, which
		// this node's first live pass replicates (credentials_live.go).
		c.noteExternalShadow(userIdentity{Username: username, CreatedAt: created, UpdatedAt: now})
	}
	return nil
}

// shadowReactivationTS is the updated_at of an external shadow that
// reactivates a tombstoned users row: two successor steps (clearTS) past the
// newest write this node holds for the row or its credential — not a fresh
// clock (re-review 3, R4; pre-existing on main). Two, because one step is
// exactly the stamp another node's credentials_clear_v1 pass gives the same
// tombstone, and an equal timestamp with different content is a tie.
//
// The shadow is a reactivation of the tombstone THIS node holds. Any write a
// peer made after that tombstone — above all the name created again as a local
// account, still in flight to this node — is newer than the successor, so it
// wins on every node, here included once it arrives, and the local account
// keeps its password and role. With a fresh clock the shadow, written later in
// real time, beat that write by LWW and wiped the local password cluster-wide.
// It still beats the tombstone, so the reactivation itself replicates. A row
// whose timestamps cannot be read keeps the fresh clock (main's behaviour).
func shadowReactivationTS(usersTS, credTS, now string) string {
	newest := usersTS
	if credTS != "" && lwwOrder(credTS, newest) > 0 {
		newest = credTS
	}
	if once, ok := clearTS(credentialSplitRow{srcTS: newest}); ok {
		if twice, ok := clearTS(credentialSplitRow{srcTS: once}); ok {
			return twice
		}
	}
	slog.Warn("users: a tombstoned row has no readable timestamp; reactivating it with a fresh clock")
	return now
}

const usersInsertSQL = `INSERT INTO users (username, role, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`

// usernameNormSQL is NormalizeUsername in SQL, over users.username. It must
// stay the exact expression of idx_users_username_norm so the lookup uses it.
const usernameNormSQL = `lower(trim(u.username, ' ' || char(9) || char(10) || char(13)))`

// usernameTrimSet is the whitespace NormalizeUsername trims, the same set the
// SQL above trims.
const usernameTrimSet = " \t\n\r"

// NormalizeUsername is how every account lookup compares names: surrounding
// spaces, tabs and newlines removed, ASCII letters folded to lower case.
// Directory realms match names case-insensitively and ignore insignificant
// spaces, so a lookup that did not would let `ALICE` or `alice ` through a
// directory bind as a different account from the disabled `alice`
// (t1-auth-review I2). Only ASCII is folded, because SQLite's lower() folds
// only ASCII and the two sides must agree exactly; a non-ASCII letter keeps
// its case.
func NormalizeUsername(s string) string {
	s = strings.Trim(s, usernameTrimSet)
	b := []byte(s)
	for i, ch := range b {
		if ch >= 'A' && ch <= 'Z' {
			b[i] = ch + ('a' - 'A')
		}
	}
	return string(b)
}

// ErrAmbiguousUsername is GetUser's refusal when two live accounts normalize
// to one name. Normalization never merges them silently: every lookup of
// either refuses until an operator renames or deletes one.
var ErrAmbiguousUsername = errors.New("accounts differ only in case or surrounding spaces")

// GetUser returns the live user whose name normalizes to username's
// (NormalizeUsername), or nil if there is none. UserRecord.Username is the
// name as stored, which is what every per-account row (lifecycle, factors,
// sessions, tokens, bindings) is keyed on: callers use it, never their input.
// Two live accounts that normalize alike is ErrAmbiguousUsername.
func GetUser(ctx context.Context, c *Client, username string) (*UserRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT u.username, u.role, u.password_hash, COALESCE(u.realm, 'local') AS realm, u.created_at,
		        u.updated_at, c.username AS cred_key, c.password_hash AS cred_val, c.updated_at AS cred_ts
		 FROM users u LEFT JOIN user_credentials c ON c.username = u.username AND c.deleted_at IS NULL
		 WHERE `+usernameNormSQL+` = ? AND u.deleted_at IS NULL`,
		NormalizeUsername(username))
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	if len(rows) > 1 {
		names := make([]string, len(rows))
		for i, r := range rows {
			names[i] = fmt.Sprintf("%q", r.String("username"))
		}
		return nil, fmt.Errorf("%w: %s — refusing to choose one; rename or delete all but one of them",
			ErrAmbiguousUsername, strings.Join(names, ", "))
	}
	r := rows[0]
	return &UserRecord{
		Username:     r.String("username"),
		Role:         r.String("role"),
		PasswordHash: resolveCredential(r.String("cred_key") != "", r.String("cred_val"), r.String("password_hash")),
		Realm:        r.String("realm"),
		CreatedAt:    r.String("created_at"),
	}, nil
}

// GetUserExact is GetUser matching the name as stored, byte for byte, with no
// normalization: only for an operator removing one of two accounts that
// normalize alike (`lv user delete --exact`), which GetUser refuses.
func GetUserExact(ctx context.Context, c *Client, username string) (*UserRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT u.username, u.role, u.password_hash, COALESCE(u.realm, 'local') AS realm, u.created_at,
		        u.updated_at, c.username AS cred_key, c.password_hash AS cred_val, c.updated_at AS cred_ts
		 FROM users u LEFT JOIN user_credentials c ON c.username = u.username AND c.deleted_at IS NULL
		 WHERE u.username = ? AND u.deleted_at IS NULL`, username)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &UserRecord{
		Username:     r.String("username"),
		Role:         r.String("role"),
		PasswordHash: resolveCredential(r.String("cred_key") != "", r.String("cred_val"), r.String("password_hash")),
		Realm:        r.String("realm"),
		CreatedAt:    r.String("created_at"),
	}, nil
}

// DeletedVariantOf returns the stored name of the newest tombstoned account
// whose name normalizes like username, or "" when there is none. A directory
// login re-creates a deleted shadow under THAT name, so the account comes
// back with its own lifecycle — a disabled legacy `Bob` stays disabled when
// `bob` logs in again (rereview m-d).
func DeletedVariantOf(ctx context.Context, c *Client, username string) (string, error) {
	rows, err := c.Query(ctx,
		`SELECT u.username FROM users u WHERE `+usernameNormSQL+` = ? AND u.deleted_at IS NOT NULL
		 ORDER BY u.deleted_at DESC, u.username ASC LIMIT 1`, NormalizeUsername(username))
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", nil
	}
	return rows[0].String("username"), nil
}

// UsersEverExisted reports whether this node's local database carries any user
// row at all, tombstoned or not.
//
// ListUsers filters `deleted_at IS NULL`, so it answers "are there live users",
// which is NOT the same fact as "has this cluster ever had an admin". Only the
// second one justifies minting one: InsertUser reactivates a soft-deleted row
// (`SET deleted_at = NULL`), so treating a tombstone as absence resurrects a
// deliberately revoked account and replicates it to every peer.
func UsersEverExisted(ctx context.Context, c *Client) (bool, error) {
	rows, err := c.Query(ctx, `SELECT username FROM users LIMIT 1`)
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// ListUsers returns all active users.
func ListUsers(ctx context.Context, c *Client) ([]UserRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT username, role, created_at FROM users WHERE deleted_at IS NULL ORDER BY username`)
	if err != nil {
		return nil, err
	}
	users := make([]UserRecord, len(rows))
	for i, r := range rows {
		users[i] = UserRecord{
			Username:  r.String("username"),
			Role:      r.String("role"),
			CreatedAt: r.String("created_at"),
		}
	}
	return users, nil
}

// UpdateUserPassword updates the password hash for a user.
func UpdateUserPassword(ctx context.Context, c *Client, username, passwordHash string) error {
	stmts, err := updateUserPasswordStatements(ctx, c, username, passwordHash, c.NowTS())
	if err != nil || len(stmts) == 0 {
		return err
	}
	return c.executeLifecycleBatch(ctx, stmts, "principal", username, "rotate")
}

// updateUserPasswordStatements is UpdateUserPassword's batch, for a caller that
// must commit the password together with other writes (ResetAdminPassword).
// No statements for an account that is not live once the credential table is
// written.
func updateUserPasswordStatements(ctx context.Context, c *Client, username, passwordHash, now string) ([]Statement, error) {
	if c.MayWriteCredentialTables() {
		// The credential row is written only for a LIVE user, matching the
		// parent UPDATE's guard: resetting a deleted account's password must
		// not give it a credential.
		live, err := c.Query(ctx, `SELECT username FROM users WHERE username = ? AND deleted_at IS NULL`, username)
		if err != nil {
			return nil, err
		}
		if len(live) == 0 {
			return nil, nil
		}
		// Once user_incarnation_v1 has latched both statements carry the
		// account's incarnation, so a lagging change to an account since
		// deleted cannot land on a re-created account of the name
		// (user_incarnation.go).
		g, err := userIncarnationGuard(ctx, c, username, true)
		if err != nil {
			return nil, err
		}
		return []Statement{
			{SQL: usersUpdatePasswordSQL, Params: []interface{}{c.oldColumnValue(passwordHash), now, username}, Guard: g},
			{SQL: userCredentialUpsertSQL, Params: []interface{}{username, passwordHash, now}, Guard: g},
		}, nil
	}
	g, err := userIncarnationGuard(ctx, c, username, true)
	if err != nil {
		return nil, err
	}
	return []Statement{{SQL: usersUpdatePasswordSQL, Params: []interface{}{passwordHash, now, username}, Guard: g}}, nil
}

const usersUpdatePasswordSQL = `UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`

// userRoleBindingsRevokeSQL is a delete's revocation of the account's role
// bindings, under both spellings of its principal.
const userRoleBindingsRevokeSQL = `UPDATE role_bindings SET deleted_at = ?, updated_at = ? WHERE (principal = ? OR principal = ?) AND deleted_at IS NULL`

// DeleteUser tombstones a user and CASCADES the tombstone to its 2FA factors,
// recovery codes, both active-set pointers, AND its role bindings — all in one
// batch sharing a single updated_at, so the whole set converges coherently
// under LWW. Tombstoning the pointers is what makes the delete
// resurrection-proof: a factor or code a partitioned peer still holds (one this
// node never saw, hence couldn't tombstone individually) lands on a now-inactive
// epoch/set and can never validate. Role bindings are tombstoned so a deleted
// user cannot retain access through a lingering (path, role) binding — both the
// canonical realm-qualified principal and the legacy bare form are removed.
// (Local users authenticate through the "local" realm; external OIDC/LDAP group
// bindings are out of scope — they are not session-persisted yet.)
//
// DeleteUser writes none of the login rules' data (it hands DeleteUserCounted
// the zero grant), as a delete before the release feature opens does.
func DeleteUser(ctx context.Context, c *Client, username string) error {
	_, _, err := DeleteUserCounted(ctx, c, capabilities.FeatureGrant{}, username)
	return err
}

// DeleteUserCounted is DeleteUser, reporting how many sessions and API tokens
// its batch revoked. With a grant for capabilities.FeatureLoginPolicy the same
// batch also voids the account's enrollment code, clears its directory
// bindings and writes its durable session and token cut-offs.
func DeleteUserCounted(ctx context.Context, c *Client, g capabilities.FeatureGrant, username string) (sessions, tokens int, err error) {
	// Whatever this node recorded about the name as an external shadow is
	// about the row this delete ends (credentials-clear M2: the delete RPC
	// calls this directly, so the forget lives here, not in DeleteUser).
	c.forgetExternalShadow(username)
	now := c.NowTS()
	marker := nowRFC3339()
	barePrincipal := "user:" + username
	localPrincipal := barePrincipal + "@local"
	// Once user_incarnation_v1 has latched the delete names the incarnation
	// it ends, so a later write to it from a node that had not seen the
	// delete cannot bring the account back (user_incarnation.go).
	//
	// Every statement that names the account by username alone carries the
	// incarnation too (a user_incarnation_v1 guard), so a lagging delete of
	// it cannot strip the factors, codes and bindings of a re-created
	// account of the name. Revocations by session and token id are not
	// bound: each names one credential of this account.
	tombstone := Statement{SQL: usersTombstoneSQL, Params: []interface{}{marker, now, username}}
	ug, err := userIncarnationGuard(ctx, c, username, false)
	if err != nil {
		return 0, 0, err
	}
	if ug != nil {
		tombstone = Statement{SQL: usersTombstoneIncarnationSQL, Params: []interface{}{marker, now, username, ug.Incarnation}, Guard: ug}
	}
	stmts := []Statement{tombstone}
	stmts = append(stmts, clearSecondFactorStatements(username, marker, now, ug)...)
	stmts = append(stmts, Statement{
		SQL:    userRoleBindingsRevokeSQL,
		Params: []interface{}{marker, now, barePrincipal, localPrincipal}, Guard: ug})
	// The account's credentials end IN THIS BATCH (rereview-2 N6, m-4): every
	// session and API token this node holds for it is revoked with the
	// existing per-row statements, so the delete cannot land without them.
	sessRows, err := c.Query(ctx, `SELECT id FROM sessions WHERE username = ? AND revoked_at IS NULL`, username)
	if err != nil {
		return 0, 0, err
	}
	for _, r := range sessRows {
		stmts = append(stmts, Statement{SQL: sessionRevokeSQL, Params: []interface{}{marker, r.String("id")}})
	}
	tokRows, err := c.Query(ctx, `SELECT id FROM tokens WHERE username = ? AND deleted_at IS NULL`, username)
	if err != nil {
		return 0, 0, err
	}
	for _, r := range tokRows {
		stmts = append(stmts, Statement{SQL: tokenRevokeSQL, Params: []interface{}{marker, now, r.String("id")}})
	}
	if g.Check(capabilities.FeatureLoginPolicy) == nil {
		// A deleted account's first-enrollment code goes with it (N3); its
		// directory binding too, so a re-created name binds afresh (N5).
		stmts = append(stmts, invalidateEnrollmentCodeStatement(username, now, ug))
		clear, err := clearIdentityBindingsStatements(ctx, c, username, marker, now, ug)
		if err != nil {
			return 0, 0, err
		}
		stmts = append(stmts, clear...)
		// And the cut-offs are durable: a session or token this node never
		// held (sessions are not anti-entropy repaired) is refused anyway
		// once these replicate, whatever comes back under the name.
		stmts = append(stmts,
			Statement{SQL: userLifecycleUpsertSQL, Params: []interface{}{username, UserAttrSessionsNotBefore, marker, "user.delete", now}, Guard: ug},
			Statement{SQL: userLifecycleUpsertSQL, Params: []interface{}{username, UserAttrTokensNotBefore, marker, "user.delete", now}, Guard: ug},
		)
	}
	// The account's lifecycle (user_lifecycle) is deliberately LEFT as it is
	// (t1-auth-review m3): a disabled account that is deleted must not come
	// back enabled when the admin floor reinstates it or a directory login
	// re-creates its shadow. Only an explicit CreateUser starts a name afresh
	// (ResetUserLifecycle).
	if err := c.executeLifecycleBatch(ctx, stmts, "principal", username, "retire"); err != nil {
		return 0, 0, err
	}
	return len(sessRows), len(tokRows), nil
}

// clearSecondFactorStatements tombstones every second factor, recovery code and
// both active-set pointers of username: DeleteUser's cascade, and
// `lv user reset-admin --clear-2fa`. The SQL text is DeleteUser's, so it adds
// no statement shape.
//
// g, when set, binds each statement to the account's incarnation
// (user_incarnation.go); nil is the previous release's wire form.
func clearSecondFactorStatements(username, marker, now string, g *MutationGuard) []Statement {
	return []Statement{
		{SQL: `UPDATE user_2fa SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`,
			Params: []interface{}{marker, now, username}, Guard: g},
		{SQL: `UPDATE user_2fa_sets SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`,
			Params: []interface{}{marker, now, username}, Guard: g},
		{SQL: `UPDATE recovery_codes SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`,
			Params: []interface{}{marker, now, username}, Guard: g},
		{SQL: `UPDATE recovery_code_sets SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`,
			Params: []interface{}{marker, now, username}, Guard: g},
	}
}

// InsertToken stores a new API token. scope_paths, when non-empty, is
// JSON-encoded and stored verbatim.
func InsertToken(ctx context.Context, c *Client, t TokenRecord) error {
	now := c.NowTS()
	var scope string
	if len(t.ScopePaths) > 0 {
		b, err := json.Marshal(t.ScopePaths)
		if err != nil {
			return err
		}
		scope = string(b)
	}
	if c.MayWriteCredentialTables() {
		return c.executeCredentialBatch(ctx, t.automationAuthentication, "token", t.ID, t.Username, []Statement{
			{SQL: tokensInsertSQL, Params: []interface{}{t.ID, t.Username, t.Name, c.oldColumnValue(t.TokenHash), t.ExpiresAt, scope, nowRFC3339(), now}},
			{SQL: tokenCredentialUpsertSQL, Params: []interface{}{t.ID, t.TokenHash, now}},
		})
	}
	return c.executeCredentialBatch(ctx, t.automationAuthentication, "token", t.ID, t.Username, []Statement{{SQL: tokensInsertSQL, Params: []interface{}{t.ID, t.Username, t.Name, t.TokenHash, t.ExpiresAt, scope, nowRFC3339(), now}}})
}

const tokensInsertSQL = `INSERT INTO tokens (id, username, name, token_hash, expires_at, scope_paths, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

// TokenLive reports whether token id is unrevoked, unexpired and belongs to a
// live user: ValidateToken's verdict for a token already matched once.
// It also returns the token's created_at, for the account's tokens_not_before.
func TokenLive(ctx context.Context, c *Client, id string) (bool, string, error) {
	rows, err := c.Query(ctx,
		`SELECT t.created_at FROM tokens t JOIN users u ON u.username = t.username
		 WHERE t.id = ? AND t.deleted_at IS NULL AND u.deleted_at IS NULL
		   AND (t.expires_at IS NULL OR t.expires_at = '' OR t.expires_at > ?)`, id, nowRFC3339())
	if err != nil {
		return false, "", err
	}
	if len(rows) == 0 {
		return false, "", nil
	}
	return true, rows[0].String("created_at"), nil
}

const tokenRevokeSQL = `UPDATE tokens SET deleted_at = ?, updated_at = ? WHERE id = ?`

// RevokeToken tombstones a token. updated_at is bumped alongside deleted_at so the
// revocation wins LWW over a stale peer's still-live copy under anti-entropy.
// (last_used_at bumps in ValidateToken deliberately do NOT touch updated_at, so a
// high-frequency token use can't out-timestamp a revoke.)
func RevokeToken(ctx context.Context, c *Client, id string) error {
	now := c.NowTS()
	return c.Execute(ctx, tokenRevokeSQL, nowRFC3339(), now, id)
}

// ValidateToken checks a raw token string against stored bcrypt hashes.
// Returns the associated UserRecord on success (with ScopePaths populated
// if the matched token is scoped), or nil if no token matches.
func ValidateToken(ctx context.Context, c *Client, rawToken string) (*UserRecord, error) {
	// Fast-reject anything that isn't shaped like one of our tokens BEFORE
	// touching the bcrypt sweep below. CreateToken always emits exactly 64
	// lowercase hex chars (hex of 32 random bytes), so a bearer that doesn't
	// match can't be valid — and rejecting it here means a flood of garbage
	// bearers can't force an O(N) run of (expensive) bcrypt comparisons per
	// request. A correctly-shaped but wrong token still falls through to the
	// sweep; eliminating that O(N) entirely needs an indexed lookup selector
	// (separate, schema-bumping change).
	if !looksLikeAPIToken(rawToken) {
		return nil, nil
	}
	// Bare RFC3339 cutoff: expires_at is stored bare, and a NowTS (fractional)
	// cutoff would let a token expiring at "…01Z" survive until the next second
	// because "…01Z" sorts AFTER "…01.5Z" ('Z' > '.'). Compare like-with-like.
	now := nowRFC3339()
	rows, err := liveTokenCandidates(ctx, c, now)
	if err != nil {
		return nil, err
	}

	for _, r := range rows {
		hash := resolveCredential(r.String("cred_key") != "", r.String("cred_val"), r.String("token_hash"))
		if hash == "" {
			continue // bcrypt rejects it anyway; skip the cost
		}
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(rawToken)) == nil {
			_ = c.Execute(ctx, `UPDATE tokens SET last_used_at = ? WHERE id = ?`,
				time.Now().UTC().Format(time.RFC3339), r.String("id"))
			rec := &UserRecord{
				Username:       r.String("username"),
				Role:           r.String("role"),
				TokenID:        r.String("id"),
				TokenCreatedAt: r.String("created_at"),
			}
			if raw := r.String("scope_paths"); raw != "" {
				var paths []string
				if err := json.Unmarshal([]byte(raw), &paths); err == nil {
					rec.ScopePaths = paths
				}
			}
			return rec, nil
		}
	}
	return nil, nil
}

// liveTokenCandidates reads every unexpired, unrevoked token of a live user
// together with its credential row, so ValidateToken can resolve the hash
// new-first (credentials_split.go). cutoff is a bare RFC3339 instant.
func liveTokenCandidates(ctx context.Context, c *Client, cutoff string) ([]Row, error) {
	return c.Query(ctx,
		`SELECT t.id, t.username, t.token_hash, t.scope_paths, u.role, t.created_at,
		        COALESCE(NULLIF(t.updated_at, ''), t.created_at) AS src_ts,
		        c.token_id AS cred_key, c.token_hash AS cred_val, c.updated_at AS cred_ts
		 FROM tokens t
		 JOIN users u ON u.username = t.username
		 LEFT JOIN token_credentials c ON c.token_id = t.id AND c.deleted_at IS NULL
		 WHERE t.deleted_at IS NULL AND u.deleted_at IS NULL
		   AND (t.expires_at IS NULL OR t.expires_at = '' OR t.expires_at > ?)`,
		cutoff)
}

// looksLikeAPIToken reports whether s has the exact shape CreateToken emits:
// 64 lowercase hex characters. Used to cheaply discard malformed bearers
// before the bcrypt comparison sweep.
func looksLikeAPIToken(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ReinstateAdminIfNoneRemain restores the "at least one admin" invariant after
// the fact, and reports which account it brought back ("" if none was needed).
//
// The delete path checks OtherLiveAdminExists and then deletes, as two
// independent operations against replicated state. Nothing makes that pair
// atomic across LWW replicas: with two admins and one delete issued on each of
// two nodes, both checks see the other admin alive, both pass, both tombstones
// replicate, and the cluster is left with no administrator and no way back in.
// Serializing within one node does not help, because the two requests never
// meet there.
//
// So the invariant is repaired instead of defended. A node that observes zero
// live admins undoes the most recent admin tombstone -- most recent because
// every replica agrees on that ordering from the replicated deleted_at, so two
// racing nodes reach the same conclusion and pick the same row. A duplicate
// reinstatement is harmless: two admins is the state the guard was trying to
// preserve. EnsureAdminFloor (admin_floor.go) is what runs this on every node
// once the racing tombstones have arrived; DeleteUser's own call right after
// its delete cannot see a peer's tombstone that has not.
//
// Reinstating an account the operator deliberately deleted is the lesser
// failure, and it is loud -- the caller logs and audits it. A cluster with no
// admin is not recoverable through any supported path.
//
// What comes back is the ROW, never the account's old credentials (re-review
// 3, I1a). The password is replaced by ReinstatedAdminPasswordHash, which no
// password matches and which marks the account as local, so no directory
// login adopts it either; every session and API token this node holds for it
// is revoked and every second factor cleared; and, when run opens the
// release feature capabilities.FeatureLoginPolicy, durable session and token
// cut-offs cover the ones it does not hold. That matters most for an admin deleted by a build before the login
// rules, whose delete revoked nothing: its never-expiring API tokens would
// otherwise authenticate as cluster admin again. Root gives the account a
// credential with `lv user reset-admin --user <name>`, which the
// no_unrestricted_admin condition names until it does. All of it is ONE batch,
// so the row never comes back without the revocations.
//
// run opens the release feature only once a reinstatement is decided, so a
// floor check that finds an admin never marks the feature used; nil writes
// without its data.
func ReinstateAdminIfNoneRemain(ctx context.Context, c *Client, run FeatureRun) (string, error) {
	// Counts only admins that can log in (t1-auth-review I4): a disabled or
	// expired admin is not an administrator anyone can use.
	usable, err := UsableAdminExists(ctx, c)
	if err != nil {
		return "", err
	}
	if usable {
		return "", nil
	}
	// Deterministic across replicas: newest tombstone, then username as the
	// tiebreak so two deletes sharing a marker still resolve identically. A
	// tombstone whose account is itself disabled or expired is passed over —
	// the floor never brings back an account an operator disabled (DeleteUser
	// keeps the lifecycle; m3), and never re-enables a live one.
	rows, err := c.Query(ctx,
		`SELECT u.username, u.password_hash, u.updated_at, u.deleted_at,
		        c.username AS cred_key, c.password_hash AS cred_val, c.updated_at AS cred_ts
		 FROM users u LEFT JOIN user_credentials c ON c.username = u.username AND c.deleted_at IS NULL
		 WHERE u.role = 'admin' AND u.deleted_at IS NOT NULL
		 ORDER BY u.deleted_at DESC, u.username ASC`)
	if err != nil {
		return "", err
	}
	pick := -1
	for i, r := range rows {
		ok, err := usableAdmin(ctx, c, r.String("username"))
		if err != nil {
			return "", err
		}
		if ok {
			pick = i
			break
		}
	}
	if pick < 0 {
		return "", nil // nothing usable to bring back; the floor raises no_unrestricted_admin
	}
	victim := rows[pick].String("username")
	// An external (LDAP/OIDC) admin stays external, a local one gets no
	// credential back (reinstatedAsExternal).
	external := reinstatedAsExternal(rows[pick].String("cred_key") != "", rows[pick].String("cred_val"))
	deletedAt := rows[pick].String("deleted_at")
	if err := run.run(ctx, func(ctx context.Context, g capabilities.FeatureGrant) error {
		stmts, err := reinstateAdminStatements(ctx, c, g, victim, external, deletedAt)
		if err != nil {
			return err
		}
		// Over the tombstone read above only: an account of the name that
		// replicated in since is not overwritten (user_incarnation.go).
		if userWriteInterleaveHook != nil {
			userWriteInterleaveHook(victim)
		}
		applied, err := c.executeGuardedLifecycleBatch(ctx, func(tx *sql.Tx) (bool, error) {
			var del sql.NullString
			err := tx.QueryRowContext(ctx, `SELECT deleted_at FROM users WHERE username = ?`, victim).Scan(&del)
			if errors.Is(err, sql.ErrNoRows) {
				return false, nil
			}
			return err == nil && del.Valid && del.String == deletedAt, err
		}, stmts, "principal", victim, "birth")
		if err == nil && !applied {
			err = ErrUserAccountChanged
		}
		return err
	}); err != nil {
		return "", err
	}
	return victim, nil
}

// AdminReinstatementNote says, for an account the floor just reinstated, how
// anyone logs in as it again: the text the floor's log line and audit row
// carry.
//
// It judges the account as the floor did (reinstatedAsExternal), from its
// live credential row, never from users.password_hash: once
// credentials_clear_v1 has latched that column is "" for every account.
func AdminReinstatementNote(ctx context.Context, c *Client, username string) string {
	rows, err := c.Query(ctx,
		`SELECT k.username AS cred_key, k.password_hash AS cred_val
		   FROM users u LEFT JOIN user_credentials k ON k.username = u.username AND k.deleted_at IS NULL
		  WHERE u.username = ? AND u.deleted_at IS NULL`, username)
	if err == nil && len(rows) > 0 && reinstatedAsExternal(rows[0].String("cred_key") != "", rows[0].String("cred_val")) {
		return "reinstated as an external (directory) admin with its directory binding; it logs in through " +
			"its realm, and its old sessions, API tokens and second factors were not restored. If its directory " +
			"entry is gone, it cannot log in: give it a local password as root on a node with " +
			"lv user reset-admin --user " + username
	}
	return "reinstated with no credential: give it one as root on a node with lv user reset-admin --user " + username
}

// reinstatedAsExternal is the admin floor's verdict on a deleted admin it
// reinstates (credentials-clear x login-policy, M5): external — reinstated
// with no local password and its directory bindings — only when the account
// has a credential row and that row is "". A credential row with a hash is a
// local account. NO credential row is reinstated as LOCAL (with
// ReinstatedAdminPasswordHash): once credentials_clear_v1 has latched, a
// local admin's users.password_hash is "" and its credential row may not have
// reached this replica yet (the sensitive lane, a withheld row), so "" in the
// old column proves nothing, and reinstating such an admin as external would
// let the first directory login under its name adopt it. Fail closed: an
// external admin with no credential row here comes back local, and root
// gives it a credential with `lv user reset-admin --user` (the
// no_unrestricted_admin condition names it). The delete batch never writes
// the credential row, so a "" row needs no comparison with the users row's
// updated_at, which the delete itself moved.
func reinstatedAsExternal(credPresent bool, credVal string) bool {
	return credPresent && credVal == ""
}

// ReinstatedAdminPasswordHash is the password hash of an account the admin
// floor reinstated and root has not yet given a credential. It is not a bcrypt
// hash, so no password matches it, and it is not "", so no directory login
// adopts the account as an external shadow (auth.EnsureUserShadow). Root
// replaces it with `lv user reset-admin --user <name>`.
const ReinstatedAdminPasswordHash = "!reinstated-by-admin-floor: run lv user reset-admin --user"

// reinstateAdminStatements is the floor's reinstatement of victim: the row,
// without one credential it had (see ReinstateAdminIfNoneRemain). A local
// admin gets ReinstatedAdminPasswordHash. An external (LDAP/OIDC) admin stays
// external: no local password (""), so it logs in through its directory realm
// as before, and the identity bindings its delete cleared are restored, so it
// is still the entry it was bound to that logs in. Either way its sessions,
// API tokens, second factors and enrollment code do not come back. Every
// statement reuses a registered shape: the reactivation InsertUser uses, the
// credential upsert, the per-row session and token revokes DeleteUser uses,
// DeleteUser's second-factor clear, the binding upsert, and the lifecycle and
// enrollment-code writes.
func reinstateAdminStatements(ctx context.Context, c *Client, g capabilities.FeatureGrant, victim string, external bool, deletedAt string) ([]Statement, error) {
	loginRules := g.Check(capabilities.FeatureLoginPolicy) == nil
	now := c.NowTS()
	marker := nowRFC3339()
	hash := ReinstatedAdminPasswordHash
	if external {
		hash = ""
	}
	// The old column takes what every writer puts there (credentials-clear
	// M3): "" once credentials_clear_v1 has latched, so the reinstatement
	// does not put a value back into a cleared column for the next clear pass.
	// Once user_incarnation_v1 has latched the reinstated account is a new
	// incarnation, which replaces the tombstone on every node
	// (user_incarnation.go).
	reinstate := Statement{SQL: usersReactivateSQL, Params: []interface{}{"admin", c.oldColumnValue(hash), now, victim}}
	if c.UserIncarnationOn() {
		prev, err := c.Query(ctx, `SELECT created_at FROM users WHERE username = ?`, victim)
		if err != nil {
			return nil, err
		}
		created := ""
		if len(prev) > 0 {
			created = prev[0].String("created_at")
		}
		reinstate = Statement{SQL: usersReactivateIncarnationSQL, Params: []interface{}{"admin", c.oldColumnValue(hash), c.newIncarnation(created), now, victim}}
	}
	stmts := []Statement{reinstate}
	if c.MayWriteCredentialTables() {
		stmts = append(stmts, Statement{SQL: userCredentialUpsertSQL, Params: []interface{}{victim, hash, now}})
	}
	if external && loginRules {
		restore, err := restoreDeletedBindingsStatements(ctx, c, victim, deletedAt, now)
		if err != nil {
			return nil, err
		}
		stmts = append(stmts, restore...)
	}
	sessRows, err := c.Query(ctx, `SELECT id FROM sessions WHERE username = ? AND revoked_at IS NULL`, victim)
	if err != nil {
		return nil, err
	}
	for _, r := range sessRows {
		stmts = append(stmts, Statement{SQL: sessionRevokeSQL, Params: []interface{}{marker, r.String("id")}})
	}
	tokRows, err := c.Query(ctx, `SELECT id FROM tokens WHERE username = ? AND deleted_at IS NULL`, victim)
	if err != nil {
		return nil, err
	}
	for _, r := range tokRows {
		stmts = append(stmts, Statement{SQL: tokenRevokeSQL, Params: []interface{}{marker, now, r.String("id")}})
	}
	stmts = append(stmts, clearSecondFactorStatements(victim, marker, now, nil)...)
	if loginRules {
		life, err := GetUserLifecycle(ctx, c, victim)
		if err != nil {
			return nil, err
		}
		// Set back like a re-create's (ResetUserLifecycle), so the login root
		// makes right after `reset-admin --user` works; never moved backwards.
		cut := setBackCutoff()
		stmts = append(stmts,
			Statement{SQL: userLifecycleUpsertSQL, Params: []interface{}{victim, UserAttrSessionsNotBefore,
				laterCutoff(life.SessionsNotBefore, cut), "admin-floor", now}},
			Statement{SQL: userLifecycleUpsertSQL, Params: []interface{}{victim, UserAttrTokensNotBefore,
				laterCutoff(life.TokensNotBefore, marker), "admin-floor", now}},
			invalidateEnrollmentCodeStatement(victim, now, nil),
		)
	}
	return stmts, nil
}

// OtherLiveAdminExists reports whether the cluster still has a live admin-role
// account other than username.
//
// DeleteUser asks this before tombstoning a user, so both of the easy wrong
// answers cost the cluster its administrator. Counting the target itself lets
// the last admin delete itself. Counting a tombstoned row does the same, and is
// the likelier mistake: InsertUser REACTIVATES a soft-deleted user rather than
// inserting a fresh one (`SET deleted_at = NULL`), so a revoked admin is a row
// that still exists, and any query that forgets `deleted_at IS NULL` sees it as
// a live successor that cannot actually log in.
//
// A read that fails is neither answer, and is returned as an error rather than
// collapsed into one — see UsersEverExisted for the same distinction on the
// seeding side.
func OtherLiveAdminExists(ctx context.Context, c *Client, username string) (bool, error) {
	rows, err := c.Query(ctx,
		`SELECT username FROM users WHERE role = 'admin' AND deleted_at IS NULL AND username != ? LIMIT 1`,
		username)
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// UserVariant is one of the live accounts whose names normalize alike, with
// what an operator needs to choose the one an exact delete removes.
type UserVariant struct {
	ID        string // stable: hash of the stored name and created_at
	Username  string
	CreatedAt string
	Role      string
	Realm     string
	LastLogin string
	Factors   int
	Tokens    int
}

// VariantID is UserVariant.ID for a stored name and created_at.
func VariantID(username, createdAt string) string {
	sum := sha256.Sum256([]byte(username + "\x00" + createdAt))
	return hex.EncodeToString(sum[:6])
}

// UserVariants lists every live account whose name normalizes like username.
func UserVariants(ctx context.Context, c *Client, username string) ([]UserVariant, error) {
	rows, err := c.Query(ctx,
		`SELECT u.username, u.role, COALESCE(u.realm, 'local') AS realm, u.created_at FROM users u
		 WHERE `+usernameNormSQL+` = ? AND u.deleted_at IS NULL ORDER BY u.created_at, u.username`,
		NormalizeUsername(username))
	if err != nil {
		return nil, err
	}
	out := make([]UserVariant, 0, len(rows))
	for _, r := range rows {
		v := UserVariant{Username: r.String("username"), Role: r.String("role"), Realm: r.String("realm"),
			CreatedAt: r.String("created_at")}
		v.ID = VariantID(v.Username, v.CreatedAt)
		if ll, err := c.Query(ctx, `SELECT MAX(created_at) AS m FROM sessions WHERE username = ?`, v.Username); err == nil && len(ll) > 0 {
			v.LastLogin = ll[0].String("m")
		}
		if f, err := ListUser2FA(ctx, c, v.Username); err == nil {
			v.Factors = len(f)
		}
		if f, err := ListHeldUser2FA(ctx, c, v.Username); err == nil {
			v.Factors += len(f)
		}
		if tk, err := c.Query(ctx, `SELECT COUNT(*) AS n FROM tokens WHERE username = ? AND deleted_at IS NULL`, v.Username); err == nil && len(tk) > 0 {
			v.Tokens = int(tk[0].Int("n"))
		}
		out = append(out, v)
	}
	return out, nil
}
