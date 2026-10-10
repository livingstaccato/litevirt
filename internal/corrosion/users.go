package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

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
}

// TokenRecord represents an API token.
type TokenRecord struct {
	ID         string
	Username   string
	Name       string
	TokenHash  string
	ExpiresAt  string
	CreatedAt  string
	ScopePaths []string // empty/nil = no scoping
}

// usersReactivateSQL is InsertUser's reactivation shape, also reused by
// ReinstateAdminIfNoneRemain so that path adds no shape of its own.
const usersReactivateSQL = `UPDATE users SET role = ?, password_hash = ?, deleted_at = NULL, updated_at = ? WHERE username = ?`

// InsertUser creates a new user. If the username was previously soft-deleted,
// it reactivates the row with the new role and password.
//
// Once credentials_split_v1 has latched the hash is written to user_credentials
// as well, in the same batch and under the same updated_at; users.password_hash
// keeps it for a previous-release reader (see credentials_split.go).
func InsertUser(ctx context.Context, c *Client, username, role, passwordHash string) error {
	now := c.NowTS()
	split := c.MayWriteCredentialTables()
	// Try reactivating a soft-deleted user first.
	rows, err := c.Query(ctx,
		`SELECT username FROM users WHERE username = ? AND deleted_at IS NOT NULL`, username)
	if err == nil && len(rows) > 0 {
		if split {
			return c.ExecuteBatch(ctx, []Statement{
				{SQL: usersReactivateSQL, Params: []interface{}{role, passwordHash, now, username}},
				{SQL: userCredentialUpsertSQL, Params: []interface{}{username, passwordHash, now}},
			})
		}
		return c.Execute(ctx, usersReactivateSQL, role, passwordHash, now, username)
	}
	if split {
		return c.ExecuteBatch(ctx, []Statement{
			{SQL: usersInsertSQL, Params: []interface{}{username, role, passwordHash, nowRFC3339(), now}},
			{SQL: userCredentialUpsertSQL, Params: []interface{}{username, passwordHash, now}},
		})
	}
	return c.Execute(ctx, usersInsertSQL, username, role, passwordHash, nowRFC3339(), now)
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
	return c.ExecuteBatch(ctx, stmts)
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
		return []Statement{
			{SQL: usersUpdatePasswordSQL, Params: []interface{}{passwordHash, now, username}},
			{SQL: userCredentialUpsertSQL, Params: []interface{}{username, passwordHash, now}},
		}, nil
	}
	return []Statement{{SQL: usersUpdatePasswordSQL, Params: []interface{}{passwordHash, now, username}}}, nil
}

const usersUpdatePasswordSQL = `UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`

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
func DeleteUser(ctx context.Context, c *Client, username string) error {
	now := c.NowTS()
	marker := nowRFC3339()
	barePrincipal := "user:" + username
	localPrincipal := barePrincipal + "@local"
	stmts := []Statement{
		{SQL: `UPDATE users SET deleted_at = ?, updated_at = ? WHERE username = ?`,
			Params: []interface{}{marker, now, username}},
	}
	stmts = append(stmts, clearSecondFactorStatements(username, marker, now)...)
	stmts = append(stmts, Statement{
		SQL:    `UPDATE role_bindings SET deleted_at = ?, updated_at = ? WHERE (principal = ? OR principal = ?) AND deleted_at IS NULL`,
		Params: []interface{}{marker, now, barePrincipal, localPrincipal}})
	// The account's lifecycle (user_lifecycle) is deliberately LEFT as it is
	// (t1-auth-review m3): a disabled account that is deleted must not come
	// back enabled when the admin floor reinstates it or a directory login
	// re-creates its shadow. Only an explicit CreateUser starts a name afresh
	// (ResetUserLifecycle).
	return c.ExecuteBatch(ctx, stmts)
}

// clearSecondFactorStatements tombstones every second factor, recovery code and
// both active-set pointers of username: DeleteUser's cascade, and
// `lv user reset-admin --clear-2fa`. The SQL text is DeleteUser's, so it adds
// no statement shape.
func clearSecondFactorStatements(username, marker, now string) []Statement {
	return []Statement{
		{SQL: `UPDATE user_2fa SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`,
			Params: []interface{}{marker, now, username}},
		{SQL: `UPDATE user_2fa_sets SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`,
			Params: []interface{}{marker, now, username}},
		{SQL: `UPDATE recovery_codes SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`,
			Params: []interface{}{marker, now, username}},
		{SQL: `UPDATE recovery_code_sets SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`,
			Params: []interface{}{marker, now, username}},
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
		return c.ExecuteBatch(ctx, []Statement{
			{SQL: tokensInsertSQL, Params: []interface{}{t.ID, t.Username, t.Name, t.TokenHash, t.ExpiresAt, scope, nowRFC3339(), now}},
			{SQL: tokenCredentialUpsertSQL, Params: []interface{}{t.ID, t.TokenHash, now}},
		})
	}
	return c.Execute(ctx, tokensInsertSQL,
		t.ID, t.Username, t.Name, t.TokenHash, t.ExpiresAt, scope, nowRFC3339(), now,
	)
}

const tokensInsertSQL = `INSERT INTO tokens (id, username, name, token_hash, expires_at, scope_paths, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

// TokenLive reports whether token id is unrevoked, unexpired and belongs to a
// live user: ValidateToken's verdict for a token already matched once.
func TokenLive(ctx context.Context, c *Client, id string) (bool, error) {
	rows, err := c.Query(ctx,
		`SELECT 1 FROM tokens t JOIN users u ON u.username = t.username
		 WHERE t.id = ? AND t.deleted_at IS NULL AND u.deleted_at IS NULL
		   AND (t.expires_at IS NULL OR t.expires_at = '' OR t.expires_at > ?)`, id, nowRFC3339())
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// RevokeToken tombstones a token. updated_at is bumped alongside deleted_at so the
// revocation wins LWW over a stale peer's still-live copy under anti-entropy.
// (last_used_at bumps in ValidateToken deliberately do NOT touch updated_at, so a
// high-frequency token use can't out-timestamp a revoke.)
func RevokeToken(ctx context.Context, c *Client, id string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE tokens SET deleted_at = ?, updated_at = ? WHERE id = ?`,
		nowRFC3339(), now, id,
	)
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
				Username: r.String("username"),
				Role:     r.String("role"),
				TokenID:  r.String("id"),
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
		`SELECT t.id, t.username, t.token_hash, t.scope_paths, u.role,
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
func ReinstateAdminIfNoneRemain(ctx context.Context, c *Client) (string, error) {
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
		`SELECT u.username, u.password_hash, u.updated_at,
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
	hash := resolveCredential(rows[pick].String("cred_key") != "", rows[pick].String("cred_val"), rows[pick].String("password_hash"))
	// The reactivation shape InsertUser already uses, with role and password
	// written back unchanged. Deliberately NOT a new `SET deleted_at = NULL`
	// statement: every replicated shape has to be in the compatibility ledger,
	// and reusing the registered one keeps this off that ledger entirely.
	now := c.NowTS()
	if c.MayWriteCredentialTables() {
		if err := c.ExecuteBatch(ctx, []Statement{
			{SQL: usersReactivateSQL, Params: []interface{}{"admin", hash, now, victim}},
			{SQL: userCredentialUpsertSQL, Params: []interface{}{victim, hash, now}},
		}); err != nil {
			return "", err
		}
		return victim, nil
	}
	if err := c.Execute(ctx, usersReactivateSQL, "admin", hash, now, victim); err != nil {
		return "", err
	}
	return victim, nil
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
