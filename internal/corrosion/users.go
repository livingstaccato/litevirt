package corrosion

import (
	"context"
	"encoding/json"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// UserRecord represents a litevirt user.
type UserRecord struct {
	Username     string
	Role         string
	PasswordHash string
	CreatedAt    string
	// ScopePaths is non-nil only when ValidateToken populates it from the
	// matched API token. Empty slice = no scoping (inherit user's full
	// perms). A scoped token may only operate on paths that are under one
	// of these prefixes.
	ScopePaths []string
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

// InsertUser creates a new user. If the username was previously soft-deleted,
// it reactivates the row with the new role and password.
func InsertUser(ctx context.Context, c *Client, username, role, passwordHash string) error {
	now := c.NowTS()
	// Try reactivating a soft-deleted user first.
	rows, err := c.Query(ctx,
		`SELECT username FROM users WHERE username = ? AND deleted_at IS NOT NULL`, username)
	if err == nil && len(rows) > 0 {
		return c.Execute(ctx,
			`UPDATE users SET role = ?, password_hash = ?, deleted_at = NULL, updated_at = ? WHERE username = ?`,
			role, passwordHash, now, username,
		)
	}
	return c.Execute(ctx,
		`INSERT INTO users (username, role, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		username, role, passwordHash, nowRFC3339(), now,
	)
}

// GetUser returns a user by username, or nil if not found.
func GetUser(ctx context.Context, c *Client, username string) (*UserRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT username, role, password_hash, created_at FROM users WHERE username = ? AND deleted_at IS NULL`,
		username)
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
		PasswordHash: r.String("password_hash"),
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
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`,
		passwordHash, now, username,
	)
}

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
	return c.ExecuteBatch(ctx, []Statement{
		{SQL: `UPDATE users SET deleted_at = ?, updated_at = ? WHERE username = ?`,
			Params: []interface{}{marker, now, username}},
		{SQL: `UPDATE user_2fa SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`,
			Params: []interface{}{marker, now, username}},
		{SQL: `UPDATE user_2fa_sets SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`,
			Params: []interface{}{marker, now, username}},
		{SQL: `UPDATE recovery_codes SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`,
			Params: []interface{}{marker, now, username}},
		{SQL: `UPDATE recovery_code_sets SET deleted_at = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`,
			Params: []interface{}{marker, now, username}},
		{SQL: `UPDATE role_bindings SET deleted_at = ?, updated_at = ? WHERE (principal = ? OR principal = ?) AND deleted_at IS NULL`,
			Params: []interface{}{marker, now, barePrincipal, localPrincipal}},
	})
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
	return c.Execute(ctx,
		`INSERT INTO tokens (id, username, name, token_hash, expires_at, scope_paths, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Username, t.Name, t.TokenHash, t.ExpiresAt, scope, nowRFC3339(), now,
	)
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
	rows, err := c.Query(ctx,
		`SELECT t.id, t.username, t.token_hash, t.scope_paths, u.role
		 FROM tokens t
		 JOIN users u ON u.username = t.username
		 WHERE t.deleted_at IS NULL AND u.deleted_at IS NULL
		   AND (t.expires_at IS NULL OR t.expires_at = '' OR t.expires_at > ?)`,
		now)
	if err != nil {
		return nil, err
	}

	for _, r := range rows {
		hash := r.String("token_hash")
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(rawToken)) == nil {
			_ = c.Execute(ctx, `UPDATE tokens SET last_used_at = ? WHERE id = ?`,
				time.Now().UTC().Format(time.RFC3339), r.String("id"))
			rec := &UserRecord{
				Username: r.String("username"),
				Role:     r.String("role"),
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
// preserve.
//
// Reinstating an account the operator deliberately deleted is the lesser
// failure, and it is loud -- the caller logs and audits it. A cluster with no
// admin is not recoverable through any supported path.
func ReinstateAdminIfNoneRemain(ctx context.Context, c *Client) (string, error) {
	live, err := c.Query(ctx,
		`SELECT username FROM users WHERE role = 'admin' AND deleted_at IS NULL LIMIT 1`)
	if err != nil {
		return "", err
	}
	if len(live) > 0 {
		return "", nil
	}
	// Deterministic across replicas: newest tombstone, then username as the
	// tiebreak so two deletes sharing a marker still resolve identically.
	rows, err := c.Query(ctx,
		`SELECT username, password_hash FROM users WHERE role = 'admin' AND deleted_at IS NOT NULL
		 ORDER BY deleted_at DESC, username ASC LIMIT 1`)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", nil // no admin ever existed; not this function's problem
	}
	victim := rows[0].String("username")
	// The reactivation shape InsertUser already uses, with role and password
	// written back unchanged. Deliberately NOT a new `SET deleted_at = NULL`
	// statement: every replicated shape has to be in the compatibility ledger,
	// and reusing the registered one keeps this off that ledger entirely.
	now := c.NowTS()
	if err := c.Execute(ctx,
		`UPDATE users SET role = ?, password_hash = ?, deleted_at = NULL, updated_at = ? WHERE username = ?`,
		"admin", rows[0].String("password_hash"), now, victim); err != nil {
		return "", err
	}
	return victim, nil
}

func OtherLiveAdminExists(ctx context.Context, c *Client, username string) (bool, error) {
	rows, err := c.Query(ctx,
		`SELECT username FROM users WHERE role = 'admin' AND deleted_at IS NULL AND username != ? LIMIT 1`,
		username)
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}
