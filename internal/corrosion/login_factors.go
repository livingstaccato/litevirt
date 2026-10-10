package corrosion

// Two facts the mandatory second-factor policy needs persisted rather than
// re-derived (schema v64; t1-auth-review C1 and I5):
//
//   - session_factors: which second factor, if any, a session's login
//     PRESENTED. A session is a full session under the policy only if this
//     says so. Deriving it from "the account has a factor now" let a
//     password-only session become a full one the moment anyone enrolled a
//     factor for the account.
//   - user_enrollment_codes: the admin-issued, single-use, short-lived code an
//     enrollment-only session needs to enroll its first factor, stored as a
//     SHA-256 of a 160-bit random value.
//
// Both are written only once login_policy_v1 has latched (the same gate as
// user_lifecycle), are replicated through the WAL, and are left out of
// anti-entropy like sessions: they are as short-lived as what they describe.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

const sessionFactorInsertSQL = `INSERT INTO session_factors (session_id, method, presented_at, updated_at) VALUES (?, ?, ?, ?)`

// InsertSessionWithFactor creates a session row and, when factor is not
// empty, records in the same batch that its login presented that second
// factor ("totp", "webauthn"). With the gate closed the factor is not
// recorded: such a session counts as password-only, which only ever confines
// it (no policy can be set before the latch).
func InsertSessionWithFactor(ctx context.Context, c *Client, s SessionRecord, factor string) error {
	if factor == "" || !c.MayWriteLoginPolicy() {
		return InsertSession(ctx, c, s)
	}
	return c.ExecuteBatch(ctx, []Statement{
		sessionInsertStatement(s),
		{SQL: sessionFactorInsertSQL, Params: []interface{}{s.ID, factor, s.CreatedAt, c.NowTS()}},
	})
}

// SessionFactor returns the second factor session id's login presented, "" if
// it presented none. A read that fails is an error, never "".
func SessionFactor(ctx context.Context, c *Client, id string) (string, error) {
	rows, err := c.Query(ctx,
		`SELECT method FROM session_factors WHERE session_id = ? AND deleted_at IS NULL`, id)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", nil
	}
	return rows[0].String("method"), nil
}

// EnrollmentCodeMaxTTL bounds IssueEnrollmentCode; EnrollmentCodeDefaultTTL
// is what a zero ttl means.
const (
	EnrollmentCodeMaxTTL     = 24 * time.Hour
	EnrollmentCodeDefaultTTL = time.Hour
)

// ErrEnrollmentCodeInvalid is the one refusal for a missing, wrong, used or
// expired code: they are not told apart.
var ErrEnrollmentCodeInvalid = errors.New("enrollment code missing, wrong, used or expired")

const enrollmentCodeUpsertSQL = `INSERT INTO user_enrollment_codes (username, code_hash, expires_at, issued_by, used_at, updated_at, deleted_at)
	 VALUES (?, ?, ?, ?, '', ?, NULL)
	 ON CONFLICT(username) DO UPDATE SET code_hash = excluded.code_hash, expires_at = excluded.expires_at,
	   issued_by = excluded.issued_by, used_at = '', updated_at = excluded.updated_at, deleted_at = NULL`

func enrollmentCodeHash(code string) string {
	sum := sha256.Sum256([]byte(strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))))
	return hex.EncodeToString(sum[:])
}

// IssueEnrollmentCode mints username's enrollment code, replacing any earlier
// one, and returns it (shown once) with its expiry. Gated on login_policy_v1.
func IssueEnrollmentCode(ctx context.Context, c *Client, username string, ttl time.Duration, issuedBy string) (string, string, error) {
	if ttl <= 0 {
		ttl = EnrollmentCodeDefaultTTL
	}
	if ttl > EnrollmentCodeMaxTTL {
		return "", "", errors.New("an enrollment code lives at most 24 hours")
	}
	if !c.MayWriteLoginPolicy() {
		return "", "", ErrLoginPolicyGateClosed
	}
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw) // 32 chars
	code := enc[0:8] + "-" + enc[8:16] + "-" + enc[16:24] + "-" + enc[24:32]
	exp := time.Now().Add(ttl).UTC().Format(time.RFC3339)
	if err := c.Execute(ctx, enrollmentCodeUpsertSQL, username, enrollmentCodeHash(code), exp, issuedBy, c.NowTS()); err != nil {
		return "", "", err
	}
	return code, exp, nil
}

// CheckEnrollmentCode reports whether code is username's live, unused,
// unexpired code, without using it up (WebAuthn's begin step).
func CheckEnrollmentCode(ctx context.Context, c *Client, username, code string) error {
	if strings.TrimSpace(code) == "" {
		return ErrEnrollmentCodeInvalid
	}
	rows, err := c.Query(ctx,
		`SELECT 1 FROM user_enrollment_codes WHERE username = ? AND code_hash = ? AND used_at = ''
		   AND expires_at > ? AND deleted_at IS NULL`,
		username, enrollmentCodeHash(code), nowRFC3339())
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return ErrEnrollmentCodeInvalid
	}
	return nil
}

// ConsumeEnrollmentCode uses code up: a guarded update that changes a row only
// while it is live, unused and unexpired, so two uses on this node cannot both
// succeed. Two uses on two nodes inside one replication window can; the code
// is held by one person and lives at most a day.
func ConsumeEnrollmentCode(ctx context.Context, c *Client, username, code string) error {
	if strings.TrimSpace(code) == "" {
		return ErrEnrollmentCodeInvalid
	}
	if !c.MayWriteLoginPolicy() {
		return ErrLoginPolicyGateClosed
	}
	n, err := c.ExecuteRowsStrict(ctx,
		`UPDATE user_enrollment_codes SET used_at = ?, updated_at = ?
		 WHERE username = ? AND code_hash = ? AND used_at = '' AND expires_at > ? AND deleted_at IS NULL`,
		nowRFC3339(), c.NowTS(), username, enrollmentCodeHash(code), nowRFC3339())
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrEnrollmentCodeInvalid
	}
	return nil
}
