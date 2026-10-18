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
//     SHA-256 of a 160-bit random value, and BOUND TO THE NODE THAT ISSUED IT
//     (issued_on). It is checked and used up only there, in one guarded
//     update, so "single use" holds cluster-wide without consensus: a
//     partition cannot let it be spent once on each side (rereview N3). A
//     disable, a delete or a re-create of the account tombstones it.
//
// Both are written only with a grant for capabilities.FeatureLoginPolicy (the
// release feature user_lifecycle is written under). session_factors is left out of anti-entropy like sessions;
// user_enrollment_codes is repaired by it (public lane — the column is a hash
// of a random value), so every replica converges on one row per account.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
)

const sessionFactorInsertSQL = `INSERT INTO session_factors (session_id, method, presented_at, updated_at) VALUES (?, ?, ?, ?)`

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

const enrollmentCodeUpsertSQL = `INSERT INTO user_enrollment_codes (username, code_hash, expires_at, issued_by, issued_on, used_at, updated_at, deleted_at)
	 VALUES (?, ?, ?, ?, ?, '', ?, NULL)
	 ON CONFLICT(username) DO UPDATE SET code_hash = excluded.code_hash, expires_at = excluded.expires_at,
	   issued_by = excluded.issued_by, issued_on = excluded.issued_on, used_at = '', updated_at = excluded.updated_at,
	   deleted_at = NULL`

// enrollmentCodeTombstoneSQL invalidates username's code: a disable, a delete,
// a re-create, or an admin enrolling a factor for the account.
const enrollmentCodeTombstoneSQL = `UPDATE user_enrollment_codes SET deleted_at = ?, updated_at = ?
	 WHERE username = ? AND deleted_at IS NULL`

// invalidateEnrollmentCodeStatement is the statement other batches append.
func invalidateEnrollmentCodeStatement(username, now string) Statement {
	return Statement{SQL: enrollmentCodeTombstoneSQL, Params: []interface{}{nowRFC3339(), now, username}}
}

// InvalidateEnrollmentCode tombstones username's outstanding code. A no-op
// without a grant for capabilities.FeatureLoginPolicy; a caller opens the
// feature for it only when HasLiveEnrollmentCode says there is one, so that
// enrolling a factor never marks the feature used by itself.
func InvalidateEnrollmentCode(ctx context.Context, c *Client, g capabilities.FeatureGrant, username string) error {
	if g.Check(capabilities.FeatureLoginPolicy) != nil {
		return nil
	}
	st := invalidateEnrollmentCodeStatement(username, c.NowTS())
	return c.ExecuteBatch(ctx, []Statement{st})
}

// HasLiveEnrollmentCode reports whether username holds an enrollment code
// that is not tombstoned (used or not, expired or not). A read that fails is
// an error, never "none".
func HasLiveEnrollmentCode(ctx context.Context, c *Client, username string) (bool, error) {
	rows, err := c.Query(ctx,
		`SELECT 1 FROM user_enrollment_codes WHERE username = ? AND deleted_at IS NULL LIMIT 1`, username)
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// ErrEnrollmentCodeElsewhere is the refusal for a code issued on another node.
type ErrEnrollmentCodeElsewhere struct{ Node string }

func (e ErrEnrollmentCodeElsewhere) Error() string {
	return fmt.Sprintf("this enrollment code was issued on node %s and can be used only there: log in "+
		"through %s, or ask an administrator to issue a new code on this node", e.Node, e.Node)
}

func enrollmentCodeHash(code string) string {
	sum := sha256.Sum256([]byte(strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))))
	return hex.EncodeToString(sum[:])
}

// IssueEnrollmentCode mints username's enrollment code, bound to node issuedOn
// (this node), replacing any earlier one, and returns it (shown once) with its
// expiry. It needs a grant for capabilities.FeatureLoginPolicy.
func IssueEnrollmentCode(ctx context.Context, c *Client, g capabilities.FeatureGrant, username string, ttl time.Duration, issuedBy, issuedOn string) (string, string, error) {
	if ttl <= 0 {
		ttl = EnrollmentCodeDefaultTTL
	}
	if ttl > EnrollmentCodeMaxTTL {
		return "", "", errors.New("an enrollment code lives at most 24 hours")
	}
	if g.Check(capabilities.FeatureLoginPolicy) != nil {
		return "", "", ErrLoginPolicyGateClosed
	}
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw) // 32 chars
	code := enc[0:8] + "-" + enc[8:16] + "-" + enc[16:24] + "-" + enc[24:32]
	exp := time.Now().Add(ttl).UTC().Format(time.RFC3339)
	if err := c.Execute(ctx, enrollmentCodeUpsertSQL, username, enrollmentCodeHash(code), exp, issuedBy, issuedOn, c.NowTS()); err != nil {
		return "", "", err
	}
	return code, exp, nil
}

// CheckEnrollmentCode reports whether code is username's live, unused,
// unexpired code, issued on node `here`, without using it up (WebAuthn's
// begin step). A matching code issued elsewhere is ErrEnrollmentCodeElsewhere.
func CheckEnrollmentCode(ctx context.Context, c *Client, username, code, here string) error {
	if strings.TrimSpace(code) == "" {
		return ErrEnrollmentCodeInvalid
	}
	rows, err := c.Query(ctx,
		`SELECT issued_on FROM user_enrollment_codes WHERE username = ? AND code_hash = ? AND used_at = ''
		   AND expires_at > ? AND deleted_at IS NULL`,
		username, enrollmentCodeHash(code), nowRFC3339())
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return ErrEnrollmentCodeInvalid
	}
	if on := rows[0].String("issued_on"); on != here {
		return ErrEnrollmentCodeElsewhere{Node: on}
	}
	return nil
}

// ConsumeEnrollmentCode uses code up, on the node that issued it: one guarded
// update that changes a row only while it is live, unused, unexpired and
// issued here, so it succeeds at most once anywhere.
func ConsumeEnrollmentCode(ctx context.Context, c *Client, g capabilities.FeatureGrant, username, code, here string) error {
	if err := CheckEnrollmentCode(ctx, c, username, code, here); err != nil {
		return err
	}
	if g.Check(capabilities.FeatureLoginPolicy) != nil {
		return ErrLoginPolicyGateClosed
	}
	n, err := c.ExecuteRowsStrict(ctx,
		`UPDATE user_enrollment_codes SET used_at = ?, updated_at = ?
		 WHERE username = ? AND code_hash = ? AND issued_on = ? AND used_at = '' AND expires_at > ? AND deleted_at IS NULL`,
		nowRFC3339(), c.NowTS(), username, enrollmentCodeHash(code), here, nowRFC3339())
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrEnrollmentCodeInvalid
	}
	return nil
}
