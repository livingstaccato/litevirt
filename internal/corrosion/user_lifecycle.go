package corrosion

// Account lifecycle (schema v64, user_lifecycle) and the cluster-wide
// mandatory second-factor policy (the login_2fa_required key in
// cluster_policies). docs/auth.md, "Account lifecycle" and "Mandatory second
// factor".
//
// WHY A TABLE OF ITS OWN AND NOT COLUMNS ON users. A disable has to survive
// every statement any node can write to the users row. users is written by
// previous-release builds too (a role change, a password reset, the admin
// floor's reactivation), and a column those builds do not know is one their
// statements can reset — an INSERT OR REPLACE, a reseed, a full-row merge would
// each bring the account back. On a row of its own, with its own LWW clock, no
// previous-release statement can touch it, because none names the table.
//
// WHY ONE ROW PER ATTRIBUTE. A disable written on one node and an expiry
// written on another are two independent decisions. On one row they would
// share one clock and the later write would silently undo the earlier — an
// expiry change made after a disable would re-enable the account. Keyed on
// (username, attribute), each keeps its own.
//
// WHY A GATE. user_lifecycle's statements are the first replicated shapes the
// table has ever had; a previous-release peer's apply fails closed on an
// unregistered shape and stalls its whole stream. And a previous-release node
// would not enforce a disable even if it could decode one, so a user disabled
// while one is listening could keep logging in through it. So every write of
// this data — the table, the second-factor policy row, session_factors,
// user_enrollment_codes and user_identity_bindings — is part of the release
// feature capabilities.FeatureLoginPolicy, and its writer takes the
// capabilities.FeatureGrant only health.Checker.WithFeature mints: the release
// token (release_2026_11_v1) has DURABLY latched, which cannot happen while any
// replication recipient runs a build that does not decode and enforce them, and
// the feature's use is recorded, and held by every recipient, before its first
// write. A rollback below the release then quarantines exactly when this data
// exists. A writer handed the zero grant writes none of it.
//
// READS ARE NEVER GATED. A node whose own latch is still forming can receive a
// row from a peer whose latch has formed; skipping the check "because nothing
// can be written yet" would let that node accept a disabled account for the
// length of the gap.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
)

const (
	// UserAttrDisabled is "true" for a disabled account. Any other value but
	// "false" reads as disabled: a value this build cannot read is never taken
	// to mean "enabled".
	UserAttrDisabled = "disabled"
	// UserAttrExpiresAt is the RFC3339 UTC instant the account stops
	// authenticating, "" for never. An unparseable value reads as expired.
	UserAttrExpiresAt = "expires_at"
	// UserAttrSessionsNotBefore is the RFC3339 instant before which no session
	// of the account is honoured, "" for none. A disable and an expiry set it,
	// so a session minted before them stays dead after a re-enable, including
	// one whose row reached a node after that node's revocation sweep had run
	// (t1-auth-review m2). Never cleared by a re-enable.
	UserAttrSessionsNotBefore = "sessions_not_before"
	// UserAttrTokensNotBefore is the RFC3339 instant before which no API
	// token of the account is honoured, "" for none. A delete and a re-create
	// set it — not a disable, whose tokens work again on re-enable — so a
	// token whose revoke never reached a node does not come back with the
	// name (rereview-2 m-4).
	UserAttrTokensNotBefore = "tokens_not_before"

	// LoginTwoFactorPolicyKey is the cluster_policies key of the mandatory
	// second-factor policy.
	LoginTwoFactorPolicyKey = "login_2fa_required"
	// LoginTwoFactorSelfEnrollKey is the cluster_policies key of the policy's
	// self-enrollment deadline: RFC3339, or "" (no row) for none, in which case
	// an enrollment-only session enrolls only with an admin-issued code.
	LoginTwoFactorSelfEnrollKey = "login_2fa_self_enroll_by"

	// TwoFactorPolicyOff and TwoFactorPolicyAll are the policy's two fixed
	// values; anything else is a comma-separated list of realm names.
	TwoFactorPolicyOff = "off"
	TwoFactorPolicyAll = "all"
)

// ErrLoginPolicyGateClosed is returned by a write of the login rules' data
// attempted without a grant for capabilities.FeatureLoginPolicy: the release
// feature's gate has not passed on this node.
var ErrLoginPolicyGateClosed = errors.New("account lifecycle and login policy are not writable here: the " +
	"login_policy feature of the release has not opened (the cluster upgrade must finish first)")

// FeatureRun runs write through the release-feature gate of
// capabilities.FeatureLoginPolicy on this node, handing it the grant its
// writer checks (grpcapi: Server.WithReleaseFeature, or the best-effort form
// that hands the zero grant when the gate does not pass). A writer that needs
// the grant only sometimes — the admin floor, reset-admin — takes one, so the
// feature is opened (and its use recorded) only for a write that carries its
// data. Nil means no gate: the zero grant.
type FeatureRun func(ctx context.Context, write func(context.Context, capabilities.FeatureGrant) error) error

// run runs write through r, or with the zero grant when r is nil.
func (r FeatureRun) run(ctx context.Context, write func(context.Context, capabilities.FeatureGrant) error) error {
	if r == nil {
		return write(ctx, capabilities.FeatureGrant{})
	}
	return r(ctx, write)
}

// userLifecycleUpsertSQL is the table's one writer. Explicit on the primary
// key, so the origin applies it whether or not it holds the row, and a
// receiver LWW-gates it on updated_at (DispExplicitUpsert).
const userLifecycleUpsertSQL = `INSERT INTO user_lifecycle (username, attribute, value, set_by, updated_at, deleted_at)
	 VALUES (?, ?, ?, ?, ?, NULL)
	 ON CONFLICT(username, attribute) DO UPDATE SET value = excluded.value, set_by = excluded.set_by,
	   updated_at = excluded.updated_at, deleted_at = NULL`

// UserLifecycle is one account's lifecycle as this node's replica holds it.
// The zero value is an enabled account that never expires.
type UserLifecycle struct {
	Disabled bool
	// ExpiresAt is the stored expiry, "" for never.
	ExpiresAt string
	// SessionsNotBefore is UserAttrSessionsNotBefore, "" for none.
	SessionsNotBefore string
	// TokensNotBefore is UserAttrTokensNotBefore, "" for none.
	TokensNotBefore string
	// Unreadable names a stored attribute this build could not parse. Such an
	// account is inactive: see InactiveReason.
	Unreadable string
}

// InactiveReason returns why the account may not authenticate at now, or ""
// when it may. Every failure to read the state is a reason: a disable or an
// expiry this build cannot parse is never taken to mean "active".
func (l UserLifecycle) InactiveReason(now time.Time) string {
	if l.Unreadable != "" {
		return "account state unreadable (" + l.Unreadable + ")"
	}
	if l.Disabled {
		return "account disabled"
	}
	if l.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, l.ExpiresAt)
		if err != nil {
			return "account expiry unreadable"
		}
		if !now.Before(exp) {
			return "account expired"
		}
	}
	return ""
}

// SessionCutoffSkewMargin widens every session cut-off, in the refusing
// direction. The cut-off is the changing node's wall clock and a session's
// created_at is the minting node's, both to the second: a session minted a
// moment before a disable by a clock running ahead, or in the same second,
// would otherwise read as minted after it and survive the re-enable
// (rereview m-a). Sessions created up to this long after the cut-off are
// refused too. 5 s is the failover coordinator's fenceSkewMargin, the margin
// the repo already budgets for wall-clock disagreement between nodes; a clock
// further off than that is the LWW skew guard's to report.
const SessionCutoffSkewMargin = 5 * time.Second

// SessionPredates reports whether a session created at createdAt (RFC3339)
// is from before the account's last lifecycle change (disable, re-enable,
// expiry set or changed, re-create), within SessionCutoffSkewMargin, and so is
// never honoured again. An unparseable instant on either side predates: it
// fails closed.
func (l UserLifecycle) SessionPredates(createdAt string) bool {
	if l.SessionsNotBefore == "" {
		return false
	}
	nb, err := time.Parse(time.RFC3339, l.SessionsNotBefore)
	if err != nil {
		return true
	}
	ca, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return true
	}
	return ca.Before(nb.Add(SessionCutoffSkewMargin))
}

// TokenPredates reports whether an API token created at createdAt is from
// before the account's last delete or re-create, within
// SessionCutoffSkewMargin as sessions are (re-review 3, m-6): a namesake's
// token stamped by a node whose clock runs ahead must not read as made after
// the cut-off. CreateToken refuses inside the margin, so no token is minted
// that this refuses. Unparseable on either side predates: it fails closed.
func (l UserLifecycle) TokenPredates(createdAt string) bool {
	if l.TokensNotBefore == "" {
		return false
	}
	nb, err := time.Parse(time.RFC3339, l.TokensNotBefore)
	if err != nil {
		return true
	}
	ca, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return true
	}
	return ca.Before(nb.Add(SessionCutoffSkewMargin))
}

// SessionsRetryAt is when a login refused by SessionPredates(now) will be
// accepted: the session cut-off plus SessionCutoffSkewMargin, RFC3339, or ""
// when there is no readable cut-off.
func (l UserLifecycle) SessionsRetryAt() string {
	nb, err := time.Parse(time.RFC3339, l.SessionsNotBefore)
	if err != nil {
		return ""
	}
	return nb.Add(SessionCutoffSkewMargin).UTC().Format(time.RFC3339)
}

// CutoffAhead reports whether a stored cut-off (RFC3339) lies further in the
// future than SessionCutoffSkewMargin from now: it was written by a node
// whose clock runs ahead, and refuses every login (or token) until that time
// (re-review 4, m-2). Every ordinary write keeps it (laterCutoff); only
// reset-admin, root's break-glass, replaces it (resetCutoff).
func CutoffAhead(stored string, now time.Time) bool {
	t, err := time.Parse(time.RFC3339, stored)
	return err == nil && t.After(now.Add(SessionCutoffSkewMargin))
}

// resetCutoff is the cut-off reset-admin stores: a set-back one, as a
// re-enable's, unless the stored one is later — then the stored one, unless
// it is ahead by more than the skew margin (CutoffAhead), which is clock error
// and is replaced, so root can correct a forward-dated cut-off that would
// otherwise refuse the admin's login for hours (re-review 4, m-2).
func resetCutoff(stored string, now time.Time) string {
	if CutoffAhead(stored, now) {
		return setBackCutoff()
	}
	return laterCutoff(stored, setBackCutoff())
}

// TokenNearCutoff reports whether a token TokenPredates refuses was created
// within SessionCutoffSkewMargin of the token cut-off, on either side: most
// likely minted for the account on a node the delete or re-create had not
// reached yet, which never works (re-review 4, m-4). Its refusal says so,
// rather than reading like any revoked token.
func (l UserLifecycle) TokenNearCutoff(createdAt string) bool {
	nb, err := time.Parse(time.RFC3339, l.TokensNotBefore)
	if err != nil {
		return false
	}
	ca, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return false
	}
	d := ca.Sub(nb)
	return d > -SessionCutoffSkewMargin && d < SessionCutoffSkewMargin
}

// laterCutoff is the cut-off a lifecycle write stores: proposed, unless the
// stored one is later (re-review 3, m-5). A cut-off never moves backwards — a
// write from a node whose clock is behind, or a reset-admin's set-back cut-off
// right after a disable, would otherwise revive sessions minted between the
// two. A stored value that does not parse is replaced: it predates everything
// already, and the write is what repairs it.
func laterCutoff(stored, proposed string) string {
	st, err := time.Parse(time.RFC3339, stored)
	if err != nil {
		return proposed
	}
	pr, err := time.Parse(time.RFC3339, proposed)
	if err != nil || st.After(pr) {
		return stored
	}
	return proposed
}

// setBackCutoff is a cut-off set back by the skew margin and a second, so a
// login or token made right after the write that stores it still works, while
// everything minted before the change — at least a second before it — is cut.
func setBackCutoff() string {
	return time.Now().Add(-SessionCutoffSkewMargin - time.Second).UTC().Format(time.RFC3339)
}

// Unrestricted reports whether the account is enabled and has no expiry —
// one that can stand in as the cluster's administrator indefinitely.
func (l UserLifecycle) Unrestricted() bool {
	return l.Unreadable == "" && !l.Disabled && l.ExpiresAt == ""
}

// applyAttribute folds one stored attribute into l. Unknown attributes are a
// later release's and are ignored: that release gates its own on a token of
// its own.
func (l *UserLifecycle) applyAttribute(attr, value string) {
	switch attr {
	case UserAttrDisabled:
		switch value {
		case "true":
			l.Disabled = true
		case "false":
		default:
			l.Disabled = true
			l.Unreadable = fmt.Sprintf("disabled=%q", value)
		}
	case UserAttrExpiresAt:
		l.ExpiresAt = value
		if value != "" {
			if _, err := time.Parse(time.RFC3339, value); err != nil {
				l.Unreadable = fmt.Sprintf("expires_at=%q", value)
			}
		}
	case UserAttrSessionsNotBefore:
		l.SessionsNotBefore = value
	case UserAttrTokensNotBefore:
		l.TokensNotBefore = value
	}
}

// GetUserLifecycle reads username's lifecycle from this node's replica. No row
// is the zero value. A read that fails is returned as an error, never as an
// active account; every caller fails closed on it.
func GetUserLifecycle(ctx context.Context, c *Client, username string) (UserLifecycle, error) {
	rows, err := c.Query(ctx,
		`SELECT attribute, value FROM user_lifecycle WHERE username = ? AND deleted_at IS NULL`, username)
	if err != nil {
		return UserLifecycle{}, err
	}
	var l UserLifecycle
	for _, r := range rows {
		l.applyAttribute(r.String("attribute"), r.String("value"))
	}
	return l, nil
}

// ListUserLifecycles reads every account's lifecycle, keyed by username. An
// account with no row is absent from the map (the zero value).
func ListUserLifecycles(ctx context.Context, c *Client) (map[string]UserLifecycle, error) {
	rows, err := c.Query(ctx,
		`SELECT username, attribute, value FROM user_lifecycle WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	out := map[string]UserLifecycle{}
	for _, r := range rows {
		u := r.String("username")
		l := out[u]
		l.applyAttribute(r.String("attribute"), r.String("value"))
		out[u] = l
	}
	return out, nil
}

// NormalizeExpiry parses an operator-supplied expiry into the stored form:
// bare RFC3339 UTC, or "" for never ("" and "never" both mean never).
func NormalizeExpiry(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "never") {
		return "", nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return "", fmt.Errorf("want an RFC3339 timestamp such as 2026-12-31T00:00:00Z, or \"never\": %w", err)
	}
	return t.UTC().Format(time.RFC3339), nil
}

// SetUserLifecycle writes the attributes it is given and leaves the others as
// they are. disabled and expiresAt are each nil for "leave it"; expiresAt must
// already be normalized (NormalizeExpiry). Both writes, when there are two,
// share one batch and one updated_at. It refuses with ErrLoginPolicyGateClosed
// without a grant for capabilities.FeatureLoginPolicy. The caller — the gRPC
// handler — owns the operator-facing preconditions (role, the last-admin
// guard).
func SetUserLifecycle(ctx context.Context, c *Client, g capabilities.FeatureGrant, username string, disabled *bool, expiresAt *string, setBy string) error {
	if username == "" {
		return errors.New("username required")
	}
	if expiresAt != nil && *expiresAt != "" {
		if _, err := time.Parse(time.RFC3339, *expiresAt); err != nil {
			return fmt.Errorf("expires_at %q is not RFC3339: %w", *expiresAt, err)
		}
	}
	if g.Check(capabilities.FeatureLoginPolicy) != nil {
		return ErrLoginPolicyGateClosed
	}
	cur, err := GetUserLifecycle(ctx, c, username)
	if err != nil {
		return fmt.Errorf("read the account's lifecycle: %w", err)
	}
	now := c.NowTS()
	var stmts []Statement
	// EVERY change is a session cut-off (rereview m-a): a disable or an
	// expiry so its sessions stay dead, and a re-enable or an extended expiry
	// too, so nothing minted before it — by a clock ahead, or on a node the
	// disable had not reached yet, or before an expiry that has since passed —
	// is honoured afterwards.
	stmts = append(stmts, Statement{SQL: userLifecycleUpsertSQL,
		Params: []interface{}{username, UserAttrSessionsNotBefore, laterCutoff(cur.SessionsNotBefore, nowRFC3339()), setBy, now}})
	if disabled != nil && *disabled {
		// A disable also voids an outstanding first-enrollment code (N3).
		stmts = append(stmts, invalidateEnrollmentCodeStatement(username, now))
	}
	if disabled != nil {
		v := "false"
		if *disabled {
			v = "true"
		}
		stmts = append(stmts, Statement{SQL: userLifecycleUpsertSQL,
			Params: []interface{}{username, UserAttrDisabled, v, setBy, now}})
	}
	if expiresAt != nil {
		stmts = append(stmts, Statement{SQL: userLifecycleUpsertSQL,
			Params: []interface{}{username, UserAttrExpiresAt, *expiresAt, setBy, now}})
	}
	return c.ExecuteBatch(ctx, stmts)
}

// enableUserStatements returns the statements that clear username's disable
// and expiry (and leave SessionsNotBefore, so nothing old revives), or nil
// without a grant for capabilities.FeatureLoginPolicy — in which case the
// caller decides whether a row written elsewhere matters.
func enableUserStatements(g capabilities.FeatureGrant, username, setBy, now string) []Statement {
	if g.Check(capabilities.FeatureLoginPolicy) != nil {
		return nil
	}
	return []Statement{
		{SQL: userLifecycleUpsertSQL, Params: []interface{}{username, UserAttrDisabled, "false", setBy, now}},
		{SQL: userLifecycleUpsertSQL, Params: []interface{}{username, UserAttrExpiresAt, "", setBy, now}},
	}
}

// ResetUserLifecycle starts username afresh: enabled, no expiry, and no
// session from before now honoured. It is what an explicit CreateUser does to
// a name, which may have belonged to a deleted, disabled account (DeleteUser
// keeps the lifecycle on purpose; m3) — and whose old sessions must not come
// back with the new account. Without a grant for
// capabilities.FeatureLoginPolicy it does nothing when there is nothing to
// reset, and refuses (ErrLoginPolicyGateClosed) when a row another node wrote
// is there.
func ResetUserLifecycle(ctx context.Context, c *Client, g capabilities.FeatureGrant, username, setBy string) error {
	if g.Check(capabilities.FeatureLoginPolicy) != nil {
		rows, err := c.Query(ctx, `SELECT 1 FROM user_lifecycle WHERE username = ? AND deleted_at IS NULL LIMIT 1`, username)
		if err != nil {
			return err
		}
		if len(rows) > 0 {
			return ErrLoginPolicyGateClosed
		}
		return nil
	}
	cur, err := GetUserLifecycle(ctx, c, username)
	if err != nil {
		return err
	}
	// Did this name have an account before, as far as this node knows: a
	// deleted row, or an API token issued under it?
	prior, err := c.Query(ctx,
		`SELECT 1 FROM users WHERE username = ? AND deleted_at IS NOT NULL
		 UNION ALL SELECT 1 FROM tokens WHERE username = ? LIMIT 1`, username, username)
	if err != nil {
		return err
	}
	now := c.NowTS()
	stmts := enableUserStatements(g, username, setBy, now)
	// The session cut-off is set back by the skew margin: the namesake's
	// sessions all predate its deletion, which predates this, while a login
	// made right after the create must work at once — also right after a
	// delete, as on the previous release. That is why this one write may move
	// the cut-off back (by at most the margin): the delete revoked every
	// session this node holds in its own batch, and the set-back cut-off still
	// refuses the namesake's sessions up to a second before the create.
	stmts = append(stmts, Statement{SQL: userLifecycleUpsertSQL,
		Params: []interface{}{username, UserAttrSessionsNotBefore, setBackCutoff(), setBy, now}})
	// A re-created name starts with no outstanding enrollment code (N3), and
	// no token of the namesake (m-4). TokenPredates applies the skew margin
	// (re-review 3, m-6). For a name this node knows had an account, the
	// token cut-off is now — so a namesake's token stamped up to 5 s later by
	// a clock running ahead is refused — and CreateToken refuses to mint a
	// token inside that margin rather than hand out one that never works. For
	// a name new to this node it is set back like the session one, so the
	// usual create-then-token-create works at once.
	tokenCut := setBackCutoff()
	if len(prior) > 0 {
		tokenCut = nowRFC3339()
	}
	stmts = append(stmts, invalidateEnrollmentCodeStatement(username, now))
	stmts = append(stmts, Statement{SQL: userLifecycleUpsertSQL,
		Params: []interface{}{username, UserAttrTokensNotBefore, laterCutoff(cur.TokensNotBefore, tokenCut), setBy, now}})
	return c.ExecuteBatch(ctx, stmts)
}

// OtherUnrestrictedAdminExists reports whether a live admin-role account
// other than username is enabled and has no expiry. Disabling or expiring an
// admin is refused unless one is, so the cluster is never left with only
// administrators who cannot log in. A read that fails is an error, not an
// answer.
//
// An admin that is one of two accounts normalizing alike does not count:
// every lookup of it is refused, so it cannot log in (rereview-2 m-7). The
// ambiguity is judged as it will be after the change (re-review 3, I1b): when
// deleting, username's own row is left out, so deleting one spelling of a pair
// counts the spelling that survives it. A disable or expiry leaves the row,
// and the pair, in place.
//
// Nor does an admin the admin floor reinstated that root has not yet given a
// credential (ReinstatedAdminPasswordHash; re-review 4, m-1): no password
// matches it and no directory login adopts it, so it is not an admin anyone
// can log in as. The credential is resolved as AdminLoginState resolves it.
//
// Nor, FAIL CLOSED, does an admin whose credential this node cannot judge
// (UserLocalCredential's known=false): an empty old column with no credential
// row and no evidence that the account is external. Once
// credentials_clear_v1 has latched, a reinstated admin's sentinel lives only
// in its credential row, which replicates separately from the users row, so
// until it arrives the account would otherwise resolve to "" and count. When
// such an admin is the only one that might count, the answer is an
// *AdminCredentialPendingError instead of true: the caller refuses and asks
// for a retry, and never lets the last admin who can log in go on the
// strength of an account that may not be able to.
func OtherUnrestrictedAdminExists(ctx context.Context, c *Client, username string, deleting bool) (bool, error) {
	rows, err := c.Query(ctx,
		`SELECT u.username, u.password_hash, u.created_at, u.updated_at,
		        k.username AS cred_key, k.password_hash AS cred_val, k.updated_at AS cred_ts
		   FROM users u LEFT JOIN user_credentials k ON k.username = u.username AND k.deleted_at IS NULL
		  WHERE u.role = 'admin' AND u.deleted_at IS NULL AND u.username != ?`, username)
	if err != nil {
		return false, err
	}
	exclude := ""
	if deleting {
		exclude = username
	}
	amb, err := ambiguousNames(ctx, c, exclude)
	if err != nil {
		return false, err
	}
	var pending []string
	for _, r := range rows {
		if amb[NormalizeUsername(r.String("username"))] {
			continue
		}
		credKey := r.String("cred_key") != ""
		if resolveCredential(credKey, r.String("cred_val"), r.String("password_hash")) == ReinstatedAdminPasswordHash {
			continue
		}
		l, err := GetUserLifecycle(ctx, c, r.String("username"))
		if err != nil {
			return false, err
		}
		if !l.Unrestricted() {
			continue
		}
		if _, known := c.judgeUserRow(rowIdentity(r), r.String("password_hash"), credKey, r.String("cred_val"), r.String("cred_ts")); !known {
			pending = append(pending, r.String("username"))
			continue
		}
		return true, nil
	}
	if len(pending) > 0 {
		return false, &AdminCredentialPendingError{Usernames: pending}
	}
	return false, nil
}

// AdminCredentialPendingError is OtherUnrestrictedAdminExists's answer when
// the only other admins that might be able to log in are ones whose
// credential has not reached this node: it cannot tell, so the change that
// asked must wait (a retry once the row has replicated, or the same request
// on a node that holds it).
type AdminCredentialPendingError struct {
	Usernames []string
}

func (e *AdminCredentialPendingError) Error() string {
	return fmt.Sprintf("cannot tell yet whether admin %s can log in: its credential has not reached this node",
		strings.Join(quoteAll(e.Usernames), ", "))
}

func quoteAll(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = strconv.Quote(n)
	}
	return out
}

// usableAdmin reports whether username's account can log in now (enabled,
// unexpired, readable): what the admin floor counts.
func usableAdmin(ctx context.Context, c *Client, username string) (bool, error) {
	l, err := GetUserLifecycle(ctx, c, username)
	if err != nil {
		return false, err
	}
	return l.InactiveReason(time.Now().UTC()) == "", nil
}

// UsableAdminExists reports whether some live admin-role account is enabled
// and unexpired: what the admin floor counts. Reinstating a deleted admin is
// the floor's answer to there being NONE.
//
// An admin that is one of a case-duplicate pair counts (re-review 3, I1a).
// Neither spelling can log in while both are live, but each is reachable by
// `lv user delete --exact` and its id, which root resolves; reinstating a
// deliberately deleted admin beside them would be the worse repair. The
// no_unrestricted_admin condition still names the pair (AdminLoginState).
func UsableAdminExists(ctx context.Context, c *Client) (bool, error) {
	rows, err := c.Query(ctx, `SELECT username FROM users WHERE role = 'admin' AND deleted_at IS NULL`)
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		ok, err := usableAdmin(ctx, c, r.String("username"))
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// AdminLoginReport is what the no_unrestricted_admin condition says about the
// cluster's admin accounts.
type AdminLoginReport struct {
	// Loggable: some admin is enabled, unexpired, unambiguous and has a
	// credential. The condition is raised while this is false.
	Loggable bool
	// Ambiguous lists, by normalized name, the duplicate pairs of usable
	// admins: neither spelling logs in until root deletes one by its id.
	Ambiguous []string
	// AwaitingCredential lists usable admins the admin floor reinstated
	// without their old password: none logs in until root runs
	// `lv user reset-admin --user <name>`.
	AwaitingCredential []string
}

// AdminLoginState reports whether some admin can actually log in now, and,
// when none can, the admins root can recover with a command. It is the
// no_unrestricted_admin condition's question; the floor's is
// UsableAdminExists, which counts the pairs and the reinstated accounts as
// present so that it does not resurrect another account beside them.
func AdminLoginState(ctx context.Context, c *Client) (AdminLoginReport, error) {
	var rep AdminLoginReport
	rows, err := c.Query(ctx,
		`SELECT u.username, u.password_hash, c.username AS cred_key, c.password_hash AS cred_val
		 FROM users u LEFT JOIN user_credentials c ON c.username = u.username AND c.deleted_at IS NULL
		 WHERE u.role = 'admin' AND u.deleted_at IS NULL ORDER BY u.username`)
	if err != nil {
		return rep, err
	}
	amb, err := ambiguousNames(ctx, c, "")
	if err != nil {
		return rep, err
	}
	seenPair := map[string]bool{}
	for _, r := range rows {
		name := r.String("username")
		ok, err := usableAdmin(ctx, c, name)
		if err != nil {
			return rep, err
		}
		if !ok {
			continue
		}
		hash := resolveCredential(r.String("cred_key") != "", r.String("cred_val"), r.String("password_hash"))
		switch norm := NormalizeUsername(name); {
		case amb[norm]:
			if !seenPair[norm] {
				seenPair[norm] = true
				rep.Ambiguous = append(rep.Ambiguous, norm)
			}
		case hash == ReinstatedAdminPasswordHash:
			rep.AwaitingCredential = append(rep.AwaitingCredential, name)
		default:
			rep.Loggable = true
		}
	}
	return rep, nil
}

// ambiguousNames is the set of normalized names two or more live accounts
// share, leaving out the account stored exactly as exclude ("" leaves out
// none).
func ambiguousNames(ctx context.Context, c *Client, exclude string) (map[string]bool, error) {
	rows, err := c.Query(ctx, `SELECT username FROM users WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	seen := map[string]int{}
	for _, r := range rows {
		if exclude != "" && r.String("username") == exclude {
			continue
		}
		seen[NormalizeUsername(r.String("username"))]++
	}
	out := map[string]bool{}
	for n, k := range seen {
		if k > 1 {
			out[n] = true
		}
	}
	return out, nil
}

// TwoFactorPolicy is the cluster-wide mandatory second-factor policy as this
// node's replica holds it.
type TwoFactorPolicy struct {
	// Value is the stored value, "off" when no row exists.
	Value string
	// All covers every realm. Realms lists the covered realms otherwise.
	All    bool
	Realms []string
	// Unknown is set when Value is not one this build understands; the policy
	// is then enforced as All.
	Unknown   bool
	SetBy     string
	UpdatedAt string
	// SelfEnrollBy is the self-enrollment deadline as stored, "" for none.
	SelfEnrollBy string
}

// SelfEnrollOpen reports whether an enrollment-only session may enroll its
// first factor without an admin-issued code at now. No deadline, an
// unparseable one, or one that has passed: no (fail closed).
func (p TwoFactorPolicy) SelfEnrollOpen(now time.Time) bool {
	if p.SelfEnrollBy == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, p.SelfEnrollBy)
	return err == nil && now.Before(t)
}

// Requires reports whether a login through realm must present a second factor.
func (p TwoFactorPolicy) Requires(realm string) bool {
	if p.All {
		return true
	}
	for _, r := range p.Realms {
		if r == realm {
			return true
		}
	}
	return false
}

// Off reports whether the policy covers nothing.
func (p TwoFactorPolicy) Off() bool { return !p.All && len(p.Realms) == 0 }

// validRealmName reports whether s names a realm the way the realm registry
// does: "local", "ldap:<name>" or "oidc:<name>".
func validRealmName(s string) bool {
	if s == "local" {
		return true
	}
	for _, prefix := range []string{"ldap:", "oidc:"} {
		if rest, ok := strings.CutPrefix(s, prefix); ok && rest != "" &&
			!strings.ContainsAny(rest, " \t\r\n,") {
			return true
		}
	}
	return false
}

// ParseTwoFactorPolicy parses an operator-supplied policy value and returns it
// with its canonical stored form in Value: "off", "all", or a sorted,
// de-duplicated comma-separated list of realm names.
func ParseTwoFactorPolicy(v string) (TwoFactorPolicy, error) {
	v = strings.TrimSpace(v)
	switch strings.ToLower(v) {
	case "", TwoFactorPolicyOff:
		return TwoFactorPolicy{Value: TwoFactorPolicyOff}, nil
	case TwoFactorPolicyAll:
		return TwoFactorPolicy{Value: TwoFactorPolicyAll, All: true}, nil
	}
	seen := map[string]bool{}
	var realms []string
	for _, part := range strings.Split(v, ",") {
		r := strings.TrimSpace(part)
		if !validRealmName(r) {
			return TwoFactorPolicy{}, fmt.Errorf("%q is not a realm name (want local, ldap:<name> or oidc:<name>)", r)
		}
		if !seen[r] {
			seen[r] = true
			realms = append(realms, r)
		}
	}
	sort.Strings(realms)
	return TwoFactorPolicy{Value: strings.Join(realms, ","), Realms: realms}, nil
}

// GetTwoFactorPolicy reads the policy from this node's replica. No row (or a
// tombstoned one) is off. A stored value this build cannot parse is a later
// release's and is enforced as "all": the policy's failure mode is asking a
// user to enroll a factor, never refusing a login outright, so the strict
// reading costs nothing a recovery path cannot undo.
func GetTwoFactorPolicy(ctx context.Context, c *Client) (TwoFactorPolicy, error) {
	rows, err := c.Query(ctx,
		`SELECT value, set_by, updated_at FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`,
		LoginTwoFactorPolicyKey)
	if err != nil {
		return TwoFactorPolicy{}, err
	}
	selfBy := ""
	if sr, err := c.Query(ctx,
		`SELECT value FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`,
		LoginTwoFactorSelfEnrollKey); err != nil {
		return TwoFactorPolicy{}, err
	} else if len(sr) > 0 {
		selfBy = sr[0].String("value")
	}
	if len(rows) == 0 {
		return TwoFactorPolicy{Value: TwoFactorPolicyOff, SelfEnrollBy: selfBy}, nil
	}
	raw := rows[0].String("value")
	p, perr := ParseTwoFactorPolicy(raw)
	if perr != nil {
		p = TwoFactorPolicy{All: true, Unknown: true}
	}
	p.Value = raw
	p.SetBy = rows[0].String("set_by")
	p.UpdatedAt = rows[0].String("updated_at")
	p.SelfEnrollBy = selfBy
	return p, nil
}

// SetTwoFactorPolicy writes the policy (already parsed, so p.Value is
// canonical). It goes through cluster_policies' existing upsert, so it needs
// that table's gate (failover_scope_v1) as well as a grant for
// capabilities.FeatureLoginPolicy: the shape is registered, but a build that
// predates the release would read the row and ignore it, so it may not be
// written while one is listening.
//
// The policy and its self-enrollment deadline (p.SelfEnrollBy, "" for none)
// are written together, in one batch: every change of the policy restates the
// deadline, so a window is open only because the latest change opened it.
func SetTwoFactorPolicy(ctx context.Context, c *Client, g capabilities.FeatureGrant, p TwoFactorPolicy, setBy string) error {
	if g.Check(capabilities.FeatureLoginPolicy) != nil {
		return ErrLoginPolicyGateClosed
	}
	if !c.MayWriteClusterPolicy() {
		return ErrClusterPolicyGateClosed
	}
	now := c.NowTS()
	return c.ExecuteBatch(ctx, []Statement{
		{SQL: clusterPolicyUpsertSQL, Params: []interface{}{LoginTwoFactorPolicyKey, p.Value, setBy, now}},
		{SQL: clusterPolicyUpsertSQL, Params: []interface{}{LoginTwoFactorSelfEnrollKey, p.SelfEnrollBy, setBy, now}},
	})
}

// LiveSession is the slice of a session the policy change needs.
type LiveSession struct {
	ID       string
	Username string
	Realm    string
}

// ListLiveSessions returns every session that is not revoked and has not
// reached its hard expiry. Sessions are replicated, so this is every node's.
func ListLiveSessions(ctx context.Context, c *Client) ([]LiveSession, error) {
	rows, err := c.Query(ctx,
		`SELECT id, username, realm FROM sessions WHERE revoked_at IS NULL AND expires_at > ?`,
		nowRFC3339())
	if err != nil {
		return nil, err
	}
	out := make([]LiveSession, len(rows))
	for i, r := range rows {
		out[i] = LiveSession{ID: r.String("id"), Username: r.String("username"), Realm: r.String("realm")}
	}
	return out, nil
}
