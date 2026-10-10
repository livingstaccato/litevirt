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
// while one is listening could keep logging in through it. Nothing writes the
// table, or the second-factor policy row, until login_policy_v1 has DURABLY
// latched, which cannot happen while any replication recipient runs a build
// that does not decode and enforce them.
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
	"strings"
	"time"
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

// ErrLoginPolicyGateClosed is returned by a user_lifecycle or second-factor
// policy write attempted before login_policy_v1 has durably latched here.
var ErrLoginPolicyGateClosed = errors.New("account lifecycle and login policy are not writable until " +
	"login_policy_v1 has latched on every host")

// userLifecycleUpsertSQL is the table's one writer. Explicit on the primary
// key, so the origin applies it whether or not it holds the row, and a
// receiver LWW-gates it on updated_at (DispExplicitUpsert).
const userLifecycleUpsertSQL = `INSERT INTO user_lifecycle (username, attribute, value, set_by, updated_at, deleted_at)
	 VALUES (?, ?, ?, ?, ?, NULL)
	 ON CONFLICT(username, attribute) DO UPDATE SET value = excluded.value, set_by = excluded.set_by,
	   updated_at = excluded.updated_at, deleted_at = NULL`

// SetLoginPolicyGate injects the predicate that permits WRITING
// user_lifecycle and the second-factor policy row, wired at daemon start to
// the durable login_policy_v1 latch. Nil-safe and FAIL CLOSED: an unset gate
// refuses every write.
func (c *Client) SetLoginPolicyGate(fn func() bool) {
	if fn == nil {
		c.loginPolicyGate.Store(nil)
		return
	}
	c.loginPolicyGate.Store(&fn)
}

// MayWriteLoginPolicy reports whether this node may write user_lifecycle and
// the second-factor policy (nil-safe, fail closed).
func (c *Client) MayWriteLoginPolicy() bool {
	fn := c.loginPolicyGate.Load()
	return fn != nil && (*fn)()
}

// UserLifecycle is one account's lifecycle as this node's replica holds it.
// The zero value is an enabled account that never expires.
type UserLifecycle struct {
	Disabled bool
	// ExpiresAt is the stored expiry, "" for never.
	ExpiresAt string
	// SessionsNotBefore is UserAttrSessionsNotBefore, "" for none.
	SessionsNotBefore string
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

// SessionPredates reports whether a session created at createdAt (RFC3339)
// is from before the account's last disable or expiry, and so is never
// honoured again. An unparseable instant on either side predates: it fails
// closed.
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
	return ca.Before(nb)
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
// until login_policy_v1 has latched. The caller — the gRPC handler — owns the
// operator-facing preconditions (role, the last-admin guard).
func SetUserLifecycle(ctx context.Context, c *Client, username string, disabled *bool, expiresAt *string, setBy string) error {
	if username == "" {
		return errors.New("username required")
	}
	if expiresAt != nil && *expiresAt != "" {
		if _, err := time.Parse(time.RFC3339, *expiresAt); err != nil {
			return fmt.Errorf("expires_at %q is not RFC3339: %w", *expiresAt, err)
		}
	}
	if !c.MayWriteLoginPolicy() {
		return ErrLoginPolicyGateClosed
	}
	now := c.NowTS()
	var stmts []Statement
	if (disabled != nil && *disabled) || (expiresAt != nil && *expiresAt != "") {
		// Sessions from before this instant are never honoured again (m2).
		stmts = append(stmts, Statement{SQL: userLifecycleUpsertSQL,
			Params: []interface{}{username, UserAttrSessionsNotBefore, nowRFC3339(), setBy, now}})
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
	if len(stmts) == 0 {
		return nil
	}
	return c.ExecuteBatch(ctx, stmts)
}

// enableUserStatements returns the statements that clear username's disable
// and expiry (and leave SessionsNotBefore, so nothing old revives), or nil when
// the gate is closed — in which case no row can have been written by this
// node, and the caller decides whether one written elsewhere matters.
func enableUserStatements(c *Client, username, setBy, now string) []Statement {
	if !c.MayWriteLoginPolicy() {
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
// back with the new account. With the gate closed it does nothing when there
// is nothing to reset, and refuses (ErrLoginPolicyGateClosed) when a row a
// latched peer wrote is there.
func ResetUserLifecycle(ctx context.Context, c *Client, username, setBy string) error {
	if !c.MayWriteLoginPolicy() {
		rows, err := c.Query(ctx, `SELECT 1 FROM user_lifecycle WHERE username = ? AND deleted_at IS NULL LIMIT 1`, username)
		if err != nil {
			return err
		}
		if len(rows) > 0 {
			return ErrLoginPolicyGateClosed
		}
		return nil
	}
	now := c.NowTS()
	stmts := enableUserStatements(c, username, setBy, now)
	stmts = append(stmts, Statement{SQL: userLifecycleUpsertSQL,
		Params: []interface{}{username, UserAttrSessionsNotBefore, nowRFC3339(), setBy, now}})
	return c.ExecuteBatch(ctx, stmts)
}

// OtherUnrestrictedAdminExists reports whether a live admin-role account
// other than username is enabled and has no expiry. Disabling or expiring an
// admin is refused unless one is, so the cluster is never left with only
// administrators who cannot log in. A read that fails is an error, not an
// answer.
func OtherUnrestrictedAdminExists(ctx context.Context, c *Client, username string) (bool, error) {
	rows, err := c.Query(ctx,
		`SELECT username FROM users WHERE role = 'admin' AND deleted_at IS NULL AND username != ?`, username)
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		l, err := GetUserLifecycle(ctx, c, r.String("username"))
		if err != nil {
			return false, err
		}
		if l.Unrestricted() {
			return true, nil
		}
	}
	return false, nil
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

// UsableAdminExists reports whether some live admin-role account can log in
// now. The admin floor raises no_unrestricted_admin while it cannot.
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
// that table's gate (failover_scope_v1) as well as this one's: the shape is
// registered, but a build that predates login_policy_v1 would read the row and
// ignore it, so it may not be written while one is listening.
//
// The policy and its self-enrollment deadline (p.SelfEnrollBy, "" for none)
// are written together, in one batch: every change of the policy restates the
// deadline, so a window is open only because the latest change opened it.
func SetTwoFactorPolicy(ctx context.Context, c *Client, p TwoFactorPolicy, setBy string) error {
	if !c.MayWriteLoginPolicy() {
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
