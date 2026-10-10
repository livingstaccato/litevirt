package corrosion

// Directory identity bindings (schema v64, user_identity_bindings;
// t1-auth-rereview-2 N5, re-review 3 m-1).
//
// An external-realm account is named by the user's normalized typed login
// name, as it always was, so no account is re-keyed on upgrade. What makes
// that name safe is this binding: the account is bound to the directory
// entry's immutable id (LDAP entryUUID / objectGUID / nsUniqueId, else its
// DN; OIDC issuer + sub) on its first login after the upgrade — positive
// evidence: the realm name-matched the entry, and the account was not yet
// bound — and every later login through an entry with another id is refused.
//
// FIRST BINDER WINS (re-review 3, m-1). A binding is never overwritten: each
// bound id is its own row, keyed (username, realm, external_id), so a node
// that had not received an account's binding — lag, a partition — and bound
// the entry that logged in through it adds a SECOND row beside the first
// instead of replacing it under last-writer-wins. Every reader resolves the
// rows the same way (ResolveIdentityBinding): the binding with the earliest
// bound_at holds when every other one was made more than the skew margin
// after it; bindings closer together than clocks can order are a conflict
// nobody wins, and the account's logins through that realm are refused until
// an administrator runs `lv user unbind`. The login handler audits every
// conflict it sees (auth.identity_conflict). The same rule decides between two
// accounts bound to one id (IdentityOwner).
//
// Written only once login_policy_v1 has latched (the same gate as
// user_lifecycle); before that, logins proceed unbound, as on main. Repaired
// by anti-entropy. Cleared one row at a time (re-review 3, m-8).

import (
	"context"
	"errors"
	"sort"
	"time"
)

const identityBindingUpsertSQL = `INSERT INTO user_identity_bindings (username, realm, external_id, bound_at, updated_at, deleted_at)
	 VALUES (?, ?, ?, ?, ?, NULL)
	 ON CONFLICT(username, realm, external_id) DO UPDATE SET bound_at = excluded.bound_at,
	   updated_at = excluded.updated_at, deleted_at = NULL`

const identityBindingClearSQL = `UPDATE user_identity_bindings SET deleted_at = ?, updated_at = ?
	 WHERE username = ? AND realm = ? AND external_id = ?`

// ErrIdentityBindingConflict is returned by BindIdentity when the id is
// already bound to another account of the realm.
var ErrIdentityBindingConflict = errors.New("directory identity already bound to another account")

// IdentityBinding is one bound id of an account in a realm.
type IdentityBinding struct {
	Username   string
	Realm      string
	ExternalID string
	BoundAt    string
}

// IdentityResolution is how the bindings of one account in one realm (or of
// one id across accounts) resolve.
type IdentityResolution struct {
	// Winner is the binding that holds; zero when there is none or Conflict.
	Winner IdentityBinding
	// Conflict: two or more bindings, and no earliest one by more than the
	// skew margin. Nobody wins until an administrator unbinds.
	Conflict bool
	// All is every live binding considered, earliest first.
	All []IdentityBinding
}

// Contested reports whether more than one binding was considered: a conflict,
// resolved or not, that the login handler audits.
func (r IdentityResolution) Contested() bool { return len(r.All) > 1 }

// IDs lists the external ids of r.All.
func (r IdentityResolution) IDs() []string {
	out := make([]string, len(r.All))
	for i, b := range r.All {
		out[i] = b.ExternalID
	}
	return out
}

// resolveBindings applies first-binder-wins to bs. A binding whose bound_at
// does not parse sorts first and wins nothing alone: it fails closed into a
// conflict when contested.
func resolveBindings(bs []IdentityBinding) IdentityResolution {
	r := IdentityResolution{All: bs}
	if len(bs) == 0 {
		return r
	}
	at := func(b IdentityBinding) (time.Time, bool) {
		t, err := time.Parse(time.RFC3339, b.BoundAt)
		return t, err == nil
	}
	sort.SliceStable(bs, func(i, j int) bool {
		ti, oki := at(bs[i])
		tj, okj := at(bs[j])
		if oki != okj {
			return !oki
		}
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		if bs[i].Username != bs[j].Username {
			return bs[i].Username < bs[j].Username
		}
		return bs[i].ExternalID < bs[j].ExternalID
	})
	if len(bs) == 1 {
		r.Winner = bs[0]
		return r
	}
	first, ok := at(bs[0])
	if !ok {
		r.Conflict = true
		return r
	}
	for _, b := range bs[1:] {
		t, ok := at(b)
		if !ok || !t.After(first.Add(SessionCutoffSkewMargin)) {
			r.Conflict = true
			return r
		}
	}
	r.Winner = bs[0]
	return r
}

func queryBindings(ctx context.Context, c *Client, where string, args ...interface{}) ([]IdentityBinding, error) {
	rows, err := c.Query(ctx,
		`SELECT username, realm, external_id, bound_at FROM user_identity_bindings WHERE deleted_at IS NULL AND `+where, args...)
	if err != nil {
		return nil, err
	}
	out := make([]IdentityBinding, len(rows))
	for i, r := range rows {
		out[i] = IdentityBinding{Username: r.String("username"), Realm: r.String("realm"),
			ExternalID: r.String("external_id"), BoundAt: r.String("bound_at")}
	}
	return out, nil
}

// ResolveIdentityBinding resolves username's bindings in realm. A read that
// fails is an error, never "unbound".
func ResolveIdentityBinding(ctx context.Context, c *Client, username, realm string) (IdentityResolution, error) {
	bs, err := queryBindings(ctx, c, `username = ? AND realm = ?`, username, realm)
	if err != nil {
		return IdentityResolution{}, err
	}
	return resolveBindings(bs), nil
}

// IdentityOwner resolves which account of realm owns external id: the
// earliest binding of it, by the same rule.
func IdentityOwner(ctx context.Context, c *Client, realm, externalID string) (IdentityResolution, error) {
	bs, err := queryBindings(ctx, c, `realm = ? AND external_id = ?`, realm, externalID)
	if err != nil {
		return IdentityResolution{}, err
	}
	return resolveBindings(bs), nil
}

// GetIdentityBinding returns the external id username is bound to in realm:
// the winning binding's, "" when it is unbound or its bindings conflict. A
// read that fails is an error, never "".
func GetIdentityBinding(ctx context.Context, c *Client, username, realm string) (string, error) {
	r, err := ResolveIdentityBinding(ctx, c, username, realm)
	if err != nil {
		return "", err
	}
	return r.Winner.ExternalID, nil
}

// AccountsBoundTo lists the accounts of realm bound to external id.
func AccountsBoundTo(ctx context.Context, c *Client, realm, externalID string) ([]string, error) {
	bs, err := queryBindings(ctx, c, `realm = ? AND external_id = ?`, realm, externalID)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = b.Username
	}
	return out, nil
}

// BindIdentity binds username in realm to externalID. It refuses
// (ErrIdentityBindingConflict) when the id is bound to another account, and
// returns ErrLoginPolicyGateClosed before the latch. It only ever ADDS a row:
// a binding another node made first is never overwritten (m-1).
func BindIdentity(ctx context.Context, c *Client, username, realm, externalID string) error {
	if !c.MayWriteLoginPolicy() {
		return ErrLoginPolicyGateClosed
	}
	others, err := AccountsBoundTo(ctx, c, realm, externalID)
	if err != nil {
		return err
	}
	for _, o := range others {
		if NormalizeUsername(o) != NormalizeUsername(username) {
			return ErrIdentityBindingConflict
		}
	}
	return c.Execute(ctx, identityBindingUpsertSQL, username, realm, externalID, nowRFC3339(), c.NowTS())
}

// ClearIdentityBinding drops every binding username has in realm, one row at a
// time, and returns the ids it cleared.
func ClearIdentityBinding(ctx context.Context, c *Client, username, realm string) ([]string, error) {
	if !c.MayWriteLoginPolicy() {
		return nil, ErrLoginPolicyGateClosed
	}
	bs, err := queryBindings(ctx, c, `username = ? AND realm = ?`, username, realm)
	if err != nil {
		return nil, err
	}
	if len(bs) == 0 {
		return nil, nil
	}
	marker, now := nowRFC3339(), c.NowTS()
	stmts := make([]Statement, 0, len(bs))
	ids := make([]string, 0, len(bs))
	for _, b := range bs {
		stmts = append(stmts, Statement{SQL: identityBindingClearSQL, Params: []interface{}{marker, now, b.Username, b.Realm, b.ExternalID}})
		ids = append(ids, b.ExternalID)
	}
	return ids, c.ExecuteBatch(ctx, stmts)
}

// restoreDeletedBindingsStatements revives the bindings of username that its
// delete cleared — tombstoned at deletedAt, the users row's own marker — with
// their original bound_at, so first-binder order is unchanged. It is the admin
// floor's for an external admin it reinstates: the account comes back bound
// to the directory entry it was bound to, not open to the next entry that
// answers to its name.
func restoreDeletedBindingsStatements(ctx context.Context, c *Client, username, deletedAt, now string) ([]Statement, error) {
	rows, err := c.Query(ctx,
		`SELECT realm, external_id, bound_at FROM user_identity_bindings WHERE username = ? AND deleted_at = ?`,
		username, deletedAt)
	if err != nil {
		return nil, err
	}
	stmts := make([]Statement, 0, len(rows))
	for _, r := range rows {
		stmts = append(stmts, Statement{SQL: identityBindingUpsertSQL,
			Params: []interface{}{username, r.String("realm"), r.String("external_id"), r.String("bound_at"), now}})
	}
	return stmts, nil
}

// ClearIdentityBindingRows tombstones exactly the bindings bs, one row each:
// the later bindings of a conflict the first-binder rule decided, cleared by a
// login through the binding that won.
func ClearIdentityBindingRows(ctx context.Context, c *Client, bs []IdentityBinding) error {
	if !c.MayWriteLoginPolicy() {
		return ErrLoginPolicyGateClosed
	}
	marker, now := nowRFC3339(), c.NowTS()
	stmts := make([]Statement, 0, len(bs))
	for _, b := range bs {
		stmts = append(stmts, Statement{SQL: identityBindingClearSQL, Params: []interface{}{marker, now, b.Username, b.Realm, b.ExternalID}})
	}
	return c.ExecuteBatch(ctx, stmts)
}

// clearIdentityBindingsStatements drops every binding of username, one row at
// a time (re-review 3, m-8): DeleteUser's batch, so a name re-created later
// binds afresh. marker is the delete's own deleted_at, so the admin floor can
// find exactly the bindings a delete cleared when it reinstates an external
// admin (restoreDeletedBindingsStatements).
func clearIdentityBindingsStatements(ctx context.Context, c *Client, username, marker, now string) ([]Statement, error) {
	bs, err := queryBindings(ctx, c, `username = ?`, username)
	if err != nil {
		return nil, err
	}
	stmts := make([]Statement, 0, len(bs))
	for _, b := range bs {
		stmts = append(stmts, Statement{SQL: identityBindingClearSQL, Params: []interface{}{marker, now, b.Username, b.Realm, b.ExternalID}})
	}
	return stmts, nil
}
