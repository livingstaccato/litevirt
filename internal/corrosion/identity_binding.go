package corrosion

// Directory identity bindings (schema v64, user_identity_bindings;
// t1-auth-rereview-2 N5).
//
// An external-realm account is named by the user's normalized typed login
// name, as it always was, so no account is re-keyed on upgrade. What makes
// that name safe is this binding: the account is bound to the directory
// entry's immutable id (LDAP entryUUID / objectGUID / nsUniqueId, else its
// DN; OIDC issuer + sub) on its first login after the upgrade — positive
// evidence: the realm name-matched the entry, and the account was not yet
// bound — and every later login through an entry with another id is refused.
// One id is never bound to two accounts of one realm.
//
// Written only once login_policy_v1 has latched (the same gate as
// user_lifecycle); before that, logins proceed unbound, as on main. Repaired
// by anti-entropy. An administrator clears a binding when the directory
// re-creates an entry (`lv user unbind`).

import (
	"context"
	"errors"
)

const identityBindingUpsertSQL = `INSERT INTO user_identity_bindings (username, realm, external_id, bound_at, updated_at, deleted_at)
	 VALUES (?, ?, ?, ?, ?, NULL)
	 ON CONFLICT(username, realm) DO UPDATE SET external_id = excluded.external_id, bound_at = excluded.bound_at,
	   updated_at = excluded.updated_at, deleted_at = NULL`

const identityBindingClearSQL = `UPDATE user_identity_bindings SET deleted_at = ?, updated_at = ?
	 WHERE username = ? AND realm = ? AND deleted_at IS NULL`

const identityBindingClearAllSQL = `UPDATE user_identity_bindings SET deleted_at = ?, updated_at = ?
	 WHERE username = ? AND deleted_at IS NULL`

// ErrIdentityBindingConflict is returned by BindIdentity when the id is
// already bound to another account of the realm.
var ErrIdentityBindingConflict = errors.New("directory identity already bound to another account")

// GetIdentityBinding returns the external id username is bound to in realm,
// "" when it is unbound. A read that fails is an error, never "".
func GetIdentityBinding(ctx context.Context, c *Client, username, realm string) (string, error) {
	rows, err := c.Query(ctx,
		`SELECT external_id FROM user_identity_bindings WHERE username = ? AND realm = ? AND deleted_at IS NULL`,
		username, realm)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", nil
	}
	return rows[0].String("external_id"), nil
}

// AccountsBoundTo lists the accounts of realm bound to external id.
func AccountsBoundTo(ctx context.Context, c *Client, realm, externalID string) ([]string, error) {
	rows, err := c.Query(ctx,
		`SELECT username FROM user_identity_bindings WHERE realm = ? AND external_id = ? AND deleted_at IS NULL`,
		realm, externalID)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.String("username")
	}
	return out, nil
}

// BindIdentity binds username in realm to externalID. It refuses
// (ErrIdentityBindingConflict) when the id is bound to another account, and
// returns ErrLoginPolicyGateClosed before the latch.
func BindIdentity(ctx context.Context, c *Client, username, realm, externalID string) error {
	if !c.MayWriteLoginPolicy() {
		return ErrLoginPolicyGateClosed
	}
	others, err := AccountsBoundTo(ctx, c, realm, externalID)
	if err != nil {
		return err
	}
	for _, o := range others {
		if o != username {
			return ErrIdentityBindingConflict
		}
	}
	return c.Execute(ctx, identityBindingUpsertSQL, username, realm, externalID, nowRFC3339(), c.NowTS())
}

// ClearIdentityBinding drops username's binding in realm.
func ClearIdentityBinding(ctx context.Context, c *Client, username, realm string) error {
	if !c.MayWriteLoginPolicy() {
		return ErrLoginPolicyGateClosed
	}
	return c.Execute(ctx, identityBindingClearSQL, nowRFC3339(), c.NowTS(), username, realm)
}

// clearIdentityBindingsStatement drops every binding of username: DeleteUser's
// batch, so a name re-created later binds afresh.
func clearIdentityBindingsStatement(username, now string) Statement {
	return Statement{SQL: identityBindingClearAllSQL, Params: []interface{}{nowRFC3339(), now, username}}
}
