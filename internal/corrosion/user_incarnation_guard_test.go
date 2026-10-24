package corrosion

import (
	"errors"
	"testing"
)

// A user_incarnation_v1 guard binds exactly the account its statement
// writes: a guard naming another account, a guard on a statement it has no
// binding rule for, and an entry mixing guard identities are refused on
// receipt, before anything applies.
func TestValidateUserIncarnationEntry(t *testing.T) {
	g := &MutationGuard{Protocol: userIncarnationGuardV1, ResourceKind: userGuardLive, ResourceID: "carol", Incarnation: "2026-10-19T00:00:00.5Z"}
	other := *g
	other.ResourceID = "dave"
	pw := func(user string, guard *MutationGuard) Statement {
		return Statement{SQL: usersUpdatePasswordSQL, Params: []interface{}{"h", "ts", user}, Guard: guard}
	}
	cred := Statement{SQL: userCredentialUpsertSQL, Params: []interface{}{"carol", "h", "ts"}, Guard: g}
	for _, tc := range []struct {
		name  string
		stmts []Statement
		ok    bool
	}{
		{"a password change and its credential", []Statement{pw("carol", g), cred}, true},
		{"beside an unguarded revocation", []Statement{pw("carol", g),
			{SQL: `UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, Params: []interface{}{"x", "s1"}}}, true},
		{"a guard naming another account", []Statement{pw("carol", &other)}, false},
		{"two guard identities", []Statement{pw("carol", g), {SQL: userCredentialUpsertSQL, Params: []interface{}{"dave", "h", "ts"}, Guard: &other}}, false},
		{"a statement the guard has no rule for", []Statement{{SQL: `UPDATE users SET deleted_at = ?, updated_at = ? WHERE username = ?`,
			Params: []interface{}{"x", "ts", "carol"}, Guard: g}}, false},
		{"mixed with a workload guard", []Statement{pw("carol", g), {SQL: usersUpdatePasswordSQL, Params: []interface{}{"h", "ts", "carol"},
			Guard: &MutationGuard{Protocol: workloadDeleteGuardV1, ResourceID: "carol"}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateGuardedMutationEntry(tc.stmts)
			if tc.ok && err != nil {
				t.Fatalf("refused a well-formed entry: %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrInvalidStmt) {
				t.Fatalf("err = %v, want ErrInvalidStmt", err)
			}
		})
	}
}
