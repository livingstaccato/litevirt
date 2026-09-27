package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func shadowTestDB(t *testing.T) *corrosion.Client {
	t.Helper()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return db
}

// users is keyed on username alone, so one name exists once across every realm.
// EnsureUserShadow looked up only the name and returned success when a row
// existed — so an account in a configured LDAP or OIDC realm whose subject
// matches a local administrator reused that administrator's ROW, and mintSession
// then handed back its role. An external directory the local cluster does not
// control could therefore mint a local admin session with neither the local
// password nor the local second factor.
func TestEnsureUserShadow_RefusesToAdoptAnotherRealmsUser(t *testing.T) {
	ctx := context.Background()
	db := shadowTestDB(t)
	if err := corrosion.InsertUser(ctx, db, "admin", "admin", "local-hash"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}

	err := EnsureUserShadow(ctx, db, &Principal{Subject: "admin", Realm: "ldap:corp"}, "viewer")

	if err == nil {
		t.Fatal("an ldap principal named \"admin\" adopted the LOCAL admin's row; its session " +
			"will carry that row's role, so an external directory can mint a local admin " +
			"without the local password or second factor")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "realm") {
		t.Errorf("error = %q; it must name the realm collision so an operator can act on it", err)
	}
}

// The ordinary path still works: a genuinely new external subject is shadowed.
func TestEnsureUserShadow_ShadowsANewExternalSubject(t *testing.T) {
	ctx := context.Background()
	db := shadowTestDB(t)

	if err := EnsureUserShadow(ctx, db, &Principal{Subject: "newcomer", Realm: "ldap:corp"}, "viewer"); err != nil {
		t.Fatalf("EnsureUserShadow for a fresh external subject: %v", err)
	}
	u, err := corrosion.GetUser(ctx, db, "newcomer")
	if err != nil || u == nil {
		t.Fatalf("shadow row not created: %v", err)
	}
	if u.Role != "viewer" {
		t.Errorf("role = %q, want viewer", u.Role)
	}
}

// And a repeat login from the SAME realm is still a no-op, not a refusal.
func TestEnsureUserShadow_IsIdempotentWithinOneRealm(t *testing.T) {
	ctx := context.Background()
	db := shadowTestDB(t)
	p := &Principal{Subject: "repeat", Realm: "ldap:corp"}

	if err := EnsureUserShadow(ctx, db, p, "viewer"); err != nil {
		t.Fatalf("first shadow: %v", err)
	}
	if err := EnsureUserShadow(ctx, db, p, "viewer"); err != nil {
		t.Fatalf("second login from the same realm was refused: %v", err)
	}
}
