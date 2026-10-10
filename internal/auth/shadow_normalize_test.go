package auth

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestEnsureUserShadow_Normalizes (review I2): a directory subject is mapped
// to the account its normalized name names, and a new shadow is stored under
// the normalized name — never a second account beside the first.
func TestEnsureUserShadow_Normalizes(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser(ctx, db, "alice", "operator", ""); err != nil {
		t.Fatal(err)
	}
	p := &Principal{Subject: "ALICE", Realm: "ldap:corp"}
	if err := EnsureUserShadow(ctx, db, p, "viewer"); err != nil {
		t.Fatal(err)
	}
	if p.Subject != "alice" {
		t.Fatalf("subject after shadowing ALICE = %q, want the stored alice", p.Subject)
	}
	q := &Principal{Subject: " Bob ", Realm: "ldap:corp"}
	if err := EnsureUserShadow(ctx, db, q, "viewer"); err != nil {
		t.Fatal(err)
	}
	rows, _ := db.Query(ctx, `SELECT username FROM users WHERE username = 'bob' AND deleted_at IS NULL`)
	if q.Subject != "bob" || len(rows) != 1 {
		t.Fatalf("new shadow for %q: subject %q, rows %d; want stored as bob", " Bob ", q.Subject, len(rows))
	}
}
