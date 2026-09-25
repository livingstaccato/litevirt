package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"golang.org/x/crypto/bcrypt"
)

// The 2FA gate is the only thing standing between a stolen password and a
// session: grpcapi.Login reads Principal.Requires2FA and nothing else. Deciding
// it from a read that may have failed means a transient database error — a busy
// write lock, an I/O error — silently downgrades an enrolled account to
// password-only, which is exactly the condition an attacker holding the password
// benefits from.
//
// The table is dropped here to make the read fail deterministically; any error
// from it must reach the caller rather than being folded into "no factors".
func TestLocalRealm_A2FAReadThatFailsDeniesRatherThanDowngrades(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-horse"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	if err := corrosion.InsertUser(ctx, db, "alice", "operator", string(hash)); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if err := db.Execute(ctx, `DROP TABLE user_2fa`); err != nil {
		t.Fatalf("DROP TABLE user_2fa: %v", err)
	}

	realm := NewLocalRealm(db)
	p, err := realm.Authenticate(ctx, Credentials{Username: "alice", Password: "correct-horse"})

	if err == nil {
		t.Fatalf("Authenticate succeeded with an unreadable 2FA table; principal = %+v "+
			"(Requires2FA=%v) — a failed enrollment lookup must not read as 'no factors enrolled'",
			p, p != nil && p.Requires2FA)
	}
	if strings.Contains(strings.ToLower(err.Error()), "invalid") {
		t.Errorf("error = %v; want one that names the lookup failure, not a credential rejection", err)
	}
}

// The ordinary path must still work: a user with no enrolled factor
// authenticates and is not asked for one.
func TestLocalRealm_NoEnrolledFactorStillAuthenticates(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct-horse"), bcrypt.DefaultCost)
	if err := corrosion.InsertUser(ctx, db, "bob", "operator", string(hash)); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}

	p, err := NewLocalRealm(db).Authenticate(ctx, Credentials{Username: "bob", Password: "correct-horse"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.Requires2FA {
		t.Error("Requires2FA = true for a user with no enrolled factor")
	}
}

// TestLocalRealm_UnhydratedCredentialsRefuse is the same downgrade reached by a
// different route.
//
// A reseed DELETEs the secret-bearing tables and repopulates them from a peer.
// Between those two steps -- or permanently, if the sensitive merge fails --
// user_2fa is readable and EMPTY, which ListUser2FA reports as "no factors
// enrolled". The table is not unreadable, so the check above does not fire, and
// every enrolled operator authenticates with a password alone on that node.
//
// The discard marks the node unhydrated and only a landed sensitive merge
// clears it; while it is set, this must refuse rather than downgrade.
func TestLocalRealm_UnhydratedCredentialsRefuse(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct-horse"), bcrypt.DefaultCost)
	if err := corrosion.InsertUser(ctx, db, "carol", "admin", string(hash)); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}

	// The state a half-finished reseed leaves: users populated, secrets empty.
	db.MarkCredentialsUnhydrated()

	p, err := NewLocalRealm(db).Authenticate(ctx, Credentials{Username: "carol", Password: "correct-horse"})
	if err == nil {
		t.Fatalf("an admin authenticated against a node whose credential tables are not "+
			"hydrated; principal = %+v (Requires2FA=%v) — an empty user_2fa is not proof "+
			"that the account has no second factor", p, p != nil && p.Requires2FA)
	}

	// And the ordinary path returns once the merge lands.
	db.ClearCredentialsUnhydrated()
	if _, err := NewLocalRealm(db).Authenticate(ctx, Credentials{Username: "carol", Password: "correct-horse"}); err != nil {
		t.Fatalf("a hydrated node refused a valid login: %v", err)
	}
}
