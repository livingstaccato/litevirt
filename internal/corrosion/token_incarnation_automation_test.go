package corrosion

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// users-L2 composed with automation credential provenance: an automation
// token is stamped with its account's incarnation, and the account check and
// the token's local provenance commit in the one transaction.
func TestTokenIncarnation_AutomationTokenIsStampedAndCheckedWithItsProvenance(t *testing.T) {
	ctx := context.Background()
	c, authenticated := lifecycleCertifiedAccount(t)
	c.SetUserIncarnationGate(func() bool { return true })
	raw := strings.Repeat("e", 64)
	hash, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := InsertAutomationToken(ctx, c, authenticated, TokenRecord{ID: "stamped", Username: "alice", Name: "n", TokenHash: string(hash)}); err != nil {
		t.Fatalf("InsertAutomationToken: %v", err)
	}
	if got, want := oneString(t, c, `SELECT user_created_at FROM tokens WHERE id = 'stamped'`, "user_created_at"),
		userCreatedAt(t, c, "alice"); got != want {
		t.Errorf("the automation token is stamped %q, want alice's incarnation %q", got, want)
	}
	if id, err := AutomationTokenPrincipal(ctx, c, raw); err != nil || id == nil {
		t.Fatalf("AutomationTokenPrincipal: %+v, %v", id, err)
	}

	// alice's incarnation moves between the writer's read and its write:
	// nothing is written, the token nor its provenance.
	userWriteInterleaveHook = func(string) {
		userWriteInterleaveHook = nil
		if _, err := c.db.Exec(`UPDATE users SET created_at = '2999-01-01T00:00:00.5Z' WHERE username = 'alice'`); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { userWriteInterleaveHook = nil })
	err = InsertAutomationToken(ctx, c, authenticated, TokenRecord{ID: "moved", Username: "alice", Name: "n", TokenHash: string(hash)})
	if !errors.Is(err, ErrUserAccountChanged) {
		t.Fatalf("InsertAutomationToken over a moved account = %v, want ErrUserAccountChanged", err)
	}
	for _, q := range []string{
		`SELECT id FROM tokens WHERE id = 'moved'`,
		`SELECT credential_id FROM local_automation_credential_issuance WHERE credential_id = 'moved'`,
	} {
		if rows, err := c.Query(ctx, q); err != nil || len(rows) != 0 {
			t.Errorf("%s: %d rows, %v; the refused write left something behind", q, len(rows), err)
		}
	}
}

// The provenance check reads the token in its own transaction: a token whose
// incarnation the account no longer holds yields no principal there, even
// past a ValidateToken made before the account moved.
func TestTokenIncarnation_AutomationProvenanceRefusesAnotherIncarnationsToken(t *testing.T) {
	ctx := context.Background()
	c, authenticated := lifecycleCertifiedAccount(t)
	c.SetUserIncarnationGate(func() bool { return true })
	hash, err := bcrypt.GenerateFromPassword([]byte(strings.Repeat("f", 64)), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := InsertAutomationToken(ctx, c, authenticated, TokenRecord{ID: "tok", Username: "alice", Name: "n", TokenHash: string(hash)}); err != nil {
		t.Fatal(err)
	}
	if id, err := automationCredentialPrincipal(ctx, c, "token", "tok"); err != nil || id == nil {
		t.Fatalf("provenance of alice's own token: %+v, %v", id, err)
	}
	if _, err := c.db.Exec(`UPDATE tokens SET user_created_at = '2000-01-01T00:00:00.5Z' WHERE id = 'tok'`); err != nil {
		t.Fatal(err)
	}
	if id, err := automationCredentialPrincipal(ctx, c, "token", "tok"); err == nil || id != nil {
		t.Errorf("provenance of another incarnation's token = %+v, %v; want refused", id, err)
	}
}
