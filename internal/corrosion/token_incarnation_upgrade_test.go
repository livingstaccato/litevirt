package corrosion

import (
	"context"
	"testing"
)

// Review I1, the upgrade: a schema-85 database (no tokens.user_created_at, no
// stamp trigger) reopened by this build gains the column and the trigger that
// invalidates an automation token's issuance on any write of it.
func TestTokenIncarnation_The85To86UpgradeInstallsTheStampTrigger(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := openFileClient(t, dir)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	// Put the database back to schema 85.
	for _, q := range []string{
		`DROP TRIGGER automation_issuance_tokens_stamp_update`,
		`ALTER TABLE tokens DROP COLUMN user_created_at`,
		`DELETE FROM applied_migrations WHERE id = 'a094_tokens_user_created_at'`,
		`UPDATE schema_state SET version = 85 WHERE id = 1`,
	} {
		if _, err := c.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	c.db.Close()

	c = openFileClient(t, dir)
	t.Cleanup(func() { c.db.Close() })
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema on the schema-85 database: %v", err)
	}
	if got := oneString(t, c, `SELECT CAST(COUNT(*) AS TEXT) AS n FROM sqlite_master WHERE type = 'trigger' AND name = 'automation_issuance_tokens_stamp_update'`, "n"); got != "1" {
		t.Fatalf("the stamp trigger is missing after the upgrade")
	}
	if got := oneString(t, c, `SELECT CAST(version AS TEXT) AS v FROM schema_state WHERE id = 1`, "v"); got != "87" {
		t.Errorf("schema_state.version = %s after the upgrade, want 87", got)
	}
	// It fires.
	for _, q := range []string{
		`INSERT INTO tokens (id, username, name, token_hash, created_at, updated_at, user_created_at) VALUES ('tok', 'alice', 'n', 'h', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00.5Z')`,
		`INSERT INTO local_automation_credential_issuance (kind, credential_id, username, witness, principal_uid, cluster_uid, credential_digest, valid) VALUES ('token', 'tok', 'alice', 'w', 'p', 'c', 'd', 1)`,
		`UPDATE tokens SET user_created_at = user_created_at WHERE id = 'tok'`,
	} {
		if _, err := c.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if v := oneString(t, c, `SELECT CAST(valid AS TEXT) AS v FROM local_automation_credential_issuance WHERE credential_id = 'tok'`, "v"); v != "0" {
		t.Errorf("after the upgrade, a stamp write leaves issuance.valid = %s, want 0", v)
	}
}
