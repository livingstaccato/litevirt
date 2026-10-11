package corrosion

// The merge of fix/credentials-clear and feat/login-policy: the semantic
// conflicts git does not flag (progress.md MERGE-TIME CHECKLIST M1, M2, M5).

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// M1 (defence in depth): UserLocalCredential's caller holds a live row, so
// no live row under exactly the name it was given means another spelling —
// never "known, and external".
func TestUserLocalCredential_NoLiveRowIsUnknown(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	openClearGates(c)
	if err := InsertUser(ctx, c, "ops", "admin", "$2a$10$ops"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Ops", "nobody"} {
		if local, known, err := UserLocalCredential(ctx, c, name); err != nil || known || local {
			t.Errorf("UserLocalCredential(%q) = local %v known %v err %v; no live row under that exact "+
				"name must read as unknown, never as a known external user", name, local, known, err)
		}
	}
}

// M2: the delete RPC calls DeleteUserCounted directly, so the forget of a
// recorded external shadow lives there, not in the DeleteUser wrapper.
func TestDeleteUserCounted_ForgetsTheExternalShadow(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	if err := InsertUser(ctx, c, "ext", "viewer", ""); err != nil {
		t.Fatal(err)
	}
	id := userIdentity{Username: "ext", CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z"}
	c.noteExternalShadow(id)
	if !c.externalEvidence(id) {
		t.Fatal("the noted shadow is not evidence; the rest is vacuous")
	}
	if _, _, err := DeleteUserCounted(ctx, c, capabilities.FeatureGrant{}, "ext"); err != nil {
		t.Fatal(err)
	}
	if c.externalEvidence(id) {
		t.Error("DeleteUserCounted left the deleted account's external-shadow evidence behind")
	}
}

// floorDeletedAdmin writes a deleted admin row as a replica holds it after
// credentials_clear_v1: an empty old column, and the credential row only when
// cred is non-nil.
func floorDeletedAdmin(t *testing.T, c *Client, name string, cred *string) {
	t.Helper()
	ctx := context.Background()
	if err := c.execLocal(ctx, `INSERT INTO users (username, role, password_hash, created_at, updated_at, deleted_at)
		VALUES (?, 'admin', '', '2026-01-01T00:00:00Z', '2026-01-02T00:00:00.000000001Z', '2026-01-02T00:00:00Z')`, name); err != nil {
		t.Fatal(err)
	}
	if cred != nil {
		if err := c.execLocal(ctx, `INSERT INTO user_credentials (username, password_hash, updated_at)
			VALUES (?, ?, '2026-01-01T00:00:00Z')`, name, *cred); err != nil {
			t.Fatal(err)
		}
	}
}

// M5: a cleared LOCAL admin whose credential row this replica has not
// received is reinstated LOCAL, with the sentinel — never as an external
// admin with an empty credential row, which the first directory login under
// its name would adopt (t1-auth-rereview-4 IM-1, hazard A).
func TestAdminFloor_ALocalAdminWithItsCredentialRowWithheldStaysLocal(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	openClearGates(c)
	floorDeletedAdmin(t, c, "ops", nil)

	who, err := ReinstateAdminIfNoneRemain(ctx, c, nil)
	if err != nil || who != "ops" {
		t.Fatalf("ReinstateAdminIfNoneRemain = %q, %v; want ops", who, err)
	}
	if got := oneString(t, c, `SELECT password_hash FROM user_credentials WHERE username = 'ops' AND deleted_at IS NULL`, "password_hash"); got != ReinstatedAdminPasswordHash {
		t.Errorf("the reinstated local admin's credential row = %q, want the sentinel %q: an empty row makes it "+
			"an external account any directory login under its name adopts", got, ReinstatedAdminPasswordHash)
	}
	if local, known, err := UserLocalCredential(ctx, c, "ops"); err != nil || !known || !local {
		t.Errorf("UserLocalCredential(ops) after the floor = local %v known %v err %v, want a known local account", local, known, err)
	}
	if note := AdminReinstatementNote(ctx, c, "ops"); !strings.Contains(note, "reset-admin --user ops") {
		t.Errorf("AdminReinstatementNote = %q; a local reinstatement must name reset-admin --user", note)
	}
}

// M5: an external admin whose empty credential row this replica holds stays
// external, and the note says so.
func TestAdminFloor_AMaterialisedExternalAdminStaysExternal(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	openClearGates(c)
	empty := ""
	floorDeletedAdmin(t, c, "ext", &empty)

	who, err := ReinstateAdminIfNoneRemain(ctx, c, nil)
	if err != nil || who != "ext" {
		t.Fatalf("ReinstateAdminIfNoneRemain = %q, %v; want ext", who, err)
	}
	if got := oneString(t, c, `SELECT password_hash FROM user_credentials WHERE username = 'ext' AND deleted_at IS NULL`, "password_hash"); got != "" {
		t.Errorf("the reinstated external admin's credential row = %q, want \"\" (it logs in through its directory)", got)
	}
	if u, _ := GetUser(ctx, c, "ext"); u == nil || u.PasswordHash != "" {
		t.Errorf("GetUser(ext) = %+v; want it external, with no local password", u)
	}
	if note := AdminReinstatementNote(ctx, c, "ext"); !strings.Contains(note, "external") {
		t.Errorf("AdminReinstatementNote = %q; an external reinstatement must say it stays external", note)
	}
}

// M4: `lv user mark-external` resolves the name as every account lookup does,
// normalized, and marks the account under its stored name — an operator who
// types `EXT` for the account `ext` is not told it does not exist.
func TestMarkUserExternal_ResolvesTheNormalizedName(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	openClearGates(c)
	if err := c.execLocal(ctx, `INSERT INTO users (username, role, password_hash, created_at, updated_at)
		VALUES ('ext', 'viewer', '', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00.000000001Z')`); err != nil {
		t.Fatal(err)
	}
	if _, known, _ := UserLocalCredential(ctx, c, "ext"); known {
		t.Fatal("ext is already judged; the rest is vacuous")
	}
	if err := MarkUserExternal(ctx, c, " EXT "); err != nil {
		t.Fatalf("MarkUserExternal(%q) = %v, want the account ext marked", " EXT ", err)
	}
	if local, known, err := UserLocalCredential(ctx, c, "ext"); err != nil || !known || local {
		t.Errorf("after the mark, UserLocalCredential(ext) = local %v known %v err %v, want a known external user", local, known, err)
	}
}

// M5: AdminReinstatementNote judges as the floor does, from the credential
// row: a reinstated admin whose credential row this replica lacks (old column
// "" after the clear) is not told it is an external admin.
func TestAdminReinstatementNote_NoCredentialRowIsNotExternal(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	openClearGates(c)
	if err := c.execLocal(ctx, `INSERT INTO users (username, role, password_hash, created_at, updated_at)
		VALUES ('ops', 'admin', '', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00.000000001Z')`); err != nil {
		t.Fatal(err)
	}
	if note := AdminReinstatementNote(ctx, c, "ops"); !strings.Contains(note, "reset-admin --user ops") {
		t.Errorf("AdminReinstatementNote = %q; with no credential row the floor reinstates the account local, "+
			"and the note must name reset-admin --user", note)
	}
}
