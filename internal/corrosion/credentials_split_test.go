package corrosion

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// credentialTables are the v56 sensitive-lane tables the split writes.
var credentialTables = []string{"host_fence_credentials", "user_credentials", "token_credentials"}

// seedSecrets writes one of each secret the way the daemon does: a user
// through InsertUser, a token through InsertToken, and a BMC password through
// the hosts UPDATE ConfigureHost emits (grpcapi owns that statement; this is
// its column effect).
func seedSecrets(t *testing.T, c *Client, userHash, tokenHash, ipmiPass string) {
	t.Helper()
	ctx := context.Background()
	if err := InsertUser(ctx, c, "alice", "operator", userHash); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if err := InsertToken(ctx, c, TokenRecord{ID: "tok-1", Username: "alice", Name: "ci", TokenHash: tokenHash}); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}
	if err := InsertHost(ctx, c, HostRecord{Name: "bmc-host", Address: "10.0.0.20", State: "active"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := c.Execute(ctx, `UPDATE hosts SET fence_strategy = 'ipmi', ipmi_address = '10.0.1.20', ipmi_user = 'root', ipmi_pass = ?, updated_at = ? WHERE name = 'bmc-host'`,
		ipmiPass, c.NowTS()); err != nil {
		t.Fatalf("set ipmi_pass: %v", err)
	}
}

func mutationLogText(t *testing.T, c *Client) string {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT stmts FROM mutation_log ORDER BY seq`)
	if err != nil {
		t.Fatalf("read mutation_log: %v", err)
	}
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r.String("stmts"))
		b.WriteByte('\n')
	}
	return b.String()
}

// TestCredentialsSplit_UnlatchedEmitsNothingAPreviousReleaseCannotDecode is the
// rolling-upgrade half: until credentials_split_v1 latches, nothing may reach
// the replication stream that names a credential table, and every secret
// stays where a previous-release node reads it.
func TestCredentialsSplit_UnlatchedEmitsNothingAPreviousReleaseCannotDecode(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	if c.MayWriteCredentialTables() {
		t.Fatal("the credentials split gate is open on a client nobody wired; it must fail closed")
	}
	seedSecrets(t, c, "$2a$10$alicehash", "$2a$10$tokenhash", "bmc-secret")
	if err := UpdateUserPassword(ctx, c, "alice", "$2a$10$alicehash2"); err != nil {
		t.Fatal(err)
	}
	if rep, err := c.SplitCredentials(ctx); err != nil || rep.Copied != 0 {
		t.Fatalf("an unlatched split pass did work: %+v err=%v", rep, err)
	}

	log := mutationLogText(t, c)
	for _, tbl := range credentialTables {
		if strings.Contains(log, tbl) {
			t.Errorf("an unlatched node put a %s statement on the replication stream. A "+
				"previous-release peer has no ledger entry for it, so its apply fails closed and "+
				"its watermark stalls:\n%s", tbl, log)
		}
		if n := tableCount(t, c, tbl); n != 0 {
			t.Errorf("%s holds %d rows before the latch", tbl, n)
		}
	}

	// What a previous-release node reads: the old columns.
	if got := oneString(t, c, `SELECT password_hash FROM users WHERE username = 'alice'`, "password_hash"); got != "$2a$10$alicehash2" {
		t.Errorf("users.password_hash = %q; an old-build reader would not see the current password", got)
	}
	if got := oneString(t, c, `SELECT token_hash FROM tokens WHERE id = 'tok-1'`, "token_hash"); got != "$2a$10$tokenhash" {
		t.Errorf("tokens.token_hash = %q", got)
	}
	if got := oneString(t, c, `SELECT ipmi_pass FROM hosts WHERE name = 'bmc-host'`, "ipmi_pass"); got != "bmc-secret" {
		t.Errorf("hosts.ipmi_pass = %q", got)
	}
	// And this build's readers fall back to them.
	if u, _ := GetUser(ctx, c, "alice"); u == nil || u.PasswordHash != "$2a$10$alicehash2" {
		t.Errorf("GetUser = %+v; the fallback to the old column is broken", u)
	}
	if h, _ := GetHost(ctx, c, "bmc-host"); h == nil || h.IPMIPass != "bmc-secret" {
		t.Errorf("GetHost = %+v; the fence would run without its password", h)
	}
}

// TestCredentialsSplit_LatchedCopiesAndDualWrites: once the gate opens the
// pass copies every old-column secret into its credential table, idempotently,
// and leaves the old column alone; every writer from then on writes BOTH the
// credential row and the old column.
func TestCredentialsSplit_LatchedCopiesAndDualWrites(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedSecrets(t, c, "$2a$10$alicehash", "$2a$10$tokenhash", "bmc-secret")

	srcTS := oneString(t, c, `SELECT updated_at FROM users WHERE username = 'alice'`, "updated_at")
	c.SetCredentialsSplitGate(func() bool { return true })
	rep, err := c.SplitCredentials(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Copied != 3 {
		t.Fatalf("pass = %+v, want 3 copied (one per table)", rep)
	}
	for _, q := range []struct{ query, col, want string }{
		{`SELECT ipmi_pass FROM host_fence_credentials WHERE host_name = 'bmc-host'`, "ipmi_pass", "bmc-secret"},
		{`SELECT password_hash FROM user_credentials WHERE username = 'alice'`, "password_hash", "$2a$10$alicehash"},
		{`SELECT token_hash FROM token_credentials WHERE token_id = 'tok-1'`, "token_hash", "$2a$10$tokenhash"},
	} {
		if got := oneString(t, c, q.query, q.col); got != q.want {
			t.Errorf("%s = %q, want %q", q.query, got, q.want)
		}
	}
	// The copy carries the parent's updated_at, so two nodes copying the same
	// parent write the same row.
	if cp := oneString(t, c, `SELECT updated_at FROM user_credentials WHERE username = 'alice'`, "updated_at"); cp != srcTS {
		t.Errorf("copied credential stamped %q, parent row %q; per-node stamps race instead of converging", cp, srcTS)
	}
	if rep, err := c.SplitCredentials(ctx); err != nil || rep.Copied != 0 {
		t.Fatalf("a second pass copied again: %+v err=%v — the pass must be idempotent", rep, err)
	}

	// After the latch: a password change lands in both copies.
	if err := UpdateUserPassword(ctx, c, "alice", "$2a$10$alicehash2"); err != nil {
		t.Fatal(err)
	}
	if got := oneString(t, c, `SELECT password_hash FROM user_credentials WHERE username = 'alice'`, "password_hash"); got != "$2a$10$alicehash2" {
		t.Errorf("user_credentials after a latched password change = %q", got)
	}
	if err := InsertUser(ctx, c, "bob", "viewer", "$2a$10$bobhash"); err != nil {
		t.Fatal(err)
	}
	if got := oneString(t, c, `SELECT password_hash FROM user_credentials WHERE username = 'bob'`, "password_hash"); got != "$2a$10$bobhash" {
		t.Errorf("user_credentials for a user created after the latch = %q", got)
	}
	for u, want := range map[string]string{"alice": "$2a$10$alicehash2", "bob": "$2a$10$bobhash"} {
		if got := oneString(t, c, `SELECT password_hash FROM users WHERE username = ?`, "password_hash", u); got != want {
			t.Errorf("users.password_hash for %s = %q after the latch, want %q; a host rolled back one "+
				"release reads only this column", u, got, want)
		}
	}
	if err := InsertToken(ctx, c, TokenRecord{ID: "tok-2", Username: "bob", Name: "x", TokenHash: "$2a$10$tok2"}); err != nil {
		t.Fatal(err)
	}
	if got := oneString(t, c, `SELECT token_hash FROM token_credentials WHERE token_id = 'tok-2'`, "token_hash"); got != "$2a$10$tok2" {
		t.Errorf("token_credentials for a token created after the latch = %q", got)
	}
	if got := oneString(t, c, `SELECT token_hash FROM tokens WHERE id = 'tok-2'`, "token_hash"); got != "$2a$10$tok2" {
		t.Errorf("tokens.token_hash for a token created after the latch = %q; a host rolled back one "+
			"release reads only this column", got)
	}

	// The sensitive lane carries every one of them.
	payload, err := decompressPayload(c.DumpSensitiveStateBytes())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, tbl := range payload.Tables {
		seen[tbl.Name] = len(tbl.Rows) > 0
	}
	for _, tbl := range credentialTables {
		if !seen[tbl] {
			t.Errorf("the sensitive dump does not carry %s; a node that missed the WAL write "+
				"has no lane to repair it from", tbl)
		}
	}
}

// TestCredentialsSplit_TheCredentialTableIsReadFirst: once a credential row
// exists, readers take it — including where the old column disagrees with it
// and is OLDER — so a stale public-lane value cannot override the split.
func TestCredentialsSplit_TheCredentialTableIsReadFirst(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	c.SetCredentialsSplitGate(func() bool { return true })

	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	const tok = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tokHash, err := bcrypt.GenerateFromPassword([]byte(tok), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := InsertUser(ctx, c, "alice", "operator", string(hash)); err != nil {
		t.Fatal(err)
	}
	if err := InsertToken(ctx, c, TokenRecord{ID: "tok-1", Username: "alice", Name: "ci", TokenHash: string(tokHash)}); err != nil {
		t.Fatal(err)
	}
	if err := InsertHost(ctx, c, HostRecord{Name: "bmc-host", Address: "10.0.0.20", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Execute(ctx, HostFenceCredentialUpsertSQL, "bmc-host", "bmc-secret", c.NowTS()); err != nil {
		t.Fatal(err)
	}

	// Corrupt the old columns with values OLDER than the credential rows: a
	// stale copy a lagging peer might still hold. (Local-only, so the test
	// controls the timestamps exactly.)
	for _, q := range []string{
		`UPDATE users SET password_hash = 'stale', updated_at = '2000-01-01T00:00:00Z' WHERE username = 'alice'`,
		`UPDATE tokens SET token_hash = 'stale', updated_at = '2000-01-01T00:00:00Z' WHERE id = 'tok-1'`,
		`UPDATE hosts SET ipmi_pass = 'stale', updated_at = '2000-01-01T00:00:00Z' WHERE name = 'bmc-host'`,
	} {
		if err := c.execLocal(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if u, _ := GetUser(ctx, c, "alice"); u == nil || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte("s3cret")) != nil {
		t.Errorf("GetUser returned hash %q; the credential row must win over an older old column", u.PasswordHash)
	}
	if u, err := ValidateToken(ctx, c, tok); err != nil || u == nil {
		t.Errorf("ValidateToken = %+v, %v; the credential row must win over an older old column", u, err)
	}
	if h, _ := GetHost(ctx, c, "bmc-host"); h == nil || h.IPMIPass != "bmc-secret" {
		t.Errorf("GetHost IPMIPass = %q; the fence must read the credential row", h.IPMIPass)
	}
}

// TestResolveCredential pins the read rule on its own: the newer copy wins,
// ties and empty old columns go to the credential row.
func TestResolveCredential(t *testing.T) {
	const older, newer = "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z"
	for _, tc := range []struct {
		name                         string
		present                      bool
		credVal, credTS, oldV, oldTS string
		want                         string
	}{
		{"no credential row: the old column", false, "", "", "old", newer, "old"},
		{"credential row, old column older", true, "new", newer, "old", older, "new"},
		{"credential row, same value", true, "same", older, "same", newer, "same"},
		{"same updated_at: the credential row", true, "new", newer, "other", newer, "new"},
		// An unlatched node wrote the old column after the row.
		{"old column newer and different", true, "new", older, "fresher", newer, "fresher"},
		// A host that ran the pre-release clearing build.
		{"old column emptied after the row", true, "new", older, "", newer, "new"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveCredential(tc.present, tc.credVal, tc.credTS, tc.oldV, tc.oldTS); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestCredentialsSplit_ThePassNeverClearsAnOldColumn: this release copies and
// never clears. After a pass every secret — a deleted user's hash and a revoked
// token's hash included — is still in its old column, where a host rolled back
// one release reads it, and the sensitive dump carries it too. Clearing is a
// later release's step (docs/design/credentials-clear.md).
func TestCredentialsSplit_ThePassNeverClearsAnOldColumn(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	secrets := []string{"$2a$10$dump-user-hash", "$2a$10$dump-token-hash", "dump-bmc-secret"}
	seedSecrets(t, c, secrets[0], secrets[1], secrets[2])
	if err := RevokeToken(ctx, c, "tok-1"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteUser(ctx, c, "alice"); err != nil {
		t.Fatal(err)
	}
	c.SetCredentialsSplitGate(func() bool { return true })
	if rep, err := c.SplitCredentials(ctx); err != nil || rep.Copied != 3 {
		t.Fatalf("pass = %+v err=%v, want 3 copied", rep, err)
	}
	for _, q := range []struct{ query, col, want string }{
		{`SELECT password_hash FROM users WHERE username = 'alice'`, "password_hash", secrets[0]},
		{`SELECT token_hash FROM tokens WHERE id = 'tok-1'`, "token_hash", secrets[1]},
		{`SELECT ipmi_pass FROM hosts WHERE name = 'bmc-host'`, "ipmi_pass", secrets[2]},
	} {
		if got := oneString(t, c, q.query, q.col); got != q.want {
			t.Errorf("%s = %q after the pass, want %q; the old column must survive this release", q.query, got, q.want)
		}
	}
	sensitive, err := decompressPayload(c.DumpSensitiveStateBytes())
	if err != nil {
		t.Fatal(err)
	}
	sensJSON, _ := json.Marshal(sensitive)
	for _, secret := range secrets {
		if !strings.Contains(string(sensJSON), secret) {
			t.Errorf("the sensitive dump does not carry %q", secret)
		}
	}
}

// TestCredentialsSplit_ThePassNeverRestampsAParentRow: the pass writes only
// credential rows, and stamps each with its parent's updated_at. It never
// writes a parent row, so it cannot out-timestamp a revoke or delete a peer
// issued just before it ran and that has not arrived yet.
func TestCredentialsSplit_ThePassNeverRestampsAParentRow(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedSecrets(t, c, "$2a$10$h", "$2a$10$t", "p")
	queries := []string{
		`SELECT updated_at FROM tokens WHERE id = 'tok-1'`,
		`SELECT updated_at FROM users WHERE username = 'alice'`,
		`SELECT updated_at FROM hosts WHERE name = 'bmc-host'`,
	}
	before := map[string]string{}
	for _, q := range queries {
		before[q] = oneString(t, c, q, "updated_at")
	}
	c.SetCredentialsSplitGate(func() bool { return true })
	if _, err := c.SplitCredentials(ctx); err != nil {
		t.Fatal(err)
	}
	for _, q := range queries {
		if got := oneString(t, c, q, "updated_at"); got != before[q] {
			t.Errorf("%s: the pass restamped the parent row %q -> %q", q, before[q], got)
		}
	}
	if log := mutationLogText(t, c); strings.Contains(log, "UPDATE users") || strings.Contains(log, "UPDATE tokens") {
		t.Errorf("the pass put a parent-row UPDATE on the replication stream:\n%s", log)
	}
}

// TestCredentialsSplit_ReadersTakeANewerOldColumnAfterThePass: there is no
// "credential table only" mode. After this node has latched and completed a
// pass, a newer, different old-column value — what an unlatched neighbour's
// password change looks like when it lands — is served at once, not at the
// next pass.
func TestCredentialsSplit_ReadersTakeANewerOldColumnAfterThePass(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedSecrets(t, c, "$2a$10$current", "$2a$10$t", "p")
	c.SetCredentialsSplitGate(func() bool { return true })
	if _, err := c.SplitCredentials(ctx); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`UPDATE users SET password_hash = 'rotated', updated_at = '2999-01-01T00:00:00Z' WHERE username = 'alice'`,
		`UPDATE hosts SET ipmi_pass = 'rotated-bmc', updated_at = '2999-01-01T00:00:00Z' WHERE name = 'bmc-host'`,
	} {
		if err := c.execLocal(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if u, _ := GetUser(ctx, c, "alice"); u == nil || u.PasswordHash != "rotated" {
		t.Errorf("GetUser after the pass returned %+v; it must serve the newer old column", u)
	}
	if h, _ := GetHost(ctx, c, "bmc-host"); h == nil || h.IPMIPass != "rotated-bmc" {
		t.Errorf("GetHost after the pass returned %+v; the fence must use the newer old column", h)
	}
}

// TestCredentialsSplit_AnEmptiedOldColumnReadsTheCredentialRow: a host that
// ran the pre-release clearing build holds emptied old columns stamped
// after the credential rows. Readers must still take the credential row, and
// the pass must not copy the empty value over it.
func TestCredentialsSplit_AnEmptiedOldColumnReadsTheCredentialRow(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedSecrets(t, c, "$2a$10$current", "$2a$10$t", "bmc-secret")
	c.SetCredentialsSplitGate(func() bool { return true })
	if _, err := c.SplitCredentials(ctx); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`UPDATE users SET password_hash = '', updated_at = '2999-01-01T00:00:00Z' WHERE username = 'alice'`,
		`UPDATE hosts SET ipmi_pass = '', updated_at = '2999-01-01T00:00:00Z' WHERE name = 'bmc-host'`,
	} {
		if err := c.execLocal(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if rep, err := c.SplitCredentials(ctx); err != nil || rep.Copied != 0 {
		t.Fatalf("pass over emptied old columns = %+v err=%v, want nothing copied", rep, err)
	}
	if u, _ := GetUser(ctx, c, "alice"); u == nil || u.PasswordHash != "$2a$10$current" {
		t.Errorf("GetUser = %+v; an emptied old column must not hide the credential row", u)
	}
	if h, _ := GetHost(ctx, c, "bmc-host"); h == nil || h.IPMIPass != "bmc-secret" {
		t.Errorf("GetHost = %+v; an emptied old column must not hide the credential row", h)
	}
}

// publicDumpJSON is the operator-safe dump as the JSON a reader would see.
func publicDumpJSON(t *testing.T, c *Client) []byte {
	t.Helper()
	payload, err := decompressPayload(c.DumpStateBytes())
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
