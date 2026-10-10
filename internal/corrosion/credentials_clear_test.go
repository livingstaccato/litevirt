package corrosion

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// Clearing the old secret columns once credentials_clear_v1 has latched
// (docs/design/credentials-clear.md, colonelpanik/litevirt#268).

// openClearGates opens both gates, the state of a node that has durably
// latched credentials_split_v1 and credentials_clear_v1.
func openClearGates(c *Client) {
	c.SetCredentialsSplitGate(func() bool { return true })
	c.SetCredentialsClearGate(func() bool { return true })
}

// oldSecretColumns reads every old secret column, tombstoned rows included.
func oldSecretColumns(t *testing.T, c *Client) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, q := range []struct{ prefix, query string }{
		{"users.", `SELECT username AS k, password_hash AS v FROM users`},
		{"tokens.", `SELECT id AS k, token_hash AS v FROM tokens`},
		{"hosts.", `SELECT name AS k, COALESCE(ipmi_pass, '') AS v FROM hosts`},
	} {
		rows, err := c.Query(context.Background(), q.query)
		if err != nil {
			t.Fatalf("%s: %v", q.query, err)
		}
		for _, r := range rows {
			out[q.prefix+r.String("k")] = r.String("v")
		}
	}
	return out
}

// TestCredentialsClear_ThePassClearsEveryOldColumn: once both gates are open,
// one pass empties every old secret column — a deleted user's hash, a revoked
// token's hash and a removed host's BMC password included — keeps every
// credential row, and the public dump carries none of the secrets while the
// sensitive dump carries every live one. Each clear rides in the same entry
// as the credential row it hands over to, credential row first.
func TestCredentialsClear_ThePassClearsEveryOldColumn(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	secrets := map[string]string{
		"users.alice":     "$2a$10$clear-alice",
		"users.bob":       "$2a$10$clear-bob",
		"tokens.tok-1":    "$2a$10$clear-tok-1",
		"tokens.tok-2":    "$2a$10$clear-tok-2",
		"hosts.bmc-host":  "clear-bmc-secret",
		"hosts.gone-host": "clear-gone-secret",
	}
	seedSecrets(t, c, secrets["users.alice"], secrets["tokens.tok-1"], secrets["hosts.bmc-host"])
	if err := InsertUser(ctx, c, "bob", "viewer", secrets["users.bob"]); err != nil {
		t.Fatal(err)
	}
	if err := DeleteUser(ctx, c, "bob"); err != nil {
		t.Fatal(err)
	}
	if err := InsertToken(ctx, c, TokenRecord{ID: "tok-2", Username: "alice", Name: "old", TokenHash: secrets["tokens.tok-2"]}); err != nil {
		t.Fatal(err)
	}
	if err := RevokeToken(ctx, c, "tok-2"); err != nil {
		t.Fatal(err)
	}
	if err := InsertHost(ctx, c, HostRecord{Name: "gone-host", Address: "10.0.0.21", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Execute(ctx, `UPDATE hosts SET ipmi_pass = ?, updated_at = ? WHERE name = 'gone-host'`,
		secrets["hosts.gone-host"], c.NowTS()); err != nil {
		t.Fatal(err)
	}
	if err := DeleteHost(ctx, c, "gone-host"); err != nil {
		t.Fatal(err)
	}

	openClearGates(c)
	rep, err := c.SplitCredentials(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Cleared != len(secrets) {
		t.Errorf("pass = %+v, want %d old columns cleared", rep, len(secrets))
	}
	for k, v := range oldSecretColumns(t, c) {
		if v != "" {
			t.Errorf("%s still holds %q after the clearing pass", k, v)
		}
	}
	for _, q := range []struct{ query, col, want string }{
		{`SELECT password_hash FROM user_credentials WHERE username = 'alice'`, "password_hash", secrets["users.alice"]},
		{`SELECT password_hash FROM user_credentials WHERE username = 'bob'`, "password_hash", secrets["users.bob"]},
		{`SELECT token_hash FROM token_credentials WHERE token_id = 'tok-1'`, "token_hash", secrets["tokens.tok-1"]},
		{`SELECT token_hash FROM token_credentials WHERE token_id = 'tok-2'`, "token_hash", secrets["tokens.tok-2"]},
		{`SELECT ipmi_pass FROM host_fence_credentials WHERE host_name = 'bmc-host'`, "ipmi_pass", secrets["hosts.bmc-host"]},
	} {
		if got := oneString(t, c, q.query, q.col); got != q.want {
			t.Errorf("%s = %q, want %q: the clear lost the secret it was handing over", q.query, got, q.want)
		}
	}
	if u, _ := GetUser(ctx, c, "alice"); u == nil || u.PasswordHash != secrets["users.alice"] {
		t.Errorf("GetUser after the clear = %+v", u)
	}
	if h, _ := GetHost(ctx, c, "bmc-host"); h == nil || h.IPMIPass != secrets["hosts.bmc-host"] {
		t.Errorf("GetHost after the clear = %+v; the fence would run without its password", h)
	}

	public := string(publicDumpJSON(t, c))
	sensitive, err := decompressPayload(c.DumpSensitiveStateBytes())
	if err != nil {
		t.Fatal(err)
	}
	sensJSON, _ := json.Marshal(sensitive)
	for k, secret := range secrets {
		if strings.Contains(public, secret) {
			t.Errorf("the operator-safe dump still carries %s (%q) after the clear", k, secret)
		}
		if k != "hosts.gone-host" && !strings.Contains(string(sensJSON), secret) {
			t.Errorf("the sensitive dump does not carry %s (%q); a node repairing from a peer would lose it", k, secret)
		}
	}

	// The credential row travels ahead of the clear, in the same entry.
	for _, e := range mutationEntries(t, c) {
		clearAt := strings.Index(e, "UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ?")
		if clearAt < 0 {
			continue
		}
		if credAt := strings.Index(e, "INSERT INTO user_credentials"); credAt < 0 || credAt > clearAt {
			t.Errorf("a users clear is not preceded by its credential row in the same entry:\n%s", e)
		}
	}

	if rep, err := c.SplitCredentials(ctx); err != nil || rep.Cleared != 0 || rep.Copied != 0 {
		t.Errorf("a second pass = %+v err=%v; the pass must be idempotent", rep, err)
	}
}

// mutationEntries is every logged entry's statements, one string per entry.
func mutationEntries(t *testing.T, c *Client) []string {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT stmts FROM mutation_log ORDER BY seq`)
	if err != nil {
		t.Fatalf("read mutation_log: %v", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.String("stmts"))
	}
	return out
}

// TestCredentialsClear_AnInFlightRevokeBeatsTheClear: every node clears every
// row at about the moment the latch forms. A revoke and a delete a peer issued
// BEFORE this node's pass ran, still in flight when it did, must still win when
// they land: the clear is stamped just past the row it read, not with a fresh
// clock. A clear stamped NowTS would be newer than both, LWW would skip them
// here, and anti-entropy would spread the un-revoked token and the undeleted
// user from this node.
func TestCredentialsClear_AnInFlightRevokeBeatsTheClear(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedSecrets(t, c, "$2a$10$h", "$2a$10$t", "p")
	// The parent rows' last writes, well before the peer's revoke.
	for _, q := range []string{
		`UPDATE tokens SET updated_at = '2026-01-01T00:00:00.000000000Z' WHERE id = 'tok-1'`,
		`UPDATE users SET updated_at = '2026-01-01T00:00:00.000000000Z' WHERE username = 'alice'`,
	} {
		if err := c.execLocal(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	inFlight := c.NowTS() // the peer's revoke and delete, minted now, not yet delivered

	openClearGates(c)
	if _, err := c.SplitCredentials(ctx); err != nil {
		t.Fatal(err)
	}
	if got := oneString(t, c, `SELECT token_hash FROM tokens WHERE id = 'tok-1'`, "token_hash"); got != "" {
		t.Fatalf("the pass did not clear tokens.token_hash (%q); the scenario would prove nothing", got)
	}

	marker := nowRFC3339()
	applyRemote(t, c, "2999000000000-0000-peer",
		Statement{SQL: `UPDATE tokens SET deleted_at = ?, updated_at = ? WHERE id = ?`,
			Params: []interface{}{marker, inFlight, "tok-1"}})
	applyRemote(t, c, "2999000000001-0000-peer",
		Statement{SQL: `UPDATE users SET deleted_at = ?, updated_at = ? WHERE username = ?`,
			Params: []interface{}{marker, inFlight, "alice"}})

	if got := oneString(t, c, `SELECT COALESCE(deleted_at, '') AS d FROM tokens WHERE id = 'tok-1'`, "d"); got == "" {
		t.Error("the in-flight revoke lost to the clear: tok-1 is live again here, and anti-entropy " +
			"would spread the un-revoked token")
	}
	if got := oneString(t, c, `SELECT COALESCE(deleted_at, '') AS d FROM users WHERE username = 'alice'`, "d"); got == "" {
		t.Error("the in-flight delete lost to the clear: alice is live again here")
	}
}

// TestCredentialsClear_ClearTSIsTheImmediateSuccessor pins the stamping rule
// for both key formats.
func TestCredentialsClear_ClearTSIsTheImmediateSuccessor(t *testing.T) {
	c := newTestDB(t)
	// Each source with keys a node could mint after seeing it, in the same
	// format: every one of them must beat the clear.
	for src, laters := range map[string][]string{
		"2026-01-01T00:00:00.000000000Z": {"2026-01-01T00:00:00.000002000Z"},
		"2026-01-01T00:00:00Z":           {"2026-01-01T00:00:00.000002000Z", "2026-01-01T00:00:01Z"},
		"1767225600000-0003-node-a":      {"1767225600000-0004-node-a", "1767225600000-0004-a", "1767225600001-0000-a"},
	} {
		got := c.clearTS(credentialSplitRow{srcTS: src})
		if lwwOrder(got, src) <= 0 {
			t.Errorf("clearTS(%q) = %q, not newer than the row it clears", src, got)
		}
		for _, later := range laters {
			if lwwOrder(got, later) >= 0 {
				t.Errorf("clearTS(%q) = %q is not older than %q, a later write", src, got, later)
			}
		}
	}
}

// TestCredentialsClear_WritersLeaveTheOldColumnEmpty: after the latch every
// writer puts the secret in its credential row and an empty string in the old column, in
// the statement shapes it already used.
func TestCredentialsClear_WritersLeaveTheOldColumnEmpty(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	openClearGates(c)

	if err := InsertUser(ctx, c, "carol", "operator", "$2a$10$carol-1"); err != nil {
		t.Fatal(err)
	}
	if err := UpdateUserPassword(ctx, c, "carol", "$2a$10$carol-2"); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser(ctx, c, "dave", "viewer", "$2a$10$dave-1"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteUser(ctx, c, "dave"); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser(ctx, c, "dave", "viewer", "$2a$10$dave-2"); err != nil { // reactivation
		t.Fatal(err)
	}
	if err := InsertUser(ctx, c, "root", "admin", "$2a$10$root"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteUser(ctx, c, "root"); err != nil {
		t.Fatal(err)
	}
	if who, err := ReinstateAdminIfNoneRemain(ctx, c); err != nil || who != "root" {
		t.Fatalf("ReinstateAdminIfNoneRemain = %q, %v", who, err)
	}
	if err := InsertToken(ctx, c, TokenRecord{ID: "tok-c", Username: "carol", Name: "ci", TokenHash: "$2a$10$tok-c"}); err != nil {
		t.Fatal(err)
	}

	for k, v := range oldSecretColumns(t, c) {
		if v != "" {
			t.Errorf("%s = %q written after the clear latched; the old column must stay empty", k, v)
		}
	}
	for user, want := range map[string]string{"carol": "$2a$10$carol-2", "dave": "$2a$10$dave-2", "root": "$2a$10$root"} {
		if u, _ := GetUser(ctx, c, user); u == nil || u.PasswordHash != want {
			t.Errorf("GetUser(%s) = %+v, want hash %q", user, u, want)
		}
	}
	if got := oneString(t, c, `SELECT token_hash FROM token_credentials WHERE token_id = 'tok-c'`, "token_hash"); got != "$2a$10$tok-c" {
		t.Errorf("token_credentials = %q", got)
	}
}

// TestCredentialsClear_NeedsTheSplitGate: the clear gate alone clears nothing
// and changes no writer. A node that is not writing the credential tables must
// never empty the column that is its only copy.
func TestCredentialsClear_NeedsTheSplitGate(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	c.SetCredentialsClearGate(func() bool { return true })
	if c.MayClearCredentialColumns() {
		t.Fatal("MayClearCredentialColumns is open with the split gate closed")
	}
	seedSecrets(t, c, "$2a$10$alice", "$2a$10$tok", "bmc")
	if rep, err := c.SplitCredentials(ctx); err != nil || rep.Cleared != 0 {
		t.Fatalf("pass = %+v err=%v", rep, err)
	}
	old := oldSecretColumns(t, c)
	for _, k := range []string{"users.alice", "tokens.tok-1", "hosts.bmc-host"} {
		if old[k] == "" {
			t.Errorf("%s was emptied with the split gate closed; it is this node's only copy", k)
		}
	}
}
