package corrosion

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
	// Each source with keys a node could mint after seeing it, in the same
	// format: every one of them must beat the clear.
	for src, laters := range map[string][]string{
		"2026-01-01T00:00:00.000000000Z": {"2026-01-01T00:00:00.000002000Z"},
		"2026-01-01T00:00:00Z":           {"2026-01-01T00:00:00.000002000Z", "2026-01-01T00:00:01Z"},
		"1767225600000-0003-node-a":      {"1767225600000-0004-node-a", "1767225600000-0004-a", "1767225600001-0000-a"},
	} {
		got, ok := clearTS(credentialSplitRow{srcTS: src})
		if !ok {
			t.Fatalf("clearTS(%q) could not stamp a readable timestamp", src)
		}
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

// TestCredentialsClear_AnUnreadableTimestampIsNotClearedWithAFreshClock: a row
// whose own updated_at cannot be read has no successor to stamp. It is left
// uncleared rather than stamped with a fresh clock, which would beat an
// in-flight revoke.
func TestCredentialsClear_AnUnreadableTimestampIsNotClearedWithAFreshClock(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedSecrets(t, c, "$2a$10$h", "$2a$10$t", "p")
	if err := c.execLocal(ctx, `UPDATE tokens SET updated_at = '', created_at = 'not-a-time' WHERE id = 'tok-1'`); err != nil {
		t.Fatal(err)
	}
	openClearGates(c)
	if _, err := c.SplitCredentials(ctx); err != nil {
		t.Fatal(err)
	}
	if got := oneString(t, c, `SELECT token_hash FROM tokens WHERE id = 'tok-1'`, "token_hash"); got != "$2a$10$t" {
		t.Errorf("tokens.token_hash = %q: a row with no readable timestamp was cleared, so its clear "+
			"was stamped with a fresh clock", got)
	}
	if got := oneString(t, c, `SELECT password_hash FROM users WHERE username = 'alice'`, "password_hash"); got != "" {
		t.Errorf("users.password_hash = %q: the readable rows must still be cleared", got)
	}
}

// TestCredentialsLive_FirstPassMaterialisesLegacyShadows: an external-realm
// user created before the split latched has an empty old column and no
// credential row. The pass that makes a node live gives it an empty credential
// row at the floor timestamp, so from then on a missing credential row means
// "not here yet" and never "external".
func TestCredentialsLive_FirstPassMaterialisesLegacyShadows(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	if err := InsertUser(ctx, c, "ext", "viewer", ""); err != nil { // a shadow, pre-latch
		t.Fatal(err)
	}
	if err := InsertUser(ctx, c, "alice", "operator", "$2a$10$alice"); err != nil {
		t.Fatal(err)
	}
	// This build first starts on a node that already holds these rows: the
	// positive evidence that an empty old column predates any clear.
	if err := c.NoteCredentialsBaseline(ctx); err != nil {
		t.Fatal(err)
	}
	if local, known, err := UserLocalCredential(ctx, c, "ext"); err != nil || local || !known {
		t.Fatalf("pre-latch shadow: local=%v known=%v err=%v, want an external user", local, known, err)
	}
	c.SetCredentialsSplitGate(func() bool { return true })
	if _, err := c.SplitCredentials(ctx); err != nil {
		t.Fatal(err)
	}
	if !c.CredentialsLive() {
		t.Fatal("a complete pass did not make the node live")
	}
	if got := oneString(t, c, `SELECT updated_at FROM user_credentials WHERE username = 'ext'`, "updated_at"); got != credentialFloorTS {
		t.Errorf("the shadow's credential row is stamped %q, want the floor %q", got, credentialFloorTS)
	}
	for user, want := range map[string]bool{"ext": false, "alice": true} {
		local, known, err := UserLocalCredential(ctx, c, user)
		if err != nil || !known || local != want {
			t.Errorf("UserLocalCredential(%s) = local %v known %v err %v, want local %v", user, local, known, err, want)
		}
	}
}

// TestCredentialsLive_AJoinerAfterTheClearMaterialisesNothing: a node that
// already holds a cleared row reaches its first pass after the clear, so an
// empty old column with no credential row may be a local account whose
// credential row is still on its way. Nothing is materialised for it, and the
// account is "unknown" until the row arrives.
func TestCredentialsLive_AJoinerAfterTheClearMaterialisesNothing(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	if err := c.NoteCredentialsBaseline(ctx); err != nil { // a joiner starts empty
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users (username, role, password_hash, created_at, updated_at) VALUES ('alice', 'operator', '', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00.000000001Z')`,
		`INSERT INTO user_credentials (username, password_hash, updated_at) VALUES ('alice', '$2a$10$alice', '2026-01-01T00:00:00Z')`,
		`INSERT INTO users (username, role, password_hash, created_at, updated_at) VALUES ('bob', 'admin', '', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00.000000001Z')`,
	} {
		if err := c.execLocal(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if _, known, _ := UserLocalCredential(ctx, c, "bob"); known {
		t.Error("before the first pass, with a cleared row in view, bob was judged known")
	}
	c.SetCredentialsSplitGate(func() bool { return true })
	if _, err := c.SplitCredentials(ctx); err != nil {
		t.Fatal(err)
	}
	if n := tableCount(t, c, "user_credentials"); n != 1 {
		t.Errorf("user_credentials holds %d rows; a joiner materialised a shadow for a lagging local account", n)
	}
	if _, known, err := UserLocalCredential(ctx, c, "bob"); err != nil || known {
		t.Errorf("UserLocalCredential(bob) known=%v err=%v; a missing credential row on a cleared cluster "+
			"must not read as an external user", known, err)
	}
}

// TestCredentialsLive_ANeverLiveJoinerWithoutEvidenceJudgesNothingExternal
// (re-review I1): a joiner whose public lane has merged cleared users rows and
// whose sensitive lane has not holds no cleared PAIR — and on a cluster with no
// API tokens and no IPMI-fenced hosts no pair of any kind. Absence of evidence
// is not evidence: before its first pass and after it, an empty old column with
// no credential row is a local account it cannot verify, never an external
// user, and its first pass writes no floor rows for it.
func TestCredentialsLive_ANeverLiveJoinerWithoutEvidenceJudgesNothingExternal(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	if err := c.NoteCredentialsBaseline(ctx); err != nil { // started empty
		t.Fatal(err)
	}
	if err := c.execLocal(ctx, `INSERT INTO users (username, role, password_hash, created_at, updated_at)
		VALUES ('admin', 'admin', '', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00.000000001Z')`); err != nil {
		t.Fatal(err)
	}
	if local, known, err := UserLocalCredential(ctx, c, "admin"); err != nil || known {
		t.Fatalf("before the first pass: local=%v known=%v err=%v; a cleared local admin read as external", local, known, err)
	}
	c.SetCredentialsSplitGate(func() bool { return true })
	if _, err := c.SplitCredentials(ctx); err != nil {
		t.Fatal(err)
	}
	if n := tableCount(t, c, "user_credentials"); n != 0 {
		t.Errorf("the joiner's first pass wrote %d floor credential rows for accounts it cannot judge", n)
	}
	if _, known, err := UserLocalCredential(ctx, c, "admin"); err != nil || known {
		t.Errorf("after the first pass: known=%v err=%v; the cleared local admin must stay unverifiable", known, err)
	}
}

// TestCredentialsLive_TheFirstPassJudgesBeforeItsOwnClears: a node whose split
// and clear gates open together must decide its legacy external users before
// its own clears are in view — a cleared row it just wrote is "clear evidence",
// and would stop the materialisation that keeps a pre-split external user
// logging in.
func TestCredentialsLive_TheFirstPassJudgesBeforeItsOwnClears(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	for _, q := range []string{
		`INSERT INTO users (username, role, password_hash, created_at, updated_at) VALUES ('legacy-ext', 'viewer', '', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')`,
		`INSERT INTO users (username, role, password_hash, created_at, updated_at) VALUES ('local', 'operator', '$2a$10$local', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')`,
	} {
		if err := c.execLocal(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.NoteCredentialsBaseline(ctx); err != nil { // held: it had these rows
		t.Fatal(err)
	}
	openClearGates(c)
	if _, err := c.SplitCredentials(ctx); err != nil {
		t.Fatal(err)
	}
	if local, known, err := UserLocalCredential(ctx, c, "legacy-ext"); err != nil || !known || local {
		t.Errorf("legacy-ext: local=%v known=%v err=%v, want a known external user", local, known, err)
	}
	if got := oneString(t, c, `SELECT password_hash FROM users WHERE username = 'local'`, "password_hash"); got != "" {
		t.Errorf("the local account was not cleared (%q)", got)
	}
}

// TestCredentialsLive_EvidenceIsPerUserAndBoundToTheRow (re-review 2, N1): the
// baseline names users, bound to their row's created_at. A local account that
// held a password at first start — and is cleared later — never matches it,
// so a node that started holding rows does not take a cleared local account
// for an external user; and a name deleted and created again does not match.
func TestCredentialsLive_EvidenceIsPerUserAndBoundToTheRow(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	for _, q := range []string{
		`INSERT INTO users (username, role, password_hash, created_at, updated_at) VALUES ('admin', 'admin', '$2a$10$stale', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')`,
		`INSERT INTO users (username, role, password_hash, created_at, updated_at) VALUES ('ext', 'viewer', '', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')`,
	} {
		if err := c.execLocal(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.NoteCredentialsBaseline(ctx); err != nil {
		t.Fatal(err)
	}
	// Anti-entropy brings the cleared admin row; its credential lags.
	if err := c.execLocal(ctx, `UPDATE users SET password_hash = '', updated_at = '2026-06-01T00:00:00Z' WHERE username = 'admin'`); err != nil {
		t.Fatal(err)
	}
	if _, known, err := UserLocalCredential(ctx, c, "admin"); err != nil || known {
		t.Errorf("admin: known=%v err=%v; a local account cleared since the baseline read as external", known, err)
	}
	if local, known, _ := UserLocalCredential(ctx, c, "ext"); !known || local {
		t.Errorf("ext: local=%v known=%v; the baseline's own external user", local, known)
	}
	// ext deleted and created again elsewhere: a new incarnation.
	if err := c.execLocal(ctx, `UPDATE users SET created_at = '2026-07-01T00:00:00Z' WHERE username = 'ext'`); err != nil {
		t.Fatal(err)
	}
	if _, known, _ := UserLocalCredential(ctx, c, "ext"); known {
		t.Error("a re-created ext matched the baseline of the user it replaced")
	}
	c.SetCredentialsSplitGate(func() bool { return true })
	if _, err := c.SplitCredentials(ctx); err != nil {
		t.Fatal(err)
	}
	if n := tableCount(t, c, "user_credentials"); n != 0 {
		t.Errorf("the first pass wrote %d floor rows; admin and the re-created ext have no evidence", n)
	}
}

// TestCredentialsLive_TheBaselineIsBoundToItsStateDB (re-review 2, N7): a
// baseline recorded for one state.db does not hold for another — a lost or
// replaced database is recorded afresh from what it holds.
func TestCredentialsLive_TheBaselineIsBoundToItsStateDB(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	// A baseline another state.db recorded, naming admin as external.
	b, _ := json.Marshal(credentialsBaseline{Incarnation: "another-state-db",
		Shadows: []userIdentity{{Username: "admin", CreatedAt: "2025-01-01T00:00:00Z"}}})
	if err := os.WriteFile(filepath.Join(dir, credentialsBaselineFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	c := newTestDB(t) // a fresh, empty state.db
	c.dataDir = dir
	if err := c.NoteCredentialsBaseline(ctx); err != nil {
		t.Fatal(err)
	}
	// The cleared admin row replicates in; its credential lags.
	if err := c.execLocal(ctx, `INSERT INTO users (username, role, password_hash, created_at, updated_at)
		VALUES ('admin', 'admin', '', '2025-01-01T00:00:00Z', '2026-06-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, known, err := UserLocalCredential(ctx, c, "admin"); err != nil || known {
		t.Errorf("admin: known=%v err=%v; a baseline from another state.db was taken as this one's", known, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, credentialsBaselineFile))
	if err != nil {
		t.Fatal(err)
	}
	var got credentialsBaseline
	if err := json.Unmarshal(data, &got); err != nil || got.Incarnation == "another-state-db" || len(got.Shadows) != 0 {
		t.Errorf("baseline file after a new state.db = %s; want this incarnation's, with no shadows", data)
	}
}

// TestCredentialsLive_ExternalSeenIsBoundToTheRowAndRecordedAfterTheInsert
// (re-review 2, N3).
func TestCredentialsLive_ExternalSeenIsBoundToTheRowAndRecordedAfterTheInsert(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	if err := InsertUser(ctx, c, "bob", "viewer", ""); err != nil { // a pre-split shadow made here
		t.Fatal(err)
	}
	if local, known, _ := UserLocalCredential(ctx, c, "bob"); !known || local {
		t.Fatalf("bob: local=%v known=%v; this node made the shadow", local, known)
	}
	if err := DeleteUser(ctx, c, "bob"); err != nil {
		t.Fatal(err)
	}
	// bob re-created as a local account elsewhere, its users row cleared and
	// its credential row still on its way here.
	if err := c.execLocal(ctx, `UPDATE users SET deleted_at = NULL, created_at = '2999-01-01T00:00:00Z', password_hash = '' WHERE username = 'bob'`); err != nil {
		t.Fatal(err)
	}
	if _, known, _ := UserLocalCredential(ctx, c, "bob"); known {
		t.Error("a deleted shadow's record judged the re-created local bob external")
	}
	// A failed insert records nothing: carol already exists.
	if err := c.execLocal(ctx, `INSERT INTO users (username, role, password_hash, created_at, updated_at) VALUES ('carol', 'operator', '', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser(ctx, c, "carol", "viewer", ""); err == nil {
		t.Fatal("precondition: inserting an existing live carol succeeded")
	}
	c.externalSeenMu.Lock()
	for id := range c.loadExternalSeenLocked() {
		if id.Username == "carol" {
			t.Errorf("a failed insert recorded carol as an external shadow (%+v)", id)
		}
	}
	c.externalSeenMu.Unlock()
}
