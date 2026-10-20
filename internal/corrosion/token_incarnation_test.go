package corrosion

import (
	"context"
	"errors"
	"testing"
	"time"
)

// users-L2: an API token names the account incarnation it was issued to
// (tokens.user_created_at), and authenticates only that account. These tests
// pin the read rule, the writer's stamp, and the three ways a stale token can
// reach a node: the WAL, anti-entropy, and a node that had not latched.

const (
	tokRawA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tokRawB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	tokRawC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func mustBcrypt(t *testing.T, raw string) string {
	t.Helper()
	h, err := bcryptHash(raw)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func userCreatedAt(t *testing.T, c *Client, name string) string {
	t.Helper()
	return oneString(t, c, `SELECT created_at FROM users WHERE username = ?`, "created_at", name)
}

// recreateUser deletes name and creates it again with the gate on, so the
// new account is a new incarnation.
func recreateUser(t *testing.T, c *Client, name string) {
	t.Helper()
	ctx := context.Background()
	if err := DeleteUser(ctx, c, name); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser(ctx, c, name, "operator", "hash-new"); err != nil {
		t.Fatal(err)
	}
}

func TestTokenIncarnation_ReadRule(t *testing.T) {
	const (
		pre    = "2026-10-01T10:00:00Z"           // an incarnation made before the latch
		older  = "2026-10-01T10:00:00.123456789Z" // made by a latched writer
		latest = "2026-10-02T10:00:00.5Z"
	)
	for _, tc := range []struct {
		name           string
		stamp, current string
		want           bool
	}{
		{"its own incarnation", latest, latest, true},
		{"its own pre-latch incarnation", pre, pre, true},
		{"an older incarnation", older, latest, false},
		{"a newer incarnation this node has not reached", latest, older, false},
		{"a pre-latch incarnation the name has left", pre, latest, false},
		{"unstamped, on a pre-latch account", "", pre, true},
		{"unstamped, on an account a latched writer made", "", latest, false},
		{"an account with no incarnation", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tokenIncarnationHolds(tc.stamp, tc.current); got != tc.want {
				t.Errorf("tokenIncarnationHolds(%q, %q) = %v, want %v", tc.stamp, tc.current, got, tc.want)
			}
		})
	}
}

// A latched writer's incarnation always carries a fractional second, even on
// an instant that falls on a whole one: that is what tells it apart from
// every created_at a previous release wrote.
func TestTokenIncarnation_ALatchedIncarnationIsNeverAWholeSecond(t *testing.T) {
	whole := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	if got := incarnationAfterAll(whole, ""); !latchedIncarnation(got) {
		t.Errorf("incarnationAfterAll(whole second) = %q: reads as a pre-latch incarnation", got)
	}
	if got := incarnationAfterAll(whole, "2026-10-20T11:59:59.999999999Z"); !latchedIncarnation(got) {
		t.Errorf("incarnationAfterAll(just after prev) = %q: reads as a pre-latch incarnation", got)
	}
	if latchedIncarnation("2026-10-20T12:00:00Z") {
		t.Error("a bare-second created_at reads as a latched incarnation")
	}
}

// Every token write stamps the account's incarnation once the receivers can
// decode it: the writer has latched, or the account was made by a writer
// that had (every host then runs this build). Before that, on an account
// made before the latch, the previous release's statement is written.
func TestTokenIncarnation_InsertTokenStampsTheAccount(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	var on bool
	c.SetUserIncarnationGate(func() bool { return on })
	stamp := func(id string) string {
		return oneString(t, c, `SELECT user_created_at FROM tokens WHERE id = ?`, "user_created_at", id)
	}
	if err := InsertUser(ctx, c, "carol", "admin", "h"); err != nil {
		t.Fatal(err)
	}
	if err := InsertToken(ctx, c, TokenRecord{ID: "t-pre", Username: "carol", Name: "n", TokenHash: "x"}); err != nil {
		t.Fatal(err)
	}
	if got := stamp("t-pre"); got != "" {
		t.Errorf("an unlatched token on a pre-latch account is stamped %q; a previous-release peer cannot decode it", got)
	}
	on = true
	if err := InsertToken(ctx, c, TokenRecord{ID: "t-on", Username: "carol", Name: "n", TokenHash: "x"}); err != nil {
		t.Fatal(err)
	}
	if got, want := stamp("t-on"), userCreatedAt(t, c, "carol"); got != want {
		t.Errorf("a latched token is stamped %q, want carol's incarnation %q", got, want)
	}
	if err := InsertUser(ctx, c, "dave", "admin", "h"); err != nil {
		t.Fatal(err)
	}
	on = false
	if err := InsertToken(ctx, c, TokenRecord{ID: "t-carried", Username: "dave", Name: "n", TokenHash: "x"}); err != nil {
		t.Fatal(err)
	}
	if got, want := stamp("t-carried"), userCreatedAt(t, c, "dave"); got != want {
		t.Errorf("an unlatched token on a latched writer's account is stamped %q, want %q", got, want)
	}
}

// A token prepared for an account that is deleted and re-created before the
// write lands fails, and writes nothing.
func TestTokenIncarnation_InsertTokenForAnAccountThatMovedIsRefused(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	c.SetUserIncarnationGate(func() bool { return true })
	if err := InsertUser(ctx, c, "carol", "admin", "h"); err != nil {
		t.Fatal(err)
	}
	userWriteInterleaveHook = func(string) {
		userWriteInterleaveHook = nil
		recreateUser(t, c, "carol")
	}
	t.Cleanup(func() { userWriteInterleaveHook = nil })
	err := InsertToken(ctx, c, TokenRecord{ID: "t1", Username: "carol", Name: "n", TokenHash: "x"})
	if !errors.Is(err, ErrUserAccountChanged) {
		t.Fatalf("InsertToken = %v, want ErrUserAccountChanged", err)
	}
	if rows, _ := c.Query(ctx, `SELECT id FROM tokens WHERE id = 't1'`); len(rows) != 0 {
		t.Error("the refused token was written")
	}
}

// The read rule, at authentication: whatever put a token row here, it opens
// only the account incarnation it names.
func TestTokenIncarnation_ValidateTokenOpensOnlyItsOwnAccount(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	c.SetUserIncarnationGate(func() bool { return true })
	if err := InsertUser(ctx, c, "carol", "admin", "h"); err != nil {
		t.Fatal(err)
	}
	old := userCreatedAt(t, c, "carol")
	recreateUser(t, c, "carol")
	now := nowRFC3339()

	// An unstamped token, minted after the re-create by a node that never
	// heard of it: the previous release's insert.
	if _, err := c.db.Exec(`INSERT INTO tokens (id, username, name, token_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		"t-unstamped", "carol", "n", mustBcrypt(t, tokRawA), now, now); err != nil {
		t.Fatal(err)
	}
	if u, err := ValidateToken(ctx, c, tokRawA); err != nil || u != nil {
		t.Errorf("an unstamped token opens the re-created carol: %+v, %v", u, err)
	}
	if live, _, _ := TokenLive(ctx, c, "t-unstamped"); live {
		t.Error("TokenLive: an unstamped token is live on the re-created carol")
	}

	if _, err := c.db.Exec(`INSERT INTO tokens (id, username, name, token_hash, created_at, updated_at, user_created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"t-old", "carol", "n", mustBcrypt(t, tokRawB), now, now, old); err != nil {
		t.Fatal(err)
	}
	if u, err := ValidateToken(ctx, c, tokRawB); err != nil || u != nil {
		t.Errorf("the deleted carol's token opens the new one: %+v, %v", u, err)
	}
	if live, _, _ := TokenLive(ctx, c, "t-old"); live {
		t.Error("TokenLive: the deleted carol's token is live on the new one")
	}

	if err := InsertToken(ctx, c, TokenRecord{ID: "t-own", Username: "carol", Name: "n", TokenHash: mustBcrypt(t, tokRawC)}); err != nil {
		t.Fatal(err)
	}
	if u, err := ValidateToken(ctx, c, tokRawC); err != nil || u == nil || u.TokenID != "t-own" {
		t.Errorf("the new carol's own token does not open her: %+v, %v", u, err)
	}
	if live, _, _ := TokenLive(ctx, c, "t-own"); !live {
		t.Error("TokenLive: the new carol's own token is not live")
	}
}

// An account made before the latch keeps its unstamped tokens: the rolling
// upgrade takes nothing away from an account that is not re-created.
func TestTokenIncarnation_APreLatchAccountKeepsItsTokens(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	var on bool
	c.SetUserIncarnationGate(func() bool { return on })
	if err := InsertUser(ctx, c, "carol", "admin", "h"); err != nil {
		t.Fatal(err)
	}
	if err := InsertToken(ctx, c, TokenRecord{ID: "t-pre", Username: "carol", Name: "n", TokenHash: mustBcrypt(t, tokRawA)}); err != nil {
		t.Fatal(err)
	}
	on = true
	if err := InsertToken(ctx, c, TokenRecord{ID: "t-post", Username: "carol", Name: "n", TokenHash: mustBcrypt(t, tokRawB)}); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{tokRawA, tokRawB} {
		if u, err := ValidateToken(ctx, c, raw); err != nil || u == nil {
			t.Errorf("a pre-latch account's token stopped working across the latch: %+v, %v", u, err)
		}
	}
}

// users-L2 over anti-entropy: a node that has not latched pulls a lagging
// node's token for the deleted account. It does not take it, and it never
// authenticates once the node latches. A token of an account that was not
// re-created is taken as before.
func TestTokenIncarnation_AnUnlatchedNodeTakesNoStaleTokenByAntiEntropy(t *testing.T) {
	ctx := context.Background()
	lag, u := newTestDB(t), newTestDB(t)
	var uOn bool
	u.SetUserIncarnationGate(func() bool { return uOn })
	for _, name := range []string{"carol", "dave"} {
		if err := InsertUser(ctx, lag, name, "admin", "h"); err != nil {
			t.Fatal(err)
		}
	}
	if err := u.MergeStateBytesLWW(lag.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	// carol is re-created where a peer had latched; u has taken the new
	// account but not latched itself yet.
	uOn = true
	recreateUser(t, u, "carol")
	uOn = false
	if err := InsertToken(ctx, lag, TokenRecord{ID: "t-stale", Username: "carol", Name: "n", TokenHash: mustBcrypt(t, tokRawA)}); err != nil {
		t.Fatal(err)
	}
	if err := InsertToken(ctx, lag, TokenRecord{ID: "t-dave", Username: "dave", Name: "n", TokenHash: mustBcrypt(t, tokRawB)}); err != nil {
		t.Fatal(err)
	}
	if err := u.MergeStateBytesLWW(lag.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	if rows, _ := u.Query(ctx, `SELECT id FROM tokens WHERE id = 't-stale'`); len(rows) != 0 {
		t.Error("an unlatched node took the deleted carol's token by anti-entropy")
	}
	uOn = true
	if got, err := ValidateToken(ctx, u, tokRawA); err != nil || got != nil {
		t.Errorf("once latched, the deleted carol's token opens the new one: %+v, %v", got, err)
	}
	if got, err := ValidateToken(ctx, u, tokRawB); err != nil || got == nil {
		t.Errorf("dave's token, of an account never re-created, was not taken: %+v, %v", got, err)
	}
}

// A node that has not latched minted a token for carol, then took her
// delete, and then takes the re-created carol by plain anti-entropy: the
// token goes with the account it was issued to, so the node holds no live
// token that no account can use.
func TestTokenIncarnation_AnUnlatchedNodeDropsItsStaleTokenWhenTheAccountMoves(t *testing.T) {
	ctx := context.Background()
	lag, u := newTestDB(t), newTestDB(t)
	lag.SetCredentialsSplitGate(func() bool { return true })
	if err := InsertUser(ctx, lag, "carol", "operator", "h"); err != nil {
		t.Fatal(err)
	}
	if err := u.MergeStateBytesLWW(lag.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	if err := InsertToken(ctx, lag, TokenRecord{ID: "t-stale", Username: "carol", Name: "n", TokenHash: "x"}); err != nil {
		t.Fatal(err)
	}
	u.SetUserIncarnationGate(func() bool { return true })
	if err := DeleteUser(ctx, u, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := lag.MergeStateBytesLWW(u.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser(ctx, u, "carol", "operator", "hash-new"); err != nil {
		t.Fatal(err)
	}
	if err := lag.MergeStateBytesLWW(u.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	if got, want := userCreatedAt(t, lag, "carol"), userCreatedAt(t, u, "carol"); got != want {
		t.Fatalf("lag did not take the new carol (%q, want %q)", got, want)
	}
	if rows, _ := lag.Query(ctx, `SELECT id FROM tokens WHERE id = 't-stale' AND deleted_at IS NULL`); len(rows) != 0 {
		t.Error("lag still holds the deleted carol's token live after taking the new carol")
	}
	if rows, _ := lag.Query(ctx, `SELECT token_id FROM token_credentials WHERE token_id = 't-stale'`); len(rows) != 0 {
		t.Error("lag dropped the stale token but kept its credential")
	}
}

// Review M2: a peer's revoke of a token is always taken, even of a token
// issued to an incarnation the name has left here and even from a sender
// that holds an older account: a revoke only takes access away. The live
// row here models one an intermediate build left (unstamped, on an account a
// latched writer made).
func TestTokenIncarnation_APeersRevokeOfAStaleTokenIsTaken(t *testing.T) {
	ctx := context.Background()
	lag, u := newTestDB(t), newTestDB(t)
	if err := InsertUser(ctx, lag, "carol", "operator", "h"); err != nil {
		t.Fatal(err)
	}
	if err := u.MergeStateBytesLWW(lag.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	u.SetUserIncarnationGate(func() bool { return true })
	recreateUser(t, u, "carol")
	const old = "2000-01-01T00:00:00Z"
	for _, c := range []*Client{lag, u} {
		if _, err := c.db.Exec(`INSERT INTO tokens (id, username, name, token_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
			"t-stale", "carol", "n", "x", old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := RevokeToken(ctx, lag, "t-stale"); err != nil {
		t.Fatal(err)
	}
	if err := u.MergeStateBytesLWW(lag.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	if got := oneString(t, u, `SELECT COALESCE(deleted_at, '') AS d FROM tokens WHERE id = 't-stale'`, "d"); got == "" {
		t.Error("a peer's revoke of a stale token was refused; the token stays live here")
	}
}

// Review M1: a node that has not latched re-creates a deleted name as a NEW
// incarnation once it holds any account a latched writer made (every host
// then decodes the form), so a token of the deleted account never opens the
// new one. Without that evidence it writes the previous release's re-create.
func TestTokenIncarnation_AnUnlatchedRecreateIsANewIncarnationOnceAnyNodeLatched(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		evidence bool
	}{{"no latched account here", false}, {"another account a latched writer made", true}} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestDB(t)
			var on bool
			c.SetUserIncarnationGate(func() bool { return on })
			if err := InsertUser(ctx, c, "carol", "operator", "h"); err != nil {
				t.Fatal(err)
			}
			if tc.evidence {
				on = true
				if err := InsertUser(ctx, c, "dave", "operator", "h"); err != nil {
					t.Fatal(err)
				}
				on = false
			}
			if err := InsertToken(ctx, c, TokenRecord{ID: "t-old", Username: "carol", Name: "n", TokenHash: mustBcrypt(t, tokRawA)}); err != nil {
				t.Fatal(err)
			}
			old := userCreatedAt(t, c, "carol")
			if err := DeleteUser(ctx, c, "carol"); err != nil {
				t.Fatal(err)
			}
			if err := InsertUser(ctx, c, "carol", "operator", "h2"); err != nil {
				t.Fatal(err)
			}
			cur := userCreatedAt(t, c, "carol")
			if tc.evidence && (cur == old || !latchedIncarnation(cur)) {
				t.Fatalf("the re-create kept the incarnation (%q -> %q)", old, cur)
			}
			if !tc.evidence && cur != old {
				t.Fatalf("with no latched writer anywhere, the re-create changed created_at (%q -> %q): a previous-release peer cannot decode it", old, cur)
			}
			if !tc.evidence {
				return
			}
			// The old carol's token, live again as a lagging node would hold it.
			if _, err := c.db.Exec(`UPDATE tokens SET deleted_at = NULL WHERE id = 't-old'`); err != nil {
				t.Fatal(err)
			}
			if u, err := ValidateToken(ctx, c, tokRawA); err != nil || u != nil {
				t.Errorf("the deleted carol's token opens the new one: %+v, %v", u, err)
			}
		})
	}
}

// users-L2 over the WAL: a replicated token insert for an older incarnation
// than the one this node holds is skipped with its credential, stamped or
// not, latched or not. One for the account this node holds applies.
func TestTokenIncarnation_AStaleReplicatedInsertIsSkipped(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	var on = true
	c.SetUserIncarnationGate(func() bool { return on })
	if err := InsertUser(ctx, c, "carol", "admin", "h"); err != nil {
		t.Fatal(err)
	}
	old := userCreatedAt(t, c, "carol")
	recreateUser(t, c, "carol")
	cur := userCreatedAt(t, c, "carol")
	on = false
	now := c.NowTS()
	tok := func(id, stamp string) []Statement {
		ins := Statement{SQL: tokensInsertSQL, Params: []interface{}{id, "carol", "n", "x", nil, "", nowRFC3339(), now}}
		if stamp != "" {
			ins = Statement{SQL: tokensInsertIncarnationSQL, Params: []interface{}{id, "carol", "n", "x", nil, "", nowRFC3339(), now, stamp}}
		}
		return []Statement{ins, {SQL: tokenCredentialUpsertSQL, Params: []interface{}{id, "x", now}}}
	}
	has := func(q, id string) bool {
		rows, err := c.Query(ctx, q, id)
		if err != nil {
			t.Fatal(err)
		}
		return len(rows) == 1
	}
	applyRemote(t, c, "2999000000001-0000-peer", tok("t-old", old)...)
	applyRemote(t, c, "2999000000002-0000-peer", tok("t-unstamped", "")...)
	applyRemote(t, c, "2999000000003-0000-peer", tok("t-own", cur)...)
	// A token for an incarnation this node has not reached yet is kept: it
	// opens nothing until the users row arrives, and is the new account's own.
	applyRemote(t, c, "2999000000004-0000-peer", tok("t-ahead", "2999-01-01T00:00:00.5Z")...)
	for id, want := range map[string]bool{"t-old": false, "t-unstamped": false, "t-own": true, "t-ahead": true} {
		if got := has(`SELECT id FROM tokens WHERE id = ?`, id); got != want {
			t.Errorf("%s: token row present = %v, want %v", id, got, want)
		}
		if got := has(`SELECT token_id FROM token_credentials WHERE token_id = ?`, id); got != want {
			t.Errorf("%s: credential row present = %v, want %v", id, got, want)
		}
	}
}

// While no token carries a stamp, a node's dump leaves the column out, so a
// previous-release node still takes its tokens by anti-entropy during the
// roll; once one does, the column is sent.
func TestTokenIncarnation_TheDumpLeavesOutAnUnsetStamp(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	var on bool
	c.SetUserIncarnationGate(func() bool { return on })
	if err := InsertUser(ctx, c, "carol", "admin", "h"); err != nil {
		t.Fatal(err)
	}
	if err := InsertToken(ctx, c, TokenRecord{ID: "t-pre", Username: "carol", Name: "n", TokenHash: "x"}); err != nil {
		t.Fatal(err)
	}
	has := func() bool {
		st, ok := c.dumpTable("tokens")
		if !ok {
			t.Fatal("dump tokens")
		}
		return indexOf(st.Columns, "user_created_at") >= 0
	}
	if has() {
		t.Fatal("an unset user_created_at column is in the dump")
	}
	on = true
	if err := InsertToken(ctx, c, TokenRecord{ID: "t-post", Username: "carol", Name: "n", TokenHash: "x"}); err != nil {
		t.Fatal(err)
	}
	if !has() {
		t.Fatal("a set user_created_at column is missing from the dump")
	}
}

// Review M1, the admin floor: a node that has not latched reinstates a
// deleted admin as a new incarnation too, once any node has latched.
func TestTokenIncarnation_AnUnlatchedReinstatementIsANewIncarnationOnceAnyNodeLatched(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	var on bool
	c.SetUserIncarnationGate(func() bool { return on })
	if err := InsertUser(ctx, c, "root", "admin", "$2a$10$root"); err != nil {
		t.Fatal(err)
	}
	on = true
	if err := InsertUser(ctx, c, "dave", "viewer", "h"); err != nil {
		t.Fatal(err)
	}
	on = false
	old := userCreatedAt(t, c, "root")
	if err := DeleteUser(ctx, c, "root"); err != nil {
		t.Fatal(err)
	}
	if who, err := ReinstateAdminIfNoneRemain(ctx, c, nil); err != nil || who != "root" {
		t.Fatalf("ReinstateAdminIfNoneRemain = %q, %v", who, err)
	}
	if cur := userCreatedAt(t, c, "root"); cur == old || !latchedIncarnation(cur) {
		t.Errorf("the reinstatement kept the incarnation (%q -> %q)", old, cur)
	}
}

// Fix round 2: a re-create that arrives by the WAL retires only the tokens
// whose stamp is not the new incarnation. The new account's own token, heard
// before the re-create or in its entry, survives with no anti-entropy; the
// old account's token and an unstamped one are retired.
func TestTokenIncarnation_AReplicatedRecreateKeepsTheNewAccountsEarlyToken(t *testing.T) {
	for _, order := range []string{"token entry before the re-create", "token in the re-create's entry, ahead of it"} {
		t.Run(order, func(t *testing.T) {
			ctx := context.Background()
			c := newTestDB(t)
			c.SetUserIncarnationGate(func() bool { return true })
			if err := InsertUser(ctx, c, "carol", "operator", "h"); err != nil {
				t.Fatal(err)
			}
			old := userCreatedAt(t, c, "carol")
			if err := InsertToken(ctx, c, TokenRecord{ID: "t-old", Username: "carol", Name: "n", TokenHash: mustBcrypt(t, tokRawA)}); err != nil {
				t.Fatal(err)
			}
			const now = "2026-12-31T00:00:00Z"
			if _, err := c.db.Exec(`INSERT INTO tokens (id, username, name, token_hash, created_at, updated_at) VALUES ('t-unstamped', 'carol', 'n', 'x', ?, ?)`, now, now); err != nil {
				t.Fatal(err)
			}
			const inc = "2999-01-01T00:00:00.5Z"
			early := []Statement{
				{SQL: tokensInsertIncarnationSQL, Params: []interface{}{"t-new", "carol", "n", mustBcrypt(t, tokRawB), nil, "", now, "2999-01-01T00:00:01.000000001Z", inc}},
				{SQL: tokenCredentialUpsertSQL, Params: []interface{}{"t-new", mustBcrypt(t, tokRawB), "2999-01-01T00:00:01.000000001Z"}},
			}
			del := Statement{SQL: usersTombstoneIncarnationSQL, Params: []interface{}{"2999-01-01T00:00:00Z", "2999-01-01T00:00:00.1Z", "carol", old}}
			recreate := Statement{SQL: usersReactivateIncarnationSQL, Params: []interface{}{"operator", "h2", inc, "2999-01-01T00:00:00.6Z", "carol"}}
			if order == "token entry before the re-create" {
				applyRemote(t, c, "2999000000001-0000-peer", early...)
				applyRemote(t, c, "2999000000002-0000-peer", del)
				applyRemote(t, c, "2999000000003-0000-peer", recreate)
			} else {
				applyRemote(t, c, "2999000000001-0000-peer", del)
				applyRemote(t, c, "2999000000002-0000-peer", append(append([]Statement{}, early...), recreate)...)
			}
			if got := userCreatedAt(t, c, "carol"); got != inc {
				t.Fatalf("carol is %q after the re-create, want %q", got, inc)
			}
			if u, err := ValidateToken(ctx, c, tokRawB); err != nil || u == nil || u.TokenID != "t-new" {
				t.Errorf("the new carol's early token was dropped: %+v, %v", u, err)
			}
			for _, id := range []string{"t-old", "t-unstamped"} {
				if rows, _ := c.Query(ctx, `SELECT id FROM tokens WHERE id = ? AND deleted_at IS NULL`, id); len(rows) != 0 {
					t.Errorf("%s is still live after the re-create", id)
				}
			}
		})
	}
}
