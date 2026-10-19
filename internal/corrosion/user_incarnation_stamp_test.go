package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// A write prepared for one account must not land on another account of the
// name: a delete and re-create that replicate in between the writer's read
// and its batch fail the write, and nothing is applied or logged (review M2).
// Receivers skip such a write by its guard, but this node would take it, and
// its newer clock would carry it to every node by anti-entropy.
//
// Red on eb047a3ac: the stale password lands on the new carol here.
// Mutation: checkOwnUserGuard always nil — red.
func TestUserGuard_OwnWriteRefusedOnceTheAccountChanged(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	c.SetUserIncarnationGate(func() bool { return true })
	c.SetCredentialsSplitGate(func() bool { return true })
	if err := InsertUser(ctx, c, "carol", "operator", "hash-old"); err != nil {
		t.Fatal(err)
	}
	stmts, err := updateUserPasswordStatements(ctx, c, "carol", "hash-stale", c.NowTS())
	if err != nil || len(stmts) != 2 {
		t.Fatalf("statements: %v, %d", err, len(stmts))
	}
	// The delete and re-create land between the read and the write.
	if err := DeleteUser(ctx, c, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser(ctx, c, "carol", "operator", "hash-new"); err != nil {
		t.Fatal(err)
	}
	var before int
	if err := c.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mutation_log`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := c.ExecuteBatch(ctx, stmts); !errors.Is(err, ErrUserAccountChanged) {
		t.Errorf("err = %v, want ErrUserAccountChanged", err)
	}
	if u, err := GetUser(ctx, c, "carol"); err != nil || u == nil || u.PasswordHash != "hash-new" {
		t.Errorf("carol = %+v (err %v), want the new account with its own password", u, err)
	}
	var after int
	if err := c.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mutation_log`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("mutation_log grew by %d: a refused write was logged", after-before)
	}
}

// Once user_incarnation_v1 has latched, a first create's incarnation has
// nanosecond precision, so two creates of one name in the same second on
// partitioned nodes are two incarnations (review L2). Before the latch it is
// the previous release's bare second.
//
// Red on eb047a3ac: the incarnation is a bare second after the latch.
func TestUserIncarnation_FirstCreateIsNanosecondPrecise(t *testing.T) {
	ctx := context.Background()
	for _, on := range []bool{false, true} {
		c := newTestDB(t)
		c.SetUserIncarnationGate(func() bool { return on })
		if err := InsertUser(ctx, c, "carol", "operator", "hash"); err != nil {
			t.Fatal(err)
		}
		u, err := GetUser(ctx, c, "carol")
		if err != nil || u == nil {
			t.Fatalf("carol: %+v, %v", u, err)
		}
		if _, err := time.Parse(time.RFC3339Nano, u.CreatedAt); err != nil {
			t.Fatalf("created_at %q: %v", u.CreatedAt, err)
		}
		if frac := strings.Contains(u.CreatedAt, "."); frac != on {
			t.Errorf("latched=%v: created_at %q", on, u.CreatedAt)
		}
	}
}

// A local write stamps the statements that grant an account something, or
// lift a restriction on it, with the account's incarnation as its users row
// stands in the write's own transaction: live, or deleted for a write to a
// deleted name. A restriction stays unguarded, so it reaches whatever account
// holds the name, and a write naming two accounts keeps the previous
// release's form (a receiver refuses an entry with two guard identities).
//
// Mutations: stamp every user-keyed statement (userStatementAccount ignores
// userStampedShapes) — "a disable" red; userStampPlan admits two accounts —
// the write naming two accounts fails; stamp a deleted name userGuardAny —
// the reset red; role_bindings left out of userStatementAccount's table
// filter — "a role binding" red.
func TestUserStamp_GrantsAndLiftsOnly(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	c.SetUserIncarnationGate(func() bool { return true })
	c.SetCredentialsSplitGate(func() bool { return true })
	g := capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
	for _, u := range []string{"carol", "dave"} {
		if err := InsertUser(ctx, c, u, "operator", "hash"); err != nil {
			t.Fatal(err)
		}
	}
	carol, _ := GetUser(ctx, c, "carol")
	last := func() []Statement {
		t.Helper()
		var raw string
		if err := c.db.QueryRowContext(ctx, `SELECT stmts FROM mutation_log ORDER BY seq DESC LIMIT 1`).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var out []Statement
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	want := func(name string, s Statement, kind string) {
		t.Helper()
		switch {
		case kind == "" && s.Guard != nil:
			t.Errorf("%s: guarded %+v, want none", name, *s.Guard)
		case kind != "" && (s.Guard == nil || s.Guard.Protocol != userIncarnationGuardV1 || s.Guard.ResourceKind != kind ||
			s.Guard.ResourceID != "carol" || s.Guard.Incarnation != carol.CreatedAt):
			t.Errorf("%s: guard %+v, want %s on carol's incarnation %s", name, s.Guard, kind, carol.CreatedAt)
		}
	}

	if err := InsertToken(ctx, c, TokenRecord{ID: "tok-1", Username: "carol", Name: "t", TokenHash: "th"}); err != nil {
		t.Fatal(err)
	}
	want("a token", last()[0], userGuardLive)

	yes := true
	if err := SetUserLifecycle(ctx, c, g, "carol", &yes, nil, "admin"); err != nil {
		t.Fatal(err)
	}
	for _, s := range last() {
		want("a disable", s, "")
	}
	no := false
	if err := SetUserLifecycle(ctx, c, g, "carol", &no, nil, "admin"); err != nil {
		t.Fatal(err)
	}
	enable := last()
	want("an enable's cut-off", enable[0], "")
	want("an enable", enable[len(enable)-1], userGuardLive)

	if err := InsertRoleBinding(ctx, c, RoleBindingRecord{ID: "rb-1", Path: "/", Role: "admin", Principal: "user:carol"}); err != nil {
		t.Fatal(err)
	}
	want("a role binding", last()[0], userGuardLive)

	// Two accounts' grants in one write: left unguarded.
	now := c.NowTS()
	if err := c.ExecuteBatch(ctx, []Statement{
		{SQL: roleBindingInsertSQL, Params: []interface{}{"rb-c", "/", "viewer", "user:carol", 1, now}},
		{SQL: roleBindingInsertSQL, Params: []interface{}{"rb-d", "/", "viewer", "user:dave", 1, now}},
	}); err != nil {
		t.Fatalf("a write naming two accounts: %v", err)
	}
	for _, s := range last() {
		if s.Guard != nil {
			t.Errorf("a write naming two accounts: guarded %+v", *s.Guard)
		}
	}

	if err := DeleteUser(ctx, c, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := ResetUserLifecycle(ctx, c, g, "carol", "admin"); err != nil {
		t.Fatal(err)
	}
	want("a reset's enable of a deleted name", last()[0], userGuardDeleted)
}
