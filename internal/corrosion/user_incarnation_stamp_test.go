package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/hlc"
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

// A local write stamps a user-keyed statement with the account's incarnation
// as its users row stands in the write's own transaction: a grant or lift
// live, or deleted for a write to a deleted name; a restriction
// user_tighten, which a receiver never drops for the account it names
// (user_holds.go). A grant naming two accounts in one write is refused; a
// restriction naming two is sent unguarded.
//
// Mutations: a disable stamped as a lift (lifecycleTightens false) — "a
// disable" red; userStampPlan admits two accounts' grants — red; stamp a
// deleted name userGuardAny — the reset red; role_bindings left out of
// userStatementAccount's table filter — "a role binding" red.
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
	disable := last()
	if len(disable) != 3 {
		t.Fatalf("a disable: %d statements", len(disable))
	}
	want("a disable's cut-off", disable[0], userGuardTighten)
	want("a disable's voided enrollment code", disable[1], "")
	want("a disable", disable[2], userGuardTighten)
	no := false
	if err := SetUserLifecycle(ctx, c, g, "carol", &no, nil, "admin"); err != nil {
		t.Fatal(err)
	}
	enable := last()
	want("an enable's cut-off", enable[0], userGuardTighten)
	want("an enable", enable[len(enable)-1], userGuardLive)

	if err := InsertRoleBinding(ctx, c, RoleBindingRecord{ID: "rb-1", Path: "/", Role: "admin", Principal: "user:carol"}); err != nil {
		t.Fatal(err)
	}
	want("a role binding", last()[0], userGuardLive)

	// Two accounts' grants in one write: refused, never sent unguarded
	// (re-review 2, L3).
	now := c.NowTS()
	if err := c.ExecuteBatch(ctx, []Statement{
		{SQL: roleBindingInsertSQL, Params: []interface{}{"rb-c", "/", "viewer", "user:carol", 1, now}},
		{SQL: roleBindingInsertSQL, Params: []interface{}{"rb-d", "/", "viewer", "user:dave", 1, now}},
	}); !errors.Is(err, ErrUserMultiAccountGrant) {
		t.Errorf("a grant naming two accounts: err = %v, want ErrUserMultiAccountGrant", err)
	}
	// Two accounts' restrictions in one write: left unguarded, and sent.
	if err := c.ExecuteBatch(ctx, []Statement{
		{SQL: userLifecycleUpsertSQL, Params: []interface{}{"carol", UserAttrSessionsNotBefore, nowRFC3339(), "admin", now}},
		{SQL: userLifecycleUpsertSQL, Params: []interface{}{"dave", UserAttrSessionsNotBefore, nowRFC3339(), "admin", now}},
	}); err != nil {
		t.Fatalf("a restriction naming two accounts: %v", err)
	}
	for _, s := range last() {
		if s.Guard != nil {
			t.Errorf("a restriction naming two accounts: guarded %+v", *s.Guard)
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

// A write prepared for a re-create must not overwrite an account of the name
// that replicated in between its read and its batch: InsertUser's re-create
// and the admin floor's reinstatement check, inside their transaction, that
// the tombstone they read is still there (re-review 2, M4: MU6, MU7).
//
// Mutations: InsertUser's in-transaction check always true — "a re-create"
// red; the admin floor's — "the admin floor" red.
func TestUserRecreate_RefusedOnceAPeersAccountReplicatedIn(t *testing.T) {
	ctx := context.Background()
	peerRecreate := func(t *testing.T, c *Client, name, role, hash string) {
		t.Helper()
		var created string
		if err := c.db.QueryRowContext(ctx, `SELECT created_at FROM users WHERE username = ?`, name).Scan(&created); err != nil {
			t.Fatal(err)
		}
		stmts, _ := json.Marshal([]Statement{
			{SQL: usersReactivateIncarnationSQL, Params: []interface{}{role, hash, nextIncarnation(created), c.NowTS(), name}},
			{SQL: userCredentialUpsertSQL, Params: []interface{}{name, hash, c.NowTS()}},
		})
		r := NewReplicator(c, "", RelayConfig{})
		if _, err := r.ApplyRemoteMutations(ctx, []*pb.MutationEntry{{Seq: 1, Hlc: c.NowTS(), Origin: "node-9", Stmts: string(stmts)}}); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("a re-create", func(t *testing.T) {
		c := newTestDB(t)
		c.SetUserIncarnationGate(func() bool { return true })
		c.SetCredentialsSplitGate(func() bool { return true })
		if err := InsertUser(ctx, c, "carol", "operator", "hash-old"); err != nil {
			t.Fatal(err)
		}
		if err := DeleteUser(ctx, c, "carol"); err != nil {
			t.Fatal(err)
		}
		userWriteInterleaveHook = func(name string) { peerRecreate(t, c, name, "viewer", "hash-peer") }
		t.Cleanup(func() { userWriteInterleaveHook = nil })
		if err := InsertUser(ctx, c, "carol", "admin", "hash-mine"); !errors.Is(err, ErrUserAccountChanged) {
			t.Errorf("err = %v, want ErrUserAccountChanged", err)
		}
		if u, _ := GetUser(ctx, c, "carol"); u == nil || u.PasswordHash != "hash-peer" || u.Role != "viewer" {
			t.Errorf("carol = %+v, want the peer's account untouched", u)
		}
	})
	t.Run("the admin floor", func(t *testing.T) {
		c := newTestDB(t)
		c.SetUserIncarnationGate(func() bool { return true })
		c.SetCredentialsSplitGate(func() bool { return true })
		if err := InsertUser(ctx, c, "root", "admin", "hash-old"); err != nil {
			t.Fatal(err)
		}
		if err := DeleteUser(ctx, c, "root"); err != nil {
			t.Fatal(err)
		}
		userWriteInterleaveHook = func(name string) { peerRecreate(t, c, name, "admin", "hash-peer") }
		t.Cleanup(func() { userWriteInterleaveHook = nil })
		if _, err := ReinstateAdminIfNoneRemain(ctx, c, nil); !errors.Is(err, ErrUserAccountChanged) {
			t.Errorf("err = %v, want ErrUserAccountChanged", err)
		}
		if u, _ := GetUser(ctx, c, "root"); u == nil || u.PasswordHash != "hash-peer" {
			t.Errorf("root = %+v, want the peer's account untouched", u)
		}
	})
}

// A create's incarnation is floored at the node's hybrid clock, which has
// seen every write that reached it, so a create on a node whose wall clock
// runs behind a peer's still orders after what the node has heard
// (re-review 2, L5).
//
// Mutation: newIncarnation ignores the hybrid clock — red.
func TestUserIncarnation_FlooredAtTheHybridClock(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	c.SetUserIncarnationGate(func() bool { return true })
	ahead := time.Now().Add(2 * time.Minute)
	c.clock.Update(hlc.Timestamp{PhysicalMS: ahead.UnixMilli(), NodeID: "peer"})
	if err := InsertUser(ctx, c, "carol", "operator", "hash"); err != nil {
		t.Fatal(err)
	}
	u, err := GetUser(ctx, c, "carol")
	if err != nil || u == nil {
		t.Fatalf("carol: %+v, %v", u, err)
	}
	created, err := time.Parse(time.RFC3339Nano, u.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if created.Before(ahead.Truncate(time.Millisecond)) {
		t.Errorf("created_at %s is behind the hybrid clock's %s", u.CreatedAt, ahead.UTC().Format(time.RFC3339Nano))
	}
}

// A write bound to an incarnation this node has not reached yet — it holds
// no row for the name — is applied at once when it tightens, so the account
// never reads as less restricted than it is even if the hold were lost (a
// restart), and held when it grants. Once the account's create lands, the
// grant is replayed (re-review 2, H1, M2).
//
// Mutation: a tightening held like a grant — "the factor" red.
func TestUserHolds_ATighteningAheadAppliesAndAGrantAheadIsHeld(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	c.SetUserIncarnationGate(func() bool { return true })
	r := NewReplicator(c, "", RelayConfig{})
	inc := nowRFC3339Nano()
	g := func(kind string) *MutationGuard {
		return &MutationGuard{Protocol: userIncarnationGuardV1, ResourceKind: kind, ResourceID: "carol", Incarnation: inc}
	}
	now := c.NowTS()
	apply := func(seq int64, stmts []Statement) {
		t.Helper()
		b, _ := json.Marshal(stmts)
		if _, err := r.ApplyRemoteMutations(ctx, []*pb.MutationEntry{{Seq: seq, Hlc: c.NowTS(), Origin: "node-1", Stmts: string(b)}}); err != nil {
			t.Fatal(err)
		}
	}
	apply(1, []Statement{
		{SQL: user2FASetUpsertSQL, Params: []interface{}{"carol", "e1", now}, Guard: g(userGuardTighten)},
		{SQL: user2FAUpsertSQL, Params: []interface{}{"carol", "totp", "s", "phone", nowRFC3339(), now, "e1"}, Guard: g(userGuardTighten)},
	})
	apply(2, []Statement{{SQL: sessionsInsertSQL, Params: []interface{}{"sess-1", "carol", "local", "", "", nowRFC3339(), nowRFC3339(), nowRFC3339()}, Guard: g(userGuardLive)}})
	var factors, sessions int
	if err := c.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_2fa WHERE username = 'carol' AND deleted_at IS NULL`).Scan(&factors); err != nil {
		t.Fatal(err)
	}
	if factors != 1 {
		t.Errorf("the factor heard before its account: %d rows, want it applied at once", factors)
	}
	if err := c.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE id = 'sess-1'`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 || c.UserHolds() == 0 {
		t.Errorf("the session heard before its account: %d rows, %d held; want it held", sessions, c.UserHolds())
	}
	apply(3, []Statement{{SQL: usersInsertSQL, Params: []interface{}{"carol", "operator", "h", inc, now}}})
	if err := c.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE id = 'sess-1'`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 {
		t.Errorf("the held session was not replayed once its account landed")
	}
}
