package corrosion

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
)

// A re-create of a newer incarnation drops the rows the older one left under
// the name (retireOlderIncarnationRows), but it cannot tell them from rows
// the NEW account's writes put on this node first, from another origin ahead
// of the re-create. So it must fail closed: a live restriction (a disable, a
// session cut-off, a second factor) and a tombstoned grant (a consumed
// enrollment code, a removed directory binding or role binding, a superseded
// recovery-code set, a retired credential) all survive it, so no account reads
// as enabled, unfactored or re-granted on this node until anti-entropy runs.
//
// Red on 5391389f4 for every row: the retirement dropped them all, and the
// disabled carol logged in. Mutation: drop a lifecycle row whatever its state
// — "a disable" red.
func TestUserRecreate_RetirementFailsClosed(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	// The rows below reach this node with nothing recording which
	// incarnation they were for — written before the latch, or recorded and
	// forgotten across a restart (user_holds.go) — so the retirement cannot
	// tell them from the new account's own. A row recorded for the older
	// incarnation is taken away instead (TestFleet_ALaggingGrantDoesNotReach-
	// ARecreatedUser, "a second factor re-enrolled").
	var gate atomic.Bool
	c.SetUserIncarnationGate(gate.Load)
	c.SetCredentialsSplitGate(func() bool { return true })
	g := capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
	if err := InsertUser(ctx, c, "carol", "operator", "hash-old"); err != nil {
		t.Fatal(err)
	}
	disabled := true
	if err := SetUserLifecycle(ctx, c, g, "carol", &disabled, nil, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser2FA(ctx, c, User2FARecord{Username: "carol", Method: "totp", Secret: "s", Label: "phone"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertRecoveryCodes(ctx, c, "carol", []string{"code-1"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := IssueEnrollmentCode(ctx, c, g, "carol", time.Hour, "admin", "node-0"); err != nil {
		t.Fatal(err)
	}
	if err := InvalidateEnrollmentCode(ctx, c, g, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := BindIdentity(ctx, c, g, "carol", "oidc", "ext-1"); err != nil {
		t.Fatal(err)
	}
	clear, err := clearIdentityBindingsStatements(ctx, c, "carol", nowRFC3339(), c.NowTS(), nil)
	if err != nil || len(clear) != 1 {
		t.Fatalf("clear binding: %v, %d", err, len(clear))
	}
	if err := c.ExecuteBatch(ctx, clear); err != nil {
		t.Fatal(err)
	}
	if err := InsertRoleBinding(ctx, c, RoleBindingRecord{ID: "rb-1", Path: "/", Role: "viewer", Principal: "user:carol"}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteRoleBinding(ctx, c, "rb-1"); err != nil {
		t.Fatal(err)
	}
	// This node now holds carol's users row tombstoned, as a node does whose
	// re-create entry has not arrived; the rows above are what reached it.
	var created string
	if err := c.db.QueryRowContext(ctx, `SELECT created_at FROM users WHERE username = 'carol'`).Scan(&created); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`UPDATE users SET deleted_at = '2026-10-19T00:00:00Z' WHERE username = 'carol'`,
		`UPDATE recovery_code_sets SET deleted_at = '2026-10-19T00:00:00Z' WHERE username = 'carol'`,
		`UPDATE user_credentials SET deleted_at = '2026-10-19T00:00:00Z' WHERE username = 'carol'`,
	} {
		if _, err := c.db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	type count struct{ live, gone int }
	counts := func() map[string]count {
		out := map[string]count{}
		for _, q := range []struct{ name, sql string }{
			{"a disable", `user_lifecycle WHERE username = 'carol' AND attribute = 'disabled'`},
			{"a second factor", `user_2fa WHERE username = 'carol'`},
			{"a second factor's set", `user_2fa_sets WHERE username = 'carol'`},
			{"a consumed enrollment code", `user_enrollment_codes WHERE username = 'carol'`},
			{"a removed directory binding", `user_identity_bindings WHERE username = 'carol'`},
			{"a removed role binding", `role_bindings WHERE id = 'rb-1'`},
			{"a superseded recovery-code set", `recovery_code_sets WHERE username = 'carol'`},
			{"a retired credential", `user_credentials WHERE username = 'carol'`},
		} {
			var cnt count
			if err := c.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(deleted_at IS NULL), 0), COALESCE(SUM(deleted_at IS NOT NULL), 0) FROM `+q.sql).
				Scan(&cnt.live, &cnt.gone); err != nil {
				t.Fatal(err)
			}
			out[q.name] = cnt
		}
		return out
	}
	before := counts()
	gate.Store(true)

	// The re-create of a newer carol arrives.
	stmts, _ := json.Marshal([]Statement{
		{SQL: usersReactivateIncarnationSQL, Params: []interface{}{"viewer", "", nextIncarnation(created), c.NowTS(), "carol"}},
	})
	r := NewReplicator(c, "", RelayConfig{})
	if _, err := r.ApplyRemoteMutations(ctx, []*pb.MutationEntry{{Seq: 1, Hlc: c.NowTS(), Origin: "node-0", Stmts: string(stmts)}}); err != nil {
		t.Fatal(err)
	}
	if u, _ := GetUser(ctx, c, "carol"); u == nil || u.Role != "viewer" {
		t.Fatalf("fixture: the re-create did not apply: %+v", u)
	}
	after := counts()
	for name, b := range before {
		if b.live+b.gone == 0 {
			t.Fatalf("fixture: no %s before the re-create", name)
		}
		if after[name] != b {
			t.Errorf("%s: %+v before the re-create, %+v after: the retirement dropped a row whose loss can grant access", name, b, after[name])
		}
	}
	lc, err := GetUserLifecycle(ctx, c, "carol")
	if err != nil {
		t.Fatal(err)
	}
	if lc.InactiveReason(time.Now().UTC()) == "" {
		t.Errorf("carol may log in on this node: the disable that reached it before the re-create was dropped")
	}
}
