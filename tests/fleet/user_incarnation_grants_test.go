package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_ALaggingGrantDoesNotReachARecreatedUser: node-2, cut off, gives
// the carol it knows something — or lifts a restriction on her — after node-0
// deleted her and created a new carol. Each write belongs to the deleted
// account: on no node may it reach the new carol, over the WAL or after
// anti-entropy (review M3).
//
// Red on eb047a3ac for every kind: the write lands on the new carol
// everywhere. Mutations: the grants left unstamped (userStampedShapes) — red
// for every kind; the lagging lifts kept by the retirement
// (retireLaggingLifts) and unrecorded (settleUserName) — "an enable" and "an
// expiry extension" red on node-2, and on every node after anti-entropy;
// settleUserName not taking recorded rows away — "a second factor
// re-enrolled" red.
func TestFleet_ALaggingGrantDoesNotReachARecreatedUser(t *testing.T) {
	ctx := context.Background()
	g := capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
	soon := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	far := time.Now().Add(480 * time.Hour).UTC().Format(time.RFC3339)
	yes, no := true, false
	for _, tc := range []struct {
		name          string
		seed          int64
		before, after func(t *testing.T, n *Node)
		lagging       func(t *testing.T, n *Node)
		check         func(t *testing.T, n *Node) string
	}{
		{
			name: "an enable", seed: 5601,
			after: func(t *testing.T, n *Node) {
				if err := corrosion.SetUserLifecycle(ctx, n.DB, g, "carol", &yes, nil, "admin"); err != nil {
					t.Fatal(err)
				}
			},
			lagging: func(t *testing.T, n *Node) {
				if err := corrosion.SetUserLifecycle(ctx, n.DB, g, "carol", &no, nil, "admin"); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, n *Node) string {
				if l, err := corrosion.GetUserLifecycle(ctx, n.DB, "carol"); err != nil || !l.Disabled {
					return "the new carol is enabled"
				}
				return ""
			},
		},
		{
			name: "an expiry extension", seed: 5602,
			after: func(t *testing.T, n *Node) {
				if err := corrosion.SetUserLifecycle(ctx, n.DB, g, "carol", nil, &soon, "admin"); err != nil {
					t.Fatal(err)
				}
			},
			lagging: func(t *testing.T, n *Node) {
				if err := corrosion.SetUserLifecycle(ctx, n.DB, g, "carol", nil, &far, "admin"); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, n *Node) string {
				if l, err := corrosion.GetUserLifecycle(ctx, n.DB, "carol"); err != nil || l.ExpiresAt != soon {
					return "the new carol's expiry is " + l.ExpiresAt
				}
				return ""
			},
		},
		{
			name: "a role binding", seed: 5603,
			lagging: func(t *testing.T, n *Node) {
				if err := corrosion.InsertRoleBinding(ctx, n.DB, corrosion.RoleBindingRecord{
					ID: "rb-lag", Path: "/", Role: "admin", Principal: "user:carol"}); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, n *Node) string {
				if b, err := corrosion.GetRoleBinding(ctx, n.DB, "rb-lag"); err != nil || b != nil {
					return "the new carol holds the lagging role binding"
				}
				return ""
			},
		},
		{
			name: "a directory binding", seed: 5604,
			lagging: func(t *testing.T, n *Node) {
				if err := corrosion.BindIdentity(ctx, n.DB, g, "carol", "oidc", "ext-lag"); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, n *Node) string {
				if id, err := corrosion.GetIdentityBinding(ctx, n.DB, "carol", "oidc"); err != nil || id != "" {
					return "the new carol is bound to " + id
				}
				return ""
			},
		},
		{
			name: "an enrollment code", seed: 5605,
			lagging: func(t *testing.T, n *Node) {
				if _, _, err := corrosion.IssueEnrollmentCode(ctx, n.DB, g, "carol", time.Hour, "admin", n.Name); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, n *Node) string {
				if live, err := corrosion.HasLiveEnrollmentCode(ctx, n.DB, "carol"); err != nil || live {
					return "the new carol holds the lagging enrollment code"
				}
				return ""
			},
		},
		{
			name: "recovery codes", seed: 5606,
			lagging: func(t *testing.T, n *Node) {
				if err := corrosion.InsertRecoveryCodes(ctx, n.DB, "carol", []string{"code-lag"}); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, n *Node) string {
				if codes, err := corrosion.ListUnusedRecoveryCodes(ctx, n.DB, "carol"); err != nil || len(codes) != 0 {
					return "the new carol holds the lagging recovery codes"
				}
				return ""
			},
		},
		{
			name: "a second factor removed", seed: 5607,
			before: func(t *testing.T, n *Node) {
				if err := corrosion.InsertUser2FA(ctx, n.DB, corrosion.User2FARecord{
					Username: "carol", Method: "totp", Secret: "s-old", Label: "phone"}); err != nil {
					t.Fatal(err)
				}
			},
			after: func(t *testing.T, n *Node) {
				if err := corrosion.InsertUser2FA(ctx, n.DB, corrosion.User2FARecord{
					Username: "carol", Method: "totp", Secret: "s-new", Label: "phone"}); err != nil {
					t.Fatal(err)
				}
			},
			lagging: func(t *testing.T, n *Node) {
				if err := corrosion.DeleteUser2FA(ctx, n.DB, "carol", "totp", "phone"); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, n *Node) string {
				if fs, err := corrosion.ListUser2FA(ctx, n.DB, "carol"); err != nil || len(fs) != 1 || fs[0].Secret != "s-new" {
					return "the new carol's factor is gone"
				}
				return ""
			},
		},
		{
			// A lagging RE-ENROLMENT of the deleted account, under the same
			// key as the new account's factor and with a later clock: node-2
			// takes it away when the re-create reaches it (its record,
			// user_holds.go), and no other node takes it (re-review 2, MU9).
			name: "a second factor re-enrolled", seed: 5609,
			after: func(t *testing.T, n *Node) {
				if err := corrosion.InsertUser2FA(ctx, n.DB, corrosion.User2FARecord{
					Username: "carol", Method: "totp", Secret: "s-new", Label: "phone"}); err != nil {
					t.Fatal(err)
				}
			},
			lagging: func(t *testing.T, n *Node) {
				if err := corrosion.InsertUser2FA(ctx, n.DB, corrosion.User2FARecord{
					Username: "carol", Method: "totp", Secret: "s-lag", Label: "phone"}); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, n *Node) string {
				if fs, err := corrosion.ListUser2FA(ctx, n.DB, "carol"); err != nil || len(fs) != 1 || fs[0].Secret != "s-new" {
					return "the new carol's factors are not her own"
				}
				return ""
			},
		},
		{
			name: "a session", seed: 5608,
			lagging: func(t *testing.T, n *Node) {
				now := time.Now().UTC()
				if err := corrosion.InsertSession(ctx, n.DB, corrosion.SessionRecord{
					ID: "sess-lag", Username: "carol", Realm: "local",
					CreatedAt: now.Format(time.RFC3339), LastUsedAt: now.Format(time.RFC3339),
					ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, n *Node) string {
				if s, err := corrosion.GetSession(ctx, n.DB, "sess-lag"); err != nil || s != nil && s.RevokedAt == "" {
					return "the new carol holds the lagging session"
				}
				return ""
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrap := func(f func(*testing.T, *Node)) func(*Node) {
				if f == nil {
					return nil
				}
				return func(n *Node) { f(t, n) }
			}
			c := recreatedWhileLagging(t, tc.seed, "hash-new", wrap(tc.before), wrap(tc.after), wrap(tc.lagging))
			check := func(when string) {
				for _, n := range c.Nodes {
					if u, err := corrosion.GetUser(ctx, n.DB, "carol"); err != nil || u == nil || u.PasswordHash != "hash-new" {
						t.Fatalf("%s, %s: carol = %+v (err %v), want the new account", when, n.Name, u, err)
					}
					if bad := tc.check(t, n); bad != "" {
						t.Errorf("%s, %s: %s", when, n.Name, bad)
					}
				}
			}
			check("over the WAL")
			antiEntropyRound(t, c)
			check("after anti-entropy")
		})
	}
}

// TestFleet_ALaggingEnablePulledByAntiEntropyIsRetired: node-2, cut off,
// re-enables the carol it knows after node-0 deleted her and created a new,
// disabled carol, and then learns the re-create by anti-entropy (it pulls
// from node-0 while its WAL is still cut). Its enable, stamped after the new
// carol was made, is the deleted account's: it must not survive the pull and
// outlast the new carol's disable by its clock, here or, by anti-entropy, on
// any node.
//
// Red on eb047a3ac: the new carol is enabled on every node. Mutation: the
// anti-entropy adoption without retireLaggingLifts — red on node-2, then on
// every node.
func TestFleet_ALaggingEnablePulledByAntiEntropyIsRetired(t *testing.T) {
	ctx := context.Background()
	g := capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 5611})
	latchUserIncarnation(t, c, nil, nil)
	for _, n := range c.Nodes {
		n.DB.SetCredentialsSplitGate(func() bool { return true })
	}
	admin, lag := c.Nodes[0], c.Nodes[2]
	if err := corrosion.InsertUser(ctx, admin.DB, "carol", "operator", "hash-old"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	c.Isolate(lag)
	if err := corrosion.DeleteUser(ctx, admin.DB, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser(ctx, admin.DB, "carol", "operator", "hash-new"); err != nil {
		t.Fatal(err)
	}
	yes, no := true, false
	if err := corrosion.SetUserLifecycle(ctx, admin.DB, g, "carol", &yes, nil, "admin"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := corrosion.SetUserLifecycle(ctx, lag.DB, g, "carol", &no, nil, "admin"); err != nil {
		t.Fatal(err)
	}
	for _, n := range c.Nodes[:2] {
		c.SetLinkFault(lag, n, LinkFault{})
	}
	corrosion.NewAntiEntropy(lag.DB, lag.PKIDir, 0).RunOnce(ctx)
	check := func(when string, nodes []*Node) {
		for _, n := range nodes {
			l, err := corrosion.GetUserLifecycle(ctx, n.DB, "carol")
			if err != nil || !l.Disabled {
				t.Errorf("%s, %s: the new carol is enabled (err %v)", when, n.Name, err)
			}
		}
	}
	check("after node-2's anti-entropy pull", []*Node{lag})
	c.ClearLinkFaults()
	eventually(t, convergeTimeout, "the WAL to drain", func() bool {
		n, err := undelivered(c.Nodes)
		return err == nil && n == 0
	})
	check("over the WAL", c.Nodes)
	for _, n := range c.Nodes {
		corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
	}
	check("after a real anti-entropy round", c.Nodes)
}

// TestFleet_ARecreatesLifecycleResetDoesNotEnableTheOldAccount: node-1 holds
// carol deleted (node-0's delete reached it by anti-entropy) and resets her
// lifecycle for a re-create, as `lv user create` does. node-2 has not seen the
// delete and holds the old carol live and disabled. The reset is a write to
// the deleted name: it must not re-enable the live old account on node-2
// before the delete reaches it.
//
// Red on eb047a3ac: node-2's old carol is enabled. Mutation: stamp a write to
// a deleted account userGuardAny instead of userGuardDeleted — red.
func TestFleet_ARecreatesLifecycleResetDoesNotEnableTheOldAccount(t *testing.T) {
	ctx := context.Background()
	g := capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 5612})
	latchUserIncarnation(t, c, nil, nil)
	for _, n := range c.Nodes {
		n.DB.SetCredentialsSplitGate(func() bool { return true })
	}
	a, b, old := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if err := corrosion.InsertUser(ctx, a.DB, "carol", "operator", "hash-old"); err != nil {
		t.Fatal(err)
	}
	yes := true
	if err := corrosion.SetUserLifecycle(ctx, a.DB, g, "carol", &yes, nil, "admin"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	c.Isolate(a)
	if err := corrosion.DeleteUser(ctx, a.DB, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := b.DB.MergeStateBytesLWW(a.DB.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	if u, _ := corrosion.GetUser(ctx, b.DB, "carol"); u != nil {
		t.Fatalf("node-1 did not take the delete: %+v", u)
	}
	if err := corrosion.ResetUserLifecycle(ctx, b.DB, g, "carol", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser(ctx, b.DB, "zed-marker", "viewer", "hash-z"); err != nil {
		t.Fatal(err)
	}
	eventually(t, convergeTimeout, "node-1's writes to reach node-2", func() bool {
		u, _ := corrosion.GetUser(ctx, old.DB, "zed-marker")
		return u != nil
	})
	if u, _ := corrosion.GetUser(ctx, old.DB, "carol"); u == nil {
		t.Fatal("fixture: node-2 already took the delete")
	}
	if l, err := corrosion.GetUserLifecycle(ctx, old.DB, "carol"); err != nil || !l.Disabled {
		t.Errorf("node-2: the live old carol was re-enabled by a reset of the deleted name (err %v)", err)
	}
}

// TestFleet_AnOldAccountsTokenIsRefusedByAntiEntropy: node-2, cut off, mints
// a token for the carol it knows after node-0 deleted her and created a new
// carol. Before node-2 learns of it, node-0 pulls node-2's state by
// anti-entropy: node-2's users row is the older incarnation, so the token,
// the deleted account's, is refused (userKeyedTables) — node-2's own
// retirement has not run to take it away (re-review 2, MU4).
//
// Mutation: tokens out of userKeyedTables — red.
func TestFleet_AnOldAccountsTokenIsRefusedByAntiEntropy(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 5613})
	latchUserIncarnation(t, c, nil, nil)
	for _, n := range c.Nodes {
		n.DB.SetCredentialsSplitGate(func() bool { return true })
	}
	admin, lag := c.Nodes[0], c.Nodes[2]
	if err := corrosion.InsertUser(ctx, admin.DB, "carol", "operator", "hash-old"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	c.Isolate(lag)
	if err := corrosion.DeleteUser(ctx, admin.DB, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser(ctx, admin.DB, "carol", "operator", "hash-new"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertToken(ctx, lag.DB, corrosion.TokenRecord{
		ID: "tok-lag", Username: "carol", Name: "mine", TokenHash: "th-lag"}); err != nil {
		t.Fatal(err)
	}
	if err := admin.DB.MergeStateBytesLWW(pullDump(t, c, lag)); err != nil {
		t.Fatal(err)
	}
	rows, err := admin.DB.Query(ctx, `SELECT id FROM tokens WHERE id = 'tok-lag'`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("node-0 took the deleted carol's token from node-2 by anti-entropy")
	}
}
