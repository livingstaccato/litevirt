package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// recreatedWhileLagging creates carol on node-0 and runs before(node-0), cuts node-2 off, deletes and
// re-creates carol on node-0 (newHash) and runs after(admin) there, then runs
// lagging(node-2) on node-2 — a write to the OLD carol, stamped after all of
// it — and heals. It returns once the WAL has drained.
func recreatedWhileLagging(t *testing.T, seed int64, newHash string, before, after, lagging func(n *Node)) *Cluster {
	t.Helper()
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: seed})
	latchUserIncarnation(t, c, nil, nil)
	// Credentials split, as every cluster on this release: a password lives
	// in user_credentials as well as users.password_hash.
	for _, n := range c.Nodes {
		n.DB.SetCredentialsSplitGate(func() bool { return true })
	}
	admin, lag := c.Nodes[0], c.Nodes[2]
	if err := corrosion.InsertUser(ctx, admin.DB, "carol", "operator", "hash-old"); err != nil {
		t.Fatal(err)
	}
	if before != nil {
		before(admin)
	}
	c.WaitConverged(t, convergeTimeout)

	c.Isolate(lag)
	if err := corrosion.DeleteUser(ctx, admin.DB, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser(ctx, admin.DB, "carol", "operator", newHash); err != nil {
		t.Fatal(err)
	}
	if after != nil {
		after(admin)
	}
	time.Sleep(10 * time.Millisecond) // the lagging write is the later one
	lagging(lag)

	c.ClearLinkFaults()
	eventually(t, convergeTimeout, "the WAL to drain", func() bool {
		n, err := undelivered(c.Nodes)
		return err == nil && n == 0
	})
	return c
}

// TestFleet_ALaggingPasswordChangeDoesNotReachARecreatedUser: node-2, cut
// off, changes the password of the carol it knows after node-0 deleted her
// and created a new carol. The change belongs to the deleted account: on no
// node may the old holder's new password log into the new carol, over the
// WAL or after anti-entropy.
//
// Red on ec450cda6: the change lands on the new carol everywhere.
// Mutations: the password change written without its incarnation guard
// (updateUserPasswordStatements) — red; the re-create applied without
// replacing node-2's credential row (applyUserIncarnation) — red on node-2.
func TestFleet_ALaggingPasswordChangeDoesNotReachARecreatedUser(t *testing.T) {
	ctx := context.Background()
	c := recreatedWhileLagging(t, 5531, "hash-new", nil, nil, func(n *Node) {
		if err := corrosion.UpdateUserPassword(ctx, n.DB, "carol", "hash-stale"); err != nil {
			t.Fatal(err)
		}
	})
	check := func(when string) {
		for _, n := range c.Nodes {
			u, err := corrosion.GetUser(ctx, n.DB, "carol")
			if err != nil || u == nil || u.PasswordHash != "hash-new" {
				t.Errorf("%s, %s: carol = %+v (err %v), want the new account with its own password", when, n.Name, u, err)
			}
		}
	}
	check("over the WAL")
	antiEntropyRound(t, c)
	check("after anti-entropy")
	c.WaitConverged(t, convergeTimeout)
}

// TestFleet_ALaggingPasswordChangeDoesNotReachARecreatedUserByAntiEntropy:
// the same change, but node-2's state reaches node-0 and node-1 by
// anti-entropy, a real exchange (AntiEntropy.RunOnce) over both lanes, while
// node-2's WAL to them is still cut. node-2 still holds the deleted carol, so
// its credential row is that account's: neither node takes it for the new
// carol.
//
// Red on ec450cda6. Mutation: keep the older incarnation's users row without
// refusing its credential on the sensitive lane (userIncarnationDecision) — red.
func TestFleet_ALaggingPasswordChangeDoesNotReachARecreatedUserByAntiEntropy(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 5533})
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
	eventually(t, convergeTimeout, "the new carol to reach node-1", func() bool {
		u, _ := corrosion.GetUser(ctx, c.Nodes[1].DB, "carol")
		return u != nil && u.PasswordHash == "hash-new"
	})
	time.Sleep(10 * time.Millisecond)
	if err := corrosion.UpdateUserPassword(ctx, lag.DB, "carol", "hash-stale"); err != nil {
		t.Fatal(err)
	}
	// node-0 and node-1 may now call node-2; node-2's pushes stay cut.
	for _, n := range c.Nodes[:2] {
		c.SetLinkFault(n, lag, LinkFault{})
	}
	for _, n := range c.Nodes[:2] {
		corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
		if u, err := corrosion.GetUser(ctx, n.DB, "carol"); err != nil || u == nil || u.PasswordHash != "hash-new" {
			t.Errorf("after anti-entropy from %s, %s: carol = %+v (err %v), want the new account with its own password",
				lag.Name, n.Name, u, err)
		}
	}
}

// TestFleet_ALaggingDeleteLeavesARecreatedUsersRows: node-2, cut off, deletes
// the carol it knows after node-0 deleted her, created a new carol and gave
// the new one a row of each kind the delete's cascade reaches by username.
// The cascade belongs to the deleted account: over the WAL, none of the new
// carol's rows is touched on any node.
//
// Red on ec450cda6 for each kind: the cascade lands on the new carol's rows.
// Mutation: the cascade written without its incarnation guard
// (DeleteUserCounted) — every kind red.
func TestFleet_ALaggingDeleteLeavesARecreatedUsersRows(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		before func(t *testing.T, n *Node)
		make   func(t *testing.T, n *Node)
		holds  func(t *testing.T, n *Node) bool
	}{
		{"role binding", nil, func(t *testing.T, n *Node) {
			if err := corrosion.InsertRoleBinding(ctx, n.DB, corrosion.RoleBindingRecord{
				ID: "rb-new", Path: "/", Role: "viewer", Principal: "user:carol"}); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, n *Node) bool {
			bs, err := corrosion.ListRoleBindings(ctx, n.DB)
			if err != nil {
				t.Fatal(err)
			}
			for _, b := range bs {
				if b.ID == "rb-new" {
					return true
				}
			}
			return false
		}},
		{"second factor", nil, func(t *testing.T, n *Node) {
			if err := corrosion.InsertUser2FA(ctx, n.DB, corrosion.User2FARecord{
				Username: "carol", Method: "totp", Secret: "s-new", Label: "phone"}); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, n *Node) bool {
			fs, err := corrosion.ListUser2FA(ctx, n.DB, "carol")
			if err != nil {
				t.Fatal(err)
			}
			return len(fs) == 1 && fs[0].Secret == "s-new"
		}},
		{"recovery codes", nil, func(t *testing.T, n *Node) {
			if err := corrosion.InsertRecoveryCodes(ctx, n.DB, "carol", []string{"code-new"}); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, n *Node) bool {
			rows, err := n.DB.Query(ctx,
				`SELECT 1 FROM recovery_codes WHERE username = 'carol' AND code_hash = 'code-new' AND deleted_at IS NULL`)
			if err != nil {
				t.Fatal(err)
			}
			return len(rows) == 1
		}},
		{"enrollment code", nil, func(t *testing.T, n *Node) {
			g := capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
			if _, _, err := corrosion.IssueEnrollmentCode(ctx, n.DB, g, "carol", time.Hour, "admin", n.Name); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, n *Node) bool {
			live, err := corrosion.HasLiveEnrollmentCode(ctx, n.DB, "carol")
			if err != nil {
				t.Fatal(err)
			}
			return live
		}},
		// The old carol was bound to the same directory identity, so the
		// lagging delete clears the very row the new carol's binding is.
		{"directory binding", func(t *testing.T, n *Node) {
			g := capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
			if err := corrosion.BindIdentity(ctx, n.DB, g, "carol", "oidc", "ext-1"); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, n *Node) {
			g := capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
			if err := corrosion.BindIdentity(ctx, n.DB, g, "carol", "oidc", "ext-1"); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, n *Node) bool {
			id, err := corrosion.GetIdentityBinding(ctx, n.DB, "carol", "oidc")
			if err != nil {
				t.Fatal(err)
			}
			return id == "ext-1"
		}},
		{"session cut-off", nil, nil, func(t *testing.T, n *Node) bool {
			lc, err := corrosion.GetUserLifecycle(ctx, n.DB, "carol")
			if err != nil {
				t.Fatal(err)
			}
			return lc.SessionsNotBefore == "" && lc.TokensNotBefore == ""
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := recreatedWhileLagging(t, 5532, "hash-new", func(n *Node) {
				if tc.before != nil {
					tc.before(t, n)
				}
			}, func(n *Node) {
				if tc.make != nil {
					tc.make(t, n)
				}
			}, func(n *Node) {
				g := capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
				if _, _, err := corrosion.DeleteUserCounted(ctx, n.DB, g, "carol"); err != nil {
					t.Fatal(err)
				}
			})
			for _, when := range []string{"over the WAL", "after anti-entropy"} {
				if when == "after anti-entropy" {
					antiEntropyRound(t, c)
				}
				for _, n := range c.Nodes {
					if !tc.holds(t, n) {
						t.Errorf("%s, %s: the lagging delete of the old carol reached the new carol's %s", when, n.Name, tc.name)
					}
				}
			}
		})
	}
}

// TestFleet_ALaggingDeleteLeavesARecreatedUsersRowsByAntiEntropy: the old
// carol had a second factor; node-2, cut off, deletes the carol it knows after
// node-0 deleted her, created a new carol and enrolled a factor for the new
// one. node-2's rows reach node-0 and node-1 by anti-entropy first, a real
// exchange over both lanes, while its WAL to them is still cut: its tombstone
// of the old carol's factor set (the same key as the new one's) and its
// session cut-offs belong to the old carol, and neither node takes them.
//
// Mutations: no refusal of an older account's rows on the sensitive lane —
// the second factor red; none on the public lane (userKeyedRowDecision) — the
// cut-off red.
func TestFleet_ALaggingDeleteLeavesARecreatedUsersRowsByAntiEntropy(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 5534})
	latchUserIncarnation(t, c, nil, nil)
	for _, n := range c.Nodes {
		n.DB.SetCredentialsSplitGate(func() bool { return true })
	}
	admin, lag := c.Nodes[0], c.Nodes[2]
	if err := corrosion.InsertUser(ctx, admin.DB, "carol", "operator", "hash-old"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser2FA(ctx, admin.DB, corrosion.User2FARecord{
		Username: "carol", Method: "totp", Secret: "s-old", Label: "phone"}); err != nil {
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
	if err := corrosion.InsertUser2FA(ctx, admin.DB, corrosion.User2FARecord{
		Username: "carol", Method: "totp", Secret: "s-new", Label: "phone"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, convergeTimeout, "the new carol's factor to reach node-1", func() bool {
		fs, _ := corrosion.ListUser2FA(ctx, c.Nodes[1].DB, "carol")
		return len(fs) == 1 && fs[0].Secret == "s-new"
	})
	time.Sleep(10 * time.Millisecond)
	g := capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
	if _, _, err := corrosion.DeleteUserCounted(ctx, lag.DB, g, "carol"); err != nil {
		t.Fatal(err)
	}
	for _, n := range c.Nodes[:2] {
		c.SetLinkFault(n, lag, LinkFault{})
	}
	for _, n := range c.Nodes[:2] {
		corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
		if fs, err := corrosion.ListUser2FA(ctx, n.DB, "carol"); err != nil || len(fs) != 1 || fs[0].Secret != "s-new" {
			t.Errorf("after anti-entropy from %s, %s: carol's factors = %+v (err %v), want the new carol's", lag.Name, n.Name, fs, err)
		}
		if lc, err := corrosion.GetUserLifecycle(ctx, n.DB, "carol"); err != nil || lc.SessionsNotBefore != "" {
			t.Errorf("after anti-entropy from %s, %s: carol's lifecycle = %+v (err %v), want no cut-off", lag.Name, n.Name, lc, err)
		}
	}
}
