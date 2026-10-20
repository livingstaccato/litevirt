package fleet

// Re-review 2 probes for user_incarnation_v1 (uinc-r2-review.md): a write
// for an account heard before its create or re-create. Red on 27d2a1990
// (R2-1, R2-2, R2-3, R2-4, R2-5, R2-6), green with user_holds.go.
//
// Mutations: a tightening held like a grant instead of applied
// (userIncarnationGuardMatches without the userGuardTighten case) — R2-1,
// R2-2, R2-5 red; a grant ahead skipped instead of held — R2-6 red;
// retireLaggingLifts with its factor branch back — R2-4 red; the local write
// path not refusing a write to an incarnation a newer one has been heard of
// (checkOwnUserGuard without newerKnown) — R2-3 red.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// seenAll waits until to has recorded every entry from's mutation_log holds.
func seenAll(t *testing.T, from, to *Node) {
	t.Helper()
	ctx := context.Background()
	eventually(t, convergeTimeout, from.Name+"'s entries to reach "+to.Name, func() bool {
		rows, err := from.DB.Query(ctx, `SELECT hlc FROM mutation_log WHERE origin = ?`, from.Name)
		if err != nil {
			return false
		}
		for _, r := range rows {
			seen, err := to.DB.Query(ctx, `SELECT 1 FROM mutation_seen WHERE origin = ? AND hlc = ?`, from.Name, r.String("hlc"))
			if err != nil || len(seen) == 0 {
				return false
			}
		}
		return true
	})
}

// learnByAE: to takes from's public and sensitive state by anti-entropy.
func learnByAE(t *testing.T, from, to *Node) {
	t.Helper()
	if err := to.DB.MergeStateBytesLWW(from.DB.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	if err := to.DB.MergeSensitiveStateBytesLWW(from.DB.DumpSensitiveStateBytes()); err != nil {
		t.Fatal(err)
	}
}

// recreatedBehindOneLink: carol is created and deleted everywhere; then
// node-0 is cut off and re-creates carol. node-1 takes the re-create by
// anti-entropy; node-2 does not, but still hears node-1. onNode1 then writes
// the NEW carol's own state on node-1, and that write reaches node-2 ahead
// of the re-create. Then the link heals and the WAL drains.
func recreatedBehindOneLink(t *testing.T, seed int64, onNode1 func(n *Node), onNode2 func(n *Node)) *Cluster {
	t.Helper()
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: seed})
	latchUserIncarnation(t, c, nil, nil)
	for _, n := range c.Nodes {
		n.DB.SetCredentialsSplitGate(func() bool { return true })
	}
	a, b, lag := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if err := corrosion.InsertUser(ctx, a.DB, "carol", "operator", "hash-old"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	if err := corrosion.DeleteUser(ctx, a.DB, "carol"); err != nil {
		t.Fatal(err)
	}
	seenAll(t, a, lag)
	seenAll(t, a, b)
	c.Isolate(a) // node-0's WAL is held; node-1 learns its writes by anti-entropy
	if err := corrosion.InsertUser(ctx, a.DB, "carol", "operator", "hash-new"); err != nil {
		t.Fatal(err)
	}
	learnByAE(t, a, b)
	if u, _ := corrosion.GetUser(ctx, b.DB, "carol"); u == nil || u.PasswordHash != "hash-new" {
		t.Fatalf("fixture: node-1 did not take the re-create: %+v", u)
	}
	if onNode1 != nil {
		onNode1(b)
	}
	seenAll(t, b, lag)
	if onNode2 != nil {
		time.Sleep(10 * time.Millisecond)
		onNode2(lag)
		seenAll(t, lag, b)
	}
	if u, _ := corrosion.GetUser(ctx, lag.DB, "carol"); u != nil {
		t.Fatalf("fixture: node-2 already holds a live carol %+v", u)
	}
	c.ClearLinkFaults()
	eventually(t, convergeTimeout, "the WAL to drain", func() bool {
		n, err := undelivered(c.Nodes)
		return err == nil && n == 0
	})
	for _, n := range c.Nodes {
		if u, err := corrosion.GetUser(ctx, n.DB, "carol"); err != nil || u == nil || u.PasswordHash != "hash-new" {
			t.Fatalf("%s: carol = %+v (err %v), want the new account", n.Name, u, err)
		}
	}
	return c
}

// PROBE R2-1 (finding: the new account's second factor is guard-skipped on a
// node that hears it before the re-create). The new carol enrols a TOTP on
// node-1. node-2 hears node-1's entry before node-0's re-create, skips it by
// its guard (node-2 holds the deleted incarnation), and after the re-create
// lands holds the new carol with NO second factor until anti-entropy.
// Expectation if the design were fail-closed for factors: the factor is there
// after the WAL drains. On eb047a3ac the enrolment was unguarded, landed on
// the tombstoned name, and the retirement kept it (live restriction).
func TestFleet_ANewFactorHeardBeforeItsRecreateIsKept(t *testing.T) {
	ctx := context.Background()
	c := recreatedBehindOneLink(t, 7101, func(n *Node) {
		if err := corrosion.InsertUser2FA(ctx, n.DB, corrosion.User2FARecord{
			Username: "carol", Method: "totp", Secret: "s-new", Label: "phone"}); err != nil {
			t.Fatal(err)
		}
	}, nil)
	check := func(when string) {
		for _, n := range c.Nodes {
			fs, err := corrosion.ListUser2FA(ctx, n.DB, "carol")
			if err != nil || len(fs) != 1 || fs[0].Secret != "s-new" {
				t.Errorf("%s, %s: the new carol's factors = %+v (err %v): she logs in with her password alone", when, n.Name, fs, err)
			}
		}
	}
	check("over the WAL")
	antiEntropyRound(t, c)
	check("after anti-entropy")
}

// PROBE R2-2 (same class, expiry). The new carol's expiry is set on node-1
// (soon). lifecycleLift treats every expiry change as a lift, so it is
// stamped and node-2, which hears it before the re-create, skips it: after
// the WAL drains the new carol has no expiry on node-2.
func TestFleet_ANewExpiryHeardBeforeItsRecreateIsKept(t *testing.T) {
	ctx := context.Background()
	g := capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
	soon := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	c := recreatedBehindOneLink(t, 7102, func(n *Node) {
		if err := corrosion.SetUserLifecycle(ctx, n.DB, g, "carol", nil, &soon, "admin"); err != nil {
			t.Fatal(err)
		}
	}, nil)
	check := func(when string) {
		for _, n := range c.Nodes {
			l, err := corrosion.GetUserLifecycle(ctx, n.DB, "carol")
			if err != nil || l.ExpiresAt != soon {
				t.Errorf("%s, %s: the new carol's expiry = %q (err %v), want %q", when, n.Name, l.ExpiresAt, err, soon)
			}
		}
	}
	check("over the WAL")
	antiEntropyRound(t, c)
	check("after anti-entropy")
}

// PROBE R2-3 (retireLaggingLifts and an early restriction). node-1 disables
// the new carol; node-2 takes the disable (unguarded) while it still holds
// the deleted name, then re-enables the carol it knows (its own lagging lift,
// later clock, overwrites the disable there). When the re-create lands,
// retireLaggingLifts drops the lift, and the disable it overwrote is gone:
// node-2 holds the new carol enabled until anti-entropy.
func TestFleet_AnEarlyDisableIsNotLostToALaggingLift(t *testing.T) {
	ctx := context.Background()
	g := capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
	yes, no := true, false
	c := recreatedBehindOneLink(t, 7103, func(n *Node) {
		if err := corrosion.SetUserLifecycle(ctx, n.DB, g, "carol", &yes, nil, "admin"); err != nil {
			t.Fatal(err)
		}
	}, func(n *Node) {
		// node-2 has heard the new carol's disable, so it knows the name was
		// re-created: its write to the deleted carol is refused.
		if err := corrosion.SetUserLifecycle(ctx, n.DB, g, "carol", &no, nil, "admin"); err != nil &&
			!errors.Is(err, corrosion.ErrUserAccountChanged) {
			t.Fatal(err)
		}
	})
	check := func(when string) {
		for _, n := range c.Nodes {
			l, err := corrosion.GetUserLifecycle(ctx, n.DB, "carol")
			if err != nil || !l.Disabled {
				t.Errorf("%s, %s: the new carol is enabled (err %v)", when, n.Name, err)
			}
		}
	}
	check("over the WAL")
	antiEntropyRound(t, c)
	check("after anti-entropy")
}

// PROBE R2-4 (sensitive pull ahead of the users row). node-2 holds carol
// deleted and is cut off; node-0 re-creates her and she enrols a factor.
// node-2's sensitive pull from node-0 completes while its public pull did
// not (usersUnjudged withholds only user_credentials), so the new factor
// lands. A later anti-entropy adoption of the re-create then runs
// retireLaggingLifts, which drops the factor as "written after the new
// incarnation". Checked before the WAL heals (node-2 is WAL-lagging).
func TestFleet_AFactorPulledBeforeItsUsersRowIsKept(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 7104})
	latchUserIncarnation(t, c, nil, nil)
	for _, n := range c.Nodes {
		n.DB.SetCredentialsSplitGate(func() bool { return true })
	}
	a, lag := c.Nodes[0], c.Nodes[2]
	if err := corrosion.InsertUser(ctx, a.DB, "carol", "operator", "hash-old"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	if err := corrosion.DeleteUser(ctx, a.DB, "carol"); err != nil {
		t.Fatal(err)
	}
	seenAll(t, a, lag)
	c.Isolate(lag)
	if err := corrosion.InsertUser(ctx, a.DB, "carol", "operator", "hash-new"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser2FA(ctx, a.DB, corrosion.User2FARecord{
		Username: "carol", Method: "totp", Secret: "s-new", Label: "phone"}); err != nil {
		t.Fatal(err)
	}
	if err := lag.DB.MergeSensitiveStateBytesLWW(a.DB.DumpSensitiveStateBytes()); err != nil {
		t.Fatal(err)
	}
	if err := lag.DB.MergeStateBytesLWW(pullDump(t, c, a)); err != nil {
		t.Fatal(err)
	}
	if u, _ := corrosion.GetUser(ctx, lag.DB, "carol"); u == nil {
		t.Fatal("fixture: node-2 did not adopt the re-create")
	}
	fs, err := corrosion.ListUser2FA(ctx, lag.DB, "carol")
	if err != nil || len(fs) != 1 {
		t.Errorf("node-2 after adopting the re-create: the new carol's factors = %+v (err %v)", fs, err)
	}
}

// createdBehindOneLink: node-0 -> node-2 is cut, and node-0 makes the FIRST
// create of carol (no earlier account of the name anywhere). node-1 takes it;
// onNode1 writes carol's own state on node-1, which reaches node-2 before the
// create does. Then the link heals and the WAL drains.
func createdBehindOneLink(t *testing.T, seed int64, onNode1 func(n *Node)) *Cluster {
	t.Helper()
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: seed})
	latchUserIncarnation(t, c, nil, nil)
	for _, n := range c.Nodes {
		n.DB.SetCredentialsSplitGate(func() bool { return true })
	}
	a, b, lag := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.Isolate(a)
	if err := corrosion.InsertUser(ctx, a.DB, "carol", "operator", "hash-1"); err != nil {
		t.Fatal(err)
	}
	learnByAE(t, a, b)
	if u, _ := corrosion.GetUser(ctx, b.DB, "carol"); u == nil {
		t.Fatal("fixture: node-1 did not take the create")
	}
	if u, _ := corrosion.GetUser(ctx, lag.DB, "carol"); u != nil {
		t.Fatalf("fixture: node-2 already holds carol %+v", u)
	}
	onNode1(b)
	seenAll(t, b, lag)
	c.ClearLinkFaults()
	eventually(t, convergeTimeout, "the WAL to drain", func() bool {
		n, err := undelivered(c.Nodes)
		return err == nil && n == 0
	})
	return c
}

// PROBE R2-5 (the R2-1 class without any re-create). A brand-new account
// enrols a factor on node-1; node-2 hears it before the create, has no users
// row, and skips it (userIncarnationGuardMatches: no row is no match). After
// the WAL drains carol has no factor on node-2 until anti-entropy.
func TestFleet_AFactorHeardBeforeItsCreateIsKept(t *testing.T) {
	ctx := context.Background()
	c := createdBehindOneLink(t, 7105, func(n *Node) {
		if err := corrosion.InsertUser2FA(ctx, n.DB, corrosion.User2FARecord{
			Username: "carol", Method: "totp", Secret: "s-1", Label: "phone"}); err != nil {
			t.Fatal(err)
		}
	})
	check := func(when string) {
		for _, n := range c.Nodes {
			fs, err := corrosion.ListUser2FA(ctx, n.DB, "carol")
			if err != nil || len(fs) != 1 {
				t.Errorf("%s, %s: carol's factors = %+v (err %v): she logs in with her password alone", when, n.Name, fs, err)
			}
		}
	}
	check("over the WAL")
	antiEntropyRound(t, c)
	check("after anti-entropy")
}

// PROBE R2-6 (a legitimate session that never heals). Same ordering, the
// write is a login session minted on node-1. Sessions are WAL-only (not in
// tableNames), so the skipped row never reaches node-2.
func TestFleet_ASessionHeardBeforeItsCreateIsKept(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	c := createdBehindOneLink(t, 7106, func(n *Node) {
		if err := corrosion.InsertSession(ctx, n.DB, corrosion.SessionRecord{
			ID: "sess-1", Username: "carol", Realm: "local",
			CreatedAt: now.Format(time.RFC3339), LastUsedAt: now.Format(time.RFC3339),
			ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}); err != nil {
			t.Fatal(err)
		}
	})
	antiEntropyRound(t, c)
	for _, n := range c.Nodes {
		if s, err := corrosion.GetSession(ctx, n.DB, "sess-1"); err != nil || s == nil {
			t.Errorf("after the WAL and anti-entropy, %s: carol's session is missing (err %v)", n.Name, err)
		}
	}
}
