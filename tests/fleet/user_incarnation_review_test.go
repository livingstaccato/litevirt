package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Red on eb047a3ac: hash-stale on node-2 after its pull and over the WAL, and
// on every node after anti-entropy. Mutation: no retirement on the
// anti-entropy adoption (userIncarnationDecision returns plain apply) — red.
//
// Review H1 (R1): the LAGGING node learns the re-create by anti-entropy
// (it pulls from node-0) before the WAL reaches it. The users row of the new
// incarnation is applied by userIncarnationDecision, but nothing retires the
// lagging node's own credential row, which carries the deleted account's later
// password change. Want: no node ever lets hash-stale log into the new carol.
func TestFleet_ALaggingNodeThatPullsARecreateKeepsNoOldPassword(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 7701})
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
	time.Sleep(10 * time.Millisecond)
	if err := corrosion.UpdateUserPassword(ctx, lag.DB, "carol", "hash-stale"); err != nil {
		t.Fatal(err)
	}
	// node-2 may call node-0 and node-1 (its anti-entropy pull); their WAL
	// pushes to node-2 stay cut.
	for _, n := range c.Nodes[:2] {
		c.SetLinkFault(lag, n, LinkFault{})
	}
	corrosion.NewAntiEntropy(lag.DB, lag.PKIDir, 0).RunOnce(ctx)
	check := func(when string, nodes []*Node) {
		for _, n := range nodes {
			u, err := corrosion.GetUser(ctx, n.DB, "carol")
			if err != nil || u == nil || u.PasswordHash != "hash-new" {
				t.Errorf("%s, %s: carol = %+v (err %v), want the new account with its own password", when, n.Name, u, err)
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

// Red on eb047a3ac: the new carol has no factor on node-2, then on every
// node. Same mutation — red.
//
// Review H2 (R2): the same ordering for a second factor. The old carol had
// a factor; node-2, cut off, deletes the old carol (its cascade tombstones the
// factor and the set, stamped after the new carol's enrolment on node-0), then
// pulls the re-create by anti-entropy before the WAL. Want: the new carol's
// factor is still required on every node.
func TestFleet_ALaggingNodeThatPullsARecreateKeepsTheNewFactor(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 7702})
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
	time.Sleep(10 * time.Millisecond)
	g := capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
	if _, _, err := corrosion.DeleteUserCounted(ctx, lag.DB, g, "carol"); err != nil {
		t.Fatal(err)
	}
	for _, n := range c.Nodes[:2] {
		c.SetLinkFault(lag, n, LinkFault{})
	}
	corrosion.NewAntiEntropy(lag.DB, lag.PKIDir, 0).RunOnce(ctx)
	check := func(when string, nodes []*Node) {
		for _, n := range nodes {
			u, _ := corrosion.GetUser(ctx, n.DB, "carol")
			fs, err := corrosion.ListUser2FA(ctx, n.DB, "carol")
			if u == nil || err != nil || len(fs) != 1 || fs[0].Secret != "s-new" {
				t.Errorf("%s, %s: carol live=%v factors = %+v (err %v), want the new carol's factor", when, n.Name, u != nil, fs, err)
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

// Red on eb047a3ac (and before the branch): the token authenticates as the
// new carol on every node. Mutations: the token insert left unstamped
// (userStampedShapes) — red on node-0 and node-1; tokens and sessions left out
// of the retirement — red on node-2.
//
// Review H4 (R3): the deleted account's holder, still able to log in on the
// lagging node-2, mints an API token there after node-0 deleted and re-created
// carol (CreateUser's ResetUserLifecycle + InsertUser). Want: the token does
// not authenticate as the new carol on any node.
func TestFleet_ALaggingTokenDoesNotOpenARecreatedUser(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 7703})
	latchUserIncarnation(t, c, nil, nil)
	for _, n := range c.Nodes {
		n.DB.SetCredentialsSplitGate(func() bool { return true })
	}
	g := capabilities.GrantForTest(t, capabilities.FeatureLoginPolicy)
	admin, lag := c.Nodes[0], c.Nodes[2]
	if err := corrosion.ResetUserLifecycle(ctx, admin.DB, g, "carol", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser(ctx, admin.DB, "carol", "admin", "hash-old"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	c.Isolate(lag)
	if _, _, err := corrosion.DeleteUserCounted(ctx, admin.DB, g, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.ResetUserLifecycle(ctx, admin.DB, g, "carol", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser(ctx, admin.DB, "carol", "admin", "hash-new"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(corrosion.SessionCutoffSkewMargin + 2*time.Second)
	if err := corrosion.InsertToken(ctx, lag.DB, corrosion.TokenRecord{
		ID: "tok-old-holder", Username: "carol", Name: "mine", TokenHash: "th-old"}); err != nil {
		t.Fatal(err)
	}
	c.ClearLinkFaults()
	eventually(t, convergeTimeout, "the WAL to drain", func() bool {
		n, err := undelivered(c.Nodes)
		return err == nil && n == 0
	})
	antiEntropyRound(t, c)
	for _, n := range c.Nodes {
		u, _ := corrosion.GetUser(ctx, n.DB, "carol")
		rows, err := n.DB.Query(ctx, `SELECT created_at FROM tokens WHERE id = 'tok-old-holder' AND deleted_at IS NULL`)
		if err != nil {
			t.Fatal(err)
		}
		life, err := corrosion.GetUserLifecycle(ctx, n.DB, "carol")
		if err != nil {
			t.Fatal(err)
		}
		if u != nil && len(rows) == 1 && !life.TokenPredates(rows[0].String("created_at")) && life.InactiveReason(time.Now().UTC()) == "" {
			t.Errorf("%s: the old holder's token (created %s, cut-off %q) authenticates as the new carol (created %s)",
				n.Name, rows[0].String("created_at"), life.TokensNotBefore, u.CreatedAt)
		}
		// Nor is its credential left behind anywhere (re-review 2, L4).
		creds, err := n.DB.Query(ctx, `SELECT token_id FROM token_credentials WHERE token_id = 'tok-old-holder'`)
		if err != nil {
			t.Fatal(err)
		}
		if len(creds) != 0 {
			t.Errorf("%s: the old holder's token credential is left behind", n.Name)
		}
	}
}

// Red on eb047a3ac: node-2's old admin carol opens with hash-new. Mutation:
// the credential upsert left unstamped — red.
//
// Review M1 (R4): the delete and the re-create come from different origins,
// and node-2 receives the re-create first. Its users statement is refused
// (older_incarnation: the local row is the old account, live), but the
// entry's unguarded credential upsert still lands — on the OLD account, with
// the old role. Want: the new password never opens the old account.
func TestFleet_ARefusedRecreateTakesNoCredential(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 7704})
	latchUserIncarnation(t, c, nil, nil)
	for _, n := range c.Nodes {
		n.DB.SetCredentialsSplitGate(func() bool { return true })
	}
	a, d, r := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if err := corrosion.InsertUser(ctx, a.DB, "carol", "admin", "hash-old"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	c.Isolate(d) // node-1's WAL held; node-0 learns the delete by anti-entropy
	if err := corrosion.DeleteUser(ctx, d.DB, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := a.DB.MergeStateBytesLWW(d.DB.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	if u, _ := corrosion.GetUser(ctx, a.DB, "carol"); u != nil {
		t.Fatalf("node-0 did not take the delete: %+v", u)
	}
	if err := corrosion.InsertUser(ctx, a.DB, "carol", "viewer", "hash-new"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser(ctx, a.DB, "zed-marker", "viewer", "hash-z"); err != nil {
		t.Fatal(err)
	}
	eventually(t, convergeTimeout, "node-0's re-create to reach node-2", func() bool {
		u, _ := corrosion.GetUser(ctx, r.DB, "zed-marker")
		return u != nil
	})
	u, err := corrosion.GetUser(ctx, r.DB, "carol")
	if err != nil {
		t.Fatal(err)
	}
	if u != nil && u.PasswordHash == "hash-new" && u.Role == "admin" {
		t.Errorf("node-2: the new carol's password opens the OLD carol (role %s, created %s)", u.Role, u.CreatedAt)
	}
}

// Red on eb047a3ac: hash-stale on node-0 over the WAL. Mutation: the WAL loop
// leaves a guard-skipped statement in the absorb — red.
//
// Review H3 (R5): the lagging node has not latched credentials_split_v1
// yet (both tokens are mandatory and latch in either order across an upgrade
// that crosses both), so its guarded password change is the old column alone.
// Its guard does not match the new carol, so the statement is skipped — but
// the receiver's unlatched-origin absorb still reads the entry and writes the
// hash into the new carol's credential row.
func TestFleet_AnUnsplitLaggingPasswordChangeIsNotAbsorbed(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 7705})
	latchUserIncarnation(t, c, nil, nil)
	admin, lag := c.Nodes[0], c.Nodes[2]
	for _, n := range c.Nodes {
		on := n != lag
		n.DB.SetCredentialsSplitGate(func() bool { return on })
	}
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
	time.Sleep(10 * time.Millisecond)
	if err := corrosion.UpdateUserPassword(ctx, lag.DB, "carol", "hash-stale"); err != nil {
		t.Fatal(err)
	}
	c.ClearLinkFaults()
	eventually(t, convergeTimeout, "the WAL to drain", func() bool {
		n, err := undelivered(c.Nodes)
		return err == nil && n == 0
	})
	for _, n := range c.Nodes[:2] {
		u, err := corrosion.GetUser(ctx, n.DB, "carol")
		if err != nil || u == nil || u.PasswordHash != "hash-new" {
			t.Errorf("over the WAL, %s: carol = %+v (err %v), want the new account with its own password", n.Name, u, err)
		}
	}
}
