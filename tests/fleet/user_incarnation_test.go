package fleet

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// latchUserIncarnation drives user_incarnation_v1 on every node through real
// checkers and wires each node's corrosion gate to its durable latch, as the
// daemon does. withhold, when set, is a node whose advertisement lacks the
// token while held reads true: a host on the previous build.
func latchUserIncarnation(t *testing.T, c *Cluster, withhold *Node, held *atomic.Bool) map[string]*health.Checker {
	t.Helper()
	gates := gateAll(t, c)
	for _, n := range c.Nodes {
		node := n
		g := gates[node.Name]
		if withhold != nil {
			g.SetPeerPinger(func(ctx context.Context, host string) ([]string, time.Time, error) {
				caps, wall, err := node.Server.PeerCapabilities(ctx, host)
				if held.Load() && host == withhold.Name {
					caps = withoutToken(caps, capabilities.UserIncarnationV1)
				}
				return caps, wall, err
			})
		}
		node.DB.SetUserIncarnationGate(func() bool { return g.DurablyLatched(capabilities.UserIncarnationV1) })
	}
	for _, n := range c.Nodes {
		if n == withhold {
			continue
		}
		latched := gates[n.Name].Enforced(context.Background(), capabilities.UserIncarnationV1)
		if withhold == nil && !latched {
			t.Fatalf("%s: user_incarnation_v1 did not latch with every host advertising it", n.Name)
		}
		if withhold != nil && latched {
			t.Fatalf("%s latched user_incarnation_v1 while %s runs a build without it", n.Name, withhold.Name)
		}
	}
	return gates
}

// drainAndExchange lets the WAL drain, then runs one anti-entropy round
// between every pair of nodes.
func drainAndExchange(t *testing.T, c *Cluster) {
	t.Helper()
	eventually(t, convergeTimeout, "the WAL to drain", func() bool {
		n, err := undelivered(c.Nodes)
		return err == nil && n == 0
	})
	antiEntropyRound(t, c)
}

// TestFleet_ALaggingPasswordChangeDoesNotBringBackADeletedUser: node-0
// deletes carol while node-2 lags, and node-2 then changes her password,
// stamped after the delete it has not seen. The password change is a write
// to the account the delete ended, not a re-create, so the delete wins
// everywhere, whichever reaches the nodes first:
//
//   - the WAL: node-2 applies the delete to the incarnation it names, over
//     its later password change;
//   - anti-entropy: a node holding the tombstone keeps it over node-2's live
//     row, and node-2 takes the tombstone over its own.
//
// Red on 13f3fbf0f: every node ends with carol live, holding hash-2.
// Mutation: let anti-entropy take a live row over a tombstone of its own
// incarnation (userIncarnationDecision) — "anti-entropy first" red. (With
// the delete written without its incarnation, "the WAL first" stays green:
// anti-entropy then ends the account, which is that rule's job.)
func TestFleet_ALaggingPasswordChangeDoesNotBringBackADeletedUser(t *testing.T) {
	for _, aeFirst := range []bool{false, true} {
		name := "the WAL first"
		if aeFirst {
			name = "anti-entropy first"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 5521})
			latchUserIncarnation(t, c, nil, nil)
			deleter, lagging := c.Nodes[0], c.Nodes[2]
			if err := corrosion.InsertUser(ctx, deleter.DB, "carol", "operator", "hash-1"); err != nil {
				t.Fatal(err)
			}
			c.WaitConverged(t, convergeTimeout)

			c.Isolate(lagging)
			if err := corrosion.DeleteUser(ctx, deleter.DB, "carol"); err != nil {
				t.Fatal(err)
			}
			time.Sleep(10 * time.Millisecond) // the password change is the later write
			if err := corrosion.UpdateUserPassword(ctx, lagging.DB, "carol", "hash-2"); err != nil {
				t.Fatal(err)
			}
			if u, _ := corrosion.GetUser(ctx, lagging.DB, "carol"); u == nil {
				t.Fatalf("fixture: %s does not hold carol live", lagging.Name)
			}
			check := func(when string) {
				for _, n := range c.Nodes {
					if u, err := corrosion.GetUser(ctx, n.DB, "carol"); err != nil || u != nil {
						t.Errorf("%s, %s: carol = %+v (err %v), want her deleted: a lagging password change brought her back",
							when, n.Name, u, err)
					}
				}
			}
			if aeFirst {
				// Anti-entropy reaches every node while the WAL to and from
				// node-2 is still cut: node-2's live row is offered to the
				// deleter first, then every pair exchanges.
				if err := deleter.DB.MergeStateBytesLWW(pullDump(t, c, lagging)); err != nil {
					t.Fatal(err)
				}
				antiEntropyRound(t, c)
				check("after anti-entropy")
			}
			c.ClearLinkFaults()
			drainAndExchange(t, c)
			check("after the WAL and anti-entropy")
			c.WaitConverged(t, convergeTimeout)
		})
	}
}

// TestFleet_ALaggingDeleteDoesNotEndARecreatedUser: a delete ends the
// account it names, not a later re-create of the name. node-0 deletes carol
// and creates her again while node-2 lags; node-2 then deletes the carol it
// knows, the first one, stamped after the re-create. Every node ends with the
// re-created carol live: node-2's delete ended an account that was already
// gone, and the re-create replaces the tombstone node-2 holds, whatever the
// clocks say.
//
// Red on 13f3fbf0f: node-2's later delete ends the re-created carol
// everywhere. Mutations: the delete written without its incarnation — red;
// a re-create applied only by the row clock (applyUserIncarnation) — red
// over the WAL.
func TestFleet_ALaggingDeleteDoesNotEndARecreatedUser(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 5522})
	latchUserIncarnation(t, c, nil, nil)
	admin, lagging := c.Nodes[0], c.Nodes[2]
	if err := corrosion.InsertUser(ctx, admin.DB, "carol", "operator", "hash-1"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)

	c.Isolate(lagging)
	if err := corrosion.DeleteUser(ctx, admin.DB, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser(ctx, admin.DB, "carol", "viewer", "hash-new"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond) // the lagging delete is the later write
	if err := corrosion.DeleteUser(ctx, lagging.DB, "carol"); err != nil {
		t.Fatal(err)
	}

	check := func(when string) {
		for _, n := range c.Nodes {
			u, err := corrosion.GetUser(ctx, n.DB, "carol")
			if err != nil || u == nil || u.Role != "viewer" {
				t.Errorf("%s, %s: carol = %+v (err %v), want the re-created account (viewer) live", when, n.Name, u, err)
			}
		}
	}
	c.ClearLinkFaults()
	// Over the WAL alone the re-create replaces node-2's tombstone; the row
	// clocks differ until anti-entropy settles them.
	eventually(t, convergeTimeout, "the WAL to drain", func() bool {
		n, err := undelivered(c.Nodes)
		return err == nil && n == 0
	})
	check("over the WAL")
	antiEntropyRound(t, c)
	check("after anti-entropy")
	c.WaitConverged(t, convergeTimeout)
}

// TestFleet_UserIncarnationBeforeTheLatch: a cluster mid-roll, node-2 on a
// build without user_incarnation_v1, so the token does not latch. Every node
// writes the previous release's users delete and re-create; a node of this
// build still accepts the incarnation-bearing delete (its peers only send it
// once latched, but a retained one may still arrive); and a latched node
// still accepts the previous release's delete from a peer's retained WAL.
func TestFleet_UserIncarnationBeforeTheLatch(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 5523})
	var held atomic.Bool
	held.Store(true)
	latchUserIncarnation(t, c, c.Nodes[2], &held)
	a := c.Nodes[0]
	for _, n := range c.Nodes {
		if n.DB.UserIncarnationOn() {
			t.Fatalf("%s writes by incarnation with user_incarnation_v1 unlatched", n.Name)
		}
	}
	if err := corrosion.InsertUser(ctx, a.DB, "dave", "operator", "hash-1"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteUser(ctx, a.DB, "dave"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser(ctx, a.DB, "dave", "viewer", "hash-2"); err != nil {
		t.Fatal(err)
	}
	logged := loggedStatements(t, a)
	if strings.Contains(logged, "AND created_at = ?") || strings.Contains(logged, "created_at = ?, updated_at = ? WHERE username") {
		t.Fatalf("%s wrote an incarnation-bearing users statement before the latch:\n%s", a.Name, logged)
	}
	if !strings.Contains(logged, "UPDATE users SET deleted_at = ?, updated_at = ? WHERE username = ?") {
		t.Fatalf("%s did not write the previous release's delete:\n%s", a.Name, logged)
	}
	c.WaitConverged(t, convergeTimeout)

	// An incarnation-bearing delete reaching unlatched nodes of this build
	// is applied, not refused.
	u, err := corrosion.GetUser(ctx, a.DB, "dave")
	if err != nil || u == nil {
		t.Fatalf("dave: %+v, %v", u, err)
	}
	if err := a.DB.ExecuteBatch(ctx, []corrosion.Statement{{
		SQL:    `UPDATE users SET deleted_at = ?, updated_at = ? WHERE username = ? AND created_at = ?`,
		Params: []interface{}{time.Now().UTC().Format(time.RFC3339), a.DB.NowTS(), "dave", u.CreatedAt},
	}}); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if u, _ := corrosion.GetUser(ctx, n.DB, "dave"); u != nil {
			t.Errorf("%s: the incarnation-bearing delete was not applied: %+v", n.Name, u)
		}
	}

	// After the latch the previous release's delete is still applied.
	held.Store(false)
	latchUserIncarnation(t, c, nil, nil)
	if err := corrosion.InsertUser(ctx, a.DB, "erin", "operator", "hash-1"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	if err := a.DB.ExecuteBatch(ctx, []corrosion.Statement{{
		SQL:    `UPDATE users SET deleted_at = ?, updated_at = ? WHERE username = ?`,
		Params: []interface{}{time.Now().UTC().Format(time.RFC3339), a.DB.NowTS(), "erin"},
	}}); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if u, _ := corrosion.GetUser(ctx, n.DB, "erin"); u != nil {
			t.Errorf("%s: the previous release's delete was not applied after the latch: %+v", n.Name, u)
		}
	}
}

// loggedStatements is every statement n logged as their origin, for reading
// which shapes it wrote.
func loggedStatements(t *testing.T, n *Node) string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), `SELECT stmts FROM mutation_log WHERE origin = ? ORDER BY seq`, n.Name)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r.String("stmts"))
		b.WriteByte('\n')
	}
	return b.String()
}
