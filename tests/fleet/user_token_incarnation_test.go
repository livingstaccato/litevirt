package fleet

import (
	"context"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/bcrypt"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const (
	fleetTokA = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	fleetTokB = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
	fleetTokC = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"
	fleetTokD = "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4"
)

func fleetTokenHash(t *testing.T, raw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

// perNodeUserIncarnationGates wires each node's user_incarnation_v1 gate to
// its own switch, so the nodes latch at different times, as they do while
// the latch forms.
func perNodeUserIncarnationGates(c *Cluster) map[*Node]*atomic.Bool {
	out := map[*Node]*atomic.Bool{}
	for _, n := range c.Nodes {
		b := &atomic.Bool{}
		out[n] = b
		n.DB.SetUserIncarnationGate(b.Load)
	}
	return out
}

// TestFleet_AnUnlatchedNodesTokenForADeletedAccountNeverOpensItsSuccessor is
// users-L2: carol is created before the latch. node-0 latches, deletes her
// and creates her again. node-2 has not latched and lags: it never heard of
// the delete, and mints an API token for the carol it holds. node-1 has the
// new carol but has not latched either.
//
//   - anti-entropy: node-1 pulls node-2's token by plain LWW, then latches;
//   - the WAL: node-2's token insert reaches every node.
//
// Then every node latches and runs an anti-entropy round. Want: the old
// carol's token never authenticates as the new carol, on any node.
//
// Red on 338784d88 in both variants: the token opens the new carol on node-1
// (and, over the WAL, on node-0).
func TestFleet_AnUnlatchedNodesTokenForADeletedAccountNeverOpensItsSuccessor(t *testing.T) {
	for _, via := range []string{"anti-entropy", "wal"} {
		t.Run(via, func(t *testing.T) {
			ctx := context.Background()
			c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 7741})
			gates := perNodeUserIncarnationGates(c)
			admin, u, lag := c.Nodes[0], c.Nodes[1], c.Nodes[2]
			if err := corrosion.InsertUser(ctx, admin.DB, "carol", "admin", "hash-old"); err != nil {
				t.Fatal(err)
			}
			c.WaitConverged(t, convergeTimeout)
			c.Isolate(lag)
			gates[admin].Store(true)
			if err := corrosion.DeleteUser(ctx, admin.DB, "carol"); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.InsertUser(ctx, admin.DB, "carol", "admin", "hash-new"); err != nil {
				t.Fatal(err)
			}
			newCarol, err := corrosion.GetUser(ctx, admin.DB, "carol")
			if err != nil || newCarol == nil {
				t.Fatalf("GetUser: %+v, %v", newCarol, err)
			}
			eventually(t, convergeTimeout, "node-1 to take the new carol", func() bool {
				got, err := corrosion.GetUser(ctx, u.DB, "carol")
				return err == nil && got != nil && got.CreatedAt == newCarol.CreatedAt
			})
			if err := corrosion.InsertToken(ctx, lag.DB, corrosion.TokenRecord{
				ID: "tok-old-carol", Username: "carol", Name: "mine", TokenHash: fleetTokenHash(t, fleetTokA)}); err != nil {
				t.Fatal(err)
			}
			switch via {
			case "anti-entropy":
				if err := u.DB.MergeStateBytesLWW(pullDump(t, c, lag)); err != nil {
					t.Fatal(err)
				}
				gates[u].Store(true)
				if got, err := corrosion.ValidateToken(ctx, u.DB, fleetTokA); err != nil || got != nil {
					t.Errorf("node-1: the old carol's token, pulled before the latch, opens the new carol: %+v, %v", got, err)
				}
				c.ClearLinkFaults()
			case "wal":
				c.ClearLinkFaults()
				eventually(t, convergeTimeout, "the WAL to drain", func() bool {
					n, err := undelivered(c.Nodes)
					return err == nil && n == 0
				})
				for _, n := range []*Node{admin, u} {
					if got, err := corrosion.ValidateToken(ctx, n.DB, fleetTokA); err != nil || got != nil {
						t.Errorf("%s: the old carol's token, over the WAL, opens the new carol: %+v, %v", n.Name, got, err)
					}
				}
			}
			for _, n := range c.Nodes {
				gates[n].Store(true)
			}
			drainAndExchange(t, c)
			for _, n := range c.Nodes {
				if got, err := corrosion.ValidateToken(ctx, n.DB, fleetTokA); err != nil || got != nil {
					t.Errorf("%s: after anti-entropy, the old carol's token opens the new carol: %+v, %v", n.Name, got, err)
				}
				rows, err := n.DB.Query(ctx, `SELECT id FROM tokens WHERE id = 'tok-old-carol' AND deleted_at IS NULL`)
				if err != nil {
					t.Fatal(err)
				}
				if len(rows) != 0 {
					t.Errorf("%s: holds the old carol's token live", n.Name)
				}
			}
		})
	}
}

// TestFleet_TokensKeepWorkingAcrossTheUserIncarnationLatch: the rolling
// upgrade takes no token away from an account that is not re-created.
//
//   - A: carol's token minted before any node latched (unstamped);
//   - B: carol's token minted by node-1 after node-0 latched, before node-1
//     did (unstamped: carol was made before the latch);
//   - C: dave, created by the latched node-0, gets a token from node-2,
//     which has not latched (stamped: dave was made by a latched writer);
//   - D: carol's token minted by the latched node-0 (stamped).
//
// After every node latches and anti-entropy runs, all four authenticate on
// every node. Green on 338784d88 too (non-regression).
func TestFleet_TokensKeepWorkingAcrossTheUserIncarnationLatch(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 7742})
	gates := perNodeUserIncarnationGates(c)
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if err := corrosion.InsertUser(ctx, n0.DB, "carol", "operator", "h"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	mint := func(n *Node, id, user, raw string) {
		t.Helper()
		if err := corrosion.InsertToken(ctx, n.DB, corrosion.TokenRecord{
			ID: id, Username: user, Name: id, TokenHash: fleetTokenHash(t, raw)}); err != nil {
			t.Fatal(err)
		}
	}
	mint(n0, "tok-a", "carol", fleetTokA)
	gates[n0].Store(true)
	mint(n1, "tok-b", "carol", fleetTokB)
	if err := corrosion.InsertUser(ctx, n0.DB, "dave", "operator", "h"); err != nil {
		t.Fatal(err)
	}
	eventually(t, convergeTimeout, "node-2 to take dave", func() bool {
		got, err := corrosion.GetUser(ctx, n2.DB, "dave")
		return err == nil && got != nil
	})
	mint(n2, "tok-c", "dave", fleetTokC)
	mint(n0, "tok-d", "carol", fleetTokD)
	for _, n := range c.Nodes {
		gates[n].Store(true)
	}
	drainAndExchange(t, c)
	for _, n := range c.Nodes {
		for raw, user := range map[string]string{fleetTokA: "carol", fleetTokB: "carol", fleetTokC: "dave", fleetTokD: "carol"} {
			got, err := corrosion.ValidateToken(ctx, n.DB, raw)
			if err != nil || got == nil || got.Username != user {
				t.Errorf("%s: %s's token %s… does not authenticate after the latch: %+v, %v", n.Name, user, raw[:4], got, err)
			}
		}
	}
}

// pushOwnTokenWrites pushes from's own token writes, and nothing else, to to
// over the real PushMutations RPC.
func pushOwnTokenWrites(t *testing.T, c *Cluster, from, to *Node) {
	t.Helper()
	ctx := context.Background()
	rows, err := from.DB.Query(ctx,
		`SELECT seq, hlc, origin, stmts FROM mutation_log WHERE origin = ? AND stmts LIKE '%INTO tokens%' ORDER BY seq`, from.Name)
	if err != nil {
		t.Fatalf("read %s mutation_log: %v", from.Name, err)
	}
	if len(rows) == 0 {
		t.Fatalf("%s logged no token write; the push would be vacuous", from.Name)
	}
	entries := make([]*pb.MutationEntry, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, &pb.MutationEntry{Seq: r.Int64("seq"), Hlc: r.String("hlc"), Origin: r.String("origin"), Stmts: r.String("stmts")})
	}
	if _, err := c.PeerClient(from, to).PushMutations(ctx, &pb.ReplicateRequest{
		Sender: from.Name, SenderVersion: "fleet-test",
		SenderSchemaVersion: int32(corrosion.CurrentSchemaVersion), Entries: entries,
	}); err != nil {
		t.Fatalf("push %s→%s: %v", from.Name, to.Name, err)
	}
}

// TestFleet_AStampedTokenOpensOnlyTheIncarnationItNames (review m3): the
// read rule for a STAMPED token, end to end. node-0 latches, deletes carol
// and creates her again. node-1 holds the new carol but has not latched; it
// mints her a token, stamped with her incarnation (a latched writer made it)
// and unguarded. node-2 still holds the old carol and receives that token
// before the re-create. The token is the new carol's: it must not open the
// old carol on node-2, and it opens the new carol once node-2 has taken the
// re-create and an anti-entropy round.
func TestFleet_AStampedTokenOpensOnlyTheIncarnationItNames(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3})
	gates := perNodeUserIncarnationGates(c)
	admin, x, lag := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if err := corrosion.InsertUser(ctx, admin.DB, "carol", "operator", "hash-old"); err != nil {
		t.Fatal(err)
	}
	pumpMutations(t, c, admin, x)
	pumpMutations(t, c, admin, lag)
	old, err := corrosion.GetUser(ctx, lag.DB, "carol")
	if err != nil || old == nil {
		t.Fatalf("node-2 has no carol: %+v, %v", old, err)
	}
	gates[admin].Store(true)
	if err := corrosion.DeleteUser(ctx, admin.DB, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser(ctx, admin.DB, "carol", "operator", "hash-new"); err != nil {
		t.Fatal(err)
	}
	pumpMutations(t, c, admin, x)
	newCarol, err := corrosion.GetUser(ctx, x.DB, "carol")
	if err != nil || newCarol == nil || newCarol.CreatedAt == old.CreatedAt {
		t.Fatalf("node-1 did not take the new carol: %+v, %v", newCarol, err)
	}
	if err := corrosion.InsertToken(ctx, x.DB, corrosion.TokenRecord{
		ID: "tok-new-carol", Username: "carol", Name: "mine", TokenHash: fleetTokenHash(t, fleetTokB)}); err != nil {
		t.Fatal(err)
	}
	pushOwnTokenWrites(t, c, x, lag)
	if got, err := corrosion.GetUser(ctx, lag.DB, "carol"); err != nil || got == nil || got.CreatedAt != old.CreatedAt {
		t.Fatalf("precondition: node-2 should still hold the old carol: %+v, %v", got, err)
	}
	if rows, err := lag.DB.Query(ctx, `SELECT user_created_at FROM tokens WHERE id = 'tok-new-carol'`); err != nil || len(rows) != 1 || rows[0].String("user_created_at") != newCarol.CreatedAt {
		t.Fatalf("precondition: node-2 should hold the new carol's stamped token: %v, %v", rows, err)
	}
	if got, err := corrosion.ValidateToken(ctx, lag.DB, fleetTokB); err != nil || got != nil {
		t.Errorf("node-2: the new carol's token opens the old carol: %+v, %v", got, err)
	}
	// The re-create reaches node-2. Taking it drops the live tokens of the
	// name (retireOlderIncarnationRows), this one too; anti-entropy brings
	// it back, because it is the new carol's own.
	pumpMutations(t, c, admin, lag)
	for _, n := range c.Nodes {
		gates[n].Store(true)
	}
	if err := lag.DB.MergeStateBytesLWW(pullDump(t, c, x)); err != nil {
		t.Fatal(err)
	}
	for _, n := range []*Node{x, lag} {
		got, err := corrosion.ValidateToken(ctx, n.DB, fleetTokB)
		if err != nil || got == nil || got.Username != "carol" {
			t.Errorf("%s: the new carol's own token does not open her: %+v, %v", n.Name, got, err)
		}
	}
}
