// Fleet scenario: two admins deleted at once, one on each of two nodes
// (colonelpanik/litevirt#228).
//
// DeleteUser refuses the last live admin, but its check and its delete are two
// operations against replicated state. Issued on two nodes at once, each check
// sees the other admin alive and both deletes land. The synchronous repair
// beside the delete runs before the peer's tombstone arrives, so it sees an
// admin and does nothing. What has to restore the floor is a check every node
// runs on its own replica once the tombstones have arrived, choosing the SAME
// account on every replica.
package fleet

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func liveAdmins(t *testing.T, n *Node) []string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT username FROM users WHERE role = 'admin' AND deleted_at IS NULL ORDER BY username`)
	if err != nil {
		t.Fatalf("%s: read admins: %v", n.Name, err)
	}
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.String("username")
	}
	return out
}

func TestFleet_LastAdmin_TwoRacingDeletesLeaveExactlyOneAdmin(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 228})
	a, b, w := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	for _, u := range []string{"alice", "bob"} {
		if err := corrosion.InsertUser(ctx, a.DB, u, "admin", u+"-hash"); err != nil {
			t.Fatalf("create admin %s: %v", u, err)
		}
	}
	c.WaitConverged(t, convergeTimeout)

	// The race: a and b cannot hear each other, so each one's last-admin check
	// sees the other admin alive. Both deletes are accepted.
	c.Isolate(a)
	c.Isolate(b)
	if _, err := c.SelfClient(a).DeleteUser(ctx, &pb.DeleteUserRequest{Username: "alice"}); err != nil {
		t.Fatalf("delete alice on %s: %v", a.Name, err)
	}
	if _, err := c.SelfClient(b).DeleteUser(ctx, &pb.DeleteUserRequest{Username: "bob"}); err != nil {
		t.Fatalf("delete bob on %s: %v", b.Name, err)
	}
	c.ClearLinkFaults()
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if got := liveAdmins(t, n); len(got) != 0 {
			t.Fatalf("%s: live admins %v before any floor check; the race did not happen", n.Name, got)
		}
	}

	// Every node runs its floor check, twice, as its periodic loop would. The
	// first sighting of zero admins only arms it; a sighting that persists acts.
	for round := 0; round < 2; round++ {
		for _, n := range c.Nodes {
			if _, err := n.DB.EnsureAdminFloor(ctx, 0); err != nil {
				t.Fatalf("%s: admin floor check: %v", n.Name, err)
			}
		}
	}
	c.WaitConverged(t, convergeTimeout)

	want := liveAdmins(t, w)
	if len(want) != 1 {
		t.Fatalf("%s: live admins %v after the floor checks, want exactly one. Zero leaves the "+
			"cluster with no administrator and no supported way back in; two means the replicas "+
			"chose different accounts and revived a deleted admin needlessly", w.Name, want)
	}
	for _, n := range c.Nodes {
		if got := liveAdmins(t, n); len(got) != 1 || got[0] != want[0] {
			t.Fatalf("%s: live admins %v, %s has %v: the replicas did not converge on one account",
				n.Name, got, w.Name, want)
		}
	}
	// A further round changes nothing: the floor holds, so nobody acts.
	for _, n := range c.Nodes {
		if who, err := n.DB.EnsureAdminFloor(ctx, 0); err != nil || who != "" {
			t.Fatalf("%s: a floor check with an admin alive reinstated %q (err %v)", n.Name, who, err)
		}
	}
}
