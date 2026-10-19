package fleet

import (
	"context"
	"io"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const (
	laggingStackV1 = "name: edge\n"
	laggingStackV2 = "name: edge\n# redeployed\n"
)

// stackRowImage is a stacks row as every replica must end up holding it,
// tombstoned or not.
type stackRowImage struct {
	hash, yaml, state, updatedAt string
	deleted                      bool
}

func readStackRow(t *testing.T, n *Node, name string) stackRowImage {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT compose_hash, compose_yaml, state, updated_at, deleted_at IS NOT NULL AS gone
		 FROM stacks WHERE name = ?`, name)
	if err != nil || len(rows) != 1 {
		t.Fatalf("stacks row %q on %s: err=%v rows=%d", name, n.Name, err, len(rows))
	}
	r := rows[0]
	return stackRowImage{hash: r.String("compose_hash"), yaml: r.String("compose_yaml"),
		state: r.String("state"), updatedAt: r.String("updated_at"), deleted: r.Int("gone") != 0}
}

// TestFleet_StackLaggingWriteConverges: an Admin redeploys a stack (a whole
// stacks row, new compose_yaml and compose_hash) on node-0 while node-2 lags,
// and node-2 then writes the stack's state on its older record: compose down
// marking it "deleting", or the teardown tombstoning it. node-2's write is
// newer, so last-write-wins makes it the row everywhere. It used to be a write
// of state and updated_at only, so node-2 kept the older compose_yaml under
// the same updated_at as every peer holding the redeploy's, and nothing ever
// reconciled them: the stacks table stayed apart for good.
//
// Each replica must end holding one row, the newer writer's whole image.
//
// Mutations, each timing out with stacks apart: MarkStackDeleting writing
// state and updated_at alone again (the deleting case); DeleteStackRecord
// writing the tombstone alone (the tombstone case); the whole row and the
// tombstone under one stamp, which a receiver skips as a tied partial update
// (both tombstone cases).
func TestFleet_StackLaggingWriteConverges(t *testing.T) {
	for _, tc := range []struct {
		name      string
		write     func(t *testing.T, c *Cluster, n *Node)
		state     string
		tombstone bool
	}{
		{name: "compose down marks it deleting", state: "deleting", write: func(t *testing.T, _ *Cluster, n *Node) {
			if err := corrosion.MarkStackDeleting(context.Background(), n.DB, "edge", false, n.Name); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "the teardown tombstones it", state: "deleted", tombstone: true, write: func(t *testing.T, _ *Cluster, n *Node) {
			if err := corrosion.DeleteStackRecord(context.Background(), n.DB, "edge"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "lv compose down end to end", state: "deleted", tombstone: true, write: func(t *testing.T, c *Cluster, n *Node) {
			stream, err := c.SelfClient(n).DeleteStack(context.Background(), &pb.DeleteStackRequest{Name: "edge"})
			for err == nil {
				_, err = stream.Recv()
			}
			if err != io.EOF {
				t.Fatalf("compose down on %s: %v", n.Name, err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 4417})
			admin, lagging := c.Nodes[0], c.Nodes[2]
			if err := corrosion.UpsertStack(ctx, admin.DB, corrosion.StackRecord{
				Name: "edge", ComposeHash: "hash-v1", ComposeYAML: laggingStackV1, State: "active"}); err != nil {
				t.Fatal(err)
			}
			c.WaitConverged(t, convergeTimeout)

			c.Isolate(lagging)
			if err := corrosion.UpsertStack(ctx, admin.DB, corrosion.StackRecord{
				Name: "edge", ComposeHash: "hash-v2", ComposeYAML: laggingStackV2, State: "active"}); err != nil {
				t.Fatal(err)
			}
			redeploy := readStackRow(t, admin, "edge")
			// The lagging node's write is stamped after the redeploy's,
			// which it has not seen.
			time.Sleep(10 * time.Millisecond)
			tc.write(t, c, lagging)
			mine := readStackRow(t, lagging, "edge")
			if mine.hash != "hash-v1" || mine.state != tc.state || mine.deleted != tc.tombstone {
				t.Fatalf("fixture: %s holds %+v, want its older record %s", lagging.Name, mine, tc.state)
			}
			if !(mine.updatedAt > redeploy.updatedAt) {
				t.Fatalf("fixture: %s's write (%s) is not newer than the redeploy (%s)",
					lagging.Name, mine.updatedAt, redeploy.updatedAt)
			}

			c.ClearLinkFaults()
			c.WaitConverged(t, convergeTimeout)
			for _, n := range c.Nodes {
				if got := readStackRow(t, n, "edge"); got != mine {
					t.Errorf("%s holds %+v, want the newer write's whole row %+v", n.Name, got, mine)
				}
			}
		})
	}
}
