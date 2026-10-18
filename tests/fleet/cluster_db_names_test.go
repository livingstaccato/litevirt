package fleet

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_AClusterNeverOpensAnEarlierClustersDatabase: a cluster is built
// and stopped while something still holds its node-0 database open, as a
// background loop still in a query at Stop did under load; the next cluster's
// node-0 starts on a database of its own, holding only its own cluster's hosts
// at its own ports.
//
// Mutation: name a node's database by the node alone (dbName returning
// "fleet-"+suffix) — the second node-0 opens the first one's database, holding
// the first cluster's ports.
func TestFleet_AClusterNeverOpensAnEarlierClustersDatabase(t *testing.T) {
	ctx := context.Background()
	var held *corrosion.Client
	t.Cleanup(func() {
		if held != nil {
			held.Close()
		}
	})
	t.Run("first", func(t *testing.T) {
		c := New(t, Options{Nodes: 2, IndependentReplicas: true})
		var err error
		if held, err = corrosion.NewSharedTestClient(c.dbName(c.Nodes[0].Name), "holder"); err != nil {
			t.Fatal(err)
		}
	})
	if held == nil {
		t.Fatal("fixture: the first cluster's database was not held")
	}
	if rows, err := held.Query(ctx, `SELECT name FROM hosts`); err != nil || len(rows) == 0 {
		t.Fatalf("fixture: the held database lost the first cluster's hosts (%d rows, %v)", len(rows), err)
	}
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	for _, n := range c.Nodes {
		h, err := corrosion.GetHost(ctx, c.Nodes[0].DB, n.Name)
		if err != nil || h == nil {
			t.Fatalf("node-0 of the second cluster reads %s: %+v, %v", n.Name, h, err)
		}
		if h.GRPCPort != n.Port {
			t.Fatalf("node-0 of the second cluster reads %s at port %d, which listens on %d: it opened the first cluster's database",
				n.Name, h.GRPCPort, n.Port)
		}
	}
}
