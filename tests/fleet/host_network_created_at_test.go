package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_HostNetwork_TwoInsertsConverge: a host network intent is keyed by
// (host, name), and the same key can be INSERTed on two replicas that never saw
// each other's row. A machine rebuilt under a removed host's name starts from
// an empty database while its peers hold the old machine's row (tombstoned by
// the re-admission), and the operator records the new machine's wiring under
// the same interface name. UpsertHostNetwork's conflict path leaves created_at
// alone, so an INSERT that bound its own wall-clock created_at left the two
// replicas as one updated_at over two created_at values, which the WAL push
// cannot settle. Modelled here as the same intent written on both sides of a
// cut link.
//
// Mutation: bind nowRFC3339Nano() as created_at in UpsertHostNetwork again —
// the replicas stay apart on host_networks.
func TestFleet_HostNetwork_TwoInsertsConverge(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 1})
	a, b := c.Nodes[0], c.Nodes[1]
	c.WaitConverged(t, convergeTimeout)

	c.SetLinkFaultBoth(a, b, LinkFault{Block: true})
	record := func(n *Node, member string) {
		t.Helper()
		if err := corrosion.UpsertHostNetwork(ctx, n.DB, corrosion.HostNetworkRecord{
			HostName: b.Name, Name: "vmbr0", Kind: "bridge", Members: []string{member},
		}); err != nil {
			t.Fatalf("%s: record intent: %v", n.Name, err)
		}
	}
	record(a, "eth1")
	record(b, "enp3s0f0")

	c.ClearLinkFaults()
	c.WaitConverged(t, convergeTimeout, a, b)
	for _, n := range []*Node{a, b} {
		got, err := corrosion.GetHostNetwork(ctx, n.DB, b.Name, "vmbr0")
		if err != nil || got == nil || len(got.Members) != 1 || got.Members[0] != "enp3s0f0" {
			t.Errorf("%s: converged on %+v (%v), want the later intent", n.Name, got, err)
		}
	}
}

// TestFleet_NetBoxHostConfig_TwoInsertsConverge is the same race on
// netbox_host_config: a machine rebuilt under a removed host's name publishes
// its NetBox cluster name from an empty database while a peer holds a row for
// the name. PublishNetBoxHostConfig's conflict path leaves created_at alone.
//
// Mutation: bind a wall-clock created_at in PublishNetBoxHostConfig again —
// the replicas stay apart on netbox_host_config.
func TestFleet_NetBoxHostConfig_TwoInsertsConverge(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 1})
	a, b := c.Nodes[0], c.Nodes[1]
	c.WaitConverged(t, convergeTimeout)

	c.SetLinkFaultBoth(a, b, LinkFault{Block: true})
	if err := corrosion.PublishNetBoxHostConfig(ctx, a.DB, b.Name, "dc1-old"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // a wall-clock created_at would differ
	if err := corrosion.PublishNetBoxHostConfig(ctx, b.DB, b.Name, "dc1-new"); err != nil {
		t.Fatal(err)
	}
	c.ClearLinkFaults()
	c.WaitConverged(t, convergeTimeout, a, b)
	for _, n := range []*Node{a, b} {
		got, err := corrosion.ListNetBoxHostConfig(ctx, n.DB)
		if err != nil || got[b.Name] != "dc1-new" {
			t.Errorf("%s: converged on %v (%v), want the later publication", n.Name, got, err)
		}
	}
}
