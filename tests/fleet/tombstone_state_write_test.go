// A VM state write must not modify a tombstone, on the node that makes it or on
// any node it replicates to.
//
// Observed on the kvm003-f3 lab, 2026-09-30, right after the stale delete that
// stale_replica_delete_test.go pins: claimvm's row was tombstoned on every node
// while the VM kept running on node-4. node-4's health checker had listed the
// VM before the tombstone arrived. It saw the domain running, and wrote
// "running" after the tombstone had landed. The name-keyed UPDATE matched the
// tombstone and replicated, and every replica ended up holding a row that was
// both running and deleted.
//
// The writer is called directly here, at the moment the lab's did: after its
// list, after the tombstone.
package fleet

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

type vmRowState struct {
	state   string
	deleted bool
}

func tombVMRow(t *testing.T, n *Node, name string) vmRowState {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT state, deleted_at FROM vms WHERE name = ?`, name)
	if err != nil {
		t.Fatalf("%s: read %s: %v", n.Name, name, err)
	}
	if len(rows) != 1 {
		t.Fatalf("%s: want one %s row, have %d", n.Name, name, len(rows))
	}
	return vmRowState{rows[0].String("state"), rows[0].String("deleted_at") != ""}
}

// tombstoneScenario: `owner` runs tombvm, whose row says stopped (the desync
// the health checker's reconcile heals). `deleter` tombstones it. Only
// `early` has the tombstone yet.
func tombstoneScenario(t *testing.T) (c *Cluster, owner, deleter, early *Node) {
	t.Helper()
	c = New(t, Options{Nodes: 3})
	owner, deleter, early = c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, owner.DB, corrosion.VMRecord{
		Name: "tombvm", HostName: owner.Name, State: "stopped", Spec: `{}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := owner.Virt.DefineDomain(`<domain><name>tombvm</name></domain>`); err != nil {
		t.Fatal(err)
	}
	owner.Virt.SetState("tombvm", libvirtfake.StateRunning)
	pumpMutations(t, c, owner, deleter)
	pumpMutations(t, c, owner, early)

	if err := corrosion.DeleteVM(ctx, deleter.DB, "tombvm"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	pumpMutations(t, c, deleter, early)
	if !tombVMRow(t, early, "tombvm").deleted {
		t.Fatal("setup: the tombstone must have reached the early node")
	}
	return c, owner, deleter, early
}

// The lab's order: the tombstone reaches the owner before its health checker
// writes. The write must be refused, so there is nothing to replicate.
func TestFleet_StateWriteAfterTheTombstoneIsRefused(t *testing.T) {
	c, owner, deleter, _ := tombstoneScenario(t)
	ctx := context.Background()
	pumpMutations(t, c, deleter, owner)

	err := corrosion.UpdateVMStateStrict(ctx, owner.DB, "tombvm", "running",
		"reconciled from libvirt: domain running")
	if !errors.Is(err, corrosion.ErrNoRowsAffected) {
		t.Errorf("a state write to a tombstone must be refused with ErrNoRowsAffected, got %v", err)
	}
	spreadFrom(t, c, owner)
	for _, n := range c.Nodes {
		if got := tombVMRow(t, n, "tombvm"); !got.deleted || got.state != "stopped" {
			t.Errorf("%s: tombvm row = %+v, want the tombstone unchanged (deleted, stopped)", n.Name, got)
		}
	}
}

// The other order: the owner writes while its own row is still live, and the
// statement reaches a node that already holds the tombstone. That receiver
// must not apply it. (The owner's row then takes the tombstone verbatim with
// the newer updated_at, and anti-entropy converges every node on that row:
// deleted, whatever state it recorded just before. The write was not made to
// a deleted row, so it is not the defect.)
func TestFleet_StateWriteDoesNotLandOnAReceiversTombstone(t *testing.T) {
	c, owner, _, early := tombstoneScenario(t)
	ctx := context.Background()

	if err := corrosion.UpdateVMStateStrict(ctx, owner.DB, "tombvm", "running",
		"reconciled from libvirt: domain running"); err != nil {
		t.Fatalf("the owner's row is still live, so its write must land: %v", err)
	}
	pumpMutations(t, c, owner, early)
	if got := tombVMRow(t, early, "tombvm"); !got.deleted || got.state != "stopped" {
		t.Errorf("early node's tombstone was modified by a replicated state write: %+v, want (deleted, stopped)", got)
	}
}
