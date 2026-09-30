// A VM operation barrier write must not modify a tombstone on any node it
// replicates to.
//
// BeginVMOperation's claim and the barrier clear CompleteVMOperation,
// AbortVMOperation and FailVMOperation share are keyed on the name plus the
// owner/generation CAS, which a tombstone carries too. The origin's Go guard
// reads its own row with `deleted_at IS NULL`, so it refuses locally; but an
// operation the owner runs while its row is still live replicates as a bare
// statement, and a peer that already holds the tombstone used to apply it:
// the deleted row gained (or lost) a barrier and a spec generation.
package fleet

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

type vmOpRowState struct {
	activeOp string
	specGen  int64
	deleted  bool
}

func tombVMOpRow(t *testing.T, n *Node, name string) vmOpRowState {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT active_operation_id, spec_generation, deleted_at FROM vms WHERE name = ?`, name)
	if err != nil {
		t.Fatalf("%s: read %s: %v", n.Name, name, err)
	}
	if len(rows) != 1 {
		t.Fatalf("%s: want one %s row, have %d", n.Name, name, len(rows))
	}
	return vmOpRowState{rows[0].String("active_operation_id"), rows[0].Int64("spec_generation"),
		rows[0].String("deleted_at") != ""}
}

func tombOp(key string) corrosion.OperationRecord {
	return corrosion.OperationRecord{
		ID:     corrosion.DeterministicOperationID("UpdateVM", "user:alice@local", "", "tombvm", key),
		Method: "UpdateVM", Principal: "user:alice@local", ResourceKind: "vm", ResourceID: "tombvm",
		OperationKind: string(corrosion.OpResourceUpdateRunning), RequestHash: "hash-" + key, IdempotencyKey: key,
	}
}

// The owner begins an operation on its still-live row; the early node already
// holds the tombstone.
func TestFleet_OperationBeginDoesNotLandOnAReceiversTombstone(t *testing.T) {
	c, owner, _, early := tombstoneScenario(t)
	ctx := context.Background()
	before := tombVMOpRow(t, early, "tombvm")

	if applied, err := owner.DB.BeginVMOperation(ctx, tombOp("k1"), `{"cpu":4}`, 0, 0); err != nil || !applied {
		t.Fatalf("the owner's row is still live, so its begin must apply: applied=%v err=%v", applied, err)
	}
	pumpMutations(t, c, owner, early)
	if got := tombVMOpRow(t, early, "tombvm"); got != before {
		t.Errorf("early node's tombstone was modified by a replicated operation begin: %+v, want %+v", got, before)
	}
}

// The owner clears a barrier on its still-live row; the early node holds a
// tombstone taken while that barrier was set.
func TestFleet_OperationClearDoesNotLandOnAReceiversTombstone(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		clear func(n *Node, opID string) (bool, error)
	}{
		{"complete", func(n *Node, id string) (bool, error) { return n.DB.CompleteVMOperation(ctx, "tombvm", id, 0, 1) }},
		{"abort", func(n *Node, id string) (bool, error) { return n.DB.AbortVMOperation(ctx, "tombvm", id, 0, 1) }},
		{"fail", func(n *Node, id string) (bool, error) {
			return n.DB.FailVMOperation(ctx, "tombvm", id, 0, 1, `{"code":"Internal"}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(t, Options{Nodes: 3})
			owner, deleter, early := c.Nodes[0], c.Nodes[1], c.Nodes[2]
			if err := corrosion.InsertVM(ctx, owner.DB, corrosion.VMRecord{
				Name: "tombvm", HostName: owner.Name, State: "stopped", Spec: `{}`,
			}, nil, nil); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			op := tombOp("k1")
			if applied, err := owner.DB.BeginVMOperation(ctx, op, `{"cpu":4}`, 0, 0); err != nil || !applied {
				t.Fatalf("BeginVMOperation: applied=%v err=%v", applied, err)
			}
			pumpMutations(t, c, owner, deleter)
			pumpMutations(t, c, owner, early)
			if err := corrosion.DeleteVM(ctx, deleter.DB, "tombvm"); err != nil {
				t.Fatalf("DeleteVM: %v", err)
			}
			pumpMutations(t, c, deleter, early)
			before := tombVMOpRow(t, early, "tombvm")
			if !before.deleted || before.activeOp != op.ID {
				t.Fatalf("setup: early must hold the tombstone with the barrier set, have %+v", before)
			}

			if applied, err := tc.clear(owner, op.ID); err != nil || !applied {
				t.Fatalf("the owner's row is still live, so its clear must apply: applied=%v err=%v", applied, err)
			}
			pumpMutations(t, c, owner, early)
			if got := tombVMOpRow(t, early, "tombvm"); got != before {
				t.Errorf("early node's tombstone was modified by a replicated barrier clear: %+v, want %+v", got, before)
			}
		})
	}
}
