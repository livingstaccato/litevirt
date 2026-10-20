package fleet

// Every writer that moves a VM's host without bumping its owner epoch must
// advance its placement generation in the same batch: a migration target's
// stub record is bound to the placement mark (owner, epoch, generation), and
// a move out and back through such a writer leaves owner and epoch as they
// were (round-13 review m2). Each writer is used for both legs here, on its
// own, and the mark is read from the other node's replica.

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Mutation: drop placementGenStmts from RescheduleVMHost (the review's S3) or
// CommitMigrationOwnership (S4) — that writer's subtest is red.
func TestFleet_EveryHostWriterWithoutAnEpochBumpAdvancesThePlacementMark(t *testing.T) {
	type leg func(t *testing.T, db *corrosion.Client, from, to string)
	ok := func(t *testing.T, what string, done bool, err error) {
		t.Helper()
		if err != nil || !done {
			t.Fatalf("%s: committed=%v err=%v", what, done, err)
		}
	}
	for _, w := range []struct {
		name string
		move leg
	}{
		{"CommitMigrationOwnership", func(t *testing.T, db *corrosion.Client, from, to string) {
			done, err := corrosion.CommitMigrationOwnership(context.Background(), db, "vm1", from, to, "running", nil)
			ok(t, "commit", done, err)
		}},
		{"RescheduleVMHost", func(t *testing.T, db *corrosion.Client, _, to string) {
			ok(t, "reschedule", true, corrosion.RescheduleVMHost(context.Background(), db, "vm1", to, "running"))
		}},
		{"RepointMigratedVM", func(t *testing.T, db *corrosion.Client, from, to string) {
			if err := corrosion.UpdateVMState(context.Background(), db, "vm1", "migrating", "to "+to); err != nil {
				t.Fatal(err)
			}
			done, err := corrosion.RepointMigratedVM(context.Background(), db, "vm1", from, to, "running")
			ok(t, "repoint", done, err)
		}},
		{"ReturnMigratedVM", func(t *testing.T, db *corrosion.Client, from, to string) {
			vm, err := corrosion.GetVM(context.Background(), db, "vm1")
			if err != nil || vm == nil {
				t.Fatalf("GetVM: %v %v", vm, err)
			}
			done, err := corrosion.ReturnMigratedVM(context.Background(), db, "vm1", from, to, "u1", vm.CreatedAt, "stopped", nil)
			ok(t, "return", done, err)
		}},
		{"UpdateVMHost", func(t *testing.T, db *corrosion.Client, _, to string) {
			ok(t, "update host", true, corrosion.UpdateVMHost(context.Background(), db, "vm1", to, "running"))
		}},
	} {
		t.Run(w.name, func(t *testing.T) {
			c := New(t, Options{Nodes: 2, IndependentReplicas: true})
			t.Cleanup(c.Stop)
			a, b := c.Nodes[0], c.Nodes[1]
			c.openClusterPolicyGate()
			if err := corrosion.InsertVM(context.Background(), a.DB, corrosion.VMRecord{
				Name: "vm1", HostName: a.Name, State: "running", Spec: `{"uuid":"u1"}`,
			}, nil, nil); err != nil {
				t.Fatal(err)
			}
			c.WaitConverged(t, convergeTimeout)
			mark := func() string {
				t.Helper()
				m, found, err := corrosion.VMPlacementMark(context.Background(), b.DB, "vm1")
				if err != nil || !found {
					t.Fatalf("VMPlacementMark on %s: %q %v %v", b.Name, m, found, err)
				}
				return m
			}
			before := mark()
			w.move(t, a.DB, a.Name, b.Name)
			w.move(t, a.DB, b.Name, a.Name)
			c.WaitConverged(t, convergeTimeout)
			after := mark()
			if vm, _ := corrosion.GetVM(context.Background(), b.DB, "vm1"); vm == nil || vm.HostName != a.Name {
				t.Fatalf("vm1 after the move out and back is %+v, want on %s", vm, a.Name)
			}
			if after == before {
				t.Fatalf("placement mark after a move out and back through %s = %q, the same as before: a stub record of the first leg would match again", w.name, after)
			}
		})
	}
}
