// Fleet scenarios: a VM's hardware_adoption_state on every replica, live and
// deleted.
//
// Observed on lab 1, 2026-10-13 (lab1-composeguard-3f3a2917.md, F2): a VM
// created, re-created and deleted within ten seconds left a tombstone whose
// hardware_adoption_state was `adopted` on some nodes and `pending` on others
// at one updated_at, flipping between reads, and `lv cluster converge --all`
// did not heal it. Two causes, each reproduced here:
//
//  1. The adoption UPDATE a create writes beside its INSERT carried the
//     INSERT's own updated_at. Every receiver dropped it as a tied partial
//     update, so only the creating host held `adopted`.
//  2. Anti-entropy applied a peer's tombstone of the same incarnation at equal
//     authority unconditionally, past the row's LWW and its tie resolver. Two
//     tombstones that differ in a column the authority does not cover were
//     swapped on every pull, so pulls in both directions at once exchanged
//     them and the table never settled.
package fleet

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func adoptionOn(t *testing.T, n *Node, name string) (state, updatedAt string) {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT hardware_adoption_state, updated_at FROM vms WHERE name = ?`, name)
	if err != nil || len(rows) != 1 {
		t.Fatalf("%s on %s: %d rows (%v)", name, n.Name, len(rows), err)
	}
	return rows[0].String("hardware_adoption_state"), rows[0].String("updated_at")
}

func createOnNode0(t *testing.T, c *Cluster, name string) {
	t.Helper()
	n0 := c.Nodes[0]
	if _, err := c.SelfClient(n0).CreateVM(context.Background(), &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: name, Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n0.Name},
	}}); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
}

// A created VM is adopted on every replica once replication has caught up,
// with no anti-entropy pass.
//
// Red against c7b052a0: adopted on node-0, pending on node-1 and node-2.
func TestFleet_ACreatedVMIsAdoptedOnEveryReplica(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.WaitConverged(t, 20*time.Second)
	createOnNode0(t, c, "web")
	c.WaitConverged(t, 20*time.Second)
	for _, n := range c.Nodes {
		if st, _ := adoptionOn(t, n, "web"); st != "adopted" {
			t.Errorf("web's hardware_adoption_state on %s = %q, want adopted", n.Name, st)
		}
	}
}

// Two replicas hold tombstones of one VM incarnation, at one updated_at and
// one authority, that differ in hardware_adoption_state — a tombstone a build
// before the fix left. Each pulls the other at once. Both must end on the
// same row, and further passes must keep the cluster converged.
//
// Red against c7b052a0: each took the other's row (node-0 pending, node-1
// adopted) — the flap the lab saw.
func TestFleet_DivergentTombstonesOfOneVMConvergeWhicheverPullsFirst(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.WaitConverged(t, 20*time.Second)
	createOnNode0(t, c, "web")
	if _, err := c.SelfClient(c.Nodes[0]).DeleteVM(context.Background(), &pb.DeleteVMRequest{Name: "web"}); err != nil {
		t.Fatalf("delete web: %v", err)
	}
	waitHistoryApplied(t, c, 20*time.Second)
	n0, n1 := c.Nodes[0], c.Nodes[1]

	// The tombstones as a build before the fix left them: the adoption the
	// create wrote landed on its host only. Set here on both, so the scenario
	// does not depend on which build wrote them; updated_at is unchanged, and
	// nothing replicates the change.
	for n, st := range map[*Node]string{n0: "adopted", n1: "pending"} {
		n.DB.Mu().Lock()
		_, err := n.DB.DB().Exec(`UPDATE vms SET hardware_adoption_state = ? WHERE name = ?`, st, "web")
		n.DB.Mu().Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	s0, at0 := adoptionOn(t, n0, "web")
	s1, at1 := adoptionOn(t, n1, "web")
	if s0 != "adopted" || s1 != "pending" || at0 != at1 {
		t.Fatalf("setup: node-0 %q at %s, node-1 %q at %s; want adopted/pending at one updated_at", s0, at0, s1, at1)
	}

	// Each pulls the other's state as it is now.
	d0, d1 := n0.DB.DumpStateBytes(), n1.DB.DumpStateBytes()
	if err := n0.DB.MergeStateBytesLWW(d1); err != nil {
		t.Fatal(err)
	}
	if err := n1.DB.MergeStateBytesLWW(d0); err != nil {
		t.Fatal(err)
	}
	s0, _ = adoptionOn(t, n0, "web")
	s1, _ = adoptionOn(t, n1, "web")
	if s0 != s1 {
		t.Fatalf("after pulling each other: node-0 %q, node-1 %q — the tombstones were exchanged, not settled", s0, s1)
	}

	for i := 0; i < 3; i++ {
		runAEPass(t, c, false)
	}
	if apart, err := divergence(c.Nodes); err != nil || len(apart) > 0 {
		t.Fatalf("after three anti-entropy passes the replicas are apart on %v (%v)", apart, err)
	}
}
