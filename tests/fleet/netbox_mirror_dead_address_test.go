// A leased NetBox address deleted by hand.
//
// The mirror assigns each NIC the address object its lease names. When an
// operator deletes that object in NetBox the lease still names it, so the
// assignment is a 404 — and one failed action failed the whole pass, before the
// primary and delete phases ran, on every sweep for as long as the lease lived.
// Nothing else the cluster did reached NetBox again.

package fleet

import "testing"

// TestMirrorDeadAddressDoesNotStallTheSweep: one dead address costs only its
// own assignment; the rest of the pass still runs, and it reports itself
// unconverged rather than succeeding.
func TestMirrorDeadAddressDoesNotStallTheSweep(t *testing.T) {
	nb, c := boundMirrorCluster(t, 1)
	n := c.Nodes[0]

	mustCreateVM(t, n, "vm-1", orphanNetwork)
	mustCreateVM(t, n, "vm-2", orphanNetwork)
	mustSyncAllNodes(t, c)
	dead := nb.InterfaceAddressID("vm-1", "eth0")
	if dead == 0 {
		t.Fatal("precondition: vm-1 has no mirrored address")
	}

	nb.DeleteAddressDirect(dead)
	// Work the pass still owes the rest of the cluster: a delete, which runs in
	// the LAST phase, after the assignment that 404s.
	mustDeleteVM(t, n, "vm-2")

	m := &mirrorSweepCounter{sweepMetrics: newSweepMetrics()}
	n.Server.SetNetBoxMetrics(m)
	for i := 0; i < 2; i++ {
		if err := n.SyncNetBoxMirror(); err != nil {
			t.Fatalf("mirror pass %d failed over one hand-deleted address: %v", i, err)
		}
	}

	if got := nb.VMCount("vm-2"); got != 0 {
		t.Fatalf("vm-2 objects = %d after its delete; the dead address on vm-1 still stalls "+
			"every phase behind the assignment", got)
	}
	if got := nb.VMCount("vm-1"); got != 1 {
		t.Fatalf("vm-1 objects = %d, want 1", got)
	}
	for i, r := range m.passes() {
		if r != "error" {
			t.Fatalf("pass %d recorded %q: a pass that could not assign a NIC its address "+
				"has not converged and must not stamp success", i, r)
		}
	}
	if len(m.passes()) == 0 {
		t.Fatal("no mirror pass was recorded")
	}
}
