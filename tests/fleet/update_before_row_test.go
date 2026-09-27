package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// An UPDATE issued on a node that has not yet received the row it targets must
// not leave the replicas apart once replication settles.
//
// The WAL lane is all there is here: IndependentReplicas runs no anti-entropy,
// so whatever the push loop leaves is what the cluster keeps. The block only
// fixes the ORDER — b updates before a's insert reaches it — and is lifted
// before convergence is judged, so the settle itself runs with no faults.
func TestFleet_IndependentReplicas_UpdateBeforeRowConverges(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	a, b, cn := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)

	c.SetLinkFault(a, b, LinkFault{Block: true})
	c.SetLinkFault(cn, b, LinkFault{Block: true}) // c must not relay a's insert to b either
	insertVM(t, a, "vm-late", a.Name)
	waitVM(t, cn, "vm-late")
	if vm := vmOn(t, b, "vm-late"); vm != nil {
		t.Fatalf("premise: b already has vm-late: %+v", vm)
	}

	// b moves a VM it has never seen. Locally that is a zero-row UPDATE.
	if err := corrosion.UpdateVMHost(context.Background(), b.DB, "vm-late", cn.Name, "stopped"); err != nil {
		t.Fatalf("b: move vm-late: %v", err)
	}
	// Give b's push loop time to deliver whatever it is going to deliver to a
	// and c while b still lacks the row.
	time.Sleep(300 * time.Millisecond)

	c.ClearLinkFaults()
	waitVM(t, b, "vm-late")
	c.WaitConverged(t, convergeTimeout)

	// One state, and it is the one with b's move in it: b's update is newer
	// than a's insert, so LWW (and anti-entropy, before this lane converged on
	// its own) says it wins.
	for _, n := range c.Nodes {
		if got := vmOn(t, n, "vm-late"); got == nil || got.HostName != cn.Name || got.State != "stopped" {
			t.Fatalf("%s: vm-late = %+v, want the move b made", n.Name, got)
		}
	}
}

// The receiving end of the same gap: c is handed b's update before the row it
// targets reaches it. Neither b nor c holds the row when the update moves, so
// only a — the row's creator — applies it on the WAL lane unless both keep it
// until the row arrives.
func TestFleet_IndependentReplicas_UpdateAheadOfRowAtAReceiverConverges(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	a, b, cn := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)

	c.SetLinkFault(a, b, LinkFault{Block: true})
	c.SetLinkFault(a, cn, LinkFault{Block: true})
	insertVM(t, a, "vm-late", a.Name)

	if err := corrosion.UpdateVMHost(context.Background(), b.DB, "vm-late", cn.Name, "stopped"); err != nil {
		t.Fatalf("b: move vm-late: %v", err)
	}
	// a applies the move (it holds the row); c receives it with no row.
	deadline := time.Now().Add(convergeTimeout)
	for {
		if vm := vmOn(t, a, "vm-late"); vm != nil && vm.HostName == cn.Name {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a never applied b's move")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	if vm := vmOn(t, cn, "vm-late"); vm != nil {
		t.Fatalf("premise: c already has vm-late: %+v", vm)
	}
	if st := c.LinkStats(b, cn); st.Applied == 0 {
		t.Fatalf("premise: b pushed nothing to c: %+v", st)
	}

	c.ClearLinkFaults()
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if got := vmOn(t, n, "vm-late"); got == nil || got.HostName != cn.Name || got.State != "stopped" {
			t.Fatalf("%s: vm-late = %+v, want the move b made", n.Name, got)
		}
	}
}

func waitVM(t *testing.T, n *Node, name string) {
	t.Helper()
	deadline := time.Now().Add(convergeTimeout)
	for vmOn(t, n, name) == nil {
		if time.Now().After(deadline) {
			t.Fatalf("%s never received %s", n.Name, name)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
