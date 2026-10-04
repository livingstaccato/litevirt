// Fleet scenarios: a per-VM start lease handed from one host to another within
// one second converges on every node.
//
// Host A takes the vm_locks lease, releases it, and host B takes it, all on one
// pinned second. A third node must end with B's row, whichever order the
// writes reach it in.
//
// vm_locks is safe from the same-second tie that dropped rebalance and restart
// transitions, and these scenarios PIN THE CURRENT HANDOFF BEHAVIOUR; they are
// not a proof against that bug. A receiver applies the lease upsert verbatim,
// with its `WHERE vm_locks.expires_at < ? OR vm_locks.holder = excluded.holder`
// guard, and expires_at derives from the same clock read as the stamp. So an
// incoming write only changes a row when the local lease has expired (its
// stamp is then a strictly earlier second) or names the same holder (an
// identical row in the same second). An LWW tie therefore never decides the
// outcome. The release is a DELETE by (vm_name, holder), applied verbatim and
// not LWW-gated at all.
//
// That breaks if the lease stops being a guarded whole-row upsert: a takeover
// or renewal written as an unguarded partial UPDATE, an expiry computed from a
// different clock read than the stamp, or a release that deletes by vm_name
// alone (it would remove a newer holder's row on a node that saw the new row
// first).
//
// NO TESTED MUTATION HAS BEEN SHOWN TO MAKE THESE FAIL for a semantic reason.
// Writing the lease as a guarded partial UPDATE stamped with the whole-second
// clock left all three green: B always takes over after A's release, so B's
// write meets no local row and stays an INSERT. A release by vm_name alone did
// go red, but only because its new statement shape is unregistered and peers
// back-pressure it, which stmtshapecheck would refuse first. Replication also
// relays A's release through B ahead of B's own lease, so a third node sees the
// handoff in causal order even with A's direct link blocked.

package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/health"
)

func vmLockHolder(t *testing.T, n *Node, vm string) string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), `SELECT holder FROM vm_locks WHERE vm_name = ?`, vm)
	if err != nil {
		t.Fatalf("%s: read vm_locks: %v", n.Name, err)
	}
	if len(rows) == 0 {
		return ""
	}
	return rows[0].String("holder")
}

func waitVMLock(t *testing.T, n *Node, vm, want string) bool {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if vmLockHolder(t, n, vm) == want {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func assertVMLockEverywhere(t *testing.T, c *Cluster, vm, want string) {
	t.Helper()
	for _, n := range c.Nodes {
		if !waitVMLock(t, n, vm, want) {
			t.Errorf("%s: vm_locks[%s] holder = %q, want %q", n.Name, vm, vmLockHolder(t, n, vm), want)
		}
	}
}

func mustTakeVMLease(t *testing.T, n *Node, vm string, at time.Time) {
	t.Helper()
	if got, err := health.TryVMStartLease(context.Background(), n.DB, n.Name, vm, at); err != nil || got != n.Name {
		t.Fatalf("%s: TryVMStartLease = %q, %v; want it held by %s", n.Name, got, err, n.Name)
	}
}

const handoffVM = "lease-vm"

func TestFleet_VMStartLeaseHandoffConvergesOnEveryNode_InOrder(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	a, b := c.Nodes[0], c.Nodes[1]
	instant := time.Now().UTC().Truncate(time.Second)

	mustTakeVMLease(t, a, handoffVM, instant)
	assertVMLockEverywhere(t, c, handoffVM, a.Name)
	health.ReleaseVMStartLease(context.Background(), a.DB, a.Name, handoffVM)
	assertVMLockEverywhere(t, c, handoffVM, "")
	mustTakeVMLease(t, b, handoffVM, instant)
	assertVMLockEverywhere(t, c, handoffVM, b.Name)
}

// The third node hears nothing from A directly until after B has taken over.
func TestFleet_VMStartLeaseHandoffConvergesOnEveryNode_BlockedFromHolder(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	a, b, third := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	instant := time.Now().UTC().Truncate(time.Second)

	c.SetLinkFault(a, third, LinkFault{Block: true})
	mustTakeVMLease(t, a, handoffVM, instant)
	if !waitVMLock(t, b, handoffVM, a.Name) {
		t.Fatal("B never saw A's lease")
	}
	health.ReleaseVMStartLease(context.Background(), a.DB, a.Name, handoffVM)
	if !waitVMLock(t, b, handoffVM, "") {
		t.Fatal("B never saw A's release")
	}
	mustTakeVMLease(t, b, handoffVM, instant)
	if !waitVMLock(t, third, handoffVM, b.Name) {
		t.Fatal("the third node never saw B's lease")
	}
	c.ClearLinkFaults()
	time.Sleep(time.Second) // A's own pushes land late
	assertVMLockEverywhere(t, c, handoffVM, b.Name)
}

// The third node has A's lease, and A's release is held back from it while B
// takes over.
func TestFleet_VMStartLeaseHandoffConvergesOnEveryNode_ReleaseHeldBack(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	a, b, third := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	instant := time.Now().UTC().Truncate(time.Second)

	mustTakeVMLease(t, a, handoffVM, instant)
	assertVMLockEverywhere(t, c, handoffVM, a.Name)
	c.SetLinkFault(a, third, LinkFault{Block: true})
	health.ReleaseVMStartLease(context.Background(), a.DB, a.Name, handoffVM)
	if !waitVMLock(t, b, handoffVM, "") {
		t.Fatal("B never saw A's release")
	}
	mustTakeVMLease(t, b, handoffVM, instant)
	c.ClearLinkFaults()
	time.Sleep(time.Second) // A's own pushes land late
	assertVMLockEverywhere(t, c, handoffVM, b.Name)
}
