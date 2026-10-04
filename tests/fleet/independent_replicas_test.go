// Fleet scenarios for the independent-replica mode itself: each node has its
// own database and the production push loop carries writes between them, with
// the per-link fault injector in the path. These pin that the mode does what a
// failover scenario built on it will assume — writes arrive unassisted, a
// blocked link really withholds them, and a link that delays, drops,
// duplicates and reorders still converges.
package fleet

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

const convergeTimeout = 20 * time.Second

func insertVM(t *testing.T, n *Node, name, host string) {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), n.DB, corrosion.VMRecord{
		Name: name, HostName: host, Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM %s on %s: %v", name, n.Name, err)
	}
}

func vmOn(t *testing.T, n *Node, name string) *corrosion.VMRecord {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), n.DB, name)
	if err != nil {
		t.Fatalf("GetVM %s on %s: %v", name, n.Name, err)
	}
	return vm
}

// A write on one node reaches every other node through the push loop alone,
// and the replicas' digests agree afterwards.
func TestFleet_IndependentReplicas_PushLoopConverges(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	a := c.Nodes[0]
	c.WaitConverged(t, convergeTimeout)

	insertVM(t, a, "vm-pushed", a.Name)
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if vm := vmOn(t, n, "vm-pushed"); vm == nil || vm.HostName != a.Name {
			t.Fatalf("%s: vm-pushed = %+v after convergence; the push loop did not carry it", n.Name, vm)
		}
	}
}

// New hands a scenario independent replicas that already agree. Every node
// writes its own copy of every seeded hosts row, so the copies differ until the
// push loops carry the seed across. A scenario write to a hosts column before
// then holds a newer clock than a peer's late seed INSERT, which loses the LWW
// gate on that node and takes its created_at with it. created_at has
// one-second resolution, so a seed that straddled a second boundary leaves
// that node's copy a second apart for good: the push loop has nothing left to
// send, and only anti-entropy, which the fleet does not run, settles the tie.
func TestFleet_IndependentReplicas_NewStartsConverged(t *testing.T) {
	c := New(t, Options{Nodes: 4, IndependentReplicas: true})
	apart, err := divergence(c.Nodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(apart) != 0 {
		t.Fatalf("New returned replicas still apart on %v; a scenario's first write races the seed", apart)
	}
}

// A blocked link withholds history in its direction only, and delivers it once
// healed.
func TestFleet_IndependentReplicas_BlockIsDirectional(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	a, b := c.Nodes[0], c.Nodes[1]
	c.WaitConverged(t, convergeTimeout)

	c.SetLinkFault(a, b, LinkFault{Block: true})
	insertVM(t, a, "vm-from-a", a.Name)
	insertVM(t, b, "vm-from-b", b.Name)

	// b→a is open: a learns b's write.
	deadline := time.Now().Add(convergeTimeout)
	for vmOn(t, a, "vm-from-b") == nil {
		if time.Now().After(deadline) {
			t.Fatal("b→a is healthy but a never received vm-from-b")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// a→b is blocked: give the loop several pushes' worth of time, then check
	// b still has not seen a's write and the injector actually refused traffic.
	time.Sleep(300 * time.Millisecond)
	if vm := vmOn(t, b, "vm-from-a"); vm != nil {
		t.Fatalf("a→b is blocked but b has vm-from-a: %+v", vm)
	}
	if st := c.LinkStats(a, b); st.Blocked == 0 {
		t.Fatalf("a→b blocked but the injector refused nothing: %+v", st)
	}

	c.ClearLinkFaults()
	c.WaitConverged(t, convergeTimeout)
	if vm := vmOn(t, b, "vm-from-a"); vm == nil {
		t.Fatal("healed a→b but b never received vm-from-a")
	}
}

// A reordered batch is acknowledged to the sender and held; the sender's
// watermark moves past it, so with no third node to relay it the held batch is
// the only copy in flight. Clearing the fault must deliver it rather than lose
// it.
func TestFleet_IndependentReplicas_ReorderHoldsUntilHealed(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	a, b := c.Nodes[0], c.Nodes[1]
	c.WaitConverged(t, convergeTimeout)

	c.SetLinkFault(a, b, LinkFault{Reorder: 1})
	insertVM(t, a, "vm-held", a.Name)
	deadline := time.Now().Add(convergeTimeout)
	for c.LinkStats(a, b).Reordered == 0 {
		if time.Now().After(deadline) {
			t.Fatal("a never pushed vm-held to b")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if vm := vmOn(t, b, "vm-held"); vm != nil {
		t.Fatalf("every a→b push is held, yet b has vm-held: %+v", vm)
	}

	c.ClearLinkFaults()
	c.WaitConverged(t, convergeTimeout)
	if vm := vmOn(t, b, "vm-held"); vm == nil {
		t.Fatal("clearing the fault lost the held batch")
	}
}

// Reordering, duplicating, dropping and delaying the same mutations on every
// link still converges to one state: the dedup, LWW and retry machinery each
// fault exercises is what makes that true.
func TestFleet_IndependentReplicas_FaultyLinksConverge(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 266})
	a := c.Nodes[0]
	c.WaitConverged(t, convergeTimeout)

	// The contested row exists everywhere BEFORE the faults start. An UPDATE
	// issued on a node that has not yet received the row is parked there until
	// the row arrives (update_before_row_test.go pins that); this scenario is
	// about the dedup, LWW and retry machinery, so it keeps the two apart.
	insertVM(t, a, "vm-shared", a.Name)
	c.WaitConverged(t, convergeTimeout)

	faulty := LinkFault{Delay: 5 * time.Millisecond, Jitter: 10 * time.Millisecond,
		Drop: 0.1, Duplicate: 0.5, Reorder: 0.3}
	for _, from := range c.Nodes {
		for _, to := range c.Nodes {
			if from != to {
				c.SetLinkFault(from, to, faulty)
			}
		}
	}

	// Concurrent, conflicting histories: every node writes its own VMs and moves
	// the shared one somewhere different, several times, so the order in which a
	// node applies the moves decides what it ends up with.
	for round := 0; round < 3; round++ {
		for i, n := range c.Nodes {
			insertVM(t, n, fmt.Sprintf("%s-vm-%d", n.Name, round), n.Name)
			dest := c.Nodes[(i+round+1)%len(c.Nodes)].Name
			if err := corrosion.UpdateVMHost(context.Background(), n.DB, "vm-shared", dest, "running"); err != nil {
				t.Fatalf("%s: move vm-shared: %v", n.Name, err)
			}
		}
	}

	// Let the faults bite, then heal — which also delivers anything a reorder is
	// still holding — and require one state.
	time.Sleep(500 * time.Millisecond)
	var total LinkStats
	for _, from := range c.Nodes {
		for _, to := range c.Nodes {
			if from != to {
				st := c.LinkStats(from, to)
				total.Pushes += st.Pushes
				total.Duplicated += st.Duplicated
				total.Reordered += st.Reordered
				total.Dropped += st.Dropped
			}
		}
	}
	t.Logf("faults injected: %+v", total)
	if total.Duplicated == 0 || total.Reordered == 0 {
		t.Fatalf("the scenario must actually duplicate and reorder to prove anything: %+v", total)
	}
	c.ClearLinkFaults()
	c.WaitConverged(t, convergeTimeout)

	want := vmOn(t, a, "vm-shared")
	for _, n := range c.Nodes {
		got := vmOn(t, n, "vm-shared")
		if got == nil || want == nil || got.HostName != want.HostName {
			t.Fatalf("%s: vm-shared = %+v, %s has %+v", n.Name, got, a.Name, want)
		}
	}
}
