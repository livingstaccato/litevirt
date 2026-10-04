// A host that restarts after its VM failed over must not move the VM's disk
// rows back with its startup hardware backfill.
//
// Observed on the kvm003 lab (main-e004c250), drills 2 and 3: node-3's
// coordinator failed the VM over to node-2 at 05:29:48, moving its vms row and,
// since the N7 fix, its vm_disks rows. node-1, the old owner, came back and at
// 05:32:06.761 rewrote the disk row. Its replica had not caught up yet, so it
// still listed the VM as its own; the backfill filled the empty `bus` column
// with an INSERT OR REPLACE of the whole row it held — host_name=node-1 — under
// a fresh timestamp. That row was the newest anywhere, so it won LWW on every
// node and the disk row named node-1 again while the VM ran on node-2.
//
// Separate per-node databases, a real coordinator failover, the real backfill,
// and both channels a write spreads by: the WAL push and anti-entropy's
// full-row merge.
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
)

const backfillVM = "bf1"

// diskRow reads the backfill VM's one disk row on n.
func diskRow(t *testing.T, n *Node) corrosion.DiskRecord {
	t.Helper()
	disks, err := corrosion.GetVMDisks(context.Background(), n.DB, backfillVM)
	if err != nil {
		t.Fatalf("%s: disks of %s: %v", n.Name, backfillVM, err)
	}
	if len(disks) != 1 {
		t.Fatalf("%s: want one live disk row for %s, have %d", n.Name, backfillVM, len(disks))
	}
	return disks[0]
}

// TestFleet_StartupBackfill_DoesNotRevertAFailover: the VM's disk row has no
// bus (a VM created before create wrote it). old owns it, fails, and a's
// coordinator moves it — VM and disk rows — to dest. old restarts with a
// replica that has not caught up and runs its startup hardware backfill.
// Whatever it publishes reaches everyone; the disk row must still name dest on
// every node. Once old has caught up, its backfill has nothing of the VM's to
// touch, and dest's own backfill fills the bus without moving the row.
//
// Mutation: drop the replica-caught-up gate from BackfillHardwareTables — old
// writes its stale row and anti-entropy carries it over dest's on every node,
// as on the lab.
func TestFleet_StartupBackfill_DoesNotRevertAFailover(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 4})
	a, old := c.Nodes[0], c.Nodes[3]

	insertVMWithDisk(t, old, backfillVM, old.Name, old.Name)
	for _, n := range c.Nodes {
		if n != old {
			pumpMutations(t, c, old, n)
		}
	}
	if got := diskRow(t, a); got.Bus != "" || got.HostName != old.Name {
		t.Fatalf("setup: want a bus-less disk row on %s, have %+v", old.Name, got)
	}

	// old fails; the three survivors watch it, and a's coordinator fails the
	// VM over. old hears none of it.
	now := time.Now().UTC()
	for _, n := range c.Nodes[:3] {
		PublishHealth(t, n, old.Name, 5, now)
		if n != a {
			pumpMutations(t, c, n, a)
		}
	}
	coord := failover.NewCoordinator(a.Name, a.DB)
	coord.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "fleet-test", Success: true}
	})
	coord.Gate = quorateGate{}
	coord.RunOnce(ctx)
	vm, err := corrosion.GetVM(ctx, a.DB, backfillVM)
	if err != nil || vm == nil || vm.HostName == old.Name {
		t.Fatalf("failover did not move %s off %s: %+v %v", backfillVM, old.Name, vm, err)
	}
	dest := c.Node(vm.HostName)
	for _, n := range c.Nodes[1:3] {
		pumpMutations(t, c, a, n)
	}
	for _, n := range c.Nodes[:3] {
		if got := diskRow(t, n); got.HostName != dest.Name {
			t.Fatalf("setup: after the failover %s's disk row on %s names %s, want %s", backfillVM, n.Name, got.HostName, dest.Name)
		}
	}

	// old restarts: its replica still says the VM and its disk are its own,
	// and no anti-entropy exchange has completed since the process started.
	old.DB.MarkReplicaStale("process restarted (fleet: modelled reboot)")
	if got := diskRow(t, old); got.HostName != old.Name {
		t.Fatalf("setup: the restarted node must still believe it owns the disk: %+v", got)
	}
	err = old.Server.BackfillHardwareTables(ctx)
	if err == nil {
		t.Error("the startup backfill ran on a replica that has not caught up; want it refused until it has")
	}
	spreadFrom(t, c, old)
	for _, n := range c.Nodes[:3] {
		if got := diskRow(t, n); got.HostName != dest.Name {
			t.Errorf("%s: the restarted node's startup backfill moved %s's disk row back to %s (want %s)",
				n.Name, backfillVM, got.HostName, dest.Name)
		}
		if vm, _ := corrosion.GetVM(ctx, n.DB, backfillVM); vm == nil || vm.HostName != dest.Name {
			t.Errorf("%s: the restarted node's startup backfill moved %s's vms row: %+v (want it on %s)",
				n.Name, backfillVM, vm, dest.Name)
		}
	}
	if t.Failed() {
		return
	}

	// old catches up through a real anti-entropy pass; its backfill now runs
	// and finds nothing of the VM's to fill. dest's own backfill fills the
	// bus, and the row stays where it is.
	if !corrosion.NewAntiEntropy(old.DB, old.PKIDir, 0).RunOnce(ctx) {
		t.Fatal("anti-entropy pass on the restarted node did not run")
	}
	if ok, why := old.DB.ReplicaCaughtUp(); !ok {
		t.Fatalf("a completed anti-entropy pass must mark the replica caught up (%s)", why)
	}
	if err := old.Server.BackfillHardwareTables(ctx); err != nil {
		t.Fatalf("backfill on the caught-up node: %v", err)
	}
	if err := dest.Server.BackfillHardwareTables(ctx); err != nil {
		t.Fatalf("backfill on the new owner: %v", err)
	}
	spreadFrom(t, c, old)
	spreadFrom(t, c, dest)
	for _, n := range c.Nodes {
		got := diskRow(t, n)
		if got.HostName != dest.Name {
			t.Errorf("%s: %s's disk row names %s after both backfills, want %s", n.Name, backfillVM, got.HostName, dest.Name)
		}
		if got.Bus != "virtio" {
			t.Errorf("%s: the owner's backfill must fill the bus: have %q, want virtio", n.Name, got.Bus)
		}
	}
}
