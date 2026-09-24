// A rejoined host must not publish a stop from a replica it has not caught up.
//
// Observed live 2026-09-24, twice: node-4 was fenced, its VM rescheduled to
// node-1 and running there. node-4 booted back; for ~75s its replica still
// said "ha1 is mine, running", and its reconciler — seeing the leftover
// shut-off domain — wrote state=stopped four times, 15s apart. The write
// replicated: the owner's row read stopped while the VM ran there, and the
// owner's vmcheck flipped it back each time. The owner-epoch guard exists for
// exactly this, but only with enforcement.owner_epoch on and latched; a
// default-config cluster took the plain name-keyed write.
//
// These scenarios run the real spine (separate per-node DBs, real gRPC + mTLS,
// real applyStatementLWW, and a REAL anti-entropy pass for the catch-up), with
// owner-epoch enforcement OFF — the default configuration the bug lives in.
package fleet

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// TestFleet_StaleReplica_RejoinedNodeDoesNotStompTheOwner pins the property
// and its release: the stop sync waits for this node's first successful
// anti-entropy reconciliation with a peer, and then proceeds for what the node
// genuinely owns.
func TestFleet_StaleReplica_RejoinedNodeDoesNotStompTheOwner(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	owner, bystander, stale := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()

	// (1) `stale` owns two running VMs; the whole cluster knows.
	//   ha1 — will be rescheduled away while `stale` is down.
	//   ha2 — genuinely stays `stale`'s, and genuinely stopped (the control:
	//         the gate must open for it once the replica has caught up).
	for _, name := range []string{"ha1", "ha2"} {
		if err := corrosion.InsertVM(ctx, stale.DB, corrosion.VMRecord{
			Name: name, HostName: stale.Name, State: "running",
			Spec: `{"on_host_failure":"restart-any"}`,
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", name, err)
		}
	}
	pumpMutations(t, c, stale, owner)
	pumpMutations(t, c, stale, bystander)

	// (2) While `stale` is down, ha1 is rescheduled to `owner` (the production
	// transfer primitive). The bystander learns; `stale` does not.
	if err := corrosion.TransferVMOwnerFresh(ctx, owner.DB, "ha1", owner.Name, "running"); err != nil {
		t.Fatalf("reschedule: %v", err)
	}
	pumpMutations(t, c, owner, bystander)

	// (3) `stale` boots back. Both leftover domains are defined and shut off
	// (the fence powered the host off). Its reconciler is wired exactly as the
	// daemon wires it; no split-brain gate, so owner_epoch is NOT enforced.
	for _, name := range []string{"ha1", "ha2"} {
		if err := stale.Virt.DefineDomain(`<domain><name>` + name + `</name></domain>`); err != nil {
			t.Fatal(err)
		}
		stale.Virt.SetState(name, libvirtfake.StateShutdown)
		stale.Virt.SetStateReason(name, "destroyed")
	}
	r := health.NewReconciler(stale.Name, t.TempDir(), stale.DB, stale.Virt)
	r.SetReplicaFreshness(stale.DB.ReplicaCaughtUp)

	// Several ticks, as observed live (four writes, 15s apart).
	for i := 0; i < 4; i++ {
		r.ReconcileOnce(ctx)
	}

	// Nothing was published from the uncaught-up replica: not locally…
	for _, name := range []string{"ha1", "ha2"} {
		if vm, _ := corrosion.GetVM(ctx, stale.DB, name); vm == nil || vm.State != "running" {
			t.Errorf("stale node published a state change for %s before its replica caught up: %+v", name, vm)
		}
	}
	// …and therefore nothing reaches the owner or the bystander.
	pumpMutations(t, c, stale, owner)
	pumpMutations(t, c, stale, bystander)
	for _, n := range []*Node{owner, bystander} {
		vm, _ := corrosion.GetVM(ctx, n.DB, "ha1")
		if vm == nil || vm.State != "running" || vm.HostName != owner.Name {
			t.Errorf("%s: the rejoined node's stale stop sync stomped the owner's running ha1: %+v", n.Name, vm)
		}
	}

	// (4) A real anti-entropy pass catches `stale` up from its peers.
	if !corrosion.NewAntiEntropy(stale.DB, stale.PKIDir, 0).RunOnce(ctx) {
		t.Fatal("anti-entropy pass did not run")
	}
	if ok, why := stale.DB.ReplicaCaughtUp(); !ok {
		t.Fatalf("a successful anti-entropy pass must mark the replica caught up (%s)", why)
	}
	if vm, _ := corrosion.GetVM(ctx, stale.DB, "ha1"); vm == nil || vm.HostName != owner.Name {
		t.Fatalf("anti-entropy did not deliver the reschedule to the stale node: %+v", vm)
	}

	// (5) The gate opens: ha2, which `stale` genuinely owns, is synced to its
	// real (stopped) state and replicates; ha1 is no longer this node's to sync.
	r.ReconcileOnce(ctx)
	pumpMutations(t, c, stale, owner)
	if vm, _ := corrosion.GetVM(ctx, owner.DB, "ha2"); vm == nil || vm.State == "running" {
		t.Errorf("once caught up, the genuine owner's out-of-band stop must sync and replicate: %+v", vm)
	}
	if vm, _ := corrosion.GetVM(ctx, owner.DB, "ha1"); vm == nil || vm.State != "running" || vm.HostName != owner.Name {
		t.Errorf("ha1 on its owner must be untouched after the catch-up: %+v", vm)
	}
}
