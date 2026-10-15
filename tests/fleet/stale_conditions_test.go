// A dual-run condition must resolve whichever voter holds the detector lease.
//
// Observed on the kvm003-f3 lab (lab 1, int-2b9fc8ae, 2026-10-14): after
// TestDrill1b_WitnessReachesBothSides a runtime_owner_mismatch on
// e2e-d1b-1442676-22-1 stayed open for good although the VM was deleted and
// no copy ran anywhere, and with it admission to node-2. The coverage_gap
// conditions the split raised on node-1 and node-2 stayed confirmed too, while
// the evaluator reported every scan complete. The lab's witness, node-6, was
// the one node the drill neither cut off nor restarted, so it kept the
// detector lease. A witness is never an active worker, so its execution gate
// refuses with local_not_active_worker, and resolution read that as an
// invalid decision gate: every pass it led proved absence and resolved
// nothing.

package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func ownerMismatchLifecycle(t *testing.T, n *Node, vm string) string {
	t.Helper()
	h, ok, err := corrosion.GetHealthCondition(context.Background(), n.DB, "dual_run", "runtime_owner_mismatch", "vm", vm)
	if err != nil {
		t.Fatalf("GetHealthCondition: %v", err)
	}
	if !ok || h.Lifecycle == corrosion.ConditionResolved {
		return ""
	}
	return h.Lifecycle
}

// TestFleet_DualRun_WitnessLeaderResolves: four voters, node-3 a witness and
// the only node running the detector, so it holds the lease. dr-vm's DB owner
// is node-0 but it runs on node-1: an owner mismatch. The VM is then deleted
// and its domain removed, as the lab's test cleanup did. Every scan is
// complete and the witness holds the voter majority, so the condition must
// resolve.
//
// Mutation: make resolveGateValid follow ExecutionGate.OK alone again — the
// witness never resolves and the last wait times out.
func TestFleet_DualRun_WitnessLeaderResolves(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, Relays: 4, RealGossip: true})
	n0, n1, witness := c.Nodes[0], c.Nodes[1], c.Nodes[3]
	insertVMPolicy(t, n0, "dr-vm", n0.Name, "restart-any")
	c.WaitConverged(t, convergeTimeout)
	if err := corrosion.UpdateHostRole(ctx, n0.DB, witness.Name, "witness"); err != nil {
		t.Fatalf("mark %s a witness: %v", witness.Name, err)
	}
	c.WaitConverged(t, convergeTimeout)
	genesisByTick(t, c, n0)

	chks := map[string]*health.Checker{}
	for _, nd := range c.Nodes {
		chk := health.NewChecker(nd.Name, nd.PKIDir, nd.DB)
		chk.SetPeerReadiness(nd.Server.PeerReady)
		go chk.Start(ctx)
		chks[nd.Name] = chk
		nd.Server.SetGate(checkerServerGate{chk: chk})
	}
	waitQuorum(t, ctx, "every node's checker to see the voter majority", chks, names(c.Nodes), health.QuorumYes)
	if g := chks[witness.Name].ExecutionGate(ctx); g.OK || g.Reason != health.ReasonLocalNotActiveWorker {
		t.Fatalf("witness execution gate = %+v, want refused as %s", g, health.ReasonLocalNotActiveWorker)
	}

	n1.Virt.SetState("dr-vm", libvirtfake.StateRunning)
	go witness.Server.RunDualRunDetector(ctx, 2*time.Second)

	eventually(t, time.Minute, "the witness to record dr-vm's owner mismatch", func() bool {
		return ownerMismatchLifecycle(t, witness, "dr-vm") != ""
	})

	if err := corrosion.DeleteVM(ctx, n0.DB, "dr-vm"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	// The cleanup removes the domain, as the lab's did: a deleted VM's
	// mismatch resolves only on positive absence from every host it names.
	n1.Virt.VanishDomain("dr-vm")
	c.WaitConverged(t, convergeTimeout)

	eventually(t, time.Minute, "the witness-led detector to resolve the deleted VM's owner mismatch", func() bool {
		return ownerMismatchLifecycle(t, witness, "dr-vm") == ""
	})
}
