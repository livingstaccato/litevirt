package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Review I-2: an operator's promotion decided vm-op's recovery for d
// (operator@d) and d then died before it started anything. The coordinator
// cannot get d to abandon the value — d does not answer — so it stands, and
// the VM waits. That is right while d may come back and run it; `lv host rm
// --dead d` is the remedy, and it used to be dead: the coordinator's operator
// branch returned on the failed request before the "destination removed for
// good" check, so recovery stalled for good. Now d's removal moves the claim
// to attempt 1, and the VM is recovered with one owner.
//
// Mutation "return on a failed abandonment request" (the round-1 shape) — red:
// the VM is never recovered.
func TestFleet_OperatorClaim_ARemovedOperatorHostNoLongerStallsRecovery(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, FaultSeed: 3343})
	a, b, e, v, d := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3], c.Nodes[4]
	insertVM(t, a, "vm-op", v.Name)
	c.WaitConverged(t, convergeTimeout)
	genesisByTick(t, c, a)
	enableRecoveryClaims(t, c)

	// v fails; an operator's promotion on d decides vm-op's recovery for d...
	c.Kill(v)
	p := corrosion.ActionProof{ID: "op-on-d", Action: corrosion.ActionPromote, TargetKind: "vm", TargetName: "vm-op",
		DestHost: d.Name, Coordinator: corrosion.OperatorClaimPrefix + d.Name, LeaseHolder: d.Name, OwnerEpoch: "0"}
	if out, err := a.Server.DecideRecoveryClaim(ctx, vmKey(a, "vm-op", 0), corrosion.ClaimValue{Proof: &p, SourceHost: v.Name}, 1, nil); err != nil || !out.Ours {
		t.Fatalf("decide the operator's promotion on %s: ours=%v err=%v", d.Name, out.Ours, err)
	}
	// ...and d dies before it starts anything: nothing reaches it any more.
	c.Kill(d)
	for _, n := range []*Node{a, b, e, v} {
		c.SetLinkFaultBoth(d, n, LinkFault{Block: true, BlockClaims: true, BlockProbe: true, BlockAll: true})
	}
	clock := NewVirtualClock(time.Now().UTC())
	for _, n := range []*Node{a, b, e} {
		PublishHealth(t, n, v.Name, 5, clock.Now())
		PublishHealth(t, n, d.Name, 5, clock.Now())
	}
	c.WaitConverged(t, convergeTimeout, a, b, e)
	cs := c.NewCoordinators(clock)
	cs.ByNode[a.Name].Gate = quorateGate{}
	cs.Tick(ctx, a)
	clock.Advance(contentionPoll)
	cs.Tick(ctx, a)
	if vm := vmOn(t, a, "vm-op"); vm.PendingActionID != "" {
		t.Fatalf("vm-op was recovered past an operator decision whose host cannot be asked: %+v", vm)
	}

	// The remedy: d confirmed off and removed for good.
	withOperatorPKI(t, a)
	lv := c.SelfClient(a)
	if err := corrosion.InsertFenceLog(ctx, a.DB, corrosion.FenceLogRecord{ID: "confirm-" + d.Name, HostName: d.Name,
		Method: "manual", Result: "manual-confirmed", Detail: "operator powered it off"}); err != nil {
		t.Fatal(err)
	}
	if err := cli.HostRemoveDead(ctx, lv, d.Name, false); err != nil {
		t.Fatalf("lv host rm --dead %s: %v", d.Name, err)
	}
	adoptAll(t, c, 2, a, b, e)
	c.WaitConverged(t, convergeTimeout, a, b, e)
	syncCRL(t, a, b, e)
	clock.Advance(contentionPoll)
	cs.Tick(ctx, a)

	pr, cert := pendingCert(t, a, "vm-op")
	if cert.Key.Attempt != 1 || pr.DestHost == d.Name {
		t.Fatalf("vm-op was not recovered at attempt 1 on a live host after %s's removal: attempt %d dest %s",
			d.Name, cert.Key.Attempt, pr.DestHost)
	}
	dest := c.Node(pr.DestHost)
	c.WaitConverged(t, convergeTimeout, a, b, e)
	claimReconciler(t, dest).ReconcileOnce(ctx)
	owners := 0
	for _, n := range []*Node{a, b, e} {
		if st, _ := n.Virt.DomainState("vm-op"); st == string(libvirtfake.StateRunning) {
			owners++
		}
	}
	if owners != 1 {
		t.Fatalf("%d owners after the recovery, want 1", owners)
	}
}
