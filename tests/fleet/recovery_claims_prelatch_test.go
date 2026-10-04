package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// TestFleet_RecoveryClaim_AProofMintedBeforeEnforcementIsCertifiedNotStranded:
// a reschedule minted without a certificate just before recovery claims are
// enforced — the latch forming, genesis, or `lv cluster voter init` after a
// reset — is refused by its destination (recovery_claim_unproven) from then
// on. The lease holder reports it waiting (ha.claim.uncertified) and claims it
// for its own value, with the old owner its fence binding names as the source
// every voter probes; the certificate is attached to the same proof and the VM
// then runs, exactly once. Nothing is grandfathered: until the claim decides,
// the proof does not run.
//
// Mutation: drop the certifyUncertified call in the coordinator's run — the
// proof stays uncertified and the VM never starts.
func TestFleet_RecoveryClaim_AProofMintedBeforeEnforcementIsCertifiedNotStranded(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, victim := claimFleet(t, clock, 2601, "vm-pre")
	// The tick that mints the proof runs with recovery claims not enforced.
	// Its fence is an IPMI power-off: proof-grade, so the reschedule binds it
	// (fence_epoch), which names the source a later claim probes.
	cs := c.NewCoordinators(clock)
	coord := cs.ByNode[a.Name]
	coord.Gate = quorateGate{}
	coord.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "ipmi", Success: true}
	})
	enforced := coord.RecoveryClaimEnforced
	coord.RecoveryClaimEnforced = func(context.Context) bool { return false }
	cs.Tick(ctx, a)
	vm := vmOn(t, a, "vm-pre")
	if vm.PendingActionID == "" {
		t.Fatalf("the pre-enforcement tick minted no reschedule: %+v", vm)
	}
	pr, ok, err := corrosion.GetActionProof(ctx, a.DB, vm.PendingActionID)
	if err != nil || !ok || pr.ClaimCertificate != "" || pr.FenceEpoch == "" {
		t.Fatalf("want an uncertified proof binding the fence, got %+v ok=%v err=%v", pr, ok, err)
	}
	dest := c.Node(pr.DestHost)
	c.WaitConverged(t, convergeTimeout, a, b)

	// Enforcement is on everywhere now: the destination refuses the proof.
	claimReconciler(t, dest).ReconcileOnce(ctx)
	if st, _ := dest.Virt.DomainState("vm-pre"); st == string(libvirtfake.StateRunning) {
		t.Fatal("an uncertified proof ran under enforcement")
	}
	a.Server.RecoveryClaimHealthTick(ctx)
	cond, found, err := corrosion.GetHealthCondition(ctx, a.DB, "recovery_claim", "ha.claim.uncertified", "cluster", "claims")
	if err != nil || !found || cond.Lifecycle == corrosion.ConditionResolved ||
		!strings.Contains(cond.Evidence, "vm/vm-pre") || !strings.Contains(cond.Evidence, victim.Name) {
		t.Fatalf("the waiting proof is not reported naming the workload and its old owner: %+v found=%v err=%v", cond, found, err)
	}

	// The next tick, enforcing, claims it for its own value.
	coord.RecoveryClaimEnforced = enforced
	cs.Tick(ctx, a)
	got, _, _ := corrosion.GetActionProof(ctx, a.DB, pr.ID)
	cert, err := corrosion.DecodeClaimCertificate(got.ClaimCertificate)
	if err != nil || cert.SourceHost != victim.Name || cert.Key.Attempt != 0 {
		t.Fatalf("the proof was not certified for its own value with source %s: %+v %v", victim.Name, cert, err)
	}
	c.WaitConverged(t, convergeTimeout, a, b)
	for _, n := range []*Node{a, b} {
		claimReconciler(t, n).ReconcileOnce(ctx)
	}
	var running []string
	for _, n := range []*Node{a, b} {
		if st, _ := n.Virt.DomainState("vm-pre"); st == string(libvirtfake.StateRunning) {
			running = append(running, n.Name)
		}
	}
	if len(running) != 1 || running[0] != dest.Name {
		t.Fatalf("vm-pre runs on %v, want exactly once on %s", running, dest.Name)
	}
	a.Server.RecoveryClaimHealthTick(ctx)
	if cond, found, _ := corrosion.GetHealthCondition(ctx, a.DB, "recovery_claim", "ha.claim.uncertified", "cluster", "claims"); found &&
		cond.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("ha.claim.uncertified stays raised after the proof was certified: %s", cond.Evidence)
	}
}
