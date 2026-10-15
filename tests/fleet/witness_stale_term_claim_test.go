// A recovery-claim value accepted in an earlier outage, at a lease term that
// has since been superseded, and adopted by the next proposer (witness drill
// design 2026-10-15, scenario 4a / question Q5).
//
// The claim key does not change between outages of the same host when
// nothing moved, so a value one voter accepted in the first outage (no
// majority, nothing decided) is the value the next proposer must adopt
// (recovery-claims.md §3.13 step 4). It carries the lease term of the
// coordinator that proposed it. Once the lease has moved on, a destination
// that enforces lease_term_v1 refuses that proof as stale, and the claim must
// not stand on it for good: the workload would stay pending on the
// destination, recovered nowhere.
package fleet

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// leaseTermClaimsGate is claimsGate with lease_term_v1 (and its ledger token)
// latched too, and the other voters as the healthy peers the lease-term
// barrier sweeps.
type leaseTermClaimsGate struct {
	claimsGate
	peers []string
}

func leaseTermLatched(tok string) bool {
	return claimsLatched(tok) || tok == capabilities.LeaseTermV1 || tok == capabilities.LeaseTermLedgerV1
}

func (leaseTermClaimsGate) CapabilityActive(_ context.Context, tok string) (bool, string) {
	return leaseTermLatched(tok), ""
}
func (leaseTermClaimsGate) CapabilityActiveForHealth(_ context.Context, tok string) (bool, string) {
	return leaseTermLatched(tok), ""
}
func (leaseTermClaimsGate) Enforced(_ context.Context, tok string) bool { return leaseTermLatched(tok) }
func (leaseTermClaimsGate) Latched(tok string) bool                     { return leaseTermLatched(tok) }
func (leaseTermClaimsGate) DurablyLatched(tok string) bool              { return leaseTermLatched(tok) }
func (g leaseTermClaimsGate) HealthyPeers(context.Context) []string     { return g.peers }

// TestFleet_RecoveryClaim_AStaleTermValueAdoptedAfterALeaseChangeIsSuperseded:
// probeFleet's d is unreachable to every voter. In an earlier outage cc, the
// lease holder at term 1, proposed moving vm-q5 to cc, and only voter a
// accepted. The lease has since moved: b leads at a newer term. b's claim
// learns cc's value from a and adopts it, so the decided proof carries term 1,
// which cc's executor refuses as stale. The workload must still be recovered,
// on exactly one host.
//
// Mutation: adoptedTermSuperseded never reports (the code before the fix) —
// b writes q5-term1, cc refuses it on every tick ("pending proof refused by
// the lease-term gate ... stale_lease_term") and vm-q5 stays pending on cc.
func TestFleet_RecoveryClaim_AStaleTermValueAdoptedAfterALeaseChangeIsSuperseded(t *testing.T) {
	ctx := context.Background()
	c, a, b, cc, d := probeFleet(t, 2515, "vm-q5")
	voters := []*Node{a, b, cc}
	for _, v := range voters {
		c.SetLinkFault(v, d, LinkFault{BlockProbe: true})
	}
	for _, n := range voters {
		var peers []string
		for _, p := range voters {
			if p != n {
				peers = append(peers, p.Name)
			}
		}
		n.Server.SetGate(leaseTermClaimsGate{peers: peers})
		n.Server.SetLeaseTermEnforce(true)
		// Term 1 was cc's, everywhere.
		seedTermOn(t, n, 1, cc.Name)
	}

	// The earlier outage's partial accept: cc's value at term 1, on a alone.
	key := vmKey(a, "vm-q5", 0)
	resp, err := c.PeerClient(cc, a).AcceptRecoveryClaim(ctx, &pb.AcceptRecoveryClaimRequest{
		Key:              claimKeyPB(key),
		Ballot:           &pb.ClaimBallot{Round: 1, Coordinator: cc.Name, BootNonce: []byte{1}},
		ConfigGeneration: 2,
		Value: &pb.RecoveryClaimValue{Id: "q5-term1", Action: corrosion.ActionReschedule, TargetKind: key.TargetKind,
			TargetName: key.TargetName, DestHost: cc.Name, Coordinator: cc.Name,
			OwnerEpoch: "0", SourceHost: d.Name, LeaseTerm: 1, LeaseKey: corrosion.LeaseKeyFailover},
	})
	if err != nil || !resp.GetAccepted() {
		t.Fatalf("setup: a did not accept cc's term-1 value: %+v %v", resp, err)
	}

	// b takes the lease at a newer term and recovers d.
	clock := NewVirtualClock(time.Now().UTC())
	cs := probeCoordinator(c, clock, b)
	// enforcement.lease_term on, as on the executors.
	cs.ByNode[b.Name].LeaseTermEnforce = true
	recs := map[string]interface{ ReconcileOnce(context.Context) }{}
	for _, n := range voters {
		rec := claimReconciler(t, n)
		rec.SetLeaseTermGate(n.Server.LeaseTermGateForPendingProof)
		recs[n.Name] = rec
	}
	running := func() []string {
		var out []string
		for _, n := range c.Nodes {
			if st, ok := n.Virt.RawState("vm-q5"); ok && st == libvirtfake.StateRunning {
				out = append(out, n.Name)
			}
		}
		return out
	}
	var adopted bool
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		cs.Tick(ctx, b)
		// Replication carries the proof and the lease term to the others.
		time.Sleep(time.Second)
		for _, n := range voters {
			recs[n.Name].ReconcileOnce(ctx)
		}
		if got := running(); len(got) > 1 {
			t.Fatalf("vm-q5 runs on %v at once", got)
		} else if len(got) == 1 {
			break
		}
		if vm := vmOn(t, b, "vm-q5"); vm != nil && vm.PendingActionID == "q5-term1" {
			adopted = true
		}
		time.Sleep(200 * time.Millisecond)
	}
	got := running()
	if len(got) != 1 {
		vm := vmOn(t, b, "vm-q5")
		t.Fatalf("vm-q5 was not recovered (runs on %v; row %+v; b adopted cc's term-1 value: %v): "+
			"a decided value at a superseded lease term stands and its destination refuses it", got, vm, adopted)
	}
	// Fixed, b moves past cc's value within one claim (its destination
	// abandons it), so the row never names it; unfixed, it does, for good.
	t.Logf("b wrote cc's term-1 value as the pending proof at some point: %v", adopted)
	if pr, ok, err := corrosion.GetActionProof(ctx, cc.DB, "q5-term1"); err == nil && ok && pr.Status == corrosion.ProofCompleted {
		t.Fatalf("cc executed the stale term-1 proof: %+v", pr)
	}
	pr, ok, err := corrosion.GetActionProof(ctx, b.DB, vmOn(t, b, "vm-q5").PendingActionID)
	if err == nil && ok {
		t.Logf("recovered on %s by proof %s at lease term %d (coordinator %s)", got[0], pr.ID, pr.LeaseTerm, pr.Coordinator)
	}
}
