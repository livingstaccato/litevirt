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

// staleTermVoters latches lease_term_v1 on voters, enforces it on each, and,
// with a holder, seeds term 1 to it in every voter's ledger.
func staleTermVoters(t *testing.T, holder *Node, voters ...*Node) {
	t.Helper()
	for _, n := range voters {
		var peers []string
		for _, p := range voters {
			if p != n {
				peers = append(peers, p.Name)
			}
		}
		n.Server.SetGate(leaseTermClaimsGate{peers: peers})
		n.Server.SetLeaseTermEnforce(true)
		if holder != nil {
			seedTermOn(t, n, 1, holder.Name)
		}
	}
}

// insertPinnedVM records name on host, running, its placement pinned to pin.
func insertPinnedVM(t *testing.T, n *Node, name, host, pin string) {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), n.DB, corrosion.VMRecord{
		Name: name, HostName: host, Spec: pinnedVMSpec(pin), State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM %s on %s: %v", name, n.Name, err)
	}
}

// termGatedReconcilers is each voter's reconciler as the daemon wires it,
// with the lease-term gate.
func termGatedReconcilers(t *testing.T, voters ...*Node) map[string]interface{ ReconcileOnce(context.Context) } {
	t.Helper()
	recs := map[string]interface{ ReconcileOnce(context.Context) }{}
	for _, n := range voters {
		rec := claimReconciler(t, n)
		rec.SetLeaseTermGate(n.Server.LeaseTermGateForPendingProof)
		recs[n.Name] = rec
	}
	return recs
}

// completedProofs lists the completed proofs n holds for target.
func completedProofs(t *testing.T, n *Node, target string) []corrosion.ProofRecord {
	t.Helper()
	ctx := context.Background()
	rows, err := n.DB.Query(ctx, `SELECT id FROM runtime_action_proofs
		WHERE target_name = ? AND status = 'completed' AND deleted_at IS NULL`, target)
	if err != nil {
		t.Fatalf("%s: read proofs: %v", n.Name, err)
	}
	var out []corrosion.ProofRecord
	for _, r := range rows {
		pr, ok, err := corrosion.GetActionProof(ctx, n.DB, r.String("id"))
		if err != nil || !ok {
			t.Fatalf("%s: read proof %s: %v %v", n.Name, r.String("id"), ok, err)
		}
		out = append(out, pr)
	}
	return out
}

// recoveredOnceBy asserts vm ran on exactly dest, by one completed proof that
// coord minted at its lease term, decided at attempt 1 of the claim, and that
// dest abandoned the stale proof it was moved past.
func recoveredOnceBy(t *testing.T, dest *Node, vm string, coord *Node, term int64, stale string) {
	t.Helper()
	ctx := context.Background()
	done := completedProofs(t, dest, vm)
	if len(done) != 1 {
		t.Fatalf("%s completed %d proofs of %s, want one", dest.Name, len(done), vm)
	}
	pr := done[0]
	if pr.ID == stale || pr.Coordinator != coord.Name || pr.LeaseTerm != term || pr.LeaseKey != corrosion.LeaseKeyFailover {
		t.Fatalf("%s ran %s on proof %s by %s at lease term %d of %q; want %s's proof at its term %d",
			dest.Name, vm, pr.ID, pr.Coordinator, pr.LeaseTerm, pr.LeaseKey, coord.Name, term)
	}
	cert, err := corrosion.DecodeClaimCertificate(pr.ClaimCertificate)
	if err != nil || cert.Key.Attempt != 1 {
		t.Fatalf("the proof %s ran on is certified at %v (%v), want attempt 1", pr.ID, cert.Key, err)
	}
	if ab, err := dest.DB.ProofAbandoned(ctx, stale); err != nil || !ab {
		t.Fatalf("%s did not record its abandonment of the stale proof %s (%v)", dest.Name, stale, err)
	}
	if spr, ok, err := corrosion.GetActionProof(ctx, dest.DB, stale); err == nil && ok && spr.Status == corrosion.ProofCompleted {
		t.Fatalf("%s executed the stale proof: %+v", dest.Name, spr)
	}
}

// TestFleet_RecoveryClaim_AStaleTermValueAdoptedAfterALeaseChangeIsSuperseded
// is the lab's W4a shape: probeFleet's d is unreachable to every voter. In an
// earlier outage cc, the lease holder at term 1, proposed moving vm-q5 to cc,
// and only voter a accepted. The lease has since moved: b leads at a newer
// term, and its own pick for vm-q5 is cc too (the VM is pinned there), so the
// adopted value names the same destination. b's claim learns cc's value from a
// and adopts it, at term 1, which cc's executor refuses as stale. cc must
// abandon it, and the VM must run on cc once, on b's own proof at b's term,
// decided at attempt 1.
//
// Mutations: adoptedTermSuperseded never reports (the code before the fix),
// or it is judged after adoptedDestProblem's same-destination return — b
// writes q5-term1, cc refuses it on every tick ("pending proof refused by the
// lease-term gate ... stale_lease_term") and vm-q5 stays pending on cc.
func TestFleet_RecoveryClaim_AStaleTermValueAdoptedAfterALeaseChangeIsSuperseded(t *testing.T) {
	ctx := context.Background()
	c, a, b, cc, d := probeFleet(t, 2515)
	insertPinnedVM(t, a, "vm-q5", d.Name, cc.Name)
	c.WaitConverged(t, convergeTimeout, a, b, cc)
	voters := []*Node{a, b, cc}
	for _, v := range voters {
		c.SetLinkFault(v, d, LinkFault{BlockProbe: true})
	}
	// Term 1 was cc's, everywhere.
	staleTermVoters(t, cc, voters...)

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
	recs := termGatedReconcilers(t, voters...)
	var adopted bool
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		cs.Tick(ctx, b)
		// Replication carries the proof and the lease term to the others.
		time.Sleep(time.Second)
		for _, n := range voters {
			recs[n.Name].ReconcileOnce(ctx)
		}
		if got := runningOn(c, "vm-q5"); len(got) > 1 {
			t.Fatalf("vm-q5 runs on %v at once", got)
		} else if len(got) == 1 {
			break
		}
		if vm := vmOn(t, b, "vm-q5"); vm != nil && vm.PendingActionID == "q5-term1" {
			adopted = true
		}
		time.Sleep(200 * time.Millisecond)
	}
	got := runningOn(c, "vm-q5")
	if len(got) != 1 || got[0] != cc.Name {
		vm := vmOn(t, b, "vm-q5")
		t.Fatalf("vm-q5 was not recovered on %s (runs on %v; row %+v; b adopted cc's term-1 value: %v): "+
			"a decided value at a superseded lease term stands and its destination refuses it", cc.Name, got, vm, adopted)
	}
	term := cs.ByNode[b.Name].LeaseTerm()
	if term <= 1 {
		t.Fatalf("setup: b holds lease term %d, want one above cc's 1", term)
	}
	recoveredOnceBy(t, cc, "vm-q5", b, term, "q5-term1")
	// b never wrote the stale value: it moved past it within the claim.
	if _, ok, err := corrosion.GetActionProof(ctx, b.DB, "q5-term1"); err != nil || ok || adopted {
		t.Fatalf("b wrote cc's term-1 value as a proof (found %v, pending on it %v, %v)", ok, adopted, err)
	}
}

// TestFleet_RecoveryClaim_APendingProofOvertakenByALeaseChangeIsReStamped: b
// leads, recovers d's vm-q6 to cc and writes the proof at its term, but cc
// has not claimed it when the lease moves to a at a newer term. cc refuses
// that proof as stale from then on. a, the new holder, must have cc abandon
// it and re-decide the move under its own term; the VM then runs on cc once,
// on a's proof, and never on two hosts.
//
// Mutation: drop sweepStaleTermProofs from the cycle — vm-q6 stays pending on
// cc, refused as stale on every tick.
func TestFleet_RecoveryClaim_APendingProofOvertakenByALeaseChangeIsReStamped(t *testing.T) {
	ctx := context.Background()
	c, a, b, cc, d := probeFleet(t, 2516)
	insertPinnedVM(t, a, "vm-q6", d.Name, cc.Name)
	c.WaitConverged(t, convergeTimeout, a, b, cc)
	voters := []*Node{a, b, cc}
	for _, v := range voters {
		c.SetLinkFault(v, d, LinkFault{BlockProbe: true})
	}
	staleTermVoters(t, nil, voters...)

	clock := NewVirtualClock(time.Now().UTC())
	cs := c.NewCoordinators(clock)
	for _, n := range []*Node{a, b} {
		cs.ByNode[n.Name].Gate = quorateGate{}
		cs.ByNode[n.Name].LeaseTermEnforce = true
	}
	recs := termGatedReconcilers(t, voters...)

	// b leads and writes the reschedule; cc's reconciler has not run.
	var written string
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) && written == "" {
		cs.Tick(ctx, b)
		if vm := vmOn(t, b, "vm-q6"); vm != nil && vm.PendingActionID != "" && vm.HostName == cc.Name {
			written = vm.PendingActionID
		}
		time.Sleep(200 * time.Millisecond)
	}
	if written == "" {
		t.Fatalf("setup: b never wrote vm-q6's reschedule (row %+v)", vmOn(t, b, "vm-q6"))
	}
	bTerm := cs.ByNode[b.Name].LeaseTerm()
	if pr, ok, err := corrosion.GetActionProof(ctx, b.DB, written); err != nil || !ok || pr.LeaseTerm != bTerm || pr.ClaimCertificate == "" {
		t.Fatalf("setup: the written proof %+v (%v %v) is not b's certified proof at its term %d", pr.ActionProof, ok, err, bTerm)
	}
	c.WaitConverged(t, convergeTimeout, a, b, cc)

	// The lease moves: b stops, its lease expires, a takes it at a newer term.
	clock.Advance(time.Minute)
	deadline = time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		cs.Tick(ctx, a)
		// Replication carries the lease term and any re-stamped proof.
		time.Sleep(time.Second)
		for _, n := range voters {
			recs[n.Name].ReconcileOnce(ctx)
		}
		if got := runningOn(c, "vm-q6"); len(got) > 1 {
			t.Fatalf("vm-q6 runs on %v at once", got)
		} else if len(got) == 1 {
			break
		}
	}
	aTerm := cs.ByNode[a.Name].LeaseTerm()
	if aTerm <= bTerm {
		t.Fatalf("setup: a holds lease term %d, not above b's %d", aTerm, bTerm)
	}
	if got := runningOn(c, "vm-q6"); len(got) != 1 || got[0] != cc.Name {
		t.Fatalf("vm-q6 was not recovered on %s (runs on %v; row %+v): a pending proof the lease outran stands "+
			"and its destination refuses it", cc.Name, got, vmOn(t, a, "vm-q6"))
	}
	recoveredOnceBy(t, cc, "vm-q6", a, aTerm, written)
}

// TestFleet_RecoveryClaim_ADestinationWithEnforcementOffWaitsForTheRepoint is
// the rolling-flip mirror of the overtaken proof: cc's enforcement.lease_term
// is off, so it would run b's term-1 proof, but a, the new holder with
// enforcement on, has cc abandon it and re-points the row. cc's reconciler
// ticks after the abandonment and before the re-point reaches it. It must
// leave the row pending for the re-point (a bounded grace), not fail it to
// error; once the re-point arrives the VM runs on cc once, on a's proof.
//
// Mutation: no grace in the reconciler's abandoned-proof arm — cc fails the
// row to error and vm-q7 is never recovered.
func TestFleet_RecoveryClaim_ADestinationWithEnforcementOffWaitsForTheRepoint(t *testing.T) {
	ctx := context.Background()
	c, a, b, cc, d := probeFleet(t, 2517)
	insertPinnedVM(t, a, "vm-q7", d.Name, cc.Name)
	c.WaitConverged(t, convergeTimeout, a, b, cc)
	voters := []*Node{a, b, cc}
	for _, v := range voters {
		c.SetLinkFault(v, d, LinkFault{BlockProbe: true})
	}
	staleTermVoters(t, nil, voters...)
	cc.Server.SetLeaseTermEnforce(false) // mid-way through a rolling flip

	clock := NewVirtualClock(time.Now().UTC())
	cs := c.NewCoordinators(clock)
	for _, n := range []*Node{a, b} {
		cs.ByNode[n.Name].Gate = quorateGate{}
		cs.ByNode[n.Name].LeaseTermEnforce = true
	}
	recs := termGatedReconcilers(t, voters...)

	var written string
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) && written == "" {
		cs.Tick(ctx, b)
		if vm := vmOn(t, b, "vm-q7"); vm != nil && vm.PendingActionID != "" && vm.HostName == cc.Name {
			written = vm.PendingActionID
		}
		time.Sleep(200 * time.Millisecond)
	}
	if written == "" {
		t.Fatalf("setup: b never wrote vm-q7's reschedule (row %+v)", vmOn(t, b, "vm-q7"))
	}
	c.WaitConverged(t, convergeTimeout, a, b, cc)

	// Nothing a writes reaches cc until the re-point is held back on purpose.
	// d relays too; its link from cc keeps the owner-probe block.
	c.SetLinkFaultBoth(a, cc, LinkFault{Block: true})
	c.SetLinkFaultBoth(b, cc, LinkFault{Block: true})
	c.SetLinkFault(d, cc, LinkFault{Block: true})
	c.SetLinkFault(cc, d, LinkFault{Block: true, BlockProbe: true})
	clock.Advance(time.Minute)
	var repointed string
	deadline = time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) && repointed == "" {
		cs.Tick(ctx, a)
		if vm := vmOn(t, a, "vm-q7"); vm != nil && vm.PendingActionID != "" && vm.PendingActionID != written {
			repointed = vm.PendingActionID
		}
		time.Sleep(200 * time.Millisecond)
	}
	if repointed == "" {
		t.Fatalf("setup: a never re-pointed vm-q7 (row %+v)", vmOn(t, a, "vm-q7"))
	}
	if ab, err := cc.DB.ProofAbandoned(ctx, written); err != nil || !ab {
		t.Fatalf("setup: cc has not abandoned %s (%v)", written, err)
	}
	// cc ticks with the row still naming the abandoned proof.
	recs[cc.Name].ReconcileOnce(ctx)
	if vm := vmOn(t, cc, "vm-q7"); vm == nil || vm.State != "pending" || vm.PendingActionID != written {
		t.Fatalf("cc did not leave the row pending for the re-point: %+v", vm)
	}
	if pr, ok, err := corrosion.GetActionProof(ctx, cc.DB, written); err != nil || !ok || pr.Status == corrosion.ProofFailed {
		t.Fatalf("cc failed the abandoned proof inside the grace: %+v (%v %v)", pr.ActionProof, ok, err)
	}

	c.SetLinkFaultBoth(a, cc, LinkFault{})
	c.SetLinkFaultBoth(b, cc, LinkFault{})
	c.SetLinkFault(d, cc, LinkFault{})
	c.SetLinkFault(cc, d, LinkFault{BlockProbe: true})
	deadline = time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		cs.Tick(ctx, a)
		time.Sleep(time.Second)
		for _, n := range voters {
			recs[n.Name].ReconcileOnce(ctx)
		}
		if got := runningOn(c, "vm-q7"); len(got) > 1 {
			t.Fatalf("vm-q7 runs on %v at once", got)
		} else if len(got) == 1 {
			break
		}
	}
	if got := runningOn(c, "vm-q7"); len(got) != 1 || got[0] != cc.Name {
		t.Fatalf("vm-q7 was not recovered on %s after the re-point (runs on %v; cc's row %+v)",
			cc.Name, got, vmOn(t, cc, "vm-q7"))
	}
	recoveredOnceBy(t, cc, "vm-q7", a, cs.ByNode[a.Name].LeaseTerm(), written)
}
