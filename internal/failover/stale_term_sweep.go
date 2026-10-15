package failover

import (
	"context"
	"errors"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/randid"
)

// sweepStaleTermProofs moves every pending VM reschedule whose proof carries a
// lease stamp below this holder's onto a proof stamped with this holder's
// term (supersedeStaleTerm). A proof written at term T whose lease then moved
// to T+1 before its destination claimed it is refused there as stale on every
// tick, and the row was otherwise left pending on it for good: the host it
// left is recovered, so nothing claimed for it again.
func (c *Coordinator) sweepStaleTermProofs(ctx context.Context) {
	if c.Claimer == nil || !c.claimsEnforced(ctx) || !c.leaseTermEnforced(ctx) {
		return
	}
	rows, err := c.db.Query(ctx, `SELECT id FROM runtime_action_proofs
		WHERE deleted_at IS NULL AND status = 'prepared' AND claim_certificate != ''
		  AND action = ? AND target_kind = 'vm'`, corrosion.ActionReschedule)
	if err != nil {
		slog.Warn("failover: list pending reschedules for the lease-term sweep", "error", err)
		return
	}
	for _, r := range rows {
		pr, ok, err := corrosion.GetActionProof(ctx, c.db, r.String("id"))
		if err != nil || !ok {
			continue
		}
		c.supersedeStaleTerm(ctx, pr)
	}
}

// supersedeStaleTerm moves pr, a certified pending VM reschedule, past its
// stamp when executors refuse it as stale against this holder's own term
// (staleTermProblem), and does nothing otherwise:
//
//  1. pr's destination signs that it has not executed pr and never will
//     (RequestAbandonment). It refuses once it has claimed pr, and then pr
//     runs and nothing here changes.
//  2. The claim moves to the next attempt of pr's key on that abandonment,
//     proposing pr's move again under this holder's stamp (claimFrom), and
//     every value it adopts is judged as at a mint site.
//  3. The VM row, still pending on pr, is re-pointed at the decided proof
//     (corrosion.ReplaceVMRescheduleProof).
//
// pr can then never run, and the decided proof is the only one the row names;
// pr is then marked failed so it is reaped. A failure at any step leaves the
// row as it is, holds the source's recovery with the reason and, where there
// is one, the remedy, and the next cycle starts again from step 1, which is
// idempotent.
func (c *Coordinator) supersedeStaleTerm(ctx context.Context, pr corrosion.ProofRecord) {
	if c.Claimer == nil || pr.Status != corrosion.ProofPrepared || pr.ExecutorHost != "" ||
		pr.Action != corrosion.ActionReschedule || pr.TargetKind != "vm" || pr.ClaimCertificate == "" {
		return
	}
	if c.staleTermProblem(ctx, pr.ActionProof, c.LeaseTerm(), corrosion.LeaseKeyFailover) == "" {
		return
	}
	if !c.claimsEnforced(ctx) {
		return
	}
	vm, err := corrosion.GetVM(ctx, c.db, pr.TargetName)
	if err != nil || vm == nil || vm.PendingActionID != pr.ID || vm.State != "pending" || vm.HostName != pr.DestHost {
		return
	}
	cert, err := corrosion.DecodeClaimCertificate(pr.ClaimCertificate)
	if err != nil {
		slog.Warn("failover: a pending reschedule at a superseded lease term has a certificate that does not parse; leaving it",
			"vm", vm.Name, "proof", pr.ID, "error", err)
		return
	}
	source, dest := cert.SourceHost, pr.DestHost
	if source == "" || source == dest {
		return
	}
	holder, exp, term, leaseKey, ok := c.leaseStamp(ctx)
	if !ok {
		return
	}
	problem := c.staleTermProblem(ctx, pr.ActionProof, term, leaseKey)
	if problem == "" {
		return
	}
	if g := c.decideGate(ctx, source); !g.OK {
		slog.Warn("failover: decision gate refused re-stamping a pending reschedule", "vm", vm.Name, "reason", g.Reason)
		return
	}
	if !c.destAdvertisesGate(ctx, dest) {
		slog.Warn("failover: the destination of a pending reschedule at a superseded lease term does not advertise "+
			"the split-brain gate; leaving it", "vm", vm.Name, "dest", dest)
		return
	}

	key := cert.Key
	ab, err := c.Claimer.RequestAbandonment(ctx, dest, key, pr.ID, corrosion.AbandonReasonLeaseOutran+": "+problem)
	if err != nil {
		slog.Warn("failover: the destination did not abandon a pending reschedule at a superseded lease term; retrying next cycle",
			"vm", vm.Name, "dest", dest, "proof", pr.ID, "claim", key.String(), "error", err,
			"fix", "if "+dest+" is down, bring it back; if it is gone for good: lv host rm --dead "+dest+" (--dry-run first)")
		c.noteHold(source, "VM "+vm.Name+": its pending reschedule to "+dest+" is at a superseded lease term and "+dest+
			" has not abandoned it ("+err.Error()+"); retried next cycle")
		return
	}
	binding := pr.ActionProof
	binding.ClaimCertificate = ""
	ev := &corrosion.SupersedeEvidence{PriorCertificate: pr.ClaimCertificate,
		PriorValue: &corrosion.ClaimValue{Proof: &binding, SourceHost: source}, Abandonment: ab}

	live, needed := c.proofQuorum(ctx, source)
	proposal := corrosion.ActionProof{
		ID: randid.New(), Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: vm.Name, DestHost: dest, Coordinator: c.hostName,
		LeaseHolder: holder, LeaseExpiresAt: exp,
		QuorumLive: live, QuorumNeeded: needed, FenceEpoch: pr.FenceEpoch,
		OwnerEpoch: pr.OwnerEpoch,
		LeaseTerm:  term, LeaseKey: leaseKey,
	}
	key.Attempt++
	cl, err := c.claimFrom(ctx, key, ev, proposal, source, func(d corrosion.HostRecord) string {
		return c.vmFitsOn(ctx, *vm, source, d)
	})
	if err != nil {
		// The abandoned proof never runs, and nothing replaces it until a
		// claim decides: the row waits on it, retried every cycle.
		slog.Warn("failover: no claim decided a re-stamped reschedule in place of one at a superseded lease term; "+
			"retrying next cycle", "vm", vm.Name, "proof", pr.ID, "claim", key.String(), "error", err,
			"fix", "lv cluster claim vm/"+vm.Name+" shows each voter's state")
		c.noteHold(source, "VM "+vm.Name+": its pending reschedule at a superseded lease term was abandoned by "+dest+
			" and no claim has decided its replacement ("+err.Error()+"); retried next cycle; `lv cluster claim vm/"+
			vm.Name+"` shows each voter's state")
		return
	}
	if cl.Proof.DestHost == source {
		c.noteClaimStranded("vm", vm.Name, source, cl.Proof)
		return
	}
	if cl.Proof.Action != corrosion.ActionReschedule || cl.Proof.DestHost == "" {
		slog.Warn("failover: the claim past a reschedule at a superseded lease term decided a value this sweep cannot "+
			"write; leaving the row", "vm", vm.Name, "proof", pr.ID, "decided", cl.Proof.ID,
			"decided_action", cl.Proof.Action, "decided_dest", cl.Proof.DestHost,
			"fix", "lv cluster claim vm/"+vm.Name+" shows the decision")
		c.noteHold(source, "VM "+vm.Name+": the claim past its abandoned reschedule decided "+cl.Proof.Action+" to "+
			cl.Proof.DestHost+" by "+cl.Proof.Coordinator+", which this coordinator does not write; `lv cluster claim vm/"+
			vm.Name+"` shows it")
		return
	}
	if c.haHold(ctx, source, haSiteReschedule+"-mint") {
		return
	}
	if err := corrosion.ReplaceVMRescheduleProof(ctx, c.db, cl.Proof, vm.Name, cl.Proof.DestHost, pr.ID); err != nil {
		if errors.Is(err, corrosion.ErrNoRowsAffected) {
			slog.Info("failover: a pending reschedule moved on before its re-stamped proof was written", "vm", vm.Name,
				"proof", pr.ID)
			return
		}
		slog.Warn("failover: write the re-stamped reschedule; retrying next cycle", "vm", vm.Name, "proof", cl.Proof.ID,
			"error", err)
		return
	}
	// The abandoned proof can never run on its only executor: fail it, so it
	// is reaped like any spent proof rather than read by every later pass.
	if err := corrosion.FailActionProof(ctx, c.db, pr.ID, "", "superseded",
		"abandoned by "+dest+" at a superseded lease term; replaced by "+cl.Proof.ID); err != nil {
		slog.Warn("failover: mark the abandoned reschedule proof failed", "proof", pr.ID, "error", err)
	}
	slog.Warn("failover: a pending reschedule at a superseded lease term was abandoned by its destination and decided "+
		"again under this holder's term", "vm", vm.Name, "abandoned_proof", pr.ID, "proof", cl.Proof.ID,
		"dest", cl.Proof.DestHost, "claim", cl.Key.String(), "term", cl.Proof.LeaseTerm)
	c.audit(ctx, "failover", vm.Name, "re-stamped the pending reschedule to "+cl.Proof.DestHost+": proof "+pr.ID+
		" was at a superseded lease term", "ok")
}
