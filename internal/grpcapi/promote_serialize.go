package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/randid"
)

// An operator's promotion and failover's recovery of the same VM (review
// PB-F1). Neither used to know of the other: the operator's promotion is
// proofless and never claimed, so with the two resolving different replica
// hosts, or with --force, both could start the VM within seconds — and with a
// shared data disk, both attach it.
//
// With recovery claims enforced the operator's same-name takeover of a VM
// recorded on another host claims too, at the VM's current owner epoch, just
// before it defines and starts the domain (claimOperatorPromote). The claim
// is one Paxos decision with the coordinator's: whichever is decided first
// holds the key, the other learns it and stands down — the coordinator's
// reschedule site defers to a decided promote, and an automated promotion
// refuses a value not its own. Without claims (the flag off, or the token not
// latched, which every node advertising it is what a rolling upgrade waits
// for) the operator's promotion refuses while this replica holds a
// recovery proof of the VM in flight at its current epoch
// (refuseWhileRecoveryInFlight): best effort, as a replica can lag.

// operatorClaimPrefix marks a claim value an operator's promotion decided:
// its Coordinator is "operator@<the host that promoted>". It is never a host
// name, so no coordinator mistakes it for its own decision — the one it would
// ask the destination to abandon on a fallback (failover.supersedeEvidence).
const operatorClaimPrefix = "operator@"

// isOperatorPromoteValue reports whether p is a value an operator's promotion
// decided.
func isOperatorPromoteValue(p corrosion.ActionProof) bool {
	return p.Action == corrosion.ActionPromote && strings.HasPrefix(p.Coordinator, operatorClaimPrefix)
}

// maxOperatorClaimAttempts bounds how many superseded attempts an operator's
// claim walks past (each needs evidence that its decided value never runs).
const maxOperatorClaimAttempts = 4

// promoteInFlightFreshness is how long a recovery proof that never recorded a
// start keeps an operator's promotion waiting without claims: one left in
// progress by an attempt that failed (a promote that fell back to a
// reschedule) stops counting this long after it was last written. A proof
// that recorded a start counts until it is completed or failed, or the VM's
// owner epoch moves on.
var promoteInFlightFreshness = time.Hour

// refuseWhileRecoveryInFlight refuses an operator's promotion of vm while this
// replica holds a reschedule or promote proof of it, at its current owner
// epoch, that is prepared or in progress and either recorded a start or was
// written within promoteInFlightFreshness: failover is moving the VM, and a
// second start elsewhere is a second writer. A read error refuses too.
func (s *Server) refuseWhileRecoveryInFlight(ctx context.Context, vm *corrosion.VMRecord) error {
	rows, err := s.db.Query(ctx, `SELECT id, action, dest_host, coordinator, status, step_state, updated_at
		FROM runtime_action_proofs
		WHERE target_kind = 'vm' AND target_name = ? AND owner_epoch = ? AND deleted_at IS NULL
		  AND action IN ('promote', 'reschedule') AND status IN ('prepared', 'in_progress')`,
		vm.Name, strconv.FormatInt(vm.OwnerEpoch, 10))
	if err != nil {
		return status.Errorf(codes.Unavailable, "promote of %s: read its recovery proofs: %v", vm.Name, err)
	}
	for _, r := range rows {
		steps := r.String("step_state")
		started := corrosion.ProofStepDone(steps, "start_attempted") || corrosion.ProofStepDone(steps, "started")
		at, ok := corrosion.ParseUpdatedAt(r.String("updated_at"))
		if !started && ok && time.Since(at) > promoteInFlightFreshness {
			continue
		}
		dest, id := r.String("dest_host"), r.String("id")
		wait := fmt.Sprintf("Wait for it to finish or fail (`lv inspect %s` shows where the VM runs) before promoting it by hand",
			vm.Name)
		if started {
			wait = fmt.Sprintf("It recorded a start on %s, so the VM may be running there: if it is, "+
				"`lv doctor repair-owner %s %s` records it; otherwise wait for it to finish or fail", dest, vm.Name, dest)
		}
		s.noteGateRefused(corrosion.ActionPromote, health.ReasonProofConflict)
		return status.Errorf(codes.FailedPrecondition,
			"promote of %s refused: failover's %s of it to %s (proof %s, by %s, %s) is in flight at owner epoch %d, and a "+
				"promotion now could start the VM a second time. %s",
			vm.Name, r.String("action"), dest, id, r.String("coordinator"), r.String("status"), vm.OwnerEpoch, wait)
	}
	return nil
}

// claimOperatorPromote claims the recovery of vm, recorded on another host,
// for an operator's takeover promotion on this host. nil means this promotion
// may start the VM: the claim decided its value, or an earlier operator's
// promotion here decided it, or a majority of the voters still reach the VM's
// owner (then no recovery can be certified either, and the promotion goes
// ahead as an override of a live owner always did). Otherwise it refuses and
// names what to wait for: a recovery decided at this owner epoch, or one in
// flight (a coordinator holds the voters at a higher ballot; this claim never
// outranks it).
func (s *Server) claimOperatorPromote(ctx context.Context, vm *corrosion.VMRecord) error {
	key := s.ClaimKeyFor(ctx, "vm", vm.Name, vm.OwnerEpoch, vm.CreatedAt)
	proposal := corrosion.ActionProof{
		ID: randid.New(), Action: corrosion.ActionPromote, TargetKind: "vm", TargetName: vm.Name,
		DestHost: s.hostName, Coordinator: operatorClaimPrefix + s.hostName, LeaseHolder: s.hostName,
		OwnerEpoch: strconv.FormatInt(vm.OwnerEpoch, 10),
	}
	var ev *corrosion.SupersedeEvidence
	for attempt := int64(0); attempt < maxOperatorClaimAttempts; attempt++ {
		key.Attempt = attempt
		out, err := s.decideRecoveryClaim(ctx, key, corrosion.ClaimValue{Proof: &proposal, SourceHost: vm.HostName}, 1, ev, 1, false)
		if err != nil {
			if ownerReachedByMajority(err) {
				slog.Warn("promote: a majority of voters still reach the VM's owner; no recovery can be certified, "+
					"so the operator's promotion goes ahead unclaimed", "vm", vm.Name, "owner", vm.HostName, "detail", err)
				return nil
			}
			s.noteGateRefused(corrosion.ActionPromote, claimRefusalReason(err))
			return status.Errorf(codes.FailedPrecondition,
				"promote of %s refused: its recovery claim at owner epoch %d could not be decided (%v). Failover may be "+
					"recovering it now: wait for that to finish (`lv cluster claim vm/%s` shows each voter's state, "+
					"`lv inspect %s` where the VM runs), then re-run", vm.Name, vm.OwnerEpoch, err, vm.Name, vm.Name)
		}
		if out.Ours {
			return nil
		}
		if out.Value.Proof == nil {
			return status.Errorf(codes.FailedPrecondition, "promote of %s refused: its recovery claim at %s decided a value with no proof",
				vm.Name, key)
		}
		decided := *out.Value.Proof
		if isOperatorPromoteValue(decided) && decided.DestHost == s.hostName {
			// An operator's promotion on this host decided it and did not get
			// as far as starting the VM: this one completes that decision.
			return nil
		}
		next := s.operatorSupersedeEvidence(ctx, out, decided)
		if next == nil {
			s.noteGateRefused(corrosion.ActionPromote, health.ReasonClaimLost)
			return status.Errorf(codes.FailedPrecondition,
				"promote of %s refused: the cluster has decided its recovery at owner epoch %d: %s to %s by %s (proof %s). "+
					"Wait for that recovery to finish (`lv inspect %s` shows where the VM runs, `lv cluster claim vm/%s` "+
					"the decision); promoting it now would start it a second time",
				vm.Name, vm.OwnerEpoch, decided.Action, decided.DestHost, decided.Coordinator, decided.ID, vm.Name, vm.Name)
		}
		ev = next
	}
	return status.Errorf(codes.FailedPrecondition,
		"promote of %s refused: %d attempts of its recovery claim at owner epoch %d were each superseded; `lv cluster claim vm/%s` "+
			"shows them", vm.Name, maxOperatorClaimAttempts, vm.OwnerEpoch, vm.Name)
}

// operatorSupersedeEvidence is the evidence that the value out decided will
// never run, so the operator's claim may move to the next attempt
// (docs/design/recovery-claims.md §3.12), or nil when there is none and the
// decided value stands: a promote this host has already abandoned (its own
// signed abandonment, which it re-signs; this never abandons anything new, so
// a recovery in flight here is never preempted), or a destination removed for
// good (the voters check the fence, the removal and the revocation).
func (s *Server) operatorSupersedeEvidence(ctx context.Context, out claims.Outcome, decided corrosion.ActionProof) *corrosion.SupersedeEvidence {
	cert, err := out.Certificate.Encode()
	if err != nil {
		return nil
	}
	value := out.Value
	ev := &corrosion.SupersedeEvidence{PriorCertificate: cert, PriorValue: &value}
	if decided.DestHost == s.hostName {
		if abandoned, err := s.db.ProofAbandoned(ctx, decided.ID); err != nil || !abandoned {
			return nil
		}
		ab, err := s.abandonRecoveryProof(ctx, out.Certificate.Key, decided.ID, "abandoned before an operator's promotion", false, false)
		if err != nil {
			return nil
		}
		enc, err := ab.Encode()
		if err != nil {
			return nil
		}
		ev.Abandonment = enc
		return ev
	}
	if h, err := corrosion.GetHost(ctx, s.db, decided.DestHost); err == nil && h == nil && decided.DestHost != "" {
		return ev
	}
	return nil
}

// ownerReachedByMajority reports whether a claim failed because a majority
// of the voters still reach the VM's owner (§3.5.1).
func ownerReachedByMajority(err error) bool {
	var nm *claims.NoMajorityError
	if !errors.As(err, &nm) || nm.Phase != "accept" {
		return false
	}
	n := 0
	for _, r := range nm.Refusals {
		if r.Reason == corrosion.RefusalOwnerReachable {
			n++
		}
	}
	return n >= nm.Need
}
