package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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

// operatorClaimPrefix marks a claim value an operator's promotion decided
// (corrosion.OperatorClaimPrefix): its Coordinator is "operator@<the host that
// promoted>". It is never a host name, so no coordinator mistakes it for its
// own decision.
const operatorClaimPrefix = corrosion.OperatorClaimPrefix

// isOperatorPromoteValue reports whether p is a value an operator's promotion
// decided.
func isOperatorPromoteValue(p corrosion.ActionProof) bool { return corrosion.IsOperatorPromoteValue(p) }

// operatorClaim is the claim an operator's promotion on this host holds, or
// may hold (review I2): the key and the proof ID of the value that would
// start the VM here. Between the claim and the start fence a failure abandons
// it (releaseOperatorClaim), so the failover coordinator can move past it;
// once the fence is recorded (fenceOperatorStart) nothing abandons it.
type operatorClaim struct {
	Key     corrosion.ClaimKey
	ProofID string
}

// operatorStartPath is where this host records that it started an
// operator's claimed promotion: beside the promote markers, keyed by the
// value's proof ID. "" for an ID that is not a bare file name.
func (s *Server) operatorStartPath(id string) string {
	if id == "" || filepath.Base(id) != id || strings.HasPrefix(id, ".") {
		return ""
	}
	return filepath.Join(s.dataDir, "promote-started", id)
}

// operatorStartRecorded reports whether this host recorded the start of the
// operator promotion whose claim value is proofID. An unreadable record fails
// closed: it may be there.
func (s *Server) operatorStartRecorded(proofID string) bool {
	p := s.operatorStartPath(proofID)
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil || !os.IsNotExist(err)
}

// fenceOperatorStart is the start fence of an operator's claimed promotion,
// recorded just before StartDomain: under operatorClaimMu, which every
// abandonment on this host also takes, it refuses if this host has abandoned
// the claim's value (a coordinator moved past it), and otherwise records the
// start durably, so the value is never abandoned again. Idempotent.
func (s *Server) fenceOperatorStart(ctx context.Context, oc *operatorClaim) error {
	s.operatorClaimMu.Lock()
	defer s.operatorClaimMu.Unlock()
	if s.operatorStartRecorded(oc.ProofID) {
		return nil
	}
	abandoned, err := s.db.ProofAbandoned(ctx, oc.ProofID)
	if err != nil {
		return status.Errorf(codes.Unavailable, "promote: read the abandonment of claim value %s: %v", oc.ProofID, err)
	}
	if abandoned {
		return status.Errorf(codes.FailedPrecondition,
			"promote refused: this host abandoned the operator's claim %s at %s before the VM started (the failover "+
				"coordinator moved past it); `lv cluster claim %s/%s` shows the recovery decided since", oc.ProofID, oc.Key,
			oc.Key.TargetKind, oc.Key.TargetName)
	}
	p := s.operatorStartPath(oc.ProofID)
	if p == "" {
		return status.Errorf(codes.Internal, "promote: claim value id %q cannot be recorded", oc.ProofID)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return status.Errorf(codes.Internal, "promote: record the start of claim %s: %v", oc.ProofID, err)
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return status.Errorf(codes.Internal, "promote: record the start of claim %s: %v", oc.ProofID, err)
	}
	_, werr := f.WriteString(oc.Key.String())
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(p)
		return status.Errorf(codes.Internal, "promote: record the start of claim %s: %v %v %v", oc.ProofID, werr, serr, cerr)
	}
	if d, err := os.Open(filepath.Dir(p)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// unfenceOperatorStart withdraws the start record of a promotion whose
// StartDomain failed and whose domain is not running: it never ran, so its
// claim may be released again.
func (s *Server) unfenceOperatorStart(oc *operatorClaim) {
	s.operatorClaimMu.Lock()
	defer s.operatorClaimMu.Unlock()
	if p := s.operatorStartPath(oc.ProofID); p != "" {
		_ = os.Remove(p)
	}
}

// releaseOperatorClaim abandons the claim of an operator's promotion that
// failed before it started the VM, so the failover coordinator can move past
// it (failover.supersedeEvidence asks this host, which re-signs). A started
// one is never released.
func (s *Server) releaseOperatorClaim(ctx context.Context, oc *operatorClaim, why string) {
	if oc == nil {
		return
	}
	s.operatorClaimMu.Lock()
	defer s.operatorClaimMu.Unlock()
	if s.operatorStartRecorded(oc.ProofID) {
		return
	}
	if err := s.db.AbandonProof(ctx, oc.ProofID, oc.Key, "an operator's promotion failed before it started the VM: "+why); err != nil {
		slog.Warn("promote: could not release the operator's claim; the coordinator asks this host again",
			"claim", oc.Key.String(), "value", oc.ProofID, "error", err)
		return
	}
	slog.Info("promote: released the operator's claim of a promotion that never started", "claim", oc.Key.String(), "value", oc.ProofID)
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
func (s *Server) claimOperatorPromote(ctx context.Context, vm *corrosion.VMRecord) (*operatorClaim, error) {
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
				// A minority may have accepted the proposal, and a later
				// coordinator would learn it: it is fenced at the start like
				// a decided one, and released on a failure (review I2).
				return &operatorClaim{Key: key, ProofID: proposal.ID}, nil
			}
			s.noteGateRefused(corrosion.ActionPromote, claimRefusalReason(err))
			// A refused accept may still have left the proposal with a
			// minority, which a later coordinator learns: released at once.
			s.releaseOperatorClaim(ctx, &operatorClaim{Key: key, ProofID: proposal.ID}, "its claim was refused")
			return nil, status.Errorf(codes.FailedPrecondition,
				"promote of %s refused: its recovery claim at owner epoch %d could not be decided (%v). Failover may be "+
					"recovering it now: wait for that to finish (`lv cluster claim vm/%s` shows each voter's state, "+
					"`lv inspect %s` where the VM runs), then re-run", vm.Name, vm.OwnerEpoch, err, vm.Name, vm.Name)
		}
		if out.Ours {
			return &operatorClaim{Key: out.Certificate.Key, ProofID: proposal.ID}, nil
		}
		if out.Value.Proof == nil {
			return nil, status.Errorf(codes.FailedPrecondition, "promote of %s refused: its recovery claim at %s decided a value with no proof",
				vm.Name, key)
		}
		decided := *out.Value.Proof
		if isOperatorPromoteValue(decided) && decided.DestHost == s.hostName {
			// An operator's promotion on this host decided it and did not get
			// as far as starting the VM: this one completes that decision,
			// unless this host has since abandoned it (then it is moved past).
			if abandoned, aerr := s.db.ProofAbandoned(ctx, decided.ID); aerr == nil && !abandoned {
				return &operatorClaim{Key: out.Certificate.Key, ProofID: decided.ID}, nil
			}
		}
		next := s.operatorSupersedeEvidence(ctx, out, decided)
		if next == nil {
			s.noteGateRefused(corrosion.ActionPromote, health.ReasonClaimLost)
			wait := fmt.Sprintf("Wait for that recovery to finish (`lv inspect %s` shows where the VM runs, `lv cluster claim vm/%s` "+
				"the decision); promoting it now would start it a second time", vm.Name, vm.Name)
			if isOperatorPromoteValue(decided) {
				wait = fmt.Sprintf("It is an operator's promotion on %s, which has started the VM or cannot be asked: re-run the "+
					"promotion there, or check where the VM runs (`lv inspect %s`); once %s confirms that promotion never "+
					"started, the failover coordinator or a re-run moves past it", decided.DestHost, vm.Name, decided.DestHost)
			}
			return nil, status.Errorf(codes.FailedPrecondition,
				"promote of %s refused: the cluster has decided its recovery at owner epoch %d: %s to %s by %s (proof %s). %s",
				vm.Name, vm.OwnerEpoch, decided.Action, decided.DestHost, decided.Coordinator, decided.ID, wait)
		}
		ev = next
	}
	return nil, status.Errorf(codes.FailedPrecondition,
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
	if isOperatorPromoteValue(decided) {
		// Another host's operator promotion: that host signs an abandonment
		// only if it never started the VM (its start fence), and records it
		// so it never will (review I2).
		enc, err := s.RequestAbandonment(ctx, decided.DestHost, out.Certificate.Key, decided.ID,
			"an operator's promotion on "+s.hostName+" moves past one that never started")
		if err == nil {
			ev.Abandonment = enc
			return ev
		}
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
