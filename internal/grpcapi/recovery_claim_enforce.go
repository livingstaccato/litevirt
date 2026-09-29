package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// recovery_claim_v1: enforcement of single-winner recovery claims
// (docs/design/recovery-claims.md §5.1–§5.2, colonelpanik/litevirt#250).
//
// voter_config_v1 is the voter side and runs whatever this file says: once a
// voter generation is adopted every member answers Prepare / Accept. This file
// is the opt-in that makes anybody RELY on the answers — coordinators claiming
// before they mint, destinations verifying before they execute.

// SetRecoveryClaimEnforce wires enforcement.recovery_claim. It is both the
// opt-in that lets recovery_claim_v1 be advertised and the reversible kill
// switch once it has latched.
func (s *Server) SetRecoveryClaimEnforce(on bool) { s.enfRecoveryClaim = on }

// RecoveryClaimReadiness evaluates whether this node may advertise
// recovery_claim_v1 (§5.1): split_brain_gate_v1 has latched — the certificate
// rides on a runtime-action proof, so there is nothing to carry it on before
// — and this node can vote durably (VoterConfigReadiness).
//
// LOCAL reads only: it is called from advertisedCapabilities inside the Ping
// handler, where anything that Pings recurses (the lease_term_v1 rule).
// Latched is the gate's in-memory read. The flag is not part of readiness —
// advertisedCapabilities checks it — so an operator can ask "would this node
// be ready" before turning it on.
func (s *Server) RecoveryClaimReadiness(ctx context.Context) (bool, string) {
	if s.gate == nil {
		return false, "no split-brain gate is wired on this node"
	}
	if !s.gate.Latched(capabilities.SplitBrainGateV1) {
		return false, capabilities.SplitBrainGateV1 + " has not latched; a claim certificate rides on a runtime-action proof"
	}
	if ok, why := s.VoterConfigReadiness(ctx); !ok {
		return false, "this node cannot vote durably: " + why
	}
	return true, ""
}

// recoveryClaimAdvertisable is the advertisement-side call, bounded because it
// runs on the Ping path.
func (s *Server) recoveryClaimAdvertisable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ok, reason := s.RecoveryClaimReadiness(ctx)
	if !ok {
		slog.Debug("recovery_claim_v1 readiness withheld", "reason", reason)
	}
	return ok
}

// ErrRecoveryClaimLost is returned by an automated promotion whose claim
// decided ANOTHER value — another coordinator's recovery of the same VM. The
// promotion is not attempted; the coordinator's fallback learns the same
// value and defers to it.
var ErrRecoveryClaimLost = errors.New("another recovery was decided for this workload")

// RecoveryClaimLostError carries the value that was decided instead.
type RecoveryClaimLostError struct {
	Decided corrosion.ActionProof
}

func (e *RecoveryClaimLostError) Error() string {
	return fmt.Sprintf("%v: %s of %s/%s to %s by %s (proof %s)", ErrRecoveryClaimLost, e.Decided.Action,
		e.Decided.TargetKind, e.Decided.TargetName, e.Decided.DestHost, e.Decided.Coordinator, e.Decided.ID)
}

func (e *RecoveryClaimLostError) Unwrap() error { return ErrRecoveryClaimLost }

// claimPromote claims an automated promotion before its proof is persisted or
// relayed, and stamps the certificate on p. The source is the VM's recorded
// owner — the fenced host. A decided value that is not this proposal refuses
// the promotion with a *RecoveryClaimLostError.
func (s *Server) claimPromote(ctx context.Context, vm *corrosion.VMRecord, p *pb.RuntimeActionProof) error {
	proposal := proofFromPB(p)
	key, err := corrosion.ClaimKeyForProof(proposal, 0)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "claim promote of %s: %v", vm.Name, err)
	}
	round := uint64(1)
	if p.GetLeaseTerm() > 0 {
		round = uint64(p.GetLeaseTerm())
	}
	value := corrosion.ClaimValue{Proof: &proposal, SourceHost: vm.HostName}
	out, err := s.DecideRecoveryClaim(ctx, key, value, round)
	if err != nil {
		s.noteGateRefused(corrosion.ActionPromote, claimRefusalReason(err))
		return status.Errorf(codes.Unavailable, "promote of %s formed no recovery-claim certificate: %v", vm.Name, err)
	}
	if !out.Ours || out.Value.Proof == nil {
		decided := corrosion.ActionProof{}
		if out.Value.Proof != nil {
			decided = *out.Value.Proof
		}
		s.noteGateRefused(corrosion.ActionPromote, health.ReasonClaimLost)
		return &RecoveryClaimLostError{Decided: decided}
	}
	cert, err := out.Certificate.Encode()
	if err != nil {
		return status.Errorf(codes.Internal, "encode certificate: %v", err)
	}
	p.ClaimCertificate = cert
	return nil
}

// claimRefusalReason names why a claim formed no certificate, for the
// gate-refusal metric (§5.4).
func claimRefusalReason(err error) string {
	var nm *claims.NoMajorityError
	if errors.As(err, &nm) {
		for _, r := range nm.Refusals {
			if r.Reason == corrosion.RefusalOwnerReachable {
				return health.ReasonClaimOwnerReachable
			}
		}
		for _, r := range nm.Refusals {
			if r.Reason == corrosion.RefusalSourceMismatch {
				return health.ReasonClaimSourceMismatch
			}
		}
	}
	return health.ReasonClaimNoMajority
}

// verifyRecoveryClaim is the executor's check (§3.10): under enforcement, an
// ownership-transfer proof executes only with a certificate that verifies
// against this node's own adopted voter set and the cluster CA. It returns the
// gate-refusal reason with the error; "" and nil when the proof may proceed.
//
// ownerMove exempts a relocate its OWNER drives (a container cold migration:
// the source host, alive, moving its own workload), which claims do not cover
// (§2 non-goals). Only the caller can tell the two apart.
func (s *Server) verifyRecoveryClaim(ctx context.Context, p corrosion.ActionProof, ownerMove bool) (string, error) {
	if !corrosion.ClaimGatedAction(p.Action) || (ownerMove && p.Action == corrosion.ActionRelocate) {
		return "", nil
	}
	if !s.RecoveryClaimEnforced(ctx) {
		return "", nil
	}
	_, verifier, err := s.claimIdentity()
	if err != nil {
		return health.ReasonClaimUnproven, status.Errorf(codes.Unavailable,
			"cannot verify the recovery-claim certificate on proof %s: %v", p.ID, err)
	}
	if _, err := corrosion.VerifyClaimCertificate(ctx, s.db, verifier, p); err != nil {
		return health.ReasonClaimUnproven, status.Errorf(codes.FailedPrecondition,
			"%s: proof %s (%s of %s/%s to %s) is not authorized by a recovery-claim certificate this node can verify: %v",
			health.ReasonClaimUnproven, p.ID, p.Action, p.TargetKind, p.TargetName, p.DestHost, err)
	}
	return "", nil
}

// RecoveryClaimGateForPendingProof is the executor-side certificate check for
// a proof read off the REPLICATED ROW rather than received over an RPC: a VM
// reschedule claimed by internal/health's reconciler, and a container
// relocate-recreate claimed by its container checker. Injected into both, for
// the LeaseTermGateForPendingProof reason — internal/health cannot import this
// package, and one implementation serves every executor. Returns the
// countable reason with the error; the caller counts it on its own observer.
func (s *Server) RecoveryClaimGateForPendingProof(ctx context.Context, pr corrosion.ProofRecord) (string, error) {
	return s.verifyRecoveryClaim(ctx, pr.ActionProof, false)
}

// RecoveryClaimEnforced is the enforcement predicate (§5.1): the flag AND the
// cluster-wide latch AND an adopted voter generation with members. Without a
// member generation there is no majority to certify anything, so enforcement
// stays off after a `lv cluster voter reset` and before genesis, and recovery
// is authorized as it was before claims. A read error on the voter set fails
// CLOSED — enforcement on — so a node that cannot tell whether a certificate
// is required does not act as though none were.
//
// Coordinators and destinations read this one predicate, so the two halves of
// the decision cannot disagree on one node.
func (s *Server) RecoveryClaimEnforced(ctx context.Context) bool {
	if !s.enfRecoveryClaim || s.gate == nil || !s.gate.Enforced(ctx, capabilities.RecoveryClaimV1) {
		return false
	}
	cfg, err := corrosion.AdoptedVoterConfig(ctx, s.db)
	if err != nil {
		slog.Warn("recovery claims: cannot read the adopted voter generation; enforcing (fail closed)", "error", err)
		return true
	}
	return cfg.Explicit()
}
