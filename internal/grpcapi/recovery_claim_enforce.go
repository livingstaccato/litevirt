package grpcapi

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
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
