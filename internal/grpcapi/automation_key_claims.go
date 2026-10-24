package grpcapi

import (
	"context"
	"fmt"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

func automationKeyValue(v corrosion.ClaimValue) bool {
	if v.Automation == nil {
		return false
	}
	d, err := contract.DecodeDecision(v.Automation.Envelope)
	if err != nil {
		return false
	}
	a, err := contract.DecodeAssignment(d)
	return err == nil && a.Version == contract.CustodyAssignmentVersion && (d.Command.Kind == contract.CustodyImportCommand || d.Command.Kind == "activate_key_epoch")
}

// Only read stored evidence. Never recursively call Accept: an empty evidence
// cycle terminates without manufacturing its own first signed vote.
func (s *Server) acceptKeyFromStoredPeer(ctx context.Context, key corrosion.ClaimKey, ballot corrosion.Ballot, value corrosion.ClaimValue, generation int64, signer *corrosion.ClaimSigner) (corrosion.AcceptResult, error) {
	refused := corrosion.AcceptResult{Voter: s.hostName, Refusal: corrosion.RefusalAutomationUnavailable}
	cfg, err := s.db.AutomationMembership(ctx)
	if err != nil {
		return refused, err
	}
	if cfg.Generation != generation {
		return refused, nil
	}
	for _, member := range cfg.Members {
		if member.Name == s.hostName {
			continue
		}
		target, err := corrosion.ResolvePeerTarget(ctx, s.db, member.Name)
		if err != nil {
			continue
		}
		call, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		peer, err := pki.DialExpectedHostPeer(call, s.pkiDir, member.Name, target)
		if err != nil {
			cancel()
			continue
		}
		response, getErr := pb.NewLiteVirtClient(peer).GetRecoveryClaim(call, &pb.GetRecoveryClaimRequest{Key: keyToPB(key)})
		_, _, chain, observedErr := peer.Observation()
		peer.Close()
		cancel()
		if getErr != nil || observedErr != nil || len(chain) == 0 || response.GetAdoptedGeneration() != generation || response.GetState().GetVoter() != member.Name || response.GetState().GetVoterIncarnation() != member.Incarnation || response.GetAccept().GetVoter() != member.Name || response.GetAccept().GetVoterIncarnation() != member.Incarnation {
			continue
		}
		prepared, err := prepareFromPB(response.GetState(), key)
		if err != nil {
			continue
		}
		state := prepared.State
		state.ConfigGeneration = generation
		state.Accept = acceptFromPB(response.GetAccept())
		if corrosion.ValidateAutomationState(state) != nil {
			continue
		}
		result, err := s.db.ClaimAcceptKeyEvidence(ctx, key, ballot, value, generation, signer, member.Name, state)
		if err != nil {
			return refused, err
		}
		if result.Accepted || result.Refusal != corrosion.RefusalAutomationUnavailable {
			return result, nil
		}
	}
	return refused, nil
}

// PrepareKeyPhase2 establishes a real first FULL vote only after the unchanged
// proposer binds the exact selected value. Nil native can only renew evidence.
func (t serverAutomationTransport) PrepareKeyPhase2(ctx context.Context, key corrosion.ClaimKey, ballot corrosion.Ballot, value corrosion.ClaimValue, cfg *corrosion.VoterConfig, native *corrosion.AutomationKeyAdmission) (corrosion.Ballot, error) {
	if cfg == nil {
		return corrosion.Ballot{}, fmt.Errorf("key membership unavailable")
	}
	if native != nil {
		if err := t.s.claimDurable(ctx); err != nil {
			return corrosion.Ballot{}, err
		}
		signer, _, err := t.s.claimIdentity()
		if err != nil {
			return corrosion.Ballot{}, err
		}
		result, err := t.s.db.ClaimAcceptKeyNative(ctx, key, ballot, value, cfg.Generation, signer, native)
		if err != nil {
			return corrosion.Ballot{}, err
		}
		if result.Accepted && result.Accept != nil {
			t.s.observeClaimVote(ClaimVote{Voter: t.s.hostName, Phase: "accept", Key: key, Ballot: ballot, Generation: cfg.Generation, Digest: result.Accept.ValueDigest})
			return corrosion.Ballot{}, nil
		}
		if result.Refusal == corrosion.RefusalBallotStale {
			return result.PromisedBallot, fmt.Errorf("key phase two superseded")
		}
		return corrosion.Ballot{}, fmt.Errorf("native key admission unavailable")
	}
	var stale corrosion.Ballot
	for _, voter := range cfg.Names() {
		call, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
		result, err := (serverClaimTransport{t.s}).Accept(call, voter, key, ballot, value, cfg.Generation)
		cancel()
		if err == nil && result.Accepted && result.Accept != nil {
			return corrosion.Ballot{}, nil
		}
		if result.Refusal == corrosion.RefusalBallotStale && corrosion.CompareBallots(result.PromisedBallot, stale) > 0 {
			stale = result.PromisedBallot
		}
		if ctx.Err() != nil {
			return stale, ctx.Err()
		}
	}
	return stale, fmt.Errorf("selected key acceptance unavailable")
}
