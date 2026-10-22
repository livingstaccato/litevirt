package grpcapi

import (
	"context"
	"fmt"
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
	"time"
)

func automationContinuityValue(v corrosion.ClaimValue) bool {
	if v.Automation == nil {
		return false
	}
	d, err := contract.DecodeDecision(v.Automation.Envelope)
	return err == nil && d.Command.Kind == contract.IdentityContinuityCommand
}

func (t serverAutomationTransport) PrepareContinuityPhase2(ctx context.Context, key corrosion.ClaimKey, ballot corrosion.Ballot, value corrosion.ClaimValue, cfg *corrosion.VoterConfig, native *corrosion.AutomationIdentityContinuity) (corrosion.Ballot, error) {
	if native != nil {
		if err := t.s.claimDurable(ctx); err != nil {
			return corrosion.Ballot{}, err
		}
		signer, _, err := t.s.claimIdentity()
		if err != nil {
			return corrosion.Ballot{}, err
		}
		res, err := t.s.db.ClaimAcceptContinuityNative(ctx, key, ballot, value, cfg.Generation, signer, native)
		if err != nil {
			return corrosion.Ballot{}, err
		}
		if res.Accepted && res.Accept != nil {
			t.s.observeClaimVote(ClaimVote{Voter: t.s.hostName, Phase: "accept", Key: key, Ballot: ballot, Generation: cfg.Generation, Digest: res.Accept.ValueDigest})
			return corrosion.Ballot{}, nil
		}
		if res.Refusal == corrosion.RefusalBallotStale {
			return res.PromisedBallot, fmt.Errorf("continuity phase two superseded")
		}
		return corrosion.Ballot{}, fmt.Errorf("native continuity admission unavailable")
	}
	// Only existing own/history or actual stored-peer induction can start this
	// selected value. No native preparation follows a losing proposal.
	var stale corrosion.Ballot
	for _, voter := range cfg.Names() {
		call, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
		res, err := (serverClaimTransport{t.s}).Accept(call, voter, key, ballot, value, cfg.Generation)
		cancel()
		if err == nil && res.Accepted && res.Accept != nil {
			return corrosion.Ballot{}, nil
		}
		if res.Refusal == corrosion.RefusalBallotStale && corrosion.CompareBallots(res.PromisedBallot, stale) > 0 {
			stale = res.PromisedBallot
		}
		if ctx.Err() != nil {
			return stale, ctx.Err()
		}
	}
	return stale, fmt.Errorf("selected continuity acceptance unavailable")
}

// Reads only: fallback never calls Accept recursively. Every returned source,
// incarnation, key, ballot and byte is checked by the transaction/trust owner.
func (s *Server) acceptContinuityFromStoredPeer(ctx context.Context, key corrosion.ClaimKey, ballot corrosion.Ballot, value corrosion.ClaimValue, generation int64, signer *corrosion.ClaimSigner) (corrosion.AcceptResult, error) {
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
		call, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		client, closePeer, dialErr := s.dialPeer(call, member.Name)
		if dialErr != nil {
			cancel()
			continue
		}
		response, getErr := client.GetRecoveryClaim(call, &pb.GetRecoveryClaimRequest{Key: keyToPB(key)})
		closePeer()
		cancel()
		if getErr != nil || response.GetAdoptedGeneration() != generation || response.GetState().GetVoter() != member.Name || response.GetState().GetVoterIncarnation() != member.Incarnation || response.GetAccept().GetVoter() != member.Name || response.GetAccept().GetVoterIncarnation() != member.Incarnation {
			continue
		}
		prepared, err := prepareFromPB(response.GetState(), key)
		if err != nil {
			continue
		}
		state := prepared.State
		state.ConfigGeneration = generation
		state.Accept = acceptFromPB(response.GetAccept())
		if err := corrosion.ValidateAutomationState(state); err != nil {
			continue
		}
		res, err := s.db.ClaimAcceptContinuityEvidence(ctx, key, ballot, value, generation, signer, member.Name, state)
		if err != nil {
			return refused, err
		}
		if res.Accepted || res.Refusal != corrosion.RefusalAutomationUnavailable {
			return res, nil
		}
	}
	return refused, nil
}
