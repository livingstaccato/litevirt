package grpcapi

import (
	"context"
	"fmt"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func automationOwnerValue(v corrosion.ClaimValue) bool {
	if v.Automation == nil {
		return false
	}
	d, err := contract.DecodeDecision(v.Automation.Envelope)
	return err == nil && corrosion.IsAutomationOwnerKind(d.Command.Kind)
}

// PrepareOwnerPhase2 runs only after Paxos selected and bound these exact
// bytes. Establish one real stored vote, then leave quorum formation to the
// unchanged proposer. A selected value belonging to another call carries no
// native submission and can only use existing accepted/history provenance.
func (t serverAutomationTransport) PrepareOwnerPhase2(ctx context.Context, key corrosion.ClaimKey, ballot corrosion.Ballot, value corrosion.ClaimValue, cfg *corrosion.VoterConfig, native *corrosion.AutomationOwnerSubmission) (corrosion.Ballot, error) {
	if native != nil {
		if err := t.s.claimDurable(ctx); err != nil {
			return corrosion.Ballot{}, err
		}
		signer, _, err := t.s.claimIdentity()
		if err != nil {
			return corrosion.Ballot{}, err
		}
		res, err := t.s.db.ClaimAcceptOwnerNative(ctx, key, ballot, value, cfg.Generation, signer, native)
		if err != nil {
			return corrosion.Ballot{}, err
		}
		if res.Accepted && res.Accept != nil {
			t.s.observeClaimVote(ClaimVote{Voter: t.s.hostName, Phase: "accept", Key: key, Ballot: ballot, Generation: cfg.Generation, Digest: res.Accept.ValueDigest})
			return corrosion.Ballot{}, nil
		}
		if res.Refusal == corrosion.RefusalBallotStale {
			return res.PromisedBallot, fmt.Errorf("owner phase two superseded")
		}
		return corrosion.Ballot{}, fmt.Errorf("native owner admission unavailable")
	}
	// A surviving holder may have an obsolete leaf certificate. Its own FULL
	// Accept renews the actual stored vote first; no bearer or Get reattest flag
	// is needed. Empty/cyclic evidence supplies no successful base case.
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
	return stale, fmt.Errorf("selected owner acceptance unavailable")
}

// This is invoked after the own-row/retained-history path refused. It performs
// network reads only, then hands the exact response to the storage trust owner.
// It never calls Accept recursively, so an empty evidence cycle terminates.
func (s *Server) acceptOwnerFromStoredPeer(ctx context.Context, key corrosion.ClaimKey, ballot corrosion.Ballot, value corrosion.ClaimValue, generation int64, signer *corrosion.ClaimSigner) (corrosion.AcceptResult, error) {
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
		res, err := s.db.ClaimAcceptOwnerEvidence(ctx, key, ballot, value, generation, signer, member.Name, state)
		if err != nil {
			return refused, err
		}
		if res.Accepted || res.Refusal != corrosion.RefusalAutomationUnavailable {
			return res, nil
		}
	}
	return refused, nil
}
