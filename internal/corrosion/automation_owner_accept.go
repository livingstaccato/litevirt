package corrosion

import (
	"bytes"
	"context"
	"crypto/x509"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/pki"
)

// ownerAcceptPreparation never crosses the wire. Incoming evidence is copied,
// verified under an owned current trust view, then consumed before lease release.
type ownerAcceptPreparation struct {
	native      *AutomationOwnerSubmission
	key         ClaimKey
	digest      string
	generation  int64
	membersHash string
	certificate ClaimCertificate
	verifier    *ClaimVerifier
	factory     *func() *ClaimVerifier
}

func (c *Client) ClaimAcceptOwnerNative(ctx context.Context, key ClaimKey, ballot Ballot, value ClaimValue, generation int64, signer *ClaimSigner, native *AutomationOwnerSubmission) (AcceptResult, error) {
	if native == nil || native.session == nil || native.session.db != c {
		return AcceptResult{Voter: c.hostName, Refusal: RefusalAutomationUnavailable}, nil
	}
	return c.claimAccept(ctx, key, ballot, value, generation, signer, nil, &ownerAcceptPreparation{native: native, key: key, digest: value.MustDigest(), generation: generation})
}

// ClaimAcceptOwnerEvidence accepts only an actual stored, signed acceptance
// obtained from source. Transport authenticates/source-binds the Get RPC;
// this owner verifies every returned field and current trust independently.
func (c *Client) ClaimAcceptOwnerEvidence(ctx context.Context, key ClaimKey, ballot Ballot, value ClaimValue, generation int64, signer *ClaimSigner, source string, state ClaimVoterState) (AcceptResult, error) {
	refused := AcceptResult{Voter: c.hostName, Refusal: RefusalAutomationUnavailable}
	digest, err := value.Digest()
	if err != nil {
		return refused, nil
	}
	if state.Key != key || state.ConfigGeneration != generation || state.Value == nil || state.Value.Automation == nil || value.Automation == nil || !bytes.Equal(state.Value.Automation.Envelope, value.Automation.Envelope) || state.ValueDigest != digest || state.Accept == nil || state.Accept.Voter != source || state.Accepted.IsZero() || !state.Accept.Ballot.Equal(state.Accepted) {
		return refused, nil
	}
	cfg, err := c.AutomationMembership(ctx)
	if err != nil {
		return refused, err
	}
	if cfg.Generation != generation {
		return refused, nil
	}
	member := false
	for _, m := range cfg.Members {
		if m.Name == source && m.Incarnation == state.Accept.VoterIncarnation {
			member = true
		}
	}
	if !member || len(state.Accept.CertPEM) > MaxAutomationSignerBytes || len(state.Accept.Signature) > 256 {
		return refused, nil
	}
	// Copy all mutable slices before acquiring the lease. No caller can alter
	// a previously checked signature/ballot while the FULL transaction consumes it.
	accept := *state.Accept
	accept.Signature = append([]byte(nil), accept.Signature...)
	accept.Ballot.Nonce = append([]byte(nil), accept.Ballot.Nonce...)
	cert := ClaimCertificate{Key: key, ConfigGeneration: generation, Ballot: accept.Ballot, ValueDigest: digest, Accepts: []ClaimAccept{accept}}
	factory := c.claimCertVerifier.Load()
	if factory == nil || *factory == nil {
		return refused, nil
	}
	v := (*factory)()
	if v == nil {
		return refused, nil
	}
	leaf, err := parseCertPEM([]byte(accept.CertPEM))
	if err != nil {
		return refused, nil
	}
	view, lease, err := pki.AcquireOrdinaryClaimTrust(ctx, v.pkiDir, []*x509.Certificate{leaf}, v.policyCell, maxProofPreparationBytes)
	if err != nil {
		return refused, err
	}
	defer lease.Release()
	pure := *v
	pure.ordinary = view
	if pure.policyCell != nil {
		pure.pinned, pure.noPin = pure.policyPinned, pure.policyNoPin
		if view.TrustRotatedPeers() {
			pure.pinned, pure.noPin = false, true
		}
	}
	p := &ownerAcceptPreparation{key: key, digest: digest, generation: generation, membersHash: MembersHash(cfg.Members), certificate: cert, verifier: &pure, factory: factory}
	return c.claimAccept(ctx, key, ballot, value, generation, signer, nil, p)
}

func (c *Client) admitAutomationOwnerTx(ctx context.Context, tx *LocalTx, key ClaimKey, generation int64, value ClaimValue, cfg *VoterConfig, d contract.Decision, prepared *ownerAcceptPreparation) (string, error) {
	if err := automationOwnerDuplicateTx(ctx, tx, d); err != nil {
		return RefusalAutomationUnavailable, nil
	}
	digest := value.MustDigest()
	row, found, err := loadClaimRowTx(ctx, tx, key)
	if err != nil {
		return "", err
	}
	standing, err := readStandingTx(ctx, tx, c.hostName)
	if err != nil {
		return "", err
	}
	// An actual own durable signed acceptance is the inductive base after a
	// restart/ordinary key renewal. Import clears Accept and cannot use this path.
	if found && row.Value != nil && row.ValueDigest == digest && row.Value.MustDigest() == digest && row.ConfigGeneration == generation && row.Accept != nil && row.Accept.Voter == c.hostName && row.Accept.VoterIncarnation == standing.incarnation && validateRetainedAutomationAccept(*row.Accept, key, row.Accepted, generation, digest) == nil {
		return "", nil
	}
	if prepared == nil || prepared.key != key || prepared.digest != digest || prepared.generation != generation {
		return RefusalAutomationUnavailable, nil
	}
	if native := prepared.native; native != nil {
		if native.session == nil || native.session.db != c {
			return RefusalAutomationUnavailable, nil
		}
		identity, err := contract.CanonicalCommand(d.Command)
		if err != nil || !bytes.Equal(identity, native.identity) || d.Command.RequestID != native.command.RequestID || d.Command.Session != native.command.Session || d.Command.SessionID != native.command.SessionID || !SameOwnerTarget(d, native.target) {
			return RefusalAutomationUnavailable, nil
		}
		if err := native.authorizeTx(ctx, tx); err != nil {
			return "", err
		}
		return "", nil
	}
	if prepared.verifier == nil || prepared.factory != c.claimCertVerifier.Load() || prepared.membersHash != MembersHash(cfg.Members) {
		return RefusalAutomationUnavailable, nil
	}
	if err := prepared.verifier.Verify(prepared.certificate, CertExpectation{Key: key, ValueDigest: digest, ConfigGeneration: generation, Electorate: cfg.Members, Quorum: 1}); err != nil {
		return RefusalAutomationUnavailable, nil
	}
	return "", nil
}
