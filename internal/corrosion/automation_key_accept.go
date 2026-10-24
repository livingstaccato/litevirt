package corrosion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/pki"
)

// keyAcceptValue owns only the incoming bytes and their pure interpretation for
// one call. It carries no retained-row, trust, membership or admission authority.
// It must not escape the acceptance invocation or replace final current checks.
type keyAcceptValue struct {
	value    ClaimValue
	decision contract.Decision
	digest   string
}

func prepareKeyAcceptValue(value ClaimValue) *keyAcceptValue {
	if value.Automation == nil || len(value.Automation.Envelope) > contract.MaxDecisionBytes {
		return nil
	}
	value.Automation = &AutomationClaimValue{Envelope: bytes.Clone(value.Automation.Envelope)}
	d, err := automationDecision(value)
	if err != nil {
		return nil
	}
	a, err := contract.DecodeAssignment(d)
	if err != nil || a.Version != contract.CustodyAssignmentVersion || (d.Command.Kind != contract.CustodyImportCommand && d.Command.Kind != "activate_key_epoch") || contract.ValidateSupportedDecision(d) != nil {
		return nil
	}
	h := sha256.New()
	claimField(h, "litevirt-automation-decision-v1")
	claimField(h, string(value.Automation.Envelope))
	return &keyAcceptValue{value: value, decision: d, digest: hex.EncodeToString(h.Sum(nil))}
}

type keyAcceptPreparation struct {
	native     *automationKeyNativeProof
	evidence   *keyAcceptedEvidence
	key        ClaimKey
	digest     string
	generation int64
}
type keyAcceptedEvidence struct {
	membersHash string
	certificate ClaimCertificate
	verifier    *ClaimVerifier
	factory     *func() *ClaimVerifier
	prefix      contract.Prefix
}

func isAutomationNativeKeyValue(v ClaimValue) bool {
	d, err := automationDecision(v)
	if err != nil {
		return false
	}
	a, err := contract.DecodeAssignment(d)
	return err == nil && a.Version == contract.CustodyAssignmentVersion && (d.Command.Kind == contract.CustodyImportCommand || d.Command.Kind == "activate_key_epoch")
}

// ClaimAcceptKeyEvidence consumes the actual stored acceptance obtained from an
// authenticated source. It is a key-class proof, never owner authorization.
func (c *Client) ClaimAcceptKeyEvidence(ctx context.Context, key ClaimKey, ballot Ballot, value ClaimValue, generation int64, signer *ClaimSigner, source string, state ClaimVoterState) (AcceptResult, error) {
	refused := AcceptResult{Voter: c.hostName, Refusal: RefusalAutomationUnavailable}
	incoming := prepareKeyAcceptValue(value)
	var digest string
	var err error
	if incoming != nil {
		value, digest = incoming.value, incoming.digest
	} else {
		if !isAutomationNativeKeyValue(value) {
			return refused, nil
		}
		digest, err = value.Digest()
		if err != nil {
			return refused, nil
		}
	}
	if state.Key != key || state.ConfigGeneration != generation || state.Value == nil || state.Value.Automation == nil || !bytes.Equal(state.Value.Automation.Envelope, value.Automation.Envelope) || state.ValueDigest != digest || state.Accept == nil || state.Accept.Voter != source || state.Accepted.IsZero() || !state.Accept.Ballot.Equal(state.Accepted) {
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
	accept := *state.Accept
	accept.Signature = append([]byte(nil), accept.Signature...)
	accept.Ballot.Nonce = append([]byte(nil), accept.Ballot.Nonce...)
	cert := ClaimCertificate{Key: key, ConfigGeneration: generation, Ballot: accept.Ballot, ValueDigest: digest, Accepts: []ClaimAccept{accept}}
	factory := c.claimCertVerifier.Load()
	if factory == nil || *factory == nil {
		return refused, nil
	}
	verifier := (*factory)()
	if verifier == nil {
		return refused, nil
	}
	leaf, err := parseCertPEM([]byte(accept.CertPEM))
	if err != nil {
		return refused, nil
	}
	view, lease, err := pki.AcquireOrdinaryClaimTrust(ctx, verifier.pkiDir, []*x509.Certificate{leaf}, verifier.policyCell, maxProofPreparationBytes)
	if err != nil {
		return refused, err
	}
	defer lease.Release()
	pure := *verifier
	pure.ordinary = view
	if pure.policyCell != nil {
		pure.pinned, pure.noPin = pure.policyPinned, pure.policyNoPin
		if view.TrustRotatedPeers() {
			pure.pinned, pure.noPin = false, true
		}
	}
	var d contract.Decision
	if incoming != nil {
		d = incoming.decision
	} else {
		d, err = automationDecision(value)
		if err != nil {
			return refused, nil
		}
	}
	evidence := &keyAcceptedEvidence{membersHash: MembersHash(cfg.Members), certificate: cert, verifier: &pure, factory: factory, prefix: contract.Prefix{ClusterUID: d.Command.ClusterUID, Sequence: d.Sequence - 1, Digest: d.ParentDigest}}
	return c.claimAcceptValue(ctx, key, ballot, value, generation, signer, nil, nil, nil, &keyAcceptPreparation{evidence: evidence, key: key, digest: digest, generation: generation}, incoming)
}
func (c *Client) checkKeyEvidenceTx(ctx context.Context, tx *LocalTx, prepared *keyAcceptPreparation) error {
	e := prepared.evidence
	if ctx.Err() != nil || e == nil || e.verifier == nil || e.factory != c.claimCertVerifier.Load() {
		return errAutomationAuthority
	}
	cfg, err := automationAuthorityTx(ctx, tx, c.hostName, prepared.generation)
	if err != nil || e.membersHash != MembersHash(cfg.Members) {
		return errAutomationAuthority
	}
	head, err := automationRetainedHeadTx(ctx, tx)
	if err != nil || head != e.prefix {
		return errAutomationAuthority
	}
	if err = e.verifier.Verify(e.certificate, CertExpectation{Key: prepared.key, ValueDigest: prepared.digest, ConfigGeneration: prepared.generation, Electorate: cfg.Members, Quorum: 1}); err != nil {
		return errAutomationAuthority
	}
	return requireAutomationFull(ctx, tx)
}
func (c *Client) admitAutomationKeyTx(ctx context.Context, tx *LocalTx, key ClaimKey, generation int64, value ClaimValue, prepared *keyAcceptPreparation, incoming *keyAcceptValue) (string, error) {
	var digest string
	if incoming != nil {
		digest = incoming.digest
	} else {
		if !isAutomationNativeKeyValue(value) {
			return RefusalAutomationUnavailable, nil
		}
		digest = value.MustDigest()
	}
	row, found, err := loadClaimRowTx(ctx, tx, key)
	if err != nil {
		return "", err
	}
	standing, err := readStandingTx(ctx, tx, c.hostName)
	if err != nil {
		return "", err
	}
	// An import clears Accept. Only our genuine durable signed vote under this
	// database incarnation can renew the inductive base without a new issuer.
	if found && row.Value != nil && row.ValueDigest == digest && row.Value.MustDigest() == digest && row.ConfigGeneration == generation && row.Accept != nil && row.Accept.Voter == c.hostName && row.Accept.VoterIncarnation == standing.incarnation && validateRetainedAutomationAccept(*row.Accept, key, row.Accepted, generation, digest) == nil {
		return "", nil
	}
	if prepared == nil || prepared.key != key || prepared.digest != digest || prepared.generation != generation {
		return RefusalAutomationUnavailable, nil
	}
	if prepared.native != nil {
		if prepared.native.producer.client != c {
			return RefusalAutomationUnavailable, nil
		}
		if err := prepared.native.checkTx(ctx, tx); err != nil {
			return "", err
		}
		return "", nil
	}
	if prepared.evidence == nil {
		return RefusalAutomationUnavailable, nil
	}
	if err := c.checkKeyEvidenceTx(ctx, tx, prepared); err != nil {
		return "", err
	}
	return "", nil
}
func (c *Client) keyCommitSeams(ctx context.Context, key ClaimKey, prepared *keyAcceptPreparation) *localCommitSeams {
	old := c.claimCommitSeams(key)
	if prepared == nil {
		return old
	}
	seams := &localCommitSeams{beforeCommit: func(tx *sql.Tx) error {
		if old != nil && old.beforeCommit != nil {
			if err := old.beforeCommit(tx); err != nil {
				return err
			}
		}
		if prepared.native != nil {
			return prepared.native.checkTx(ctx, &LocalTx{tx: tx})
		}
		return c.checkKeyEvidenceTx(ctx, &LocalTx{tx: tx}, prepared)
	}}
	if old != nil {
		seams.afterCommit = old.afterCommit
	}
	return seams
}
