package corrosion

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/pki"
	"sync/atomic"
)

type continuityEvidenceKind uint8

const (
	continuityNative continuityEvidenceKind = iota + 1
	continuityLocal
	continuityPeer
	continuityCertificate
	continuityPredecessor
)

// AutomationContinuityReleaseEvidence is an invocation-local bridge to health.
// Private construction and the held trust lease bind it to exact selected bytes.
type AutomationContinuityReleaseEvidence struct {
	client                   *Client
	self                     *AutomationContinuityReleaseEvidence
	active                   atomic.Bool
	kind                     continuityEvidenceKind
	key                      ClaimKey
	value                    ClaimValue
	digest                   string
	generation               int64
	membersHash, incarnation string
	certificate              ClaimCertificate
	anchorDigest             string
	anchorSequence           uint64
	factory                  *func() *ClaimVerifier
	verifier                 *ClaimVerifier
}
type continuityAcceptPreparation struct {
	proof  *AutomationContinuityReleaseEvidence
	native *AutomationIdentityContinuity
	grant  capabilities.FeatureGrant
}

func (c *Client) SetAutomationContinuityReleaseRestorer(fn func(context.Context, *AutomationContinuityReleaseEvidence) error) {
	c.continuityReleaseRestorer.Store(&fn)
}
func isAutomationContinuityValue(value ClaimValue) bool {
	d, err := automationDecision(value)
	return err == nil && d.Command.Kind == contract.IdentityContinuityCommand
}

// Copy mutable inputs before acquiring trust. Preparation alone is not proof:
// health must validate it in a completed FULL snapshot before restoring use.
func (c *Client) prepareContinuityProof(ctx context.Context, kind continuityEvidenceKind, key ClaimKey, value ClaimValue, generation int64, cert ClaimCertificate, signer *ClaimSigner) (*AutomationContinuityReleaseEvidence, func(), error) {
	if validateAutomationValue(key, value) != nil || !isAutomationContinuityValue(value) {
		return nil, nil, ErrAutomationLifecycleUnavailable
	}
	value = ClaimValue{Automation: &AutomationClaimValue{Envelope: append([]byte(nil), value.Automation.Envelope...)}}
	cert.Ballot.Nonce = append([]byte(nil), cert.Ballot.Nonce...)
	cert.Accepts = append([]ClaimAccept(nil), cert.Accepts...)
	var leaves []*x509.Certificate
	for i := range cert.Accepts {
		a := &cert.Accepts[i]
		if len(a.CertPEM) > MaxAutomationSignerBytes || len(a.Signature) > 256 {
			return nil, nil, ErrAutomationLifecycleUnavailable
		}
		a.Signature = append([]byte(nil), a.Signature...)
		a.Ballot.Nonce = append([]byte(nil), a.Ballot.Nonce...)
		leaf, err := parseCertPEM([]byte(a.CertPEM))
		if err != nil {
			return nil, nil, err
		}
		leaves = append(leaves, leaf)
	}
	if signer != nil {
		leaf, err := parseCertPEM([]byte(signer.certPEM))
		if err != nil {
			return nil, nil, err
		}
		leaves = append(leaves, leaf)
	}
	cfg, err := c.AutomationMembership(ctx)
	if err != nil {
		return nil, nil, err
	}
	if cfg.Generation != generation {
		return nil, nil, ErrAutomationLifecycleUnavailable
	}
	factory := c.claimCertVerifier.Load()
	if factory == nil || *factory == nil {
		return nil, nil, ErrAutomationLifecycleUnavailable
	}
	v := (*factory)()
	if v == nil || v.historical || v.renewalBlind {
		return nil, nil, ErrAutomationLifecycleUnavailable
	}
	view, lease, err := pki.AcquireOrdinaryClaimTrust(ctx, v.pkiDir, leaves, v.policyCell, maxProofPreparationBytes)
	if err != nil {
		return nil, nil, err
	}
	pure := *v
	pure.ordinary = view
	if pure.policyCell != nil {
		pure.pinned, pure.noPin = pure.policyPinned, pure.policyNoPin
		if view.TrustRotatedPeers() {
			pure.pinned, pure.noPin = false, true
		}
	}
	p := &AutomationContinuityReleaseEvidence{client: c, kind: kind, key: key, value: value, digest: value.MustDigest(), generation: generation, membersHash: MembersHash(cfg.Members), certificate: cert, factory: factory, verifier: &pure}
	err = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		st, err := readStandingTx(ctx, tx, c.hostName)
		if err == nil {
			p.incarnation = st.incarnation
		}
		return err
	})
	if err != nil {
		lease.Release()
		return nil, nil, err
	}
	p.self = p
	p.active.Store(true)
	return p, func() { p.active.Store(false); lease.Release() }, nil
}

func (c *Client) ValidateAutomationContinuityReleaseEvidence(ctx context.Context, p *AutomationContinuityReleaseEvidence) error {
	if p == nil || p.kind == continuityNative {
		return ErrAutomationLifecycleUnavailable
	}
	return c.ExecuteLocal(ctx, func(tx *LocalTx) error { return c.validateContinuityProofTx(ctx, tx, p) })
}

func (c *Client) validateContinuityProofTx(ctx context.Context, tx *LocalTx, p *AutomationContinuityReleaseEvidence) error {
	if p == nil || p.self != p || p.client != c || !p.active.Load() || p.verifier == nil || p.factory != c.claimCertVerifier.Load() || p.digest != p.value.MustDigest() || !isAutomationContinuityValue(p.value) {
		return ErrAutomationLifecycleUnavailable
	}
	if err := requireAutomationFull(ctx, tx); err != nil {
		return err
	}
	cfg, err := automationEstablishedAuthorityTx(ctx, tx, c.hostName, p.generation)
	if err != nil {
		return err
	}
	if cfg == nil || MembersHash(cfg.Members) != p.membersHash {
		return ErrAutomationLifecycleUnavailable
	}
	st, err := readStandingTx(ctx, tx, c.hostName)
	if err != nil {
		return err
	}
	if st.incarnation != p.incarnation {
		return ErrAutomationLifecycleUnavailable
	}
	switch p.kind {
	case continuityNative:
		return nil
	case continuityPeer, continuityCertificate:
		quorum := 1
		if p.kind == continuityCertificate {
			quorum = MajorityOf(len(cfg.Members))
		}
		if err := p.verifier.Verify(p.certificate, CertExpectation{Key: p.key, ValueDigest: p.digest, ConfigGeneration: p.generation, Electorate: cfg.Members, Quorum: quorum}); err != nil {
			return fmt.Errorf("%w: %w", ErrAutomationLifecycleUnavailable, err)
		}
		return nil
	case continuityLocal:
		digest, found, err := automationTrustedDigestTx(ctx, tx, uint64(p.key.OwnerEpoch))
		if err != nil {
			return err
		}
		if found && digest == p.digest {
			return nil
		}
		row, found, err := loadClaimRowTx(ctx, tx, p.key)
		if err != nil {
			return err
		}
		if found && row.Value != nil && row.ValueDigest == p.digest && row.Value.MustDigest() == p.digest && row.ConfigGeneration == p.generation && row.Accept != nil && row.Accept.Voter == c.hostName && row.Accept.VoterIncarnation == st.incarnation && validateRetainedAutomationAccept(*row.Accept, p.key, row.Accepted, p.generation, p.digest) == nil {
			return nil
		}
	case continuityPredecessor:
		rows, err := tx.Query(ctx, `SELECT sequence,digest,next_sequence,next_digest,generation,members_hash,certificate FROM local_automation_recovery WHERE id=1`)
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			return ErrAutomationLifecycleUnavailable
		}
		r := rows[0]
		if uint64(r.Int64("sequence")) != p.anchorSequence || r.String("digest") != p.anchorDigest || r.Int64("next_sequence") != p.key.OwnerEpoch || r.String("next_digest") != p.digest || r.Int64("generation") != p.generation || r.String("members_hash") != p.membersHash {
			return ErrAutomationLifecycleUnavailable
		}
		encoded, err := p.certificate.Encode()
		if err != nil {
			return err
		}
		if r.String("certificate") != encoded {
			return ErrAutomationLifecycleUnavailable
		}
		anchor, _ := AutomationClaimKey(p.anchorSequence)
		if err := p.verifier.Verify(p.certificate, CertExpectation{Key: anchor, ValueDigest: p.anchorDigest, ConfigGeneration: p.generation, Electorate: cfg.Members, Quorum: MajorityOf(len(cfg.Members))}); err != nil {
			return fmt.Errorf("%w: %w", ErrAutomationLifecycleUnavailable, err)
		}
		return nil
	}
	return ErrAutomationLifecycleUnavailable
}
func (c *Client) restoreContinuityRelease(ctx context.Context, p *AutomationContinuityReleaseEvidence) error {
	fn := c.continuityReleaseRestorer.Load()
	if fn == nil || *fn == nil {
		return ErrAutomationLifecycleUnavailable
	}
	return (*fn)(ctx, p)
}

func (c *Client) ClaimAcceptContinuityNative(ctx context.Context, key ClaimKey, ballot Ballot, value ClaimValue, generation int64, signer *ClaimSigner, native *AutomationIdentityContinuity) (out AcceptResult, err error) {
	ballot.Nonce = append([]byte(nil), ballot.Nonce...)
	value = copyContinuityRecord(AutomationRecord{Value: value}).Value
	out = AcceptResult{Voter: c.hostName, Refusal: RefusalAutomationUnavailable}
	if !native.UsesClient(c) {
		return out, nil
	}
	// Network readiness precedes acquisition of the trust lease used in FULL.
	err = c.WithReleaseFeature(ctx, capabilities.FeatureAutomationIdentityContinuity, func(ctx context.Context, g capabilities.FeatureGrant) error {
		p, release, e := c.prepareContinuityProof(ctx, continuityNative, key, value, generation, ClaimCertificate{}, signer)
		if e != nil {
			return e
		}
		defer release()
		out, e = c.claimAcceptContinuityWithGrant(ctx, g, key, ballot, p.value, generation, signer, &continuityAcceptPreparation{proof: p, native: native})
		return e
	})
	return
}

func (c *Client) ClaimAcceptContinuityEvidence(ctx context.Context, key ClaimKey, ballot Ballot, value ClaimValue, generation int64, signer *ClaimSigner, source string, state ClaimVoterState) (AcceptResult, error) {
	refused := AcceptResult{Voter: c.hostName, Refusal: RefusalAutomationUnavailable}
	digest, err := value.Digest()
	if err != nil {
		return refused, nil
	}
	if state.Key != key || state.ConfigGeneration != generation || state.Value == nil || state.Value.Automation == nil || value.Automation == nil || !bytes.Equal(state.Value.Automation.Envelope, value.Automation.Envelope) || state.ValueDigest != digest || state.Accept == nil || state.Accept.Voter != source || state.Accepted.IsZero() || !state.Accept.Ballot.Equal(state.Accepted) {
		return refused, nil
	}
	cert := ClaimCertificate{Key: key, ConfigGeneration: generation, Ballot: state.Accepted, ValueDigest: digest, Accepts: []ClaimAccept{*state.Accept}}
	return c.claimAcceptContinuityRecovery(ctx, key, ballot, value, generation, signer, continuityPeer, cert)
}
func (c *Client) claimAcceptContinuityRecovery(ctx context.Context, key ClaimKey, ballot Ballot, value ClaimValue, generation int64, signer *ClaimSigner, kind continuityEvidenceKind, cert ClaimCertificate) (out AcceptResult, err error) {
	ballot.Nonce = append([]byte(nil), ballot.Nonce...)
	out = AcceptResult{Voter: c.hostName, Refusal: RefusalAutomationUnavailable}
	p, release, err := c.prepareContinuityProof(ctx, kind, key, value, generation, cert, signer)
	if err != nil {
		return out, err
	}
	defer release()
	if err = c.ValidateAutomationContinuityReleaseEvidence(ctx, p); err != nil {
		if errors.Is(err, ErrAutomationLifecycleUnavailable) || errors.Is(err, errAutomationAuthority) {
			return out, nil
		}
		return out, err
	}
	if err = c.restoreContinuityRelease(ctx, p); err != nil {
		return out, err
	}
	err = c.WithReleaseFeature(ctx, capabilities.FeatureAutomationIdentityContinuity, func(ctx context.Context, g capabilities.FeatureGrant) error {
		var e error
		out, e = c.claimAcceptContinuityWithGrant(ctx, g, key, ballot, p.value, generation, signer, &continuityAcceptPreparation{proof: p})
		return e
	})
	return
}
func (c *Client) claimAcceptContinuityWithGrant(ctx context.Context, g capabilities.FeatureGrant, key ClaimKey, ballot Ballot, value ClaimValue, generation int64, signer *ClaimSigner, prepared *continuityAcceptPreparation) (AcceptResult, error) {
	if err := g.Check(capabilities.FeatureAutomationIdentityContinuity); err != nil {
		return AcceptResult{}, err
	}
	prepared.grant = g
	return c.claimAccept(ctx, key, ballot, value, generation, signer, nil, nil, prepared, nil)
}
func (c *Client) admitAutomationContinuityTx(ctx context.Context, tx *LocalTx, key ClaimKey, generation int64, value ClaimValue, d contract.Decision, p *continuityAcceptPreparation) error {
	if p == nil || p.proof == nil || p.proof.key != key || p.proof.generation != generation || p.proof.digest != value.MustDigest() {
		return ErrAutomationLifecycleUnavailable
	}
	if err := p.grant.Check(capabilities.FeatureAutomationIdentityContinuity); err != nil {
		return err
	}
	if err := c.validateContinuityProofTx(ctx, tx, p.proof); err != nil {
		return err
	}
	if p.native == nil {
		return nil
	}
	n := p.native
	identity, err := contract.CanonicalCommand(d.Command)
	if err != nil {
		return err
	}
	assignment, err := contract.DecodeAssignment(d)
	if err != nil {
		return err
	}
	if !n.UsesClient(c) || d.Command.RequestID != n.command.RequestID || !bytes.Equal(identity, n.identity) || assignment.Continuity == nil || *assignment.Continuity != n.facts {
		return ErrAutomationLifecycleUnavailable
	}
	if err = n.authorizeTx(ctx, tx); err != nil {
		return err
	}
	old, err := automationRequestTx(ctx, tx, contract.Scope(d), d.Command.RequestID)
	if err != nil {
		return err
	}
	if old != nil && !bytes.Equal(old.Identity, n.identity) {
		return ownerRequestError(contract.CodeIdempotencyConflict)
	}
	return nil
}

// Protect authoritative materialization. Opaque bounded transport frames remain
// inert and cannot invoke this proof owner or restore local release state.
func (c *Client) executeContinuityMaterialization(ctx context.Context, r AutomationRecord, kind continuityEvidenceKind, write func(*LocalTx) error) error {
	if !isAutomationContinuityValue(r.Value) {
		return c.ExecuteLocal(ctx, write)
	}
	d, err := automationDecision(r.Value)
	if err != nil {
		return err
	}
	key, _ := AutomationClaimKey(d.Sequence)
	cfg, err := c.AutomationMembership(ctx)
	if err != nil {
		return err
	}
	cert := r.Certificate
	var anchorSequence uint64
	var anchorDigest string
	if kind == continuityPredecessor {
		err = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
			rows, e := tx.Query(ctx, `SELECT sequence,digest,certificate FROM local_automation_recovery WHERE id=1`)
			if e != nil {
				return e
			}
			if len(rows) != 1 {
				return ErrAutomationLifecycleUnavailable
			}
			anchorSequence = uint64(rows[0].Int64("sequence"))
			anchorDigest = rows[0].String("digest")
			cert, e = DecodeClaimCertificate(rows[0].String("certificate"))
			return e
		})
		if err != nil {
			return err
		}
	}
	p, release, err := c.prepareContinuityProof(ctx, kind, key, r.Value, cfg.Generation, cert, nil)
	if err != nil {
		return err
	}
	defer release()
	p.anchorSequence, p.anchorDigest = anchorSequence, anchorDigest
	if err = c.restoreContinuityRelease(ctx, p); err != nil {
		return err
	}
	return c.WithReleaseFeature(ctx, capabilities.FeatureAutomationIdentityContinuity, func(ctx context.Context, g capabilities.FeatureGrant) error {
		return c.materializeAutomationContinuity(ctx, g, p, write)
	})
}
func (c *Client) materializeAutomationContinuity(ctx context.Context, g capabilities.FeatureGrant, p *AutomationContinuityReleaseEvidence, write func(*LocalTx) error) error {
	if err := g.Check(capabilities.FeatureAutomationIdentityContinuity); err != nil {
		return err
	}
	return c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		if err := g.Check(capabilities.FeatureAutomationIdentityContinuity); err != nil {
			return err
		}
		if err := c.validateContinuityProofTx(ctx, tx, p); err != nil {
			return fmt.Errorf("continuity materialization: %w", err)
		}
		return write(tx)
	})
}

func copyContinuityImportStates(states []ClaimVoterState) ([]ClaimVoterState, error) {
	needed := false
	for _, s := range states {
		if s.Value != nil && isAutomationContinuityValue(*s.Value) {
			needed = true
			break
		}
	}
	if !needed {
		return states, nil
	}
	// Preserve every legacy alternative, ballot and promise while severing all
	// caller-owned slice/pointer aliases for the protected import invocation.
	raw, err := json.Marshal(states)
	if err != nil {
		return nil, err
	}
	var copied []ClaimVoterState
	err = json.Unmarshal(raw, &copied)
	return copied, err
}

func copyContinuityRecord(r AutomationRecord) AutomationRecord {
	if !isAutomationContinuityValue(r.Value) {
		return r
	}
	r.Value = ClaimValue{Automation: &AutomationClaimValue{Envelope: append([]byte(nil), r.Value.Automation.Envelope...)}}
	r.Certificate.Ballot.Nonce = append([]byte(nil), r.Certificate.Ballot.Nonce...)
	r.Certificate.Accepts = append([]ClaimAccept(nil), r.Certificate.Accepts...)
	for i := range r.Certificate.Accepts {
		a := &r.Certificate.Accepts[i]
		a.Signature = append([]byte(nil), a.Signature...)
		a.Ballot.Nonce = append([]byte(nil), a.Ballot.Nonce...)
	}
	return r
}

func (c *Client) executeContinuityImport(ctx context.Context, states []ClaimVoterState, write func(*LocalTx) error) error {
	needed := false
	for _, s := range states {
		if s.Value != nil && isAutomationContinuityValue(*s.Value) {
			needed = true
			break
		}
	}
	if !needed {
		return c.ExecuteLocal(ctx, write)
	}
	// A genuine signed pre-import row may restore the completed barrier. A
	// previously imported unsigned value never does. Without such provenance,
	// ordinary WithFeature still protects inert import and may refuse readiness.
	cfg, err := c.AutomationMembership(ctx)
	if err != nil {
		return err
	}
	var proof *AutomationContinuityReleaseEvidence
	var release func()
	for _, s := range states {
		if s.Value == nil || !isAutomationContinuityValue(*s.Value) || s.Accept == nil || s.ConfigGeneration != cfg.Generation || ValidateAutomationState(s) != nil {
			continue
		}
		cert := ClaimCertificate{Key: s.Key, ConfigGeneration: s.ConfigGeneration, Ballot: s.Accepted, ValueDigest: s.ValueDigest, Accepts: []ClaimAccept{*s.Accept}}
		p, done, e := c.prepareContinuityProof(ctx, continuityPeer, s.Key, *s.Value, cfg.Generation, cert, nil)
		if e != nil {
			return e
		}
		if e = c.ValidateAutomationContinuityReleaseEvidence(ctx, p); e != nil {
			done()
			continue
		}
		proof, release = p, done
		break
	}
	if proof != nil {
		defer release()
		if err = c.restoreContinuityRelease(ctx, proof); err != nil {
			return err
		}
	}
	return c.WithReleaseFeature(ctx, capabilities.FeatureAutomationIdentityContinuity, func(ctx context.Context, g capabilities.FeatureGrant) error {
		return c.importAutomationContinuity(ctx, g, proof, write)
	})
}

func (c *Client) importAutomationContinuity(ctx context.Context, g capabilities.FeatureGrant, p *AutomationContinuityReleaseEvidence, write func(*LocalTx) error) error {
	if err := g.Check(capabilities.FeatureAutomationIdentityContinuity); err != nil {
		return err
	}
	return c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		if err := requireAutomationFull(ctx, tx); err != nil {
			return err
		}
		if err := g.Check(capabilities.FeatureAutomationIdentityContinuity); err != nil {
			return err
		}
		if p != nil {
			if err := c.validateContinuityProofTx(ctx, tx, p); err != nil {
				return err
			}
		}
		return write(tx)
	})
}
