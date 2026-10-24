package corrosion

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/pki"
	"sync"
	"time"
)

// ImportCommand is inert request identity. It grants no native vote.
func (r *AutomationCustodyReady) ImportCommand() (contract.Command, error) {
	if r == nil {
		return contract.Command{}, errAutomationAuthority
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.self != r || r.owner == nil || r.attempt == nil {
		return contract.Command{}, errAutomationAuthority
	}
	v := r.record
	body, err := json.Marshal(contract.CustodyImportBody{Version: 1, Attempt: v.Attempt, MembershipGeneration: v.MembershipGeneration, ConfigDigest: v.ConfigDigest, RecipientEpoch: v.RecipientEpoch, EqualityEpoch: v.EqualityEpoch, Genesis: v.Genesis})
	if err != nil {
		return contract.Command{}, err
	}
	return contract.Command{Kind: contract.CustodyImportCommand, ClusterUID: v.ClusterUID, PrincipalID: r.attempt.snapshot.principal, RequestID: r.attempt.importRequest, Body: body}, nil
}

// AutomationKeyAdmission owns one native first-vote attempt. A byte-identical
// copied handle fails self identity; consumption precedes every native outcome.
type AutomationKeyAdmission struct {
	mu    sync.Mutex
	self  *AutomationKeyAdmission
	proof *automationKeyNativeProof
}
type automationKeyNativeProof struct {
	imported    contract.HistoryReference
	producer    *AutomationCustodyProducer
	origin      context.Context
	expires     time.Time
	prefix      contract.Prefix
	key         ClaimKey
	digest      string
	record      contract.CustodyImportRecord
	view        *pki.HostTrust
	pair        *tls.Certificate
	lease       *pki.HostCertificateLease
	validations []*pki.HostCertificateValidation
}

func (a *AutomationKeyAdmission) Release() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.self != a {
		return
	}
	a.self = nil
	if a.proof != nil {
		a.proof.release()
		a.proof = nil
	}
}
func (p *AutomationCustodyProducer) PrepareCustodyValue(ctx context.Context, r *AutomationCustodyReady, base contract.Decision) (ClaimValue, *AutomationKeyAdmission, error) {
	if p == nil || r == nil {
		return ClaimValue{}, nil, errAutomationAuthority
	}
	command, err := r.ImportCommand()
	if err != nil {
		return ClaimValue{}, nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.self != r || r.owner != p || r.historical != nil || r.ctx == nil || r.ctx.Err() != nil || ctx.Err() != nil || !time.Now().Before(r.expires) {
		return ClaimValue{}, nil, errAutomationAuthority
	}
	expected, err := contract.CanonicalCommand(command)
	if err != nil {
		return ClaimValue{}, nil, err
	}
	actual, err := contract.CanonicalCommand(base.Command)
	if err != nil || !bytes.Equal(actual, expected) || base.Command.RequestID != command.RequestID {
		return ClaimValue{}, nil, errAutomationAuthority
	}
	operation, err := custodyRandomID()
	if err != nil {
		return ClaimValue{}, nil, err
	}
	base.Assignment, err = custodyProtocolEncode(contract.Assignment{Version: 4, ClusterUID: r.record.ClusterUID, OperationID: operation, RecordedAt: time.Now().UTC().Format(time.RFC3339Nano), CustodyImport: &r.record})
	if err != nil {
		return ClaimValue{}, nil, err
	}
	encoded, err := contract.EncodeDecision(base)
	if err != nil {
		return ClaimValue{}, nil, err
	}
	value := ClaimValue{Automation: &AutomationClaimValue{Envelope: encoded}}
	proof, err := p.prepareKeyProof(ctx, r, base, value, contract.HistoryReference{})
	if err != nil {
		return ClaimValue{}, nil, err
	}
	admission := &AutomationKeyAdmission{proof: proof}
	admission.self = admission
	return value, admission, nil
}
func (p *AutomationCustodyProducer) prepareKeyProof(ctx context.Context, r *AutomationCustodyReady, d contract.Decision, value ClaimValue, imported contract.HistoryReference) (*automationKeyNativeProof, error) {
	view, pair, self, err := p.localTrust(ctx)
	if err != nil {
		return nil, err
	}
	caps := []*pki.HostCertificateValidation{self}
	transferred := false
	defer func() {
		if transferred {
			return
		}
		for _, cap := range caps {
			cap.Discard()
		}
	}()
	for _, m := range r.record.Members {
		if verifyCustodyCompletion(m.Completion, m.Recipient) != nil {
			return nil, errAutomationAuthority
		}
		cap, err := view.ValidateHostCertificate(ctx, m.Completion.Chain, m.Completion.Candidate.Target.Host)
		if err != nil {
			return nil, err
		}
		caps = append(caps, cap)
	}
	lease, err := pki.AcquireHostCertificateLease(ctx, p.pkiDir, caps...)
	if err != nil {
		return nil, err
	}
	key, err := AutomationClaimKey(d.Sequence)
	if err != nil {
		lease.Release()
		return nil, err
	}
	proof := &automationKeyNativeProof{imported: imported, producer: p, origin: r.ctx, expires: r.expires, prefix: contract.Prefix{ClusterUID: d.Command.ClusterUID, Sequence: d.Sequence - 1, Digest: d.ParentDigest}, key: key, digest: value.MustDigest(), record: r.record, view: view, pair: pair, lease: lease}
	if err = p.client.ExecuteLocal(ctx, func(tx *LocalTx) error { return proof.checkTx(ctx, tx) }); err != nil {
		lease.Release()
		return nil, err
	}
	lease.Release()
	proof.lease = nil
	caps = nil
	self, err = view.ValidateServedHost(ctx, pair)
	if err != nil {
		return nil, err
	}
	caps = append(caps, self)
	for _, m := range r.record.Members {
		cap, e := view.ValidateHostCertificate(ctx, m.Completion.Chain, m.Completion.Candidate.Target.Host)
		if e != nil {
			return nil, e
		}
		caps = append(caps, cap)
	}
	proof.validations = caps
	transferred = true
	return proof, nil
}
func (p *automationKeyNativeProof) checkTx(ctx context.Context, tx *LocalTx) error {
	if p == nil || p.producer == nil || p.origin == nil || p.origin.Err() != nil || ctx.Err() != nil || !time.Now().Before(p.expires) || p.lease.Check() != nil {
		return errAutomationAuthority
	}
	snap, err := p.producer.snapshotTx(ctx, tx)
	if err != nil || snap.head != p.prefix || len(snap.cfg.Members) != len(p.record.Members) {
		return errAutomationAuthority
	}
	if p.imported.Sequence != 0 {
		if p.imported.Sequence > p.prefix.Sequence {
			return errAutomationAuthority
		}
		digest, found, err := automationTrustedDigestTx(ctx, tx, p.imported.Sequence)
		if err != nil || !found || digest != p.imported.Digest {
			return errAutomationAuthority
		}
		summary, err := (localAutomationKeySource{tx}).keyHistory(ctx, p.imported.Sequence)
		body, encodeErr := custodyProtocolEncode(p.record)
		if err != nil || encodeErr != nil || summary.CustodyImport == nil || summary.Kind != contract.CustodyImportCommand || summary.PrincipalID != snap.principal || summary.CustodyImport.RecordDigest != contract.CiphertextDigest(body) {
			return errAutomationAuthority
		}
	}
	var local *contract.CustodyMemberImport
	for i, m := range p.record.Members {
		c := m.Recipient.Candidate
		if !custodyCandidateMatches(snap, c) || verifyCustodyCompletion(m.Completion, m.Recipient) != nil || sourceAdmission(p.view, snap.hosts[c.Target.Host].endpoint, m.Completion.Chain[0]) != nil {
			return errAutomationAuthority
		}
		if c.Target.Host == p.producer.client.hostName {
			local = &p.record.Members[i]
		}
	}
	if local == nil || sourceAdmission(p.view, snap.hosts[p.producer.client.hostName].endpoint, p.pair.Certificate[0]) != nil {
		return errAutomationAuthority
	}
	c := local.Recipient.Candidate
	store, err := p.producer.openStore(custodyScope(c.ClusterUID, c.Target), false)
	if err != nil {
		return err
	}
	voter, _, equality := custodyRefs(c)
	if _, err = store.OpenVoterIdentity(voter, local.Recipient.Recipient); err != nil {
		return err
	}
	if _, err = store.OpenEqualityKey(equality); err != nil {
		return err
	}
	raw, err := store.ReadProvisionRecord(custodyProvisionRef(c), "completion")
	if err != nil {
		return err
	}
	expected, err := custodyProtocolEncode(local.Completion)
	if err != nil || !bytes.Equal(raw, expected) {
		return errAutomationAuthority
	}
	return requireAutomationFull(ctx, tx)
}
func (c *Client) ClaimAcceptKeyNative(ctx context.Context, key ClaimKey, ballot Ballot, value ClaimValue, generation int64, signer *ClaimSigner, a *AutomationKeyAdmission) (AcceptResult, error) {
	refused := AcceptResult{Voter: c.hostName, Refusal: RefusalAutomationUnavailable}
	if a == nil {
		return refused, nil
	}
	a.mu.Lock()
	if a.self != a || a.proof == nil {
		a.mu.Unlock()
		return refused, nil
	}
	proof := a.proof
	a.self = nil
	a.proof = nil
	a.mu.Unlock()
	defer proof.release()
	if proof.producer.client != c || proof.key != key || proof.digest != value.MustDigest() || int64(proof.record.MembershipGeneration) != generation || signer == nil {
		return refused, nil
	}
	leaf, err := parseCertPEM([]byte(signer.certPEM))
	if err != nil || !bytes.Equal(leaf.Raw, proof.pair.Certificate[0]) {
		return refused, nil
	}
	if proof.origin.Err() != nil || ctx.Err() != nil || !time.Now().Before(proof.expires) {
		return refused, nil
	}
	proof.lease, err = pki.AcquireHostCertificateLease(ctx, proof.producer.pkiDir, proof.validations...)
	if err != nil {
		return refused, err
	}
	return c.claimAccept(ctx, key, ballot, value, generation, signer, nil, nil, nil, &keyAcceptPreparation{native: proof, key: key, digest: proof.digest, generation: generation})
}

func (p *automationKeyNativeProof) release() {
	if p == nil {
		return
	}
	if p.lease != nil {
		p.lease.Release()
		p.lease = nil
	} else {
		for _, cap := range p.validations {
			cap.Discard()
		}
	}
	p.validations = nil
}

// ActivationCommand carries immutable request identity only. Prefix is checked
// against the actual current semantic head by the native admission owner.
func (r *AutomationCustodyReady) ActivationCommand(prefix contract.HistoryReference) (contract.Command, error) {
	if r == nil {
		return contract.Command{}, errAutomationAuthority
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.self != r || r.owner == nil || r.attempt == nil {
		return contract.Command{}, errAutomationAuthority
	}
	if r.activationCommand != nil {
		c := *r.activationCommand
		c.Body = append([]byte(nil), c.Body...)
		return c, nil
	}
	candidate := r.record.Members[0].Recipient.Candidate
	store, err := r.owner.openStore(custodyScope(candidate.ClusterUID, candidate.Source), false)
	if err != nil {
		return contract.Command{}, err
	}
	ref := r.attempt.plan
	ref.Voter.KeyID = r.attempt.activationRequest
	exists, err := store.HasProvisionRecord(ref, "plan")
	if err != nil {
		return contract.Command{}, err
	}
	var c contract.Command
	if exists {
		raw, err := store.ReadProvisionRecord(ref, "plan")
		if err != nil || custodyProtocolDecode(raw, &c) != nil {
			return contract.Command{}, errAutomationAuthority
		}
		body, err := contract.DecodeActivateKeyEpochBody(c)
		if err != nil {
			return contract.Command{}, err
		}
		expected, err := r.activationCommandFor(body.Prefix, r.attempt.activationRequest)
		if err != nil {
			return contract.Command{}, err
		}
		a, _ := contract.CanonicalCommand(c)
		b, _ := contract.CanonicalCommand(expected)
		if c.RequestID != expected.RequestID || !bytes.Equal(a, b) {
			return contract.Command{}, errAutomationAuthority
		}
	} else {
		if r.ctx == nil || r.ctx.Err() != nil || !time.Now().Before(r.expires) {
			return contract.Command{}, errAutomationAuthority
		}
		request := r.attempt.activationRequest
		if r.attempt.resumed {
			// Missing intent metadata may be loss, not first creation. Resolve
			// the known original, then reserve a distinct request identity.
			probe, e := r.activationCommandFor(prefix, request)
			if e != nil {
				return contract.Command{}, e
			}
			original, e := r.owner.client.AutomationRequest(r.ctx, AutomationScope(contract.Decision{Command: probe}), request)
			if e != nil || original != nil {
				return contract.Command{}, errAutomationAuthority
			}
			request, err = custodyRandomID()
			if err != nil {
				return contract.Command{}, err
			}
		}
		c, err = r.activationCommandFor(prefix, request)
		if err != nil {
			return contract.Command{}, err
		}
		if err = r.persistActivationCommand(c); err != nil {
			return contract.Command{}, err
		}
	}
	r.activationCommand = &c
	c.Body = append([]byte(nil), c.Body...)
	return c, nil
}
func (r *AutomationCustodyReady) activationCommandFor(prefix contract.HistoryReference, request string) (contract.Command, error) {
	v := r.record
	body, err := json.Marshal(contract.ActivateKeyEpochBody{Version: 1, MembershipGeneration: v.MembershipGeneration, ConfigDigest: v.ConfigDigest, RecipientEpoch: v.RecipientEpoch, PreviousActivation: 0, EqualityEpoch: v.EqualityEpoch, Prefix: prefix})
	if err != nil {
		return contract.Command{}, err
	}
	return contract.Command{Kind: "activate_key_epoch", ClusterUID: v.ClusterUID, PrincipalID: r.attempt.snapshot.principal, RequestID: request, Body: body}, nil
}
func (r *AutomationCustodyReady) persistActivationCommand(c contract.Command) error {
	candidate := r.record.Members[0].Recipient.Candidate
	store, err := r.owner.openStore(custodyScope(candidate.ClusterUID, candidate.Source), false)
	if err != nil {
		return err
	}
	ref := r.attempt.plan
	ref.Voter.KeyID = c.RequestID
	raw, err := custodyProtocolEncode(c)
	if err != nil {
		return err
	}
	return store.SaveProvisionRecord(ref, "plan", raw)
}

// AdvanceActivation ends an unchosen intent only after looking up its original.
// It reserves a new inert request, never changes an existing request's body.
func (r *AutomationCustodyReady) AdvanceActivation(ctx context.Context) (contract.Command, error) {
	if r == nil {
		return contract.Command{}, errAutomationAuthority
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.self != r || r.owner == nil || r.historical != nil || r.activationCommand == nil || r.ctx == nil || r.ctx.Err() != nil || ctx.Err() != nil || !time.Now().Before(r.expires) {
		return contract.Command{}, errAutomationAuthority
	}
	old := *r.activationCommand
	body, err := contract.DecodeActivateKeyEpochBody(old)
	if err != nil {
		return contract.Command{}, err
	}
	var prefix contract.HistoryReference
	err = r.owner.client.ExecuteLocal(ctx, func(tx *LocalTx) error {
		original, err := automationRequestTx(ctx, tx, AutomationScope(contract.Decision{Command: old}), old.RequestID)
		if err != nil {
			return err
		}
		if original != nil {
			return errAutomationAuthority
		}
		snap, err := r.owner.snapshotTx(ctx, tx)
		if err != nil {
			return err
		}
		for _, member := range r.record.Members {
			if !custodyCandidateMatches(snap, member.Recipient.Candidate) {
				return errAutomationAuthority
			}
		}
		prefix = contract.HistoryReference{Sequence: snap.head.Sequence, Digest: snap.head.Digest}
		if prefix == body.Prefix {
			return errAutomationAuthority
		}
		return nil
	})
	if err != nil {
		return contract.Command{}, err
	}
	request, err := custodyRandomID()
	if err != nil {
		return contract.Command{}, err
	}
	c, err := r.activationCommandFor(prefix, request)
	if err != nil {
		return contract.Command{}, err
	}
	if err = r.persistActivationCommand(c); err != nil {
		return contract.Command{}, err
	}
	r.activationCommand = &c
	c.Body = append([]byte(nil), c.Body...)
	return c, nil
}

func (p *AutomationCustodyProducer) PrepareInitialActivation(ctx context.Context, r *AutomationCustodyReady, imported contract.HistoryReference, base contract.Decision) (ClaimValue, *AutomationKeyAdmission, error) {
	if p == nil || r == nil || base.Sequence == 0 || imported.Sequence == 0 || imported.Sequence >= base.Sequence {
		return ClaimValue{}, nil, errAutomationAuthority
	}
	expected, err := r.ActivationCommand(contract.HistoryReference{Sequence: base.Sequence - 1, Digest: base.ParentDigest})
	if err != nil {
		return ClaimValue{}, nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.self != r || r.owner != p || r.historical != nil || r.ctx == nil || r.ctx.Err() != nil || ctx.Err() != nil || !time.Now().Before(r.expires) {
		return ClaimValue{}, nil, errAutomationAuthority
	}
	body, err := contract.DecodeActivateKeyEpochBody(base.Command)
	if err != nil || body.Prefix != (contract.HistoryReference{Sequence: base.Sequence - 1, Digest: base.ParentDigest}) {
		return ClaimValue{}, nil, errAutomationAuthority
	}
	expectedIdentity, err := contract.CanonicalCommand(expected)
	if err != nil {
		return ClaimValue{}, nil, err
	}
	actualIdentity, err := contract.CanonicalCommand(base.Command)
	if err != nil || !bytes.Equal(expectedIdentity, actualIdentity) || base.Command.RequestID != expected.RequestID {
		return ClaimValue{}, nil, errAutomationAuthority
	}
	facts := &contract.KeyTransitionAssignment{Class: "bootstrap", Bootstrap: &r.record.Genesis}
	for _, member := range r.record.Members {
		facts.Recipients = append(facts.Recipients, contract.CustodyRecipientBinding(member.Recipient, imported))
	}
	operation, err := custodyRandomID()
	if err != nil {
		return ClaimValue{}, nil, err
	}
	base.Assignment, err = custodyProtocolEncode(contract.Assignment{Version: 4, ClusterUID: r.record.ClusterUID, OperationID: operation, RecordedAt: time.Now().UTC().Format(time.RFC3339Nano), KeyTransition: facts})
	if err != nil {
		return ClaimValue{}, nil, err
	}
	encoded, err := contract.EncodeDecision(base)
	if err != nil {
		return ClaimValue{}, nil, err
	}
	value := ClaimValue{Automation: &AutomationClaimValue{Envelope: encoded}}
	proof, err := p.prepareKeyProof(ctx, r, base, value, imported)
	if err != nil {
		return ClaimValue{}, nil, err
	}
	admission := &AutomationKeyAdmission{proof: proof}
	admission.self = admission
	return value, admission, nil
}

// These methods retain the actual native owner; no caller can substitute one.
func (r *AutomationCustodyReady) UsesClient(c *Client) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.self == r && r.owner != nil && r.owner.client == c
}
func (r *AutomationCustodyReady) preparationOwner() *AutomationCustodyProducer {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.self != r {
		return nil
	}
	return r.owner
}
func (r *AutomationCustodyReady) PrepareImport(ctx context.Context, base contract.Decision) (ClaimValue, *AutomationKeyAdmission, error) {
	return r.preparationOwner().PrepareCustodyValue(ctx, r, base)
}
func (r *AutomationCustodyReady) PrepareActivation(ctx context.Context, imported contract.HistoryReference, base contract.Decision) (ClaimValue, *AutomationKeyAdmission, error) {
	return r.preparationOwner().PrepareInitialActivation(ctx, r, imported, base)
}

// ConfirmActivationOriginal verifies a selected historical result against the
// actual local authority/original anchors and this attempt's exact key/import
// facts. It updates inert retry identity only and issues no native admission.
func (r *AutomationCustodyReady) ConfirmActivationOriginal(ctx context.Context, imported contract.HistoryReference, receipt contract.Receipt, d contract.Decision) error {
	if r == nil {
		return errAutomationAuthority
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.self != r || r.owner == nil || r.attempt == nil || ctx.Err() != nil || receipt.Code != "" || receipt.Sequence != d.Sequence || receipt.RequestID != d.Command.RequestID || imported.Sequence == 0 || imported.Sequence >= d.Sequence {
		return errAutomationAuthority
	}
	body, err := contract.DecodeActivateKeyEpochBody(d.Command)
	if err != nil || body.Prefix != (contract.HistoryReference{Sequence: d.Sequence - 1, Digest: d.ParentDigest}) {
		return errAutomationAuthority
	}
	expected, err := r.activationCommandFor(body.Prefix, d.Command.RequestID)
	if err != nil {
		return err
	}
	identity, err := contract.CanonicalCommand(d.Command)
	if err != nil {
		return err
	}
	expectedIdentity, err := contract.CanonicalCommand(expected)
	if err != nil || !bytes.Equal(identity, expectedIdentity) {
		return errAutomationAuthority
	}
	a, err := contract.DecodeAssignment(d)
	if err != nil || a.Version != contract.CustodyAssignmentVersion || a.ClusterUID != r.record.ClusterUID || receipt.OperationID != a.OperationID {
		return errAutomationAuthority
	}
	facts := &contract.KeyTransitionAssignment{Class: "bootstrap", Bootstrap: &r.record.Genesis}
	for _, member := range r.record.Members {
		facts.Recipients = append(facts.Recipients, contract.CustodyRecipientBinding(member.Recipient, imported))
	}
	actualFacts, err := custodyProtocolEncode(a.KeyTransition)
	if err != nil {
		return err
	}
	expectedFacts, err := custodyProtocolEncode(facts)
	if err != nil || !bytes.Equal(actualFacts, expectedFacts) {
		return errAutomationAuthority
	}
	encoded, err := contract.EncodeDecision(d)
	if err != nil {
		return err
	}
	value := ClaimValue{Automation: &AutomationClaimValue{Envelope: encoded}}
	digest, err := value.Digest()
	if err != nil {
		return err
	}
	record, err := custodyProtocolEncode(r.record)
	if err != nil {
		return err
	}
	err = r.owner.client.ExecuteLocal(ctx, func(tx *LocalTx) error {
		standing, e := readStandingTx(ctx, tx, r.owner.client.hostName)
		if e != nil {
			return e
		}
		if _, e = automationAuthorityTx(ctx, tx, r.owner.client.hostName, standing.adopted); e != nil {
			return e
		}
		head, e := automationHeadTx(ctx, tx)
		if e != nil {
			return e
		}
		retained, e := automationRetainedHeadTx(ctx, tx)
		if e != nil || head != retained || head.Sequence < d.Sequence {
			return errAutomationAuthority
		}
		trusted, found, e := automationTrustedDigestTx(ctx, tx, d.Sequence)
		if e != nil || !found || trusted != digest {
			return errAutomationAuthority
		}
		trusted, found, e = automationTrustedDigestTx(ctx, tx, imported.Sequence)
		if e != nil || !found || trusted != imported.Digest {
			return errAutomationAuthority
		}
		summary, e := (localAutomationKeySource{tx}).keyHistory(ctx, imported.Sequence)
		if e != nil || summary.Kind != contract.CustodyImportCommand || summary.CustodyImport == nil || summary.CustodyImport.RecordDigest != contract.CiphertextDigest(record) {
			return errAutomationAuthority
		}
		original, e := automationRequestTx(ctx, tx, AutomationScope(d), d.Command.RequestID)
		if e != nil || original == nil || original.Receipt != receipt || !bytes.Equal(original.Identity, identity) {
			return errAutomationAuthority
		}
		return requireAutomationFull(ctx, tx)
	})
	if err != nil {
		return err
	}
	command := d.Command
	command.Body = append([]byte(nil), command.Body...)
	r.activationCommand = &command
	return nil
}

// custodyCertifiedOriginal is authenticated result data, never native authority.
type custodyCertifiedOriginal struct {
	imported contract.HistoryReference
	receipt  contract.Receipt
	decision contract.Decision
}

// CertifiedActivation returns only an exact already-certified original. A
// resumed historical handle cannot enter the proposer or issue a native vote.
func (r *AutomationCustodyReady) CertifiedActivation(ctx context.Context) (contract.Receipt, contract.Decision, bool, error) {
	if r == nil {
		return contract.Receipt{}, contract.Decision{}, false, errAutomationAuthority
	}
	r.mu.Lock()
	if r.self != r || r.owner == nil {
		r.mu.Unlock()
		return contract.Receipt{}, contract.Decision{}, false, errAutomationAuthority
	}
	h := r.historical
	if h == nil {
		r.mu.Unlock()
		return contract.Receipt{}, contract.Decision{}, false, nil
	}
	original := *h
	original.decision.Command.Body = append([]byte(nil), h.decision.Command.Body...)
	original.decision.Assignment = append([]byte(nil), h.decision.Assignment...)
	r.mu.Unlock()
	if err := r.ConfirmActivationOriginal(ctx, original.imported, original.receipt, original.decision); err != nil {
		return contract.Receipt{}, contract.Decision{}, true, err
	}
	return original.receipt, original.decision, true, nil
}

// The projection supplies a sequence hint only. Both actual majority
// certificates, trusted anchors, exact originals and complete immutable plan
// bindings must authenticate before this produces a historical result.
func (p *AutomationCustodyProducer) recoverCertifiedInitialEpoch(ctx context.Context, attempt *AutomationInitialEpoch) (*AutomationCustodyReady, error) {
	candidate := attempt.candidates[0]
	verifier, err := LoadClaimVerifier(p.pkiDir)
	if err != nil {
		return nil, err
	}
	var ready *AutomationCustodyReady
	var historical custodyCertifiedOriginal
	err = p.client.ExecuteLocal(ctx, func(tx *LocalTx) error {
		rows, e := tx.Query(ctx, `SELECT activation_sequence FROM local_automation_key_epochs WHERE stage='' AND cluster_uid=? AND recipient_epoch=? LIMIT 1`, candidate.ClusterUID, candidate.RecipientEpoch)
		if e != nil || len(rows) == 0 {
			return e
		}
		sequence := rows[0].Int64("activation_sequence")
		if sequence <= 0 {
			return errAutomationAuthority
		}
		decision, receipt, e := custodyCertifiedRecordTx(ctx, tx, uint64(sequence), attempt.snapshot.cfg, verifier)
		if e != nil {
			return e
		}
		assignment, e := contract.DecodeAssignment(decision)
		if e != nil || decision.Command.Kind != "activate_key_epoch" || assignment.Version != contract.CustodyAssignmentVersion || assignment.KeyTransition == nil || len(assignment.KeyTransition.Recipients) == 0 {
			return errAutomationAuthority
		}
		imported := assignment.KeyTransition.Recipients[0].RecipientAck
		importDecision, importReceipt, e := custodyCertifiedRecordTx(ctx, tx, imported.Sequence, attempt.snapshot.cfg, verifier)
		if e != nil {
			return e
		}
		importAssignment, e := contract.DecodeAssignment(importDecision)
		if e != nil || importDecision.Command.Kind != contract.CustodyImportCommand || importDecision.Command.RequestID != attempt.importRequest || importAssignment.CustodyImport == nil || importReceipt.Code != "" {
			return errAutomationAuthority
		}
		record := *importAssignment.CustodyImport
		if len(record.Members) != len(attempt.candidates) {
			return errAutomationAuthority
		}
		for i, member := range record.Members {
			if member.Recipient.Candidate != attempt.candidates[i] || member.Completion.Candidate != attempt.candidates[i] {
				return errAutomationAuthority
			}
		}
		ready = &AutomationCustodyReady{owner: p, attempt: attempt, ctx: attempt.ctx, expires: attempt.expires, record: record}
		ready.self = ready
		expected, e := ready.ImportCommand()
		if e != nil {
			return e
		}
		actualID, e := contract.CanonicalCommand(importDecision.Command)
		if e != nil {
			return e
		}
		expectedID, e := contract.CanonicalCommand(expected)
		if e != nil || !bytes.Equal(actualID, expectedID) {
			return errAutomationAuthority
		}
		historical = custodyCertifiedOriginal{imported: imported, receipt: receipt, decision: decision}
		return requireAutomationFull(ctx, tx)
	})
	if err != nil || ready == nil {
		return nil, err
	}
	if err = ready.ConfirmActivationOriginal(ctx, historical.imported, historical.receipt, historical.decision); err != nil {
		return nil, err
	}
	ready.historical = &historical
	return ready, nil
}

func custodyCertifiedRecordTx(ctx context.Context, tx *LocalTx, sequence uint64, cfg *VoterConfig, verifier *ClaimVerifier) (contract.Decision, contract.Receipt, error) {
	var zero contract.Decision
	var noReceipt contract.Receipt
	// Existing history adapter probes all record lengths and checks typed imports.
	summary, err := (localAutomationKeySource{tx}).keyHistory(ctx, sequence)
	if err != nil {
		return zero, noReceipt, err
	}
	rows, err := tx.Query(ctx, `SELECT value_json,certificate,receipt_json FROM local_automation_history WHERE sequence=? LIMIT 1`, sequence)
	if err != nil || len(rows) != 1 {
		return zero, noReceipt, errAutomationAuthority
	}
	var value ClaimValue
	key, err := AutomationClaimKey(sequence)
	if err != nil {
		return zero, noReceipt, err
	}
	if err = decodeClaimValue(key, rows[0].String("value_json"), &value); err != nil {
		return zero, noReceipt, err
	}
	decision, err := automationDecision(value)
	if err != nil {
		return zero, noReceipt, err
	}
	certificate, err := sourceCertificate(rows[0].String("certificate"))
	if err != nil {
		return zero, noReceipt, err
	}
	if err = verifier.Verify(certificate, CertExpectation{Key: key, ValueDigest: summary.Digest, ConfigGeneration: cfg.Generation, Electorate: cfg.Members, Quorum: MajorityOf(len(cfg.Members))}); err != nil {
		return zero, noReceipt, err
	}
	trusted, found, err := automationTrustedDigestTx(ctx, tx, sequence)
	if err != nil || !found || trusted != summary.Digest {
		return zero, noReceipt, errAutomationAuthority
	}
	var receipt contract.Receipt
	if retainedCanonical([]byte(rows[0].String("receipt_json")), maxRetainedReceiptBytes, &receipt) != nil || receipt.Code != "" || receipt.Sequence != sequence || receipt.RequestID != decision.Command.RequestID {
		return zero, noReceipt, errAutomationAuthority
	}
	original, err := automationRequestTx(ctx, tx, AutomationScope(decision), decision.Command.RequestID)
	identity, e := contract.CanonicalCommand(decision.Command)
	if err != nil || e != nil || original == nil || original.Receipt != receipt || !bytes.Equal(original.Identity, identity) {
		return zero, noReceipt, errAutomationAuthority
	}
	return decision, receipt, nil
}
