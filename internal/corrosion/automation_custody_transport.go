package corrosion

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/automation/custody"
	"github.com/litevirt/litevirt/internal/pki"
)

const CustodyProvisionRequestVersion = 1
const maxCustodyProtocolBytes = 1 << 20
const custodyRecipientDomain = "litevirt/automation/custody-recipient/v1\x00"
const custodyCompletionDomain = "litevirt/automation/custody-import-completion/v1\x00"

type CustodyProvisionRequest struct {
	Version       int                                 `json:"version"`
	Purpose       string                              `json:"purpose"`
	Candidate     contract.CustodyCandidate           `json:"candidate"`
	Recipient     *contract.CustodyRecipientStatement `json:"recipient,omitempty"`
	CapsuleDigest string                              `json:"capsule_digest,omitempty"`
}

func custodyProtocolEncode(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil || len(b) > maxCustodyProtocolBytes {
		return nil, errAutomationAuthority
	}
	return b, nil
}
func custodyProtocolDecode(b []byte, v any) error {
	if len(b) == 0 || len(b) > maxCustodyProtocolBytes {
		return errAutomationAuthority
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return errAutomationAuthority
	}
	canonical, err := custodyProtocolEncode(v)
	if err != nil || !bytes.Equal(b, canonical) {
		return errAutomationAuthority
	}
	return nil
}
func decodeCustodyRequest(raw []byte, purpose string) (CustodyProvisionRequest, error) {
	var r CustodyProvisionRequest
	if custodyProtocolDecode(raw, &r) != nil || r.Version != CustodyProvisionRequestVersion || r.Purpose != purpose || contract.ValidateCustodyCandidate(r.Candidate) != nil {
		return r, errAutomationAuthority
	}
	switch purpose {
	case "automation-custody-recipient-request":
		if r.Recipient != nil || r.CapsuleDigest != "" {
			return r, errAutomationAuthority
		}
	case "automation-custody-equality-request":
		if r.Recipient == nil || r.Recipient.Candidate != r.Candidate || !receiverDigest(r.CapsuleDigest) {
			return r, errAutomationAuthority
		}
	default:
		return r, errAutomationAuthority
	}
	return r, nil
}
func custodyCandidateMatches(s custodySnapshot, c contract.CustodyCandidate) bool {
	return s.head.ClusterUID == c.ClusterUID && s.cfg.Generation == int64(c.MembershipGeneration) && s.cfg.MembersHash == c.ConfigDigest && s.genesis == c.Genesis && s.hosts[c.Source.Host].binding == c.Source && s.hosts[c.Target.Host].binding == c.Target
}

type custodyLive struct {
	producer    *AutomationCustodyProducer
	candidate   contract.CustodyCandidate
	view        *pki.HostTrust
	pair        *tls.Certificate
	sourceChain [][]byte
	lease       *pki.HostCertificateLease
	expires     time.Time
}

func (p *AutomationCustodyProducer) beginCustody(ctx context.Context, c contract.CustodyCandidate, peerLeaf []byte) (*custodyLive, error) {
	if p == nil || p.client == nil || c.Target.Host != p.client.hostName || contract.ValidateCustodyCandidate(c) != nil {
		return nil, errAutomationAuthority
	}
	expires, err := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if err != nil || ctx.Err() != nil || !time.Now().Before(expires) || time.Until(expires) > sourcePreparationLifetime {
		return nil, errAutomationAuthority
	}
	var snap custodySnapshot
	if err = p.client.ExecuteLocal(ctx, func(tx *LocalTx) error { var err error; snap, err = p.snapshotTx(ctx, tx); return err }); err != nil || !custodyCandidateMatches(snap, c) {
		return nil, errAutomationAuthority
	}
	var sourceChain [][]byte
	if c.Source.Host != p.client.hostName {
		if len(peerLeaf) == 0 {
			return nil, errAutomationAuthority
		}
		response, source, err := sourceQueryPeer(ctx, p.pkiDir, snap.hosts[c.Source.Host].endpoint, int64(c.MembershipGeneration), false)
		if err != nil || response.GetAdoptedGeneration() != int64(c.MembershipGeneration) || source.Incarnation != c.Source.VoterIncarnation || len(source.Chain) == 0 || !bytes.Equal(source.Chain[0], peerLeaf) {
			return nil, errAutomationAuthority
		}
		sourceChain = source.Chain
	} else if len(peerLeaf) != 0 {
		return nil, errAutomationAuthority
	}
	view, pair, self, err := p.localTrust(ctx)
	if err != nil {
		return nil, err
	}
	caps := []*pki.HostCertificateValidation{self}
	success := false
	defer func() {
		if !success {
			for _, cap := range caps {
				cap.Discard()
			}
		}
	}()
	if c.Source.Host == p.client.hostName {
		sourceChain = pair.Certificate
	} else {
		cap, err := view.ValidateHostCertificate(ctx, sourceChain, c.Source.Host)
		if err != nil {
			return nil, err
		}
		caps = append(caps, cap)
	}
	if sourceAdmission(view, snap.hosts[c.Target.Host].endpoint, pair.Certificate[0]) != nil || sourceAdmission(view, snap.hosts[c.Source.Host].endpoint, sourceChain[0]) != nil {
		return nil, errAutomationAuthority
	}
	lease, err := pki.AcquireHostCertificateLease(ctx, p.pkiDir, caps...)
	if err != nil {
		return nil, err
	}
	success = true
	return &custodyLive{producer: p, candidate: c, view: view, pair: pair, sourceChain: sourceChain, lease: lease, expires: expires}, nil
}
func (l *custodyLive) checkTx(ctx context.Context, tx *LocalTx) error {
	if ctx.Err() != nil || !time.Now().Before(l.expires) || l.lease.Check() != nil {
		return errAutomationAuthority
	}
	s, err := l.producer.snapshotTx(ctx, tx)
	if err != nil || !custodyCandidateMatches(s, l.candidate) {
		return errAutomationAuthority
	}
	if sourceAdmission(l.view, s.hosts[l.candidate.Source.Host].endpoint, l.sourceChain[0]) != nil || sourceAdmission(l.view, s.hosts[l.candidate.Target.Host].endpoint, l.pair.Certificate[0]) != nil {
		return errAutomationAuthority
	}
	return nil
}
func (l *custodyLive) barrier(ctx context.Context, physical func() error) error {
	p := l.producer
	old := p.client.automationSeams
	seams := &localCommitSeams{beforeCommit: func(tx *sql.Tx) error {
		if old != nil && old.beforeCommit != nil {
			if err := old.beforeCommit(tx); err != nil {
				return err
			}
		}
		if err := l.checkTx(ctx, &LocalTx{tx: tx}); err != nil {
			return err
		}
		return physical()
	}}
	if old != nil {
		seams.afterCommit = old.afterCommit
	}
	err := p.client.executeLocal(ctx, func(tx *LocalTx) error { return l.checkTx(ctx, tx) }, seams)
	if err == nil && old != nil && old.beforeReply != nil {
		old.beforeReply()
	}
	return err
}
func custodySign(pair *tls.Certificate, domain string, body []byte) ([]byte, error) {
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errAutomationAuthority
	}
	hash := sha256.Sum256(append([]byte(domain), body...))
	signature, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		return nil, errAutomationAuthority
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, errAutomationAuthority
	}
	public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !ecdsa.VerifyASN1(public, hash[:], signature) {
		return nil, errAutomationAuthority
	}
	return signature, nil
}
func custodyVerifyTranscript(domain string, body, signature []byte, chain [][]byte, trust []byte, host contract.CustodyHost, recorded string) error {
	evidence, err := pki.DecodeHostTrustEvidence(trust)
	if err != nil {
		return errAutomationAuthority
	}
	at, err := time.Parse(time.RFC3339Nano, recorded)
	if err != nil {
		return errAutomationAuthority
	}
	if err = evidence.VerifyRecordedCustodyAt(chain, host.Host, host.AdmissionSerial, at); err != nil {
		return errAutomationAuthority
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return errAutomationAuthority
	}
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	hash := sha256.Sum256(append([]byte(domain), body...))
	if !ok || !ecdsa.VerifyASN1(key, hash[:], signature) {
		return errAutomationAuthority
	}
	return nil
}
func verifyCustodyRecipient(s contract.CustodyRecipientStatement) error {
	if contract.ValidateCustodyRecipient(s) != nil {
		return errAutomationAuthority
	}
	signature := s.Signature
	s.Signature = nil
	body, err := custodyProtocolEncode(s)
	if err != nil {
		return err
	}
	return custodyVerifyTranscript(custodyRecipientDomain, body, signature, s.Chain, s.Trust, s.Candidate.Target, s.RecordedAt)
}
func verifyCustodyCompletion(s contract.CustodyImportCompletion, r contract.CustodyRecipientStatement) error {
	if contract.ValidateCustodyCompletion(s) != nil || verifyCustodyRecipient(r) != nil || s.Candidate != r.Candidate || s.Recipient != r.Recipient {
		return errAutomationAuthority
	}
	recipient, err := custodyProtocolEncode(r)
	if err != nil || s.RecipientDigest != contract.CiphertextDigest(recipient) {
		return errAutomationAuthority
	}
	signature := s.Signature
	s.Signature = nil
	body, err := custodyProtocolEncode(s)
	if err != nil {
		return err
	}
	return custodyVerifyTranscript(custodyCompletionDomain, body, signature, s.Chain, s.Trust, s.Candidate.Target, s.RecordedAt)
}
func (p *AutomationCustodyProducer) PrepareCustodyRecipient(ctx context.Context, request, peerLeaf []byte) (out []byte, err error) {
	defer func() {
		if err != nil {
			out = nil
			err = errAutomationAuthority
		}
	}()
	r, err := decodeCustodyRequest(request, "automation-custody-recipient-request")
	if err != nil {
		return nil, err
	}
	live, err := p.beginCustody(ctx, r.Candidate, peerLeaf)
	if err != nil {
		return nil, err
	}
	defer live.lease.Release()
	store, err := p.openStore(custodyScope(r.Candidate.ClusterUID, r.Candidate.Target), true)
	if err != nil {
		return nil, err
	}
	ref := custodyProvisionRef(r.Candidate)
	voterRef, _, _ := custodyRefs(r.Candidate)
	exists, err := store.HasProvisionRecord(ref, "recipient")
	if err != nil {
		return nil, err
	}
	var statement contract.CustodyRecipientStatement
	if exists {
		out, err = store.ReadProvisionRecord(ref, "recipient")
		if err != nil || custodyProtocolDecode(out, &statement) != nil || verifyCustodyRecipient(statement) != nil || statement.Candidate != r.Candidate || !bytes.Equal(statement.Chain[0], live.pair.Certificate[0]) {
			return nil, errAutomationAuthority
		}
	} else {
		key, err := store.CreateVoterIdentity(voterRef)
		if errors.Is(err, custody.ErrCustodyConflict) {
			return nil, custody.ErrCustodyRecoveryRequired
		}
		if err != nil {
			return nil, err
		}
		trust, err := live.view.PublicEvidence()
		if err != nil {
			return nil, err
		}
		chain, err := cloneSourceChain(live.pair.Certificate)
		if err != nil {
			return nil, err
		}
		statement = contract.CustodyRecipientStatement{Version: 1, Purpose: "automation-custody-recipient", Candidate: r.Candidate, Recipient: key.Recipient(), RecordedAt: time.Now().UTC().Format(time.RFC3339Nano), Chain: chain, Trust: trust}
		body, err := custodyProtocolEncode(statement)
		if err != nil {
			return nil, err
		}
		statement.Signature, err = custodySign(live.pair, custodyRecipientDomain, body)
		if err != nil {
			return nil, err
		}
		if verifyCustodyRecipient(statement) != nil {
			return nil, errAutomationAuthority
		}
		out, err = custodyProtocolEncode(statement)
		if err != nil {
			return nil, err
		}
		if err = store.SaveProvisionRecord(ref, "recipient", out); err != nil {
			return nil, err
		}
	}
	if err = live.barrier(ctx, func() error { _, err := store.OpenVoterIdentity(voterRef, statement.Recipient); return err }); err != nil {
		return nil, err
	}
	return out, nil
}
func custodyImportBinding(c contract.CustodyCandidate, recipient string) custody.EqualityImportBinding {
	voter, source, target := custodyRefs(c)
	return custody.EqualityImportBinding{Source: custodyScope(c.ClusterUID, c.Source), Target: custodyScope(c.ClusterUID, c.Target), SourceVoter: c.Source.VoterIncarnation, TargetVoter: c.Target.VoterIncarnation, VoterRef: voter, SourceEquality: source, TargetEquality: target, Recipient: recipient, Attempt: c.Attempt, ExpiresAt: c.ExpiresAt}
}
func (p *AutomationCustodyProducer) CompleteCustodyImport(ctx context.Context, request, capsule, peerLeaf []byte) (out []byte, err error) {
	defer func() {
		if err != nil {
			out = nil
			err = errAutomationAuthority
		}
	}()
	r, err := decodeCustodyRequest(request, "automation-custody-equality-request")
	if err != nil || len(capsule) == 0 || len(capsule) > 65536 || contract.CiphertextDigest(capsule) != r.CapsuleDigest || verifyCustodyRecipient(*r.Recipient) != nil {
		return nil, errAutomationAuthority
	}
	live, err := p.beginCustody(ctx, r.Candidate, peerLeaf)
	if err != nil {
		return nil, err
	}
	defer live.lease.Release()
	store, err := p.openStore(custodyScope(r.Candidate.ClusterUID, r.Candidate.Target), false)
	if err != nil {
		return nil, err
	}
	ref := custodyProvisionRef(r.Candidate)
	recipient, err := custodyProtocolEncode(r.Recipient)
	if err != nil {
		return nil, err
	}
	original, err := store.ReadProvisionRecord(ref, "recipient")
	if err != nil || !bytes.Equal(recipient, original) || !bytes.Equal(r.Recipient.Chain[0], live.pair.Certificate[0]) {
		return nil, errAutomationAuthority
	}
	voterRef, _, targetRef := custodyRefs(r.Candidate)
	if err = store.ImportSealedEquality(voterRef, r.Recipient.Recipient, targetRef, custodyImportBinding(r.Candidate, r.Recipient.Recipient), capsule); err != nil {
		return nil, err
	}
	exists, err := store.HasProvisionRecord(ref, "completion")
	if err != nil {
		return nil, err
	}
	var completion contract.CustodyImportCompletion
	if exists {
		out, err = store.ReadProvisionRecord(ref, "completion")
		if err != nil || custodyProtocolDecode(out, &completion) != nil || verifyCustodyCompletion(completion, *r.Recipient) != nil || completion.CapsuleDigest != r.CapsuleDigest || !bytes.Equal(completion.Chain[0], live.pair.Certificate[0]) {
			return nil, errAutomationAuthority
		}
	} else {
		trust, err := live.view.PublicEvidence()
		if err != nil {
			return nil, err
		}
		chain, err := cloneSourceChain(live.pair.Certificate)
		if err != nil {
			return nil, err
		}
		completion = contract.CustodyImportCompletion{Version: 1, Purpose: "automation-custody-import-completion", Candidate: r.Candidate, Recipient: r.Recipient.Recipient, RecipientDigest: contract.CiphertextDigest(recipient), CapsuleDigest: r.CapsuleDigest, RecordedAt: time.Now().UTC().Format(time.RFC3339Nano), Chain: chain, Trust: trust}
		body, err := custodyProtocolEncode(completion)
		if err != nil {
			return nil, err
		}
		completion.Signature, err = custodySign(live.pair, custodyCompletionDomain, body)
		if err != nil {
			return nil, err
		}
		if verifyCustodyCompletion(completion, *r.Recipient) != nil {
			return nil, errAutomationAuthority
		}
		out, err = custodyProtocolEncode(completion)
		if err != nil {
			return nil, err
		}
		if err = store.SaveProvisionRecord(ref, "completion", out); err != nil {
			return nil, err
		}
	}
	if err = live.barrier(ctx, func() error {
		if _, err := store.OpenVoterIdentity(voterRef, r.Recipient.Recipient); err != nil {
			return err
		}
		_, err := store.OpenEqualityKey(targetRef)
		return err
	}); err != nil {
		return nil, err
	}
	return out, nil
}
