package corrosion

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/litevirt/litevirt/internal/pki"
)

const receiverEstablishedDomain = "litevirt/receiver-established/v1"
const maxReceiverEstablishedManifest = 4096

// JSON's base64 encoding is included, along with finite per-chain framing.
const maxReceiverEstablishedBytes = 4*((pki.MaxHostTrustEvidenceBytes+2*maxSourceChainBytes+maxReceiverEstablishedManifest+256+2)/3) + 2048

type receiverEstablishedManifest struct {
	Version                                                                                               int
	Purpose, Attempt, Binding, Host, Incarnation, Root, Validation, SigningEvidence, Chain, OriginalChain string
}
type receiverEstablishedArtifact struct {
	Manifest, Evidence   []byte
	Chain, OriginalChain [][]byte
	Signature            []byte
}
type receiverEstablished struct {
	manifest         receiverEstablishedManifest
	original, signer *pki.HostTrustEvidence
	originalChain    [][]byte
}

// Preparation is outside SQL and the PKI lease. The real current owner validates
// the served pair; storage must subsequently acquire a fresh lease and recheck
// every original and exact selection before inserting any prepared artifact.
func (r *AutomationReceiver) prepareEstablishment(ctx context.Context, a *AutomationReceiverAttempt, original []byte) ([]byte, error) {
	if a == nil || a.self != a || a.owner != r || a.pair == nil || a.view == nil {
		return nil, errors.New("foreign receiver establishment owner")
	}
	binding, err := decodeReceiverBinding(a.id, a.request.Job, a.request.Revision, a.binding)
	if err != nil {
		return nil, err
	}
	return r.prepareEstablishmentFor(ctx, a, binding, original)
}

func (r *AutomationReceiver) prepareEstablishmentFor(ctx context.Context, a *AutomationReceiverAttempt, binding *receiverPredecessor, original []byte) ([]byte, error) {
	if a == nil || a.self != a || a.owner != r || a.pair == nil || a.view == nil || binding == nil || binding.value.Intent.Target != r.client.hostName || binding.value.Facts.Incarnation != a.facts.Incarnation {
		return nil, errors.New("receiver establishment current local identity differs")
	}
	evidence, err := pki.DecodeHostTrustEvidence(original)
	if err != nil {
		return nil, err
	}
	var originalChain [][]byte
	if evidence.Digest() == a.view.EvidenceDigest() {
		originalChain = a.pair.Certificate
	} else {
		leaf, e := evidence.RecordedLocalHost(r.client.hostName)
		if e != nil {
			return nil, e
		}
		originalChain = [][]byte{leaf.Raw}
	}
	return r.prepareEstablishmentChain(ctx, a, binding, original, originalChain)
}
func (r *AutomationReceiver) prepareEstablishmentChain(ctx context.Context, a *AutomationReceiverAttempt, binding *receiverPredecessor, original []byte, originalChain [][]byte) ([]byte, error) {
	if a == nil || a.self != a || a.owner != r || a.view == nil || a.pair == nil || binding == nil || binding.value.Intent.Target != r.client.hostName || binding.value.Facts.Incarnation != a.facts.Incarnation {
		return nil, errors.New("receiver establishment current local identity differs")
	}
	evidence, err := pki.DecodeHostTrustEvidence(original)
	if err != nil {
		return nil, err
	}
	if err = evidence.VerifyRecordedHost(originalChain, r.client.hostName); err != nil {
		return nil, err
	}
	root := evidence.RootDigest()
	if binding.value.Root != hex.EncodeToString(root[:]) || a.view.RootDigest() != root {
		return nil, errors.New("receiver establishment local domain differs")
	}
	if err = sourceAdmission(a.view, a.facts.Target, a.pair.Certificate[0]); err != nil {
		return nil, err
	}
	cap, err := a.view.ValidateServedHost(ctx, a.pair)
	if err != nil {
		return nil, err
	}
	cap.Discard()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	signerEvidence, err := a.view.PublicEvidence()
	if err != nil {
		return nil, err
	}
	validation, signing := evidence.Digest(), a.view.EvidenceDigest()
	m := receiverEstablishedManifest{1, receiverEstablishedDomain, binding.id, sourceDigest(binding.binding), r.client.hostName, binding.value.Facts.Incarnation, hex.EncodeToString(root[:]), hex.EncodeToString(validation[:]), hex.EncodeToString(signing[:]), sourceDigest(a.pair.Certificate...), sourceDigest(originalChain...)}
	manifest, err := json.Marshal(m)
	if err != nil || len(manifest) > maxReceiverEstablishedManifest {
		return nil, errors.New("receiver establishment manifest bound")
	}
	key, ok := a.pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("receiver establishment key is not ECDSA")
	}
	digest, _ := hex.DecodeString(sourceDigest([]byte(receiverEstablishedDomain), manifest))
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(receiverEstablishedArtifact{Manifest: manifest, Evidence: signerEvidence, Chain: a.pair.Certificate, OriginalChain: originalChain, Signature: signature})
	if err != nil {
		return nil, err
	}
	if _, err = decodeReceiverEstablished(raw, binding, original, r.client.hostName); err != nil {
		return nil, err
	}
	return raw, nil
}

// Authentication is historical only. It proves the local owner signed the exact
// original validation for the exact durable job; it cannot resurrect a process
// proof or authorize current work. Call only outside SQL and the PKI lease.
func decodeReceiverEstablished(raw []byte, binding *receiverPredecessor, original []byte, host string) (*receiverEstablished, error) {
	if binding == nil || len(raw) == 0 || len(raw) > maxReceiverEstablishedBytes || len(original) > pki.MaxHostTrustEvidenceBytes {
		return nil, errors.New("receiver establishment native bounds")
	}
	var signed receiverEstablishedArtifact
	if err := json.Unmarshal(raw, &signed); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(signed)
	if err != nil || !bytes.Equal(canonical, raw) || len(signed.Manifest) > maxReceiverEstablishedManifest || len(signed.Evidence) > pki.MaxHostTrustEvidenceBytes || len(signed.Signature) == 0 || len(signed.Signature) > 256 || sourceChainBounds(signed.Chain) != nil || sourceChainBounds(signed.OriginalChain) != nil {
		return nil, errors.New("receiver establishment noncanonical artifact")
	}
	var m receiverEstablishedManifest
	if err = json.Unmarshal(signed.Manifest, &m); err != nil {
		return nil, err
	}
	canonical, err = json.Marshal(m)
	if err != nil || !bytes.Equal(canonical, signed.Manifest) || m.Version != 1 || m.Purpose != receiverEstablishedDomain || m.Attempt != binding.id || m.Binding != sourceDigest(binding.binding) || m.Host != host || m.Host != binding.value.Intent.Target || m.Incarnation != binding.value.Facts.Incarnation || m.Root != binding.value.Root {
		return nil, errors.New("receiver establishment exact job identity differs")
	}
	e, err := pki.DecodeHostTrustEvidence(original)
	if err != nil {
		return nil, err
	}
	signer, err := pki.DecodeHostTrustEvidence(signed.Evidence)
	if err != nil {
		return nil, err
	}
	root, validation, signing := e.RootDigest(), e.Digest(), signer.Digest()
	if signer.RootDigest() != root || m.Root != hex.EncodeToString(root[:]) || m.Validation != hex.EncodeToString(validation[:]) || m.SigningEvidence != hex.EncodeToString(signing[:]) {
		return nil, errors.New("receiver establishment original evidence differs")
	}
	if m.Chain != sourceDigest(signed.Chain...) {
		return nil, errors.New("receiver establishment original chain differs")
	}
	if err = signer.VerifyRecordedHost(signed.Chain, host); err != nil {
		return nil, err
	}
	if m.OriginalChain != sourceDigest(signed.OriginalChain...) {
		return nil, errors.New("receiver establishment validation original chain differs")
	}
	if err = e.VerifyRecordedHost(signed.OriginalChain, host); err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(signed.Chain[0])
	if err != nil {
		return nil, err
	}
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	digest, _ := hex.DecodeString(sourceDigest([]byte(receiverEstablishedDomain), signed.Manifest))
	if !ok || !ecdsa.VerifyASN1(key, digest, signed.Signature) {
		return nil, errors.New("receiver establishment signature differs")
	}
	return &receiverEstablished{m, e, signer, signed.OriginalChain}, nil
}

// No digest is authority: this helper is used only to name exact immutable bytes
// already checked by the storage owner and later rechecked in its FULL snapshot.
func receiverEstablishedRawDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
