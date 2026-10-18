package corrosion

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const retainedHolderDomain = "litevirt/automation-retained-holder/v1"
const maxRetainedHolderBodyBytes = 64 << 10

type retainedHolderBody struct {
	Version               int
	Purpose               string
	Donor                 string
	DonorIncarnation      string
	Generation            int64
	ConfigDigest          string
	MembersDigest         string
	AdmissionDigest       string
	Signer                string
	ReceiptDigest         string
	AggregateDigest       string
	DirectoryRoot         string
	DirectoryObjects      int64
	DirectoryBytes        int64
	OriginalSource        string
	OriginalIncarnation   string
	OriginalCut           string
	OriginalRoot          string
	Key                   ClaimKey
	Accepted              Ballot
	ValueDigest           string
	AcceptanceDigest      string
	Receiver              string
	ReceiverIncarnation   string
	Attempt               string
	Job                   string
	Revision              int64
	ReceiverConfigDigest  string
	ReceiverMembersDigest string
}

type retainedSignedHolder struct {
	Body      json.RawMessage
	Signature []byte
	Chain     [][]byte
}

type retainedHolder struct {
	body   retainedHolderBody
	signed retainedSignedHolder
	raw    []byte
	id     string
}

func decodeRetainedHolder(raw []byte) (retainedHolder, error) {
	var h retainedHolder
	if err := retainedCanonical(raw, maxSourceArtifactBytes, &h.signed); err != nil {
		return h, err
	}
	if err := retainedCanonical(h.signed.Body, maxRetainedHolderBodyBytes, &h.body); err != nil {
		return h, err
	}
	b := h.body
	if b.Version != 1 || b.Purpose != "automation-retained-holder" || b.Generation <= 0 ||
		b.DirectoryObjects <= 0 || b.DirectoryBytes < 0 || b.Revision <= 0 ||
		b.Key.Validate() != nil || !b.Key.IsGenerationScoped() || validateAutomationBallot(b.Accepted, false) != nil || !retainedNativeIdentity(b.OriginalCut) {
		return h, errors.New("invalid retained holder metadata")
	}
	for _, field := range []string{b.Donor, b.OriginalSource, b.Receiver} {
		if !retainedField(field, 253) {
			return h, errors.New("invalid retained holder host")
		}
	}
	for _, field := range []string{b.DonorIncarnation, b.OriginalIncarnation, b.ReceiverIncarnation, b.Job} {
		if !retainedField(field, 128) {
			return h, errors.New("invalid retained holder lifetime or job")
		}
	}
	for _, d := range []string{b.ConfigDigest, b.MembersDigest, b.AdmissionDigest, b.Signer,
		b.ReceiptDigest, b.AggregateDigest, b.DirectoryRoot, b.OriginalRoot,
		b.ValueDigest, b.AcceptanceDigest, b.Attempt, b.ReceiverConfigDigest, b.ReceiverMembersDigest} {
		if !receiverDigest(d) {
			return h, errors.New("invalid retained holder digest")
		}
	}
	if sourceChainBounds(h.signed.Chain) != nil || len(h.signed.Signature) == 0 || len(h.signed.Signature) > 256 {
		return h, errors.New("retained holder signature bounds")
	}
	leaf, err := x509.ParseCertificate(h.signed.Chain[0])
	if err != nil {
		return h, err
	}
	fp := sha256.Sum256(leaf.Raw)
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	hash, _ := hex.DecodeString(sourceDigest([]byte(retainedHolderDomain), h.signed.Body))
	if !ok || b.Signer != hex.EncodeToString(fp[:]) || !ecdsa.VerifyASN1(key, hash, h.signed.Signature) {
		return h, errors.New("invalid retained holder signature")
	}
	h.raw = append([]byte(nil), raw...)
	h.id = sourceDigest([]byte("litevirt/retained-delivery/v1"), raw)
	return h, nil
}

// This authenticates the fresh statement only. Complete pinned bundle audit is
// mandatory before a candidate can obtain inert completion evidence.
func (r *AutomationReceiver) authorizeRetainedHolder(ctx context.Context, a *AutomationReceiverAttempt, holder retainedHolder) (receiverSourceAuthorization, error) {
	var out receiverSourceAuthorization
	if a == nil || a.self != a || a.owner != r || a.facts.Next == nil {
		return out, errors.New("foreign retained receiver attempt")
	}
	// Derive all bindings again from exact signed bytes, never mutable decoded
	// fields carried by a caller or a previously authenticated metadata object.
	holder, err := decodeRetainedHolder(holder.raw)
	if err != nil {
		return out, err
	}
	b := holder.body
	next := a.facts.Next
	member, ok := next.Member(b.Donor)
	if !ok || member.Incarnation != b.DonorIncarnation || b.Generation != next.Generation ||
		b.ConfigDigest != sourceConfigDigest(next) || b.MembersDigest != next.MembersHash {
		return out, errors.New("retained holder is not exact successor member")
	}
	if b.Receiver != r.client.hostName || b.Receiver != a.request.Target ||
		b.ReceiverIncarnation != a.facts.Incarnation || b.Attempt != a.id || b.Job != a.request.Job ||
		b.Revision != a.request.Revision || b.ReceiverConfigDigest != sourceConfigDigest(next) ||
		b.ReceiverMembersDigest != next.MembersHash {
		return out, errors.New("retained holder delivery binding differs")
	}
	out, err = r.authorizeMember(ctx, a, member, next.Generation)
	if err != nil {
		return out, err
	}
	admission, _ := json.Marshal(out.host)
	if b.AdmissionDigest != sourceDigest([]byte("litevirt/retained-admission/v1"), admission) ||
		b.Signer != out.peer.Fingerprint || !bytes.Equal(holder.signed.Chain[0], out.peer.Chain[0]) {
		out.discard()
		return receiverSourceAuthorization{}, errors.New("retained holder observed admission or signer differs")
	}
	// Both the actual observed peer path and the signed envelope path are
	// required current evidence, even if their exact leaf is identical. Bind the
	// intersection into the existing attempt/final-time/private-binding guard.
	before, after := a.notBefore, a.notAfter
	for _, chain := range [][][]byte{out.peer.Chain, holder.signed.Chain} {
		start, end, e := a.view.VerifyHostCertificate(chain, b.Donor)
		if e != nil {
			out.discard()
			return receiverSourceAuthorization{}, e
		}
		if start.After(before) {
			before = start
		}
		if end.Before(after) {
			after = end
		}
	}
	cap, err := a.view.ValidateHostCertificate(ctx, holder.signed.Chain, b.Donor)
	if err != nil {
		out.discard()
		return receiverSourceAuthorization{}, err
	}
	out.source.Discard()
	out.source = cap
	a.notBefore, a.notAfter = before, after
	return out, nil
}
