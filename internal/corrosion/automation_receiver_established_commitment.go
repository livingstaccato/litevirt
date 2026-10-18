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
	"hash"
	"math"
)

const receiverInventoryDomain = "litevirt/receiver-established-inventory/v1"
const maxReceiverInventoryBytes = 4*((pki.MaxHostTrustEvidenceBytes+maxSourceChainBytes+maxReceiverEstablishedManifest+256+2)/3) + 2048

type receiverValidationKey struct{ attempt, digest string }
type receiverInventoryRoot struct {
	Count  int64
	Digest string
}
type receiverInventoryManifest struct {
	Version                                            int
	Purpose, Attempt, Binding, Host, Incarnation, Root string
	Inventory                                          receiverInventoryRoot
	Evidence, Chain                                    string
}
type receiverInventoryArtifact struct {
	Manifest, Evidence []byte
	Chain              [][]byte
	Signature          []byte
}
type receiverInventoryCommitment struct {
	manifest receiverInventoryManifest
	signer   *pki.HostTrustEvidence
}
type receiverPreparedInventory struct {
	raw  []byte
	root receiverInventoryRoot
}

// A finite rolling root, not a retained list of historical keys. The optional
// prospective key is merged in canonical order and deduplicated only by exact key.
type receiverInventoryStream struct {
	h         hash.Hash
	count     int64
	last      string
	candidate *receiverValidationKey
	added     bool
}

func newReceiverInventoryStream(candidate *receiverValidationKey) *receiverInventoryStream {
	h := sha256.New()
	sourceHash(h, []byte(receiverInventoryDomain), []byte("complete-validation-keys"))
	return &receiverInventoryStream{h: h, candidate: candidate}
}
func (s *receiverInventoryStream) put(k receiverValidationKey) error {
	if !receiverDigest(k.attempt) || !receiverDigest(k.digest) || s.count == math.MaxInt64 {
		return errors.New("receiver inventory key/count bound")
	}
	key := k.attempt + k.digest
	if s.count > 0 && key <= s.last {
		return errors.New("receiver inventory duplicate or unordered key")
	}
	sourceHash(s.h, []byte(k.attempt), []byte(k.digest))
	s.count++
	s.last = key
	return nil
}
func (s *receiverInventoryStream) add(k receiverValidationKey) error {
	if s.candidate != nil && !s.added {
		candidate := *s.candidate
		if candidate.attempt+candidate.digest <= k.attempt+k.digest {
			if err := s.put(candidate); err != nil {
				return err
			}
			s.added = true
			if candidate == k {
				return nil
			}
		}
	}
	return s.put(k)
}
func (s *receiverInventoryStream) finish() (receiverInventoryRoot, error) {
	if s.candidate != nil && !s.added {
		if err := s.put(*s.candidate); err != nil {
			return receiverInventoryRoot{}, err
		}
	}
	sourceHash(s.h, []byte("end"), automationCutInteger(s.count))
	return receiverInventoryRoot{s.count, hex.EncodeToString(s.h.Sum(nil))}, nil
}
func receiverInventoryKeysTable() aggregateLocalTable {
	return aggregateLocalTable{"local_automation_receiver_validations", "attempt,digest", "attempt,digest", "tt", false}
}
func (r *AutomationReceiver) inventoryRoot(ctx context.Context, candidate *receiverValidationKey) (receiverInventoryRoot, error) {
	s := newReceiverInventoryStream(candidate)
	var after []any
	for {
		row, err := r.establishmentRow(ctx, receiverInventoryKeysTable(), after)
		if err != nil {
			return receiverInventoryRoot{}, err
		}
		if len(row.Columns) == 0 {
			break
		}
		key := receiverValidationKey{row.String("attempt"), row.String("digest")}
		if err = s.add(key); err != nil {
			return receiverInventoryRoot{}, err
		}
		after = []any{key.attempt, key.digest}
	}
	return s.finish()
}
func receiverInventoryRootTx(ctx context.Context, tx *LocalTx) (receiverInventoryRoot, error) {
	s := newReceiverInventoryStream(nil)
	err := walkAggregateBoundedTable(ctx, tx, receiverInventoryKeysTable(), "", currentEvidenceLimit, 128, func(_ int64, row Row) error {
		return s.add(receiverValidationKey{row.String("attempt"), row.String("digest")})
	})
	if err != nil {
		return receiverInventoryRoot{}, err
	}
	return s.finish()
}

// Authenticate surviving current-row commitment and exact ALL-key inventory
// before any current capture or retained-floor reconciliation. An empty field
// is a legacy repair premise only when no establishment artifact exists.
func (r *AutomationReceiver) verifyInventoryCommitment(ctx context.Context, allowLegacy bool) (*receiverInventoryCommitment, error) {
	rows, err := r.client.sourceExportQuery(ctx, `SELECT id,CASE WHEN typeof(attempt)='text' AND length(attempt)=64 THEN attempt END AS attempt,typeof(established_inventory) AS kind,length(established_inventory) AS size,CASE WHEN typeof(established_inventory)='blob' AND length(established_inventory)<=? THEN established_inventory END AS inventory FROM local_automation_receiver_current LIMIT 2`, maxReceiverInventoryBytes)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	if len(rows) != 1 || rows[0].Int64("id") != 1 || !receiverDigest(rows[0].String("attempt")) || rows[0].String("kind") != "blob" || rows[0].Int64("size") > maxReceiverInventoryBytes {
		return nil, errors.New("receiver inventory current-row type or bound")
	}
	raw := rows[0].Bytes("inventory")
	if len(raw) == 0 {
		if allowLegacy {
			counts, e := r.client.sourceExportQuery(ctx, `SELECT COUNT(*) AS n FROM local_automation_receiver_established`)
			if e == nil && len(counts) == 1 && counts[0].Int64("n") == 0 {
				return nil, nil
			}
		}
		return nil, errors.New("receiver establishment inventory missing; explicit genuine legacy reestablishment required")
	}
	binding, _, err := r.establishmentJob(ctx, rows[0].String("attempt"))
	if err != nil {
		return nil, err
	}
	commitment, err := decodeReceiverInventory(raw, binding, r.client.hostName)
	if err != nil {
		return nil, err
	}
	actual, err := r.inventoryRoot(ctx, nil)
	if err != nil {
		return nil, err
	}
	if actual != commitment.manifest.Inventory {
		return nil, errors.New("receiver establishment complete inventory changed or missing originals")
	}
	return commitment, nil
}
func decodeReceiverInventory(raw []byte, binding *receiverPredecessor, host string) (*receiverInventoryCommitment, error) {
	if len(raw) == 0 || len(raw) > maxReceiverInventoryBytes || binding == nil {
		return nil, errors.New("receiver inventory native bound")
	}
	var signed receiverInventoryArtifact
	if err := json.Unmarshal(raw, &signed); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(signed)
	if err != nil || !bytes.Equal(canonical, raw) || len(signed.Manifest) > maxReceiverEstablishedManifest || len(signed.Evidence) > pki.MaxHostTrustEvidenceBytes || len(signed.Signature) == 0 || len(signed.Signature) > 256 || sourceChainBounds(signed.Chain) != nil {
		return nil, errors.New("receiver inventory noncanonical artifact")
	}
	var m receiverInventoryManifest
	if err = json.Unmarshal(signed.Manifest, &m); err != nil {
		return nil, err
	}
	canonical, err = json.Marshal(m)
	if err != nil || !bytes.Equal(canonical, signed.Manifest) || m.Version != 1 || m.Purpose != receiverInventoryDomain || m.Attempt != binding.id || m.Binding != sourceDigest(binding.binding) || m.Host != host || m.Host != binding.value.Intent.Target || m.Incarnation != binding.value.Facts.Incarnation || m.Root != binding.value.Root || m.Inventory.Count < 1 || !receiverDigest(m.Inventory.Digest) || m.Chain != sourceDigest(signed.Chain...) {
		return nil, errors.New("receiver inventory exact context differs")
	}
	signer, err := pki.DecodeHostTrustEvidence(signed.Evidence)
	if err != nil {
		return nil, err
	}
	root, evidence := signer.RootDigest(), signer.Digest()
	if m.Root != hex.EncodeToString(root[:]) || m.Evidence != hex.EncodeToString(evidence[:]) {
		return nil, errors.New("receiver inventory signing evidence differs")
	}
	if err = signer.VerifyRecordedHost(signed.Chain, host); err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(signed.Chain[0])
	if err != nil {
		return nil, err
	}
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	digest, _ := hex.DecodeString(sourceDigest([]byte(receiverInventoryDomain), signed.Manifest))
	if !ok || !ecdsa.VerifyASN1(key, digest, signed.Signature) {
		return nil, errors.New("receiver inventory signature differs")
	}
	return &receiverInventoryCommitment{m, signer}, nil
}
func (r *AutomationReceiver) prepareInventoryCommitment(ctx context.Context, a *AutomationReceiverAttempt) (*receiverPreparedInventory, error) {
	if a == nil || a.self != a || a.owner != r || a.view == nil || a.pair == nil {
		return nil, errors.New("receiver inventory current owner missing")
	}
	evidenceDigest := a.view.EvidenceDigest()
	candidate := receiverValidationKey{a.id, hex.EncodeToString(evidenceDigest[:])}
	root, err := r.inventoryRoot(ctx, &candidate)
	if err != nil {
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
	evidence, err := a.view.PublicEvidence()
	if err != nil {
		return nil, err
	}
	ca := a.view.RootDigest()
	m := receiverInventoryManifest{1, receiverInventoryDomain, a.id, sourceDigest(a.binding), r.client.hostName, a.facts.Incarnation, hex.EncodeToString(ca[:]), root, hex.EncodeToString(evidenceDigest[:]), sourceDigest(a.pair.Certificate...)}
	manifest, err := json.Marshal(m)
	if err != nil || len(manifest) > maxReceiverEstablishedManifest {
		return nil, errors.New("receiver inventory manifest bound")
	}
	// Exact duplicate validation/context retains the same authenticated inert bytes.
	// Fresh authorization and the eventual real lease are still mandatory; this
	// avoids rewriting durable evidence merely because ECDSA uses a fresh nonce.
	existing, err := r.client.sourceExportQuery(ctx, `SELECT CASE WHEN typeof(established_inventory)='blob' AND length(established_inventory)<=? THEN established_inventory END AS inventory FROM local_automation_receiver_current WHERE id=1 AND attempt=?`, maxReceiverInventoryBytes, a.id)
	if err != nil {
		return nil, err
	}
	if len(existing) == 1 && len(existing[0].Bytes("inventory")) > 0 {
		binding, err := decodeReceiverBinding(a.id, a.request.Job, a.request.Revision, a.binding)
		if err != nil {
			return nil, err
		}
		retained, err := decodeReceiverInventory(existing[0].Bytes("inventory"), binding, r.client.hostName)
		if err != nil {
			return nil, err
		}
		previous, err := json.Marshal(retained.manifest)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(previous, manifest) {
			return &receiverPreparedInventory{existing[0].Bytes("inventory"), root}, nil
		}
	}
	key, ok := a.pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("receiver inventory key is not ECDSA")
	}
	digest, _ := hex.DecodeString(sourceDigest([]byte(receiverInventoryDomain), manifest))
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(receiverInventoryArtifact{manifest, evidence, a.pair.Certificate, signature})
	if err != nil {
		return nil, err
	}
	binding, err := decodeReceiverBinding(a.id, a.request.Job, a.request.Revision, a.binding)
	if err != nil {
		return nil, err
	}
	if _, err = decodeReceiverInventory(raw, binding, r.client.hostName); err != nil {
		return nil, err
	}
	return &receiverPreparedInventory{raw, root}, nil
}
