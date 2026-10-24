package custody

import (
	"bytes"
	"encoding/json"
	"io"
	"time"

	"filippo.io/age"
)

const EqualityImportVersion = 1
const maxCustodyTransferBytes = custodyRecordMax
const equalityImportDomain = "litevirt/automation/equality-import/v1\x00"

// EqualityImportBinding identifies both physical stores and the immutable
// transfer attempt. It is authenticated inside the age envelope. Expiry is an
// immutable binding here; the native authority owner enforces current time.
type EqualityImportBinding struct {
	Source, Target                           CustodyScope
	SourceVoter, TargetVoter                 string
	VoterRef, SourceEquality, TargetEquality CustodyKeyRef
	Recipient, Attempt, ExpiresAt            string
}

type equalityImportRecord struct {
	Version  int
	Purpose  string
	Binding  EqualityImportBinding
	Material []byte
}

func (b EqualityImportBinding) valid() bool {
	if !b.Source.valid() || !b.Target.valid() || b.Source.ClusterUID != b.Target.ClusterUID || !secretStringValid(b.SourceVoter) || !secretStringValid(b.TargetVoter) || !secretStringValid(b.Attempt) || !b.VoterRef.valid() || !b.SourceEquality.valid() || !b.TargetEquality.valid() {
		return false
	}
	if b.SourceEquality.Epoch != b.TargetEquality.Epoch || b.SourceEquality.Generation != b.TargetEquality.Generation || b.SourceEquality.ConfigDigest != b.TargetEquality.ConfigDigest || b.VoterRef.Generation != b.TargetEquality.Generation || b.VoterRef.ConfigDigest != b.TargetEquality.ConfigDigest {
		return false
	}
	recipient, err := age.ParseX25519Recipient(b.Recipient)
	if err != nil || recipient.String() != b.Recipient {
		return false
	}
	_, err = time.Parse(time.RFC3339Nano, b.ExpiresAt)
	return err == nil && len(b.ExpiresAt) <= 4096
}

// SealEqualityImport exports only age ciphertext; equality material never
// leaves the custody owner in plaintext or through a generic key getter.
func (s *LocalCustody) SealEqualityImport(source CustodyKeyRef, binding EqualityImportBinding, recipient string) ([]byte, error) {
	if !binding.valid() || source != binding.SourceEquality || recipient != binding.Recipient {
		return nil, ErrCustodyCorrupt
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scope != binding.Source {
		return nil, ErrCustodyConflict
	}
	record, err := s.load(custodyEqualityPurpose, source)
	if err != nil {
		return nil, err
	}
	defer clear(record.Material)
	body, err := json.Marshal(equalityImportRecord{EqualityImportVersion, "automation-equality-import", binding, record.Material})
	if err != nil || len(body)+len(equalityImportDomain) > maxCustodyTransferBytes {
		return nil, ErrCustodyCorrupt
	}
	defer clear(body)
	target, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return nil, ErrCustodyCorrupt
	}
	var output bytes.Buffer
	writer, err := age.Encrypt(&output, target)
	if err != nil {
		return nil, ErrCustodyUnavailable
	}
	if _, err = io.WriteString(writer, equalityImportDomain); err != nil {
		return nil, ErrCustodyUnavailable
	}
	if _, err = writer.Write(body); err != nil {
		return nil, ErrCustodyUnavailable
	}
	if err = writer.Close(); err != nil {
		return nil, ErrCustodyUnavailable
	}
	if output.Len() > maxCustodyTransferBytes {
		return nil, ErrCustodyCorrupt
	}
	return output.Bytes(), nil
}

// ImportSealedEquality authenticates the complete stream before touching the
// target material. Retried imports match immutable material and reopen both
// physical keys; neither partial plaintext nor a valid prefix is sufficient.
func (s *LocalCustody) ImportSealedEquality(voterRef CustodyKeyRef, expectedRecipient string, target CustodyKeyRef, binding EqualityImportBinding, capsule []byte) error {
	if !binding.valid() || voterRef != binding.VoterRef || expectedRecipient != binding.Recipient || target != binding.TargetEquality || s.scope != binding.Target || len(capsule) == 0 || len(capsule) > maxCustodyTransferBytes {
		return ErrCustodyCorrupt
	}
	voter, err := s.OpenVoterIdentity(voterRef, expectedRecipient)
	if err != nil {
		return err
	}
	reader, err := age.Decrypt(bytes.NewReader(capsule), voter.identity)
	if err != nil {
		return ErrCustodyCorrupt
	}
	body, err := io.ReadAll(io.LimitReader(reader, maxCustodyTransferBytes+1))
	defer clear(body)
	if err != nil || len(body) > maxCustodyTransferBytes || !bytes.HasPrefix(body, []byte(equalityImportDomain)) {
		return ErrCustodyCorrupt
	}
	encoded := body[len(equalityImportDomain):]
	var record equalityImportRecord
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil {
		return ErrCustodyCorrupt
	}
	defer clear(record.Material)
	canonical, err := json.Marshal(record)
	defer clear(canonical)
	if err != nil || !bytes.Equal(encoded, canonical) || record.Version != EqualityImportVersion || record.Purpose != "automation-equality-import" || record.Binding != binding || len(record.Material) != 32 {
		return ErrCustodyCorrupt
	}
	if _, err = s.ImportEqualityKey(target, record.Material); err != nil {
		return err
	}
	if _, err = s.OpenVoterIdentity(voterRef, expectedRecipient); err != nil {
		return err
	}
	_, err = s.OpenEqualityKey(target)
	return err
}
