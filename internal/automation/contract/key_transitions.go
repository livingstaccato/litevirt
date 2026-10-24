package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"filippo.io/age"
)

// These facts describe already-certified history. They are not live custody,
// enrollment, plaintext-equivalence or command-class authority providers.
const MaxKeyRecipients = 64
const MaxRetainedPayloads = 1024

type HistoryReference struct {
	Sequence uint64 `json:"sequence"`
	Digest   string `json:"digest"`
}

// SecretBinding preserves the native secret codec identity and its existing
// default JSON representation. PayloadBinding is its strictly tagged wire view.
type SecretBinding struct {
	ClusterUID, ProjectUID, ResourceUID, OperationID, PayloadID string
	AdmittedGeneration                                          uint64
}
type PayloadBinding struct {
	ClusterUID         string `json:"cluster_uid"`
	ProjectUID         string `json:"project_uid"`
	ResourceUID        string `json:"resource_uid"`
	OperationID        string `json:"operation_id"`
	PayloadID          string `json:"payload_id"`
	AdmittedGeneration uint64 `json:"admitted_generation"`
}
type RecipientBinding struct {
	ClusterUID           string           `json:"cluster_uid"`
	MembershipGeneration uint64           `json:"membership_generation"`
	ConfigDigest         string           `json:"config_digest"`
	Host                 string           `json:"host"`
	HostIncarnation      uint64           `json:"host_incarnation"`
	AdmittedAt           string           `json:"admitted_at"`
	AdmissionSerial      string           `json:"admission_serial"`
	VoterIncarnation     string           `json:"voter_incarnation"`
	RecipientEpoch       string           `json:"recipient_epoch"`
	KeyID                string           `json:"key_id"`
	Recipient            string           `json:"recipient"`
	Enrollment           HistoryReference `json:"enrollment"`
	RecipientAck         HistoryReference `json:"recipient_ack"`
	EqualityAck          HistoryReference `json:"equality_ack"`
}
type RewrapPayloadBody struct {
	Version              int              `json:"version"`
	MembershipGeneration uint64           `json:"membership_generation"`
	ConfigDigest         string           `json:"config_digest"`
	RecipientEpoch       string           `json:"recipient_epoch"`
	AdmissionSequence    uint64           `json:"admission_sequence"`
	OperationID          string           `json:"operation_id"`
	PayloadID            string           `json:"payload_id"`
	PreviousWrapping     HistoryReference `json:"previous_wrapping"`
}
type ActivateKeyEpochBody struct {
	Version              int              `json:"version"`
	MembershipGeneration uint64           `json:"membership_generation"`
	ConfigDigest         string           `json:"config_digest"`
	RecipientEpoch       string           `json:"recipient_epoch"`
	PreviousActivation   uint64           `json:"previous_activation"`
	EqualityEpoch        string           `json:"equality_epoch"`
	Prefix               HistoryReference `json:"prefix"`
}
type RetainedPayload struct {
	OperationID string           `json:"operation_id"`
	PayloadID   string           `json:"payload_id"`
	Admission   HistoryReference `json:"admission"`
}
type PayloadCoverage struct {
	OperationID string           `json:"operation_id"`
	Wrapping    HistoryReference `json:"wrapping"`
}

// Class is a purpose in the immutable certified assignment, not an API for
// constructing a live permit. Bootstrap also binds the original genesis below.
type RewrapPreparation struct {
	Purpose           string           `json:"purpose"`
	SourceWrapping    HistoryReference `json:"source_wrapping"`
	ReplacementDigest string           `json:"replacement_digest"`
}
type KeyTransitionAssignment struct {
	Recipients        []RecipientBinding `json:"recipients"`
	OriginalHistory   *HistoryReference  `json:"original_history,omitempty"`
	Binding           *PayloadBinding    `json:"binding,omitempty"`
	EqualityEpoch     string             `json:"equality_epoch,omitempty"`
	EqualityTag       []byte             `json:"equality_tag,omitempty"`
	Preparation       *RewrapPreparation `json:"preparation,omitempty"`
	RetainedInventory []RetainedPayload  `json:"retained_inventory,omitempty"`
	Coverage          []PayloadCoverage  `json:"coverage,omitempty"`
	Class             string             `json:"class,omitempty"`
	Bootstrap         *HistoryReference  `json:"bootstrap,omitempty"`
}
type KeyEpochRecord struct {
	ClusterUID, RecipientEpoch, ConfigDigest, EqualityEpoch                 string
	MembershipGeneration, PredecessorActivationSequence, ActivationSequence uint64
}
type KeyRecipientRecord struct {
	Binding       RecipientBinding
	FirstSequence uint64
}
type PayloadWrappingRecord struct {
	ClusterUID, OperationID, PayloadID, WrappingDigest, RecipientEpoch, ConfigDigest string
	AdmissionSequence, WrappingSequence, MembershipGeneration                        uint64
}

// HistoricalDecision is a copied finite summary, never a retained envelope,
// ciphertext, body, configuration or database Row. Its digest belongs to the
// original certified record from which the history adapter derives it.
type HistoricalDecision struct {
	CustodyImport                                                                     *CustodyImportSummary
	Sequence, MembershipGeneration                                                    uint64
	Digest, Kind, ClusterUID, CommandClusterUID, ProjectUID, PrincipalID, OperationID string
	Binding                                                                           *PayloadBinding
	RecipientEpoch, EqualityEpoch                                                     string
	EqualityTag                                                                       []byte
	CiphertextBytes                                                                   int
}

func SummarizeKeyHistory(d Decision, digest string, generation uint64) (HistoricalDecision, error) {
	a, e := DecodeAssignment(d)
	if e != nil || !keyDigest(digest) || !keyNumber(generation) {
		return HistoricalDecision{}, codedError(CodeValidation)
	}
	h := HistoricalDecision{Sequence: d.Sequence, MembershipGeneration: generation, Digest: strings.Clone(digest), Kind: strings.Clone(d.Command.Kind), ClusterUID: strings.Clone(a.ClusterUID), CommandClusterUID: strings.Clone(d.Command.ClusterUID), ProjectUID: strings.Clone(d.Command.ProjectUID), PrincipalID: strings.Clone(d.Command.PrincipalID), OperationID: strings.Clone(a.OperationID), EqualityEpoch: strings.Clone(d.Command.SecretKeyEpoch), EqualityTag: append([]byte(nil), d.Command.SecretIntentTag...), CiphertextBytes: len(d.Command.Ciphertext)}
	if d.Command.Kind == CustodyImportCommand {
		if err := validateCustodyImport(d, a); err != nil {
			return HistoricalDecision{}, err
		}
		record, err := json.Marshal(a.CustodyImport)
		if err != nil {
			return HistoricalDecision{}, err
		}
		h.CustodyImport = &CustodyImportSummary{RecordDigest: CiphertextDigest(record), EqualityEpoch: a.CustodyImport.EqualityEpoch, Genesis: a.CustodyImport.Genesis}
		for _, m := range a.CustodyImport.Members {
			h.CustodyImport.Recipients = append(h.CustodyImport.Recipients, CustodyRecipientBinding(m.Recipient, HistoryReference{d.Sequence, digest}))
		}
	}
	if a.Binding != nil {
		b := a.Binding
		h.Binding = &PayloadBinding{ClusterUID: h.ClusterUID, ProjectUID: h.ProjectUID, ResourceUID: strings.Clone(b.ResourceUID), OperationID: h.OperationID, PayloadID: strings.Clone(b.PayloadID), AdmittedGeneration: b.AdmittedGeneration}
		h.RecipientEpoch = strings.Clone(b.RecipientEpoch)
	}
	return h, nil
}

// HistoricalReference is derived from an actual decoded certified record. It
// avoids retaining up to 1024 complete ciphertext envelopes for an inventory.
type HistoricalReference struct {
	Reference            HistoryReference
	ClusterUID           string
	MembershipGeneration uint64
}
type KeyMember struct{ Host, VoterIncarnation string }
type KeyTransitionProjection struct {
	MembershipGeneration uint64
	ConfigDigest         string
	Members              []KeyMember
	Epochs               []KeyEpochRecord
	Recipients           []KeyRecipientRecord
	Wrappings            []PayloadWrappingRecord
	Admissions           []AdmissionRecord
	History              []HistoricalDecision
	References           []HistoricalReference
}

func keyText(s string) bool {
	return s != "" && len(s) <= MaxStringBytes && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}
func keyNumber(n uint64) bool { return n > 0 && n <= math.MaxInt64 }
func keyDigest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && s == strings.ToLower(s)
}
func keyReference(r HistoryReference) bool { return keyNumber(r.Sequence) && keyDigest(r.Digest) }
func keyBody(c Command, out any) error {
	if !keyText(c.ClusterUID) || !keyText(c.PrincipalID) || !keyText(c.RequestID) || c.OwnerID != "" || c.ManagementKey != "" || c.Session != 0 || c.SessionID != "" || c.Generation != 0 || c.ExpectedRevision != 0 {
		return codedError(CodeValidation)
	}
	if _, e := canonicalBody(c.Body); e != nil {
		return e
	}
	if exactBindingJSON(c.Body, reflect.TypeOf(out).Elem()) != nil || json.Unmarshal(c.Body, out) != nil {
		return codedError(CodeValidation)
	}
	return nil
}
func DecodeRewrapPayloadBody(c Command) (RewrapPayloadBody, error) {
	var b RewrapPayloadBody
	if c.Kind != "rewrap_payload" || keyBody(c, &b) != nil || b.Version != 1 || !keyNumber(b.MembershipGeneration) || !keyDigest(b.ConfigDigest) || !keyText(b.RecipientEpoch) || !keyNumber(b.AdmissionSequence) || !keyText(b.OperationID) || !keyText(b.PayloadID) || !keyReference(b.PreviousWrapping) || !keyText(c.ProjectUID) || !keyText(c.ResourceUID) || len(c.Ciphertext) == 0 || len(c.Ciphertext) > MaxDecisionBytes || len(c.SecretIntentTag) != 32 || !keyText(c.SecretKeyEpoch) {
		return b, codedError(CodeValidation)
	}
	return b, nil
}
func DecodeActivateKeyEpochBody(c Command) (ActivateKeyEpochBody, error) {
	var b ActivateKeyEpochBody
	if c.Kind != "activate_key_epoch" || keyBody(c, &b) != nil || b.Version != 1 || !keyNumber(b.MembershipGeneration) || !keyDigest(b.ConfigDigest) || !keyText(b.RecipientEpoch) || !keyText(b.EqualityEpoch) || b.PreviousActivation > math.MaxInt64 || !keyReference(b.Prefix) || c.ProjectUID != "" || c.ResourceUID != "" || len(c.Ciphertext) != 0 || len(c.SecretIntentTag) != 0 || c.SecretKeyEpoch != "" {
		return b, codedError(CodeValidation)
	}
	return b, nil
}
func keyTransitionKind(kind string) bool {
	return kind == "rewrap_payload" || kind == "activate_key_epoch"
}
func validateKeyTransition(d Decision, a Assignment) error {
	if a.Version == CustodyAssignmentVersion {
		body, err := DecodeActivateKeyEpochBody(d.Command)
		if d.Command.Kind != "activate_key_epoch" || err != nil || body.PreviousActivation != 0 || a.KeyTransition == nil || a.KeyTransition.Class != "bootstrap" || a.KeyTransition.Bootstrap == nil || a.KeyTransition.Bootstrap.Sequence != 1 || len(a.KeyTransition.RetainedInventory) != 0 || len(a.KeyTransition.Coverage) != 0 {
			return codedError(CodeValidation)
		}
	}
	var generation uint64
	var config, epoch string
	if d.Command.Kind == "rewrap_payload" {
		b, e := DecodeRewrapPayloadBody(d.Command)
		if e != nil {
			return e
		}
		generation, config, epoch = b.MembershipGeneration, b.ConfigDigest, b.RecipientEpoch
	} else {
		b, e := DecodeActivateKeyEpochBody(d.Command)
		if e != nil {
			return e
		}
		generation, config, epoch = b.MembershipGeneration, b.ConfigDigest, b.RecipientEpoch
	}
	f := a.KeyTransition
	if f == nil || a.ClusterUID != d.Command.ClusterUID || len(f.Recipients) == 0 || len(f.Recipients) > MaxKeyRecipients {
		return codedError(CodeValidation)
	}
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(d.Assignment, &raw)
	if exactBindingJSON(raw["key_transition"], reflect.TypeOf(KeyTransitionAssignment{})) != nil {
		return codedError(CodeValidation)
	}
	hosts, keys, recipients := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, r := range f.Recipients {
		native, e := age.ParseX25519Recipient(r.Recipient)
		if e != nil || native.String() != r.Recipient || r.ClusterUID != a.ClusterUID || r.MembershipGeneration != generation || r.ConfigDigest != config || r.RecipientEpoch != epoch || !keyText(r.Host) || !keyText(r.VoterIncarnation) || !keyText(r.KeyID) || r.HostIncarnation > math.MaxInt64 || !keyText(r.AdmittedAt) || !keyText(r.AdmissionSerial) || r.AdmissionSerial != strings.ToLower(r.AdmissionSerial) || !keyReference(r.Enrollment) || !keyReference(r.RecipientAck) || !keyReference(r.EqualityAck) || hosts[r.Host] || keys[r.KeyID] || recipients[r.Recipient] {
			return codedError(CodeValidation)
		}
		if _, e := time.Parse(time.RFC3339Nano, r.AdmittedAt); e != nil {
			return codedError(CodeValidation)
		}
		hosts[r.Host], keys[r.KeyID], recipients[r.Recipient] = true, true, true
	}
	if d.Command.Kind == "rewrap_payload" {
		b, _ := DecodeRewrapPayloadBody(d.Command)
		if f.OriginalHistory == nil || !keyReference(*f.OriginalHistory) || f.OriginalHistory.Sequence != b.AdmissionSequence || f.Binding == nil || f.Preparation == nil || f.Preparation.Purpose != "bootstrap-equivalence/v1" || !keyReference(f.Preparation.SourceWrapping) || !keyDigest(f.Preparation.ReplacementDigest) || f.Preparation.ReplacementDigest != CiphertextDigest(d.Command.Ciphertext) || f.EqualityEpoch != d.Command.SecretKeyEpoch || !bytes.Equal(f.EqualityTag, d.Command.SecretIntentTag) || f.RetainedInventory != nil || f.Coverage != nil || f.Bootstrap != nil || f.Class != "" {
			return codedError(CodeValidation)
		}
		v := f.Binding
		if v.ClusterUID != a.ClusterUID || v.ProjectUID != d.Command.ProjectUID || v.ResourceUID != d.Command.ResourceUID || v.OperationID != b.OperationID || v.PayloadID != b.PayloadID || !keyNumber(v.AdmittedGeneration) {
			return codedError(CodeValidation)
		}
	} else {
		if f.OriginalHistory != nil || f.Binding != nil || f.Preparation != nil || f.EqualityEpoch != "" || len(f.EqualityTag) != 0 || len(f.RetainedInventory) > MaxRetainedPayloads || len(f.Coverage) > MaxRetainedPayloads {
			return codedError(CodeValidation)
		}
		if f.Class != "" && f.Class != "bootstrap" && f.Class != "protocol" {
			return codedError(CodeValidation)
		}
		if f.Bootstrap != nil && !keyReference(*f.Bootstrap) {
			return codedError(CodeValidation)
		}
		seen := map[string]bool{}
		for _, r := range f.RetainedInventory {
			if !keyText(r.OperationID) || !keyText(r.PayloadID) || !keyReference(r.Admission) || seen[r.OperationID] {
				return codedError(CodeValidation)
			}
			seen[r.OperationID] = true
		}
		seen = map[string]bool{}
		for _, r := range f.Coverage {
			if !keyText(r.OperationID) || !keyReference(r.Wrapping) || seen[r.OperationID] {
				return codedError(CodeValidation)
			}
			seen[r.OperationID] = true
		}
	}
	return nil
}

func historicalKeyDecision(p *KeyTransitionProjection, ref HistoryReference, head uint64) (HistoricalDecision, bool) {
	if ref.Sequence > head {
		return HistoricalDecision{}, false
	}
	for _, h := range p.History {
		if h.Sequence == ref.Sequence {
			return h, h.Digest == ref.Digest
		}
	}
	return HistoricalDecision{}, false
}
func resolvedKeyReference(p *KeyTransitionProjection, ref HistoryReference, head uint64, cluster string, generation uint64) bool {
	if !keyReference(ref) || ref.Sequence > head {
		return false
	}
	for _, h := range p.References {
		if h.Reference.Sequence == ref.Sequence {
			return h.Reference == ref && h.ClusterUID == cluster && h.MembershipGeneration == generation
		}
	}
	h, ok := historicalKeyDecision(p, ref, head)
	return ok && h.ClusterUID == cluster && h.MembershipGeneration == generation
}
func inventoryHistoryReference(p *KeyTransitionProjection, sequence uint64) HistoryReference {
	for _, h := range p.References {
		if h.Reference.Sequence == sequence {
			return h.Reference
		}
	}
	for _, h := range p.History {
		if h.Sequence == sequence {
			return HistoryReference{sequence, h.Digest}
		}
	}
	return HistoryReference{}
}
func latestKeyEpoch(f *KeyTransitionProjection, head uint64) *KeyEpochRecord {
	var latest *KeyEpochRecord
	for i := range f.Epochs {
		e := &f.Epochs[i]
		if e.ActivationSequence <= head && (latest == nil || e.ActivationSequence > latest.ActivationSequence) {
			latest = e
		}
	}
	return latest
}

// Reduce needs causal, stage-local facts. Its return value is never authority to
// accept a new transition or proof that this process can open any ciphertext.
func reduceKeyTransition(out *Reduction, p Projection, d Decision, a Assignment) error {
	f := p.KeyTransition
	if f == nil || p.Head.ClusterUID != d.Command.ClusterUID || p.Head.Sequence+1 != d.Sequence || p.Head.Digest != d.ParentDigest || !keyNumber(f.MembershipGeneration) || !keyDigest(f.ConfigDigest) || len(f.Members) == 0 || len(f.Members) > MaxKeyRecipients {
		return codedError(CodeUnavailable)
	}
	var gen uint64
	var config, epoch string
	if d.Command.Kind == "rewrap_payload" {
		b, _ := DecodeRewrapPayloadBody(d.Command)
		gen, config, epoch = b.MembershipGeneration, b.ConfigDigest, b.RecipientEpoch
	} else {
		b, _ := DecodeActivateKeyEpochBody(d.Command)
		gen, config, epoch = b.MembershipGeneration, b.ConfigDigest, b.RecipientEpoch
	}
	if gen != f.MembershipGeneration || config != f.ConfigDigest {
		rejectReduction(out, CodeRevisionConflict)
		return nil
	}
	target := a.KeyTransition.Recipients
	if len(target) != len(f.Members) {
		rejectReduction(out, CodeValidation)
		return nil
	}
	members := map[string]string{}
	for _, m := range f.Members {
		if m.Host == "" || m.VoterIncarnation == "" || members[m.Host] != "" {
			return codedError(CodeUnavailable)
		}
		members[m.Host] = m.VoterIncarnation
	}
	var newRecipients []KeyRecipientRecord
	for _, r := range target {
		if a.Version == CustodyAssignmentVersion {
			body, _ := DecodeActivateKeyEpochBody(d.Command)
			h, ok := historicalKeyDecision(f, r.EqualityAck, p.Head.Sequence)
			if !ok || h.Kind != CustodyImportCommand || h.ClusterUID != d.Command.ClusterUID || h.MembershipGeneration != gen || h.PrincipalID != d.Command.PrincipalID || h.CustodyImport == nil || h.CustodyImport.EqualityEpoch != body.EqualityEpoch || h.CustodyImport.Genesis != *a.KeyTransition.Bootstrap || len(h.CustodyImport.Recipients) != len(f.Members) || r.Enrollment != r.EqualityAck || r.RecipientAck != r.EqualityAck {
				return codedError(CodeUnavailable)
			}
			matched := false
			for _, imported := range h.CustodyImport.Recipients {
				if imported == r {
					matched = true
				}
			}
			if !matched {
				return codedError(CodeUnavailable)
			}
		}
		for _, ref := range []HistoryReference{r.Enrollment, r.RecipientAck, r.EqualityAck} {
			if !resolvedKeyReference(f, ref, p.Head.Sequence, d.Command.ClusterUID, gen) {
				return codedError(CodeUnavailable)
			}
		}
		if members[r.Host] != r.VoterIncarnation {
			rejectReduction(out, CodeValidation)
			return nil
		}
		existing := false
		for _, old := range f.Recipients {
			if old.FirstSequence > p.Head.Sequence {
				return codedError(CodeUnavailable)
			}
			if old.Binding.RecipientEpoch == epoch && old.Binding.Host == r.Host {
				if old.Binding != r {
					rejectReduction(out, CodeRevisionConflict)
					return nil
				}
				existing = true
			} else if old.Binding.KeyID == r.KeyID || old.Binding.Recipient == r.Recipient {
				rejectReduction(out, CodeValidation)
				return nil
			}
		}
		if !existing {
			newRecipients = append(newRecipients, KeyRecipientRecord{Binding: r, FirstSequence: d.Sequence})
		}
	}
	if d.Command.Kind == "rewrap_payload" {
		if err := reducePayloadWrapping(out, p, d, a); err != nil {
			return err
		}
	} else if err := reduceKeyActivation(out, p, d, a); err != nil {
		return err
	}
	if out.Receipt.Code == "" {
		out.RecipientEffects = newRecipients
	}
	return nil
}
func reducePayloadWrapping(out *Reduction, p Projection, d Decision, a Assignment) error {
	f := p.KeyTransition
	b, _ := DecodeRewrapPayloadBody(d.Command)
	v := a.KeyTransition
	var original *AdmissionRecord
	for i := range f.Admissions {
		r := &f.Admissions[i]
		if r.OperationID == b.OperationID {
			original = r
			break
		}
	}
	if original == nil || original.Sequence != b.AdmissionSequence || original.Method != "admit_create" || original.PayloadID != b.PayloadID || original.Sequence > p.Head.Sequence {
		return codedError(CodeUnavailable)
	}
	binding := PayloadBinding{original.ClusterUID, original.ProjectUID, original.ResourceUID, original.OperationID, original.PayloadID, original.AdmittedGeneration}
	if binding != *v.Binding {
		return codedError(CodeUnavailable)
	}
	old, ok := historicalKeyDecision(f, *v.OriginalHistory, p.Head.Sequence)
	if !ok || old.Kind != "admit_create" {
		return codedError(CodeUnavailable)
	}
	if old.Binding == nil || *old.Binding != binding || old.RecipientEpoch == "" || old.CommandClusterUID != original.ClusterUID || old.CiphertextBytes == 0 || !bytes.Equal(old.EqualityTag, v.EqualityTag) || old.EqualityEpoch != v.EqualityEpoch {
		return codedError(CodeUnavailable)
	}

	originalEpoch := false
	for _, epoch := range f.Epochs {
		if epoch.RecipientEpoch == old.RecipientEpoch && epoch.ActivationSequence < original.Sequence && epoch.ClusterUID == original.ClusterUID {
			originalEpoch = true
		}
	}
	active := latestKeyEpoch(f, p.Head.Sequence)
	if !originalEpoch || active == nil || active.MembershipGeneration != b.MembershipGeneration || active.ConfigDigest != b.ConfigDigest {
		return codedError(CodeUnavailable)
	}
	previous := HistoryReference{Sequence: original.Sequence, Digest: v.OriginalHistory.Digest}
	previousEpoch := old.RecipientEpoch
	for _, w := range f.Wrappings {
		if w.OperationID == b.OperationID {
			if w.WrappingSequence > p.Head.Sequence || w.AdmissionSequence != original.Sequence || w.PayloadID != original.PayloadID {
				return codedError(CodeUnavailable)
			}
			if w.WrappingSequence > previous.Sequence {
				previous = HistoryReference{w.WrappingSequence, w.WrappingDigest}
				previousEpoch = w.RecipientEpoch
			}
		}
	}
	if previous != b.PreviousWrapping || previousEpoch == b.RecipientEpoch {
		rejectReduction(out, CodeRevisionConflict)
		return nil
	}
	for _, e := range f.Epochs {
		if e.RecipientEpoch == b.RecipientEpoch {
			rejectReduction(out, CodeRevisionConflict)
			return nil
		}
	}
	// Preparation is a reference carried by the original certified decision;
	// replay checks its causal identity, never invokes a success crypto callback.
	if v.Preparation.SourceWrapping != previous {
		return codedError(CodeUnavailable)
	}
	out.WrappingEffect = &PayloadWrappingRecord{ClusterUID: original.ClusterUID, OperationID: original.OperationID, PayloadID: original.PayloadID, AdmissionSequence: original.Sequence, WrappingSequence: d.Sequence, RecipientEpoch: b.RecipientEpoch, MembershipGeneration: b.MembershipGeneration, ConfigDigest: b.ConfigDigest}
	out.WrappingPrevious = &previous
	return nil
}
func reduceKeyActivation(out *Reduction, p Projection, d Decision, a Assignment) error {
	f := p.KeyTransition
	b, _ := DecodeActivateKeyEpochBody(d.Command)
	v := a.KeyTransition
	if b.Prefix != (HistoryReference{p.Head.Sequence, p.Head.Digest}) {
		rejectReduction(out, CodeRevisionConflict)
		return nil
	}
	old := latestKeyEpoch(f, p.Head.Sequence)
	for _, e := range f.Epochs {
		if e.ActivationSequence > p.Head.Sequence {
			return codedError(CodeUnavailable)
		}
		if e.RecipientEpoch == b.RecipientEpoch || e.EqualityEpoch == b.EqualityEpoch {
			rejectReduction(out, CodeValidation)
			return nil
		}
	}
	prior := uint64(0)
	if old != nil {
		if old.MembershipGeneration != b.MembershipGeneration || old.ConfigDigest != b.ConfigDigest {
			return codedError(CodeUnavailable)
		}
		prior = old.ActivationSequence
	}
	if prior != b.PreviousActivation {
		rejectReduction(out, CodeRevisionConflict)
		return nil
	}
	inventory := map[string]RetainedPayload{}
	for _, r := range f.Admissions {
		if r.Sequence > p.Head.Sequence {
			return codedError(CodeUnavailable)
		}
		if r.Method != "admit_create" || r.PayloadID == "" {
			continue
		}
		if len(inventory) >= MaxRetainedPayloads {
			return codedError(CodeUnavailable)
		}
		ref := inventoryHistoryReference(f, r.Sequence)
		if !keyReference(ref) {
			return codedError(CodeUnavailable)
		}
		inventory[r.OperationID] = RetainedPayload{r.OperationID, r.PayloadID, ref}
	}
	if old == nil {
		if v.Class != "bootstrap" || v.Bootstrap == nil || len(inventory) != 0 {
			return codedError(CodeUnavailable)
		}
		genesis, ok := historicalKeyDecision(f, *v.Bootstrap, p.Head.Sequence)
		if !ok || genesis.Sequence != 1 || genesis.Kind != "initialize_cluster" || genesis.PrincipalID != d.Command.PrincipalID || genesis.MembershipGeneration != b.MembershipGeneration {
			return codedError(CodeUnavailable)
		}
		if genesis.ClusterUID != d.Command.ClusterUID {
			return codedError(CodeUnavailable)
		}
	} else if v.Class != "protocol" || v.Bootstrap != nil {
		return codedError(CodeUnavailable)
	}
	if len(inventory) != len(v.RetainedInventory) || len(inventory) != len(v.Coverage) {
		rejectReduction(out, CodeRevisionConflict)
		return nil
	}
	for _, r := range v.RetainedInventory {
		if inventory[r.OperationID] != r {
			rejectReduction(out, CodeRevisionConflict)
			return nil
		}
	}
	for _, cover := range v.Coverage {
		original, ok := inventory[cover.OperationID]
		if !ok {
			rejectReduction(out, CodeRevisionConflict)
			return nil
		}
		var latest *PayloadWrappingRecord
		for i := range f.Wrappings {
			w := &f.Wrappings[i]
			if w.WrappingSequence > p.Head.Sequence {
				return codedError(CodeUnavailable)
			}
			if w.OperationID == cover.OperationID && (latest == nil || w.WrappingSequence > latest.WrappingSequence) {
				latest = w
			}
		}
		if latest == nil || latest.PayloadID != original.PayloadID || latest.AdmissionSequence != original.Admission.Sequence || latest.RecipientEpoch != b.RecipientEpoch || latest.MembershipGeneration != b.MembershipGeneration || latest.ConfigDigest != b.ConfigDigest || (HistoryReference{latest.WrappingSequence, latest.WrappingDigest}) != cover.Wrapping {
			rejectReduction(out, CodeRevisionConflict)
			return nil
		}
	}
	out.EpochEffect = &KeyEpochRecord{ClusterUID: d.Command.ClusterUID, RecipientEpoch: b.RecipientEpoch, MembershipGeneration: b.MembershipGeneration, ConfigDigest: b.ConfigDigest, EqualityEpoch: b.EqualityEpoch, PredecessorActivationSequence: prior, ActivationSequence: d.Sequence}
	return nil
}

// CiphertextDigest identifies envelope bytes, never plaintext or an unkeyed
// equality tag. It is only useful bound to immutable certified preparation.
func CiphertextDigest(b []byte) string { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }
