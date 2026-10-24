package contract

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"time"

	"filippo.io/age"
)

const CustodyImportCommand = "record_custody_import"
const CustodyAssignmentVersion = 4
const CustodyImportBodyVersion = 1
const CustodyRecipientStatementVersion = 1
const CustodyImportCompletionVersion = 1
const maxCustodyProtocolBytes = 1 << 20

type CustodyHost struct {
	Host             string `json:"host"`
	HostIncarnation  uint64 `json:"host_incarnation"`
	AdmittedAt       string `json:"admitted_at"`
	AdmissionSerial  string `json:"admission_serial"`
	VoterIncarnation string `json:"voter_incarnation"`
}

type CustodyCandidate struct {
	ClusterUID           string           `json:"cluster_uid"`
	Attempt              string           `json:"attempt"`
	MembershipGeneration uint64           `json:"membership_generation"`
	ConfigDigest         string           `json:"config_digest"`
	RecipientEpoch       string           `json:"recipient_epoch"`
	EqualityEpoch        string           `json:"equality_epoch"`
	ExpiresAt            string           `json:"expires_at"`
	Genesis              HistoryReference `json:"genesis"`
	Source               CustodyHost      `json:"source"`
	Target               CustodyHost      `json:"target"`
	VoterKeyID           string           `json:"voter_key_id"`
	SourceEqualityKeyID  string           `json:"source_equality_key_id"`
	EqualityKeyID        string           `json:"equality_key_id"`
}

type CustodyRecipientStatement struct {
	Version    int              `json:"version"`
	Purpose    string           `json:"purpose"`
	Candidate  CustodyCandidate `json:"candidate"`
	Recipient  string           `json:"recipient"`
	RecordedAt string           `json:"recorded_at"`
	Chain      [][]byte         `json:"chain"`
	Trust      []byte           `json:"trust"`
	Signature  []byte           `json:"signature"`
}

type CustodyImportCompletion struct {
	Version         int              `json:"version"`
	Purpose         string           `json:"purpose"`
	Candidate       CustodyCandidate `json:"candidate"`
	Recipient       string           `json:"recipient"`
	RecipientDigest string           `json:"recipient_digest"`
	CapsuleDigest   string           `json:"capsule_digest"`
	RecordedAt      string           `json:"recorded_at"`
	Chain           [][]byte         `json:"chain"`
	Trust           []byte           `json:"trust"`
	Signature       []byte           `json:"signature"`
}

type CustodyMemberImport struct {
	Recipient  CustodyRecipientStatement `json:"recipient"`
	Completion CustodyImportCompletion   `json:"completion"`
}

type CustodyImportBody struct {
	Version              int              `json:"version"`
	Attempt              string           `json:"attempt"`
	MembershipGeneration uint64           `json:"membership_generation"`
	ConfigDigest         string           `json:"config_digest"`
	RecipientEpoch       string           `json:"recipient_epoch"`
	EqualityEpoch        string           `json:"equality_epoch"`
	Genesis              HistoryReference `json:"genesis"`
}

type CustodyImportRecord struct {
	Version              int                   `json:"version"`
	ClusterUID           string                `json:"cluster_uid"`
	Attempt              string                `json:"attempt"`
	MembershipGeneration uint64                `json:"membership_generation"`
	ConfigDigest         string                `json:"config_digest"`
	RecipientEpoch       string                `json:"recipient_epoch"`
	EqualityEpoch        string                `json:"equality_epoch"`
	Genesis              HistoryReference      `json:"genesis"`
	ExpiresAt            string                `json:"expires_at"`
	Members              []CustodyMemberImport `json:"members"`
}

// These checks validate structure only. The native custody and history owners
// separately verify the served-host signatures and recorded trust evidence.
func custodyHostValid(h CustodyHost) bool {
	_, err := time.Parse(time.RFC3339Nano, h.AdmittedAt)
	return err == nil && keyText(h.Host) && h.HostIncarnation <= math.MaxInt64 && keyText(h.AdmittedAt) && keyText(h.AdmissionSerial) && h.AdmissionSerial == strings.ToLower(h.AdmissionSerial) && keyText(h.VoterIncarnation)
}
func ValidateCustodyCandidate(c CustodyCandidate) error {
	_, err := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if err != nil || !keyText(c.ClusterUID) || !keyText(c.Attempt) || !keyNumber(c.MembershipGeneration) || !keyDigest(c.ConfigDigest) || !keyText(c.RecipientEpoch) || !keyText(c.EqualityEpoch) || !keyText(c.ExpiresAt) || !keyReference(c.Genesis) || c.Genesis.Sequence != 1 || !custodyHostValid(c.Source) || !custodyHostValid(c.Target) || !keyText(c.VoterKeyID) || !keyText(c.SourceEqualityKeyID) || !keyText(c.EqualityKeyID) {
		return codedError(CodeValidation)
	}
	return nil
}
func custodyTranscriptValid(candidate CustodyCandidate, recipient, at string, chain [][]byte, trust, signature []byte) bool {
	if ValidateCustodyCandidate(candidate) != nil || len(chain) == 0 || len(trust) == 0 || len(signature) == 0 || len(signature) > 256 {
		return false
	}
	total := len(trust) + len(signature)
	for _, cert := range chain {
		if len(cert) == 0 || len(cert) > maxCustodyProtocolBytes-total {
			return false
		}
		total += len(cert)
	}
	if total > maxCustodyProtocolBytes {
		return false
	}
	native, err := age.ParseX25519Recipient(recipient)
	if err != nil || native.String() != recipient {
		return false
	}
	recorded, err := time.Parse(time.RFC3339Nano, at)
	if err != nil || !keyText(at) {
		return false
	}
	expiry, _ := time.Parse(time.RFC3339Nano, candidate.ExpiresAt)
	return recorded.Before(expiry)
}
func ValidateCustodyRecipient(s CustodyRecipientStatement) error {
	if s.Version != CustodyRecipientStatementVersion || s.Purpose != "automation-custody-recipient" || !custodyTranscriptValid(s.Candidate, s.Recipient, s.RecordedAt, s.Chain, s.Trust, s.Signature) {
		return codedError(CodeValidation)
	}
	return nil
}
func ValidateCustodyCompletion(s CustodyImportCompletion) error {
	if s.Version != CustodyImportCompletionVersion || s.Purpose != "automation-custody-import-completion" || !keyDigest(s.RecipientDigest) || !keyDigest(s.CapsuleDigest) || !custodyTranscriptValid(s.Candidate, s.Recipient, s.RecordedAt, s.Chain, s.Trust, s.Signature) {
		return codedError(CodeValidation)
	}
	return nil
}
func DecodeCustodyImportBody(c Command) (CustodyImportBody, error) {
	var b CustodyImportBody
	if c.Kind != CustodyImportCommand || keyBody(c, &b) != nil || b.Version != CustodyImportBodyVersion || !keyText(b.Attempt) || !keyNumber(b.MembershipGeneration) || !keyDigest(b.ConfigDigest) || !keyText(b.RecipientEpoch) || !keyText(b.EqualityEpoch) || !keyReference(b.Genesis) || b.Genesis.Sequence != 1 || c.ProjectUID != "" || c.ResourceUID != "" || len(c.Ciphertext) != 0 || len(c.SecretIntentTag) != 0 || c.SecretKeyEpoch != "" {
		return b, codedError(CodeValidation)
	}
	return b, nil
}
func validateCustodyImport(d Decision, a Assignment) error {
	body, err := DecodeCustodyImportBody(d.Command)
	if err != nil {
		return err
	}
	r := a.CustodyImport
	if a.Version != CustodyAssignmentVersion || a.ClusterUID != d.Command.ClusterUID || r == nil || r.Version != 1 || r.ClusterUID != a.ClusterUID || r.Attempt != body.Attempt || r.MembershipGeneration != body.MembershipGeneration || r.ConfigDigest != body.ConfigDigest || r.RecipientEpoch != body.RecipientEpoch || r.EqualityEpoch != body.EqualityEpoch || r.Genesis != body.Genesis || len(r.Members) == 0 || len(r.Members) > MaxKeyRecipients {
		return codedError(CodeValidation)
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(d.Assignment, &raw) != nil || exactBindingJSON(raw["custody_import"], reflect.TypeOf(CustodyImportRecord{})) != nil {
		return codedError(CodeValidation)
	}
	keys, recipients := map[string]bool{}, map[string]bool{}
	source := r.Members[0].Recipient.Candidate.Source
	sourceKey := r.Members[0].Recipient.Candidate.SourceEqualityKeyID
	sourceFound := false
	previous := ""
	for _, m := range r.Members {
		s, c := m.Recipient, m.Completion
		v := s.Candidate
		if ValidateCustodyRecipient(s) != nil || ValidateCustodyCompletion(c) != nil || c.Candidate != v || c.Recipient != s.Recipient || v.ClusterUID != r.ClusterUID || v.Attempt != r.Attempt || v.MembershipGeneration != r.MembershipGeneration || v.ConfigDigest != r.ConfigDigest || v.RecipientEpoch != r.RecipientEpoch || v.EqualityEpoch != r.EqualityEpoch || v.Genesis != r.Genesis || v.ExpiresAt != r.ExpiresAt || v.Source != source || v.SourceEqualityKeyID != sourceKey || v.Target.Host <= previous || keys[v.VoterKeyID] || keys[v.EqualityKeyID] || v.VoterKeyID == v.EqualityKeyID || recipients[s.Recipient] {
			return codedError(CodeValidation)
		}
		first, _ := time.Parse(time.RFC3339Nano, s.RecordedAt)
		last, _ := time.Parse(time.RFC3339Nano, c.RecordedAt)
		if last.Before(first) {
			return codedError(CodeValidation)
		}
		if v.Target == source {
			if v.EqualityKeyID != sourceKey {
				return codedError(CodeValidation)
			}
			sourceFound = true
		}
		previous = v.Target.Host
		keys[v.VoterKeyID], keys[v.EqualityKeyID], recipients[s.Recipient] = true, true, true
	}
	if !sourceFound {
		return codedError(CodeValidation)
	}
	return nil
}

func reduceCustodyImport(out *Reduction, p Projection, d Decision, a Assignment) error {
	r := a.CustodyImport
	f := p.KeyTransition
	if f == nil || p.Head.ClusterUID != r.ClusterUID || p.Head.Sequence+1 != d.Sequence || p.Head.Digest != d.ParentDigest || f.MembershipGeneration != r.MembershipGeneration || f.ConfigDigest != r.ConfigDigest {
		return codedError(CodeUnavailable)
	}
	if len(f.Epochs) != 0 || len(f.Admissions) != 0 || len(f.Wrappings) != 0 || len(f.Members) != len(r.Members) {
		rejectReduction(out, CodeValidation)
		return nil
	}
	genesis, ok := historicalKeyDecision(f, r.Genesis, p.Head.Sequence)
	if !ok || genesis.Kind != "initialize_cluster" || genesis.ClusterUID != r.ClusterUID || genesis.PrincipalID != d.Command.PrincipalID || genesis.MembershipGeneration != r.MembershipGeneration {
		return codedError(CodeUnavailable)
	}
	members := map[string]string{}
	for _, m := range f.Members {
		if m.Host == "" || m.VoterIncarnation == "" || members[m.Host] != "" {
			return codedError(CodeUnavailable)
		}
		members[m.Host] = m.VoterIncarnation
	}
	for _, m := range r.Members {
		h := m.Recipient.Candidate.Target
		if members[h.Host] != h.VoterIncarnation {
			rejectReduction(out, CodeValidation)
			return nil
		}
	}
	return nil
}

// CustodyImportSummary retains only finite public causal facts, never a complete
// envelope, certificate bundle, material, or a live permission.
type CustodyImportSummary struct {
	RecordDigest  string
	EqualityEpoch string
	Genesis       HistoryReference
	Recipients    []RecipientBinding
}

func CustodyRecipientBinding(statement CustodyRecipientStatement, ref HistoryReference) RecipientBinding {
	c := statement.Candidate
	h := c.Target
	return RecipientBinding{ClusterUID: c.ClusterUID, MembershipGeneration: c.MembershipGeneration, ConfigDigest: c.ConfigDigest, Host: h.Host, HostIncarnation: h.HostIncarnation, AdmittedAt: h.AdmittedAt, AdmissionSerial: h.AdmissionSerial, VoterIncarnation: h.VoterIncarnation, RecipientEpoch: c.RecipientEpoch, KeyID: c.VoterKeyID, Recipient: statement.Recipient, Enrollment: ref, RecipientAck: ref, EqualityAck: ref}
}
