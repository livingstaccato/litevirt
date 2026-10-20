// Retained ordinary-target consumer contract. This is not native admission authority.
package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/litevirt/litevirt/internal/safename"
	"io"
	"math"
	"strings"
	"time"
)

const LegacyRebuildCommand = "admit_legacy_rebuild"
const OrdinaryCreateCommand = "admit_ordinary_create"
const MaxTargetKeys = 64
const MaxTargetPreparationBytes = 64 << 10

type OrdinarySnapshot struct {
	CreatedAt      string `json:"created_at"`
	HostName       string `json:"host_name"`
	OwnerEpoch     int64  `json:"owner_epoch"`
	SpecGeneration int64  `json:"spec_generation"`
	IdentityHash   string `json:"identity_hash"`
	FirewallID     string `json:"firewall_id"`
}
type TargetKey struct {
	Kind     string             `json:"kind"` // exactly "vm_name" or "artifact"
	Name     string             `json:"name"` // nonempty only for vm_name
	Artifact *TargetArtifactKey `json:"artifact,omitempty"`
}
type TargetArtifactKey struct {
	OwnerKind string `json:"owner_kind"`
	OwnerUID  string `json:"owner_uid"`
	ObjectID  string `json:"object_id"`
}
type TargetPredecessor struct {
	Kind                  string `json:"kind"` // exactly "none", "unowned", "retired"
	ResourceUID           string `json:"resource_uid"`
	NameGeneration        uint64 `json:"name_generation"`
	Incarnation           string `json:"incarnation"`
	Revision              string `json:"revision"`
	RetirementOperationID string `json:"retirement_operation_id"`
}
type LegacyRebuildBody struct {
	Version     int               `json:"version"`
	Name        string            `json:"name"`
	ProjectName string            `json:"project_name"`
	Snapshot    OrdinarySnapshot  `json:"snapshot"`
	Expected    TargetPredecessor `json:"expected"`
	Keys        []TargetKey       `json:"keys"`
}
type OrdinaryCreateBody struct {
	Version  int               `json:"version"`
	Desired  VMIntent          `json:"desired"`
	Expected TargetPredecessor `json:"expected"`
	Keys     []TargetKey       `json:"keys"`
}
type TargetProjectFact struct {
	Name         string `json:"name"`
	Kind         string `json:"kind"` // exactly "default" or "project"
	Lifetime     string `json:"lifetime"`
	CertifiedUID string `json:"certified_uid"`
}
type TargetHostFact struct {
	Host            string `json:"host"`
	Incarnation     int64  `json:"incarnation"`
	AdmittedAt      string `json:"admitted_at"`
	AdmissionSerial string `json:"admission_serial"`
}
type TargetPreparation struct {
	Key                   TargetKey           `json:"key"`
	Expected              TargetPredecessor   `json:"expected"`
	EvidenceID            string              `json:"evidence_id"`
	Host                  TargetHostFact      `json:"host"`
	DomainUUID            string              `json:"domain_uuid"`
	Snapshot              *OrdinarySnapshot   `json:"snapshot,omitempty"`
	JournalOperationID    string              `json:"journal_operation_id"`
	JournalFrontierDigest string              `json:"journal_frontier_digest"`
	JournalState          string              `json:"journal_state"`
	JournalSteps          []TargetJournalStep `json:"journal_steps"`
	OwnerPreparationID    string              `json:"owner_preparation_id"`
	EffectScopeDigest     string              `json:"effect_scope_digest"`
}
type TargetJournalStep struct {
	Name  string `json:"name"`
	Facts string `json:"facts"` // bounded nonsecret canonical object, retained verbatim
}
type TargetAssignment struct {
	Version              int                 `json:"version"`
	AttemptID            string              `json:"attempt_id"`
	ParentSequence       uint64              `json:"parent_sequence"`
	ParentDigest         string              `json:"parent_digest"`
	MembershipGeneration uint64              `json:"membership_generation"`
	ConfigDigest         string              `json:"config_digest"`
	Project              TargetProjectFact   `json:"project"`
	Permission           PermissionFacts     `json:"permission"`
	Preparations         []TargetPreparation `json:"preparations"`
	Configuration        VMIntent            `json:"configuration"`
	PayloadID            string              `json:"payload_id"`
	Allocation           *OrdinaryAllocation `json:"allocation,omitempty"`
}
type OrdinaryAllocation struct {
	ResourceUID    string `json:"resource_uid"`
	DomainUUID     string `json:"domain_uuid"`
	Incarnation    string `json:"incarnation"`
	NameGeneration uint64 `json:"name_generation"`
	Revision       string `json:"revision"`
}

// Assignment gets Target *TargetAssignment `json:"target,omitempty"` appended,
// preserving all existing fields/order and their omission behavior.
// Projection gets Target *TargetProjection.
// Reduction gets TargetEffect *TargetOperationRecord and TargetReservations []TargetReservation.
type TargetReservation struct {
	ClusterUID, Key, OperationID string
	Sequence                     uint64
}
type TargetOperationRecord struct {
	ClusterUID, OperationID, Kind, ProjectUID, PrincipalUID, RequestID string
	ResourceUID, TargetName, DecisionDigest                            string
	Sequence                                                           uint64
	Body                                                               []byte
	Assignment                                                         []byte
}
type TargetKeyProjection struct {
	Key         TargetKey
	Reservation *TargetReservation
	Name        *NameRecord
	Identity    *IdentityRecord
	Resource    *ResourceRecord
}
type TargetProjection struct {
	Keys             []TargetKeyProjection
	AssignedIdentity *IdentityRecord
	AssignedResource *ResourceRecord
	Project          *IdentityRecord
	Principal        *IdentityRecord
	Dependencies     []*IdentityRecord
}

func targetCommand(kind string) bool {
	return kind == LegacyRebuildCommand || kind == OrdinaryCreateCommand
}
func targetText(s string) bool { return s != "" && len(s) <= MaxStringBytes }
func targetUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' || s != strings.ToLower(s) {
		return false
	}
	b, e := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if e != nil || len(b) != 16 {
		return false
	}
	for _, v := range b {
		if v != 0 {
			return true
		}
	}
	return false
}
func validOrdinarySnapshot(s OrdinarySnapshot) bool {
	return targetText(s.CreatedAt) && targetText(s.HostName) && s.OwnerEpoch >= 0 && s.SpecGeneration >= 0 && validFactsDigest(s.IdentityHash) && len(s.FirewallID) <= MaxStringBytes
}
func validTargetPredecessor(p TargetPredecessor) bool {
	switch p.Kind {
	case "none":
		return p.ResourceUID == "" && p.NameGeneration == 0 && p.Incarnation == "" && p.Revision == "" && p.RetirementOperationID == ""
	case "unowned", "retired":
		return targetText(p.ResourceUID) && p.NameGeneration > 0 && p.NameGeneration <= math.MaxInt64 && targetText(p.Incarnation) && targetText(p.Revision) && ((p.Kind == "unowned" && p.RetirementOperationID == "") || (p.Kind == "retired" && targetText(p.RetirementOperationID)))
	}
	return false
}

// TargetKeyEncoding is an injective canonical JSON array, ordered by UTF8 bytes.
func TargetKeyEncoding(k TargetKey) (string, error) {
	var fields []string
	switch k.Kind {
	case "vm_name":
		if k.Artifact != nil || safename.ValidateVMName(k.Name) != nil {
			return "", codedError(CodeValidation)
		}
		fields = []string{"vm_name", k.Name}
	case "artifact":
		if k.Name != "" || k.Artifact == nil || !targetText(k.Artifact.OwnerUID) || !targetText(k.Artifact.ObjectID) {
			return "", codedError(CodeValidation)
		}
		switch k.Artifact.OwnerKind {
		case "pool", "image", "firmware", "seed", "tpm":
		default:
			return "", codedError(CodeValidation)
		}
		fields = []string{"artifact", k.Artifact.OwnerKind, k.Artifact.OwnerUID, k.Artifact.ObjectID}
	default:
		return "", codedError(CodeValidation)
	}
	b, _ := json.Marshal(fields)
	return string(b), nil
}
func validTargetKeys(keys []TargetKey, name string) bool {
	if len(keys) == 0 || len(keys) > MaxTargetKeys {
		return false
	}
	last := ""
	found := false
	for _, k := range keys {
		encoded, e := TargetKeyEncoding(k)
		if e != nil || encoded <= last {
			return false
		}
		last = encoded
		if k.Kind == "vm_name" && k.Name == name {
			found = true
		}
	}
	return found
}
func targetEnvelope(c Command) error {
	for _, s := range []string{c.ClusterUID, c.PrincipalID, c.RequestID} {
		if !targetText(s) {
			return codedError(CodeValidation)
		}
	}
	if len(c.ProjectUID) > MaxStringBytes || c.OwnerID != "" || c.ManagementKey != "" || c.SessionID != "" || c.Session != 0 || c.Generation != 0 || c.ExpectedRevision != 0 || c.ResourceUID != "" || len(c.Ciphertext) != 0 || len(c.SecretIntentTag) != 0 || c.SecretKeyEpoch != "" {
		return codedError(CodeValidation)
	}
	return nil
}
func DecodeLegacyRebuildBody(c Command) (LegacyRebuildBody, error) {
	var b LegacyRebuildBody
	if c.Kind != LegacyRebuildCommand {
		return b, codedError(CodeUnsupported)
	}
	if targetEnvelope(c) != nil || strictBindingObject(c.Body, &b) != nil || b.Version != 1 || safename.ValidateVMName(b.Name) != nil || !targetText(b.ProjectName) || !validOrdinarySnapshot(b.Snapshot) || !validTargetPredecessor(b.Expected) || b.Expected.Kind == "retired" || !validTargetKeys(b.Keys, b.Name) {
		return b, codedError(CodeValidation)
	}
	return b, nil
}
func DecodeOrdinaryCreateBody(c Command) (OrdinaryCreateBody, error) {
	var b OrdinaryCreateBody
	if c.Kind != OrdinaryCreateCommand {
		return b, codedError(CodeUnsupported)
	}
	if targetEnvelope(c) != nil || c.ProjectUID == "" || strictBindingObject(c.Body, &b) != nil || b.Version != 1 || validateVMIntent(b.Desired, c.ClusterUID) != nil || !validTargetPredecessor(b.Expected) || b.Expected.Kind == "unowned" || !validTargetKeys(b.Keys, b.Desired.Name) {
		return b, codedError(CodeValidation)
	}
	return b, nil
}
func targetBody(c Command) (name, project string, expected TargetPredecessor, keys []TargetKey, snapshot *OrdinarySnapshot, err error) {
	if c.Kind == LegacyRebuildCommand {
		b, e := DecodeLegacyRebuildBody(c)
		return b.Name, b.ProjectName, b.Expected, b.Keys, &b.Snapshot, e
	}
	b, e := DecodeOrdinaryCreateBody(c)
	return b.Desired.Name, "", b.Expected, b.Keys, nil, e
}
func canonicalTargetFacts(text string) bool {
	if text == "" || len(text) > MaxTargetPreparationBytes {
		return false
	}
	d := json.NewDecoder(strings.NewReader(text))
	d.UseNumber()
	v, e := jsonValue(d, 0)
	if e != nil {
		return false
	}
	if _, e = d.Token(); e != io.EOF {
		return false
	}
	if _, ok := v.(map[string]any); !ok {
		return false
	}
	b, e := json.Marshal(v)
	return e == nil && bytes.Equal(b, []byte(text))
}

// Journal digest v1 = SHA256(domain NUL || JSON struct below), UTF8, no trailing
// newline. Steps are sorted unique; Facts is exact canonical OBJECT JSON TEXT,
// encoded as a JSON string, never decoded into the enclosing preimage. Idle
// always encodes steps:[] and empty operation_id. Neither digest is a permit.
func TargetJournalDigest(operation, state string, steps []TargetJournalStep) (string, error) {
	if state != "idle" && state != "settled" {
		return "", codedError(CodeValidation)
	}
	if len(steps) > 128 || (state == "idle" && (operation != "" || len(steps) != 0)) || (state == "settled" && !targetText(operation)) {
		return "", codedError(CodeValidation)
	}
	last := ""
	size := 0
	for _, s := range steps {
		if !targetText(s.Name) || s.Name <= last || !canonicalTargetFacts(s.Facts) {
			return "", codedError(CodeValidation)
		}
		last = s.Name
		size += len(s.Name) + len(s.Facts)
		if size > MaxTargetPreparationBytes {
			return "", codedError(CodeValidation)
		}
	}
	normalized := append([]TargetJournalStep{}, steps...)
	v := struct {
		Operation string              `json:"operation_id"`
		State     string              `json:"state"`
		Steps     []TargetJournalStep `json:"steps"`
	}{operation, state, normalized}
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(append([]byte("litevirt/automation/target-journal/v1\x00"), b...))
	return hex.EncodeToString(sum[:]), nil
}

// Scope digest v1 retains ALL preparation fields in declaration order, except
// EffectScopeDigest itself (set empty). JSON tags/omitempty are normative; exact
// Facts text and snapshot nil/presence are retained. No newline. A producer may
// issue this evidence only after checking its actual effect scope; computing or
// retaining the digest here confers NO grant or complete-producer assertion.
func TargetPreparationScopeDigest(p TargetPreparation) string {
	p.EffectScopeDigest = ""
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(append([]byte("litevirt/automation/target-effect-scope/v1\x00"), b...))
	return hex.EncodeToString(sum[:])
}
func validateTargetAssignment(d Decision, a Assignment) error {
	c := d.Command
	t := a.Target
	name, project, expected, keys, snapshot, e := targetBody(c)
	if e != nil {
		return e
	}
	if strictBindingObject(d.Assignment, new(Assignment)) != nil || t == nil || a.ClusterUID != c.ClusterUID || t.Version != 1 || !targetText(t.AttemptID) || d.Sequence == 0 || d.Sequence > math.MaxInt64 || t.ParentSequence != d.Sequence-1 || t.ParentDigest != d.ParentDigest || !validFactsDigest(t.ParentDigest) || t.MembershipGeneration == 0 || t.MembershipGeneration > math.MaxInt64 || !validFactsDigest(t.ConfigDigest) || t.PayloadID != "" {
		return codedError(CodeValidation)
	}
	f := t.Project
	if !targetText(f.Name) || !targetText(f.Lifetime) || (f.Kind != "default" && f.Kind != "project") || f.CertifiedUID != c.ProjectUID || (project != "" && f.Name != project) {
		return codedError(CodeValidation)
	}
	purpose, verb := "legacy_rebuild", "vm.rebuild"
	if c.Kind == OrdinaryCreateCommand {
		purpose, verb = "ordinary_create", "vm.create"
	}
	q := t.Permission
	if q.Purpose != purpose || q.Verb != verb || q.PrincipalUID != c.PrincipalID || q.ClusterUID != c.ClusterUID || q.ProjectUID != c.ProjectUID || q.ProjectName != f.Name || q.ResourceName != name || q.OwnerID != "" || q.ResourceUID != expected.ResourceUID || !targetText(q.EvidenceID) || !validFactsDigest(q.CoverageDigest) || q.FenceSequence == 0 || q.FenceSequence > d.Sequence-1 {
		return codedError(CodeValidation)
	}
	if validateVMIntent(t.Configuration, c.ClusterUID) != nil || !configurationMatches(t.Configuration, t.Configuration, c.ClusterUID) || t.Configuration.Name != name {
		return codedError(CodeValidation)
	}
	if c.Kind == OrdinaryCreateCommand {
		body, _ := DecodeOrdinaryCreateBody(c)
		alloc := t.Allocation
		if alloc == nil || !targetText(alloc.ResourceUID) || !targetUUID(alloc.DomainUUID) || !targetText(alloc.Incarnation) || !targetText(alloc.Revision) || alloc.NameGeneration == 0 || alloc.NameGeneration > math.MaxInt64 || !configurationMatches(body.Desired, t.Configuration, c.ClusterUID) {
			return codedError(CodeValidation)
		}
	} else if t.Allocation != nil {
		return codedError(CodeValidation)
	}
	if len(t.Preparations) != len(keys) {
		return codedError(CodeValidation)
	}
	var envelope map[string]json.RawMessage
	var nested map[string]json.RawMessage
	if json.Unmarshal(d.Assignment, &envelope) != nil || json.Unmarshal(envelope["target"], &nested) != nil || len(nested["preparations"]) > MaxTargetPreparationBytes {
		return codedError(CodeValidation)
	}
	raw, _ := json.Marshal(t.Preparations)
	if len(raw) > MaxTargetPreparationBytes {
		return codedError(CodeValidation)
	}
	for i, p := range t.Preparations {
		key, _ := TargetKeyEncoding(keys[i])
		pk, e := TargetKeyEncoding(p.Key)
		if e != nil || pk != key || !validTargetPredecessor(p.Expected) || !targetText(p.EvidenceID) || !targetText(p.OwnerPreparationID) || !validFactsDigest(p.EffectScopeDigest) || !targetText(p.Host.Host) || p.Host.Incarnation < 0 || !targetText(p.Host.AdmissionSerial) {
			return codedError(CodeValidation)
		}
		at, e := time.Parse(time.RFC3339Nano, p.Host.AdmittedAt)
		if e != nil || at.Format(time.RFC3339Nano) != p.Host.AdmittedAt {
			return codedError(CodeValidation)
		}
		digest, e := TargetJournalDigest(p.JournalOperationID, p.JournalState, p.JournalSteps)
		if e != nil || p.JournalFrontierDigest != digest {
			return codedError(CodeValidation)
		}
		if p.Key.Kind == "artifact" {
			if p.Expected.Kind != "none" || p.Snapshot != nil || p.DomainUUID != "" {
				return codedError(CodeValidation)
			}
			continue
		}
		if !targetUUID(p.DomainUUID) || (p.Snapshot != nil && (!validOrdinarySnapshot(*p.Snapshot) || p.Snapshot.HostName != p.Host.Host)) {
			return codedError(CodeValidation)
		}
		if p.Key.Name == name {
			if p.Expected != expected {
				return codedError(CodeValidation)
			}
			if c.Kind == LegacyRebuildCommand {
				if p.Snapshot == nil || *p.Snapshot != *snapshot || p.Host.Host != snapshot.HostName {
					return codedError(CodeValidation)
				}
			} else if p.Snapshot != nil || p.DomainUUID != t.Allocation.DomainUUID {
				return codedError(CodeValidation)
			}
		} else if p.Expected.Kind != "unowned" || p.Snapshot == nil || !validOrdinarySnapshot(*p.Snapshot) {
			return codedError(CodeValidation)
		}
	}
	return nil
}

// Existing VM handlers require an explicit target projection even when empty.
// Duplicate receipt handling precedes this guard in Reduce; nil is unavailable.
func guardTargetReservation(out *Reduction, p Projection, cluster, name string) (bool, error) {
	if p.Target == nil {
		return false, codedError(CodeUnavailable)
	}
	want, _ := TargetKeyEncoding(TargetKey{Kind: "vm_name", Name: name})
	seen := map[string]bool{}
	for _, f := range p.Target.Keys {
		key, e := TargetKeyEncoding(f.Key)
		if e != nil || seen[key] {
			return false, codedError(CodeUnavailable)
		}
		seen[key] = true
		if f.Reservation != nil {
			r := f.Reservation
			if r.ClusterUID != cluster || r.Key != key || !targetText(r.OperationID) || r.Sequence == 0 || r.Sequence > p.Head.Sequence {
				return false, codedError(CodeUnavailable)
			}
			if key == want {
				rejectReduction(out, CodeOwnershipConflict)
				return false, nil
			}
		}
	}
	return true, nil
}
func targetPredecessorMatches(f TargetKeyProjection, p TargetPredecessor, cluster, project string) bool {
	if p.Kind == "none" {
		return f.Name == nil && f.Identity == nil && f.Resource == nil
	}
	n, id, r := f.Name, f.Identity, f.Resource
	if n == nil || id == nil || r == nil || n.ClusterUID != cluster || n.Name != f.Key.Name || n.ResourceUID != p.ResourceUID || n.Generation != p.NameGeneration || id.ClusterUID != cluster || id.ProjectUID != project || id.Kind != "vm" || id.UID != p.ResourceUID || id.Alias != f.Key.Name || id.Generation != p.NameGeneration || id.Witness == "" || r.ClusterUID != cluster || r.ProjectUID != project || r.UID != p.ResourceUID || r.Name != f.Key.Name || r.Incarnation != p.Incarnation || r.Revision != p.Revision {
		return false
	}
	if p.Kind == "retired" {
		return n.Disposition == "reusable" && n.RetirementOperationID == p.RetirementOperationID && id.Retired && r.Retired
	}
	return (n.Disposition == "live" || n.Disposition == "reserved") && n.RetirementOperationID == "" && !id.Retired && !r.Retired && r.OwnerID == "" && r.ManagementKey == "" && r.BindingGeneration == 0
}
func reduceTarget(out *Reduction, p Projection, d Decision, a Assignment) error {
	c, t := d.Command, a.Target
	name, _, expected, keys, _, _ := targetBody(c)
	if p.Head.Sequence == 0 || p.Head.ClusterUID != c.ClusterUID || p.Head.Sequence != t.ParentSequence || p.Head.Digest != t.ParentDigest || p.Target == nil || len(p.Target.Keys) != len(keys) {
		return codedError(CodeUnavailable)
	}
	f := p.Target
	if !liveIdentity(f.Principal, c.ClusterUID, "principal", c.PrincipalID) {
		return codedError(CodeUnavailable)
	}
	if c.ProjectUID != "" {
		if !liveIdentity(f.Project, c.ClusterUID, "project", c.ProjectUID) || f.Project.Alias != t.Project.Name || f.Project.Witness != t.Project.Lifetime {
			return codedError(CodeUnavailable)
		}
	} else if f.Project != nil {
		return codedError(CodeUnavailable)
	}
	for i, k := range keys {
		actual := f.Keys[i]
		key, _ := TargetKeyEncoding(k)
		ak, e := TargetKeyEncoding(actual.Key)
		if e != nil || ak != key {
			return codedError(CodeUnavailable)
		}
		if actual.Reservation != nil {
			r := actual.Reservation
			if r.ClusterUID != c.ClusterUID || r.Key != key || !targetText(r.OperationID) || r.Sequence == 0 || r.Sequence > p.Head.Sequence {
				return codedError(CodeUnavailable)
			}
			rejectReduction(out, CodeOwnershipConflict)
			return nil
		}
		prep := t.Preparations[i]
		if k.Kind == "artifact" {
			if actual.Name != nil || actual.Identity != nil || actual.Resource != nil {
				return codedError(CodeUnavailable)
			}
			continue
		}
		if actual.Resource != nil && (actual.Resource.OwnerID != "" || actual.Resource.ManagementKey != "" || actual.Resource.BindingGeneration != 0) && prep.Expected.Kind != "retired" {
			rejectReduction(out, CodeOwnershipConflict)
			return nil
		}
		if !targetPredecessorMatches(actual, prep.Expected, c.ClusterUID, c.ProjectUID) {
			return codedError(CodeUnavailable)
		}
		if actual.Resource != nil && actual.Resource.DomainUUID != prep.DomainUUID && !(k.Name == name && c.Kind == OrdinaryCreateCommand && prep.Expected.Kind == "retired") {
			return codedError(CodeUnavailable)
		}
	}
	deps := map[string]*IdentityRecord{}
	for _, r := range f.Dependencies {
		if r == nil || deps[r.UID] != nil {
			return codedError(CodeUnavailable)
		}
		deps[r.UID] = r
	}
	for _, dep := range BindingDependencies(t.Configuration) {
		r := deps[dep.UID]
		if r == nil || r.ClusterUID != dep.ClusterUID || r.ProjectUID != dep.ProjectUID || r.Kind != dep.Kind || r.Generation == 0 {
			return codedError(CodeUnavailable)
		}
		if r.Retired {
			rejectReduction(out, CodeRetired)
			return nil
		}
	}
	if c.Kind == OrdinaryCreateCommand {
		alloc := t.Allocation
		if f.AssignedIdentity != nil || f.AssignedResource != nil {
			rejectReduction(out, CodeValidation)
			return nil
		}
		want := uint64(1)
		if expected.Kind == "retired" {
			if expected.NameGeneration >= math.MaxInt64 {
				rejectReduction(out, CodeRevisionConflict)
				return nil
			}
			want = expected.NameGeneration + 1
			if alloc.Incarnation == expected.Incarnation || alloc.ResourceUID == expected.ResourceUID {
				rejectReduction(out, CodeValidation)
				return nil
			}
		}
		if alloc.NameGeneration != want {
			rejectReduction(out, CodeRevisionConflict)
			return nil
		}
		out.IdentityEffect = &IdentityRecord{ClusterUID: c.ClusterUID, ProjectUID: c.ProjectUID, Kind: "vm", UID: alloc.ResourceUID, Alias: name, Witness: alloc.Incarnation, Generation: alloc.NameGeneration}
		out.ResourceEffect = &ResourceRecord{ClusterUID: c.ClusterUID, ProjectUID: c.ProjectUID, UID: alloc.ResourceUID, Name: name, DomainUUID: alloc.DomainUUID, Incarnation: alloc.Incarnation, LastOperationID: a.OperationID, OriginalOperationID: a.OperationID, AppliedSequence: d.Sequence, Revision: alloc.Revision}
		out.NameEffect = &NameRecord{ClusterUID: c.ClusterUID, Name: name, ResourceUID: alloc.ResourceUID, Generation: alloc.NameGeneration, Disposition: "reserved"}
		out.Receipt.ResourceUID = alloc.ResourceUID
		out.Receipt.ResourceRevision = alloc.Revision
	} else {
		out.Receipt.ResourceUID = expected.ResourceUID
		out.Receipt.ResourceRevision = expected.Revision
	}
	out.TargetEffect = &TargetOperationRecord{ClusterUID: c.ClusterUID, OperationID: a.OperationID, Kind: c.Kind, ProjectUID: c.ProjectUID, PrincipalUID: c.PrincipalID, RequestID: c.RequestID, ResourceUID: out.Receipt.ResourceUID, TargetName: name, Sequence: d.Sequence, Body: append([]byte(nil), c.Body...), Assignment: append([]byte(nil), d.Assignment...)}
	for _, k := range keys {
		key, _ := TargetKeyEncoding(k)
		out.TargetReservations = append(out.TargetReservations, TargetReservation{ClusterUID: c.ClusterUID, Key: key, OperationID: a.OperationID, Sequence: d.Sequence})
	}
	out.Receipt.State = "accepted"
	out.Receipt.Generation = 0
	return nil
}
