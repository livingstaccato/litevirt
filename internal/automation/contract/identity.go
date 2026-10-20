package contract

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/litevirt/litevirt/internal/safename"
	"math"
	"reflect"
	"strings"
)

// IdentityEnrollment names a positive legacy lifetime in a closed migration
// inventory. EvidenceID identifies server-verified coverage; it is not itself
// authority to enroll the caller's witness.
type IdentityEnrollment struct {
	Version            int    `json:"version"`
	Kind               string `json:"kind"`
	Alias              string `json:"alias"`
	Witness            string `json:"witness"`
	EvidenceID         string `json:"evidence_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
}

// IdentityAssignment is prepared once outside the transaction and certified in
// the decision. It never derives a lifetime from a mutable name or domain UUID.
type IdentityAssignment struct {
	UID        string                   `json:"uid"`
	Generation uint64                   `json:"generation"`
	Enrollment *IdentityEnrollmentFacts `json:"enrollment"`
}

func DecodeIdentityEnrollment(c Command) (IdentityEnrollment, error) {
	var b IdentityEnrollment
	if decodeFields(c.Body, &b, "version", "kind", "alias", "witness", "evidence_id", "expected_generation") != nil || !requiredIdentityFields(c.Body, "expected_generation") || b.Version != 1 || b.Alias == "" || b.Witness == "" || b.EvidenceID == "" || b.ExpectedGeneration >= math.MaxInt64 {
		return b, codedError(CodeValidation)
	}
	switch b.Kind {
	case "project", "principal", "vm", "pool", "network", "image", "host":
	default:
		return b, codedError(CodeValidation)
	}
	for _, s := range []string{b.Alias, b.Witness, b.EvidenceID} {
		if len(s) > MaxStringBytes {
			return b, codedError(CodeValidation)
		}
	}
	if c.ClusterUID == "" || c.PrincipalID == "" || c.RequestID == "" || c.OwnerID != "" || c.ManagementKey != "" || c.ResourceUID != "" || c.Session != 0 || c.SessionID != "" || c.Generation != 0 || c.ExpectedRevision != 0 || len(c.Ciphertext) != 0 || len(c.SecretIntentTag) != 0 || c.SecretKeyEpoch != "" {
		return b, codedError(CodeValidation)
	}
	if (b.Kind == "project" || b.Kind == "principal" || b.Kind == "host") && c.ProjectUID != "" {
		return b, codedError(CodeValidation)
	}
	if b.Kind == "vm" && c.ProjectUID == "" {
		return b, codedError(CodeValidation)
	}
	return b, nil
}

func validateIdentityAssignment(d Decision, a Assignment) error {
	b, err := DecodeIdentityEnrollment(d.Command)
	if err != nil {
		return err
	}
	if a.Identity == nil || a.Identity.UID == "" || len(a.Identity.UID) > MaxStringBytes || a.Identity.Generation != b.ExpectedGeneration+1 || a.ClusterUID != d.Command.ClusterUID {
		return codedError(CodeValidation)
	}
	// Nested objects require the same exact field spellings as the envelope.
	var envelope map[string]json.RawMessage
	if json.Unmarshal(d.Assignment, &envelope) != nil {
		return codedError(CodeValidation)
	}
	var nested IdentityAssignment
	if decodeFieldsObject(envelope["identity"], &nested, "uid", "generation", "enrollment") != nil {
		return codedError(CodeValidation)
	}
	var nestedFields map[string]json.RawMessage
	if json.Unmarshal(envelope["identity"], &nestedFields) != nil {
		return codedError(CodeValidation)
	}
	var facts IdentityEnrollmentFacts
	if decodeFields(nestedFields["enrollment"], &facts, "version", "evidence_id", "cluster_uid", "project_uid", "kind", "alias", "witness", "previous_generation", "coverage_digest", "fence_sequence", "vm") != nil || !requiredIdentityFields(nestedFields["enrollment"], "project_uid", "previous_generation") {
		return codedError(CodeValidation)
	}
	digest, e := hex.DecodeString(facts.CoverageDigest)
	if facts.Version != 1 || e != nil || len(digest) != 32 || facts.CoverageDigest != strings.ToLower(facts.CoverageDigest) || facts.FenceSequence == 0 || facts.FenceSequence >= d.Sequence || facts.EvidenceID != b.EvidenceID || facts.ClusterUID != d.Command.ClusterUID || facts.ProjectUID != d.Command.ProjectUID || facts.Kind != b.Kind || facts.Alias != b.Alias || facts.Witness != b.Witness || facts.PreviousGeneration != b.ExpectedGeneration {
		return codedError(CodeValidation)
	}
	var enrollmentFields map[string]json.RawMessage
	if json.Unmarshal(nestedFields["enrollment"], &enrollmentFields) != nil {
		return codedError(CodeValidation)
	}
	if b.Kind != "vm" {
		if _, present := enrollmentFields["vm"]; present {
			return codedError(CodeValidation)
		}
	}
	if b.Kind == "vm" {
		if facts.VM == nil || facts.VM.Version != 1 || facts.VM.DomainUUID == "" || facts.VM.Incarnation == "" || facts.VM.Revision == "" || safename.ValidateVMName(b.Alias) != nil {
			return codedError(CodeValidation)
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(nestedFields["enrollment"], &fields) != nil || exactBindingJSON(fields["vm"], reflect.TypeOf(VMEnrollmentRuntime{})) != nil {
			return codedError(CodeValidation)
		}
	} else if facts.VM != nil {
		return codedError(CodeValidation)
	}
	return nil
}

type VMEnrollmentRuntime struct {
	Version     int    `json:"version"`
	DomainUUID  string `json:"domain_uuid"`
	Incarnation string `json:"incarnation"`
	Revision    string `json:"revision"`
}

// IdentityRecord retains one lifetime even after its readable alias is reused.
type IdentityRecord struct {
	ClusterUID, ProjectUID, Kind, UID, Alias, Witness string
	Generation                                        uint64
	Retired                                           bool
}

// IdentityEnrollmentFacts are immutable nonsecret facts certified with the
// assigned UID. Fresh admission must compare every field to a storage-issued
// closed-cutover permit; these data alone authenticate nothing. Anchored replay
// does not require that retired permit or a current mutable inventory.
type IdentityEnrollmentFacts struct {
	VM                 *VMEnrollmentRuntime `json:"vm,omitempty"`
	Version            int                  `json:"version"`
	EvidenceID         string               `json:"evidence_id"`
	ClusterUID         string               `json:"cluster_uid"`
	ProjectUID         string               `json:"project_uid"`
	Kind               string               `json:"kind"`
	Alias              string               `json:"alias"`
	Witness            string               `json:"witness"`
	PreviousGeneration uint64               `json:"previous_generation"`
	CoverageDigest     string               `json:"coverage_digest"`
	FenceSequence      uint64               `json:"fence_sequence"`
}

type IdentityProjection struct {
	Resource, AssignedResource *ResourceRecord
	Name                       *NameRecord
	Alias                      *IdentityRecord
	Assigned                   *IdentityRecord
	Project                    *IdentityRecord
}

func reduceIdentity(out *Reduction, p Projection, d Decision, a Assignment) error {
	b, err := DecodeIdentityEnrollment(d.Command)
	if err != nil {
		return err
	}
	c := d.Command
	if p.Head.ClusterUID != c.ClusterUID || p.Head.Sequence == 0 || p.Identity == nil {
		return codedError(CodeUnavailable)
	}
	if b.Kind == "vm" {
		if ok, err := guardTargetReservation(out, p, c.ClusterUID, b.Alias); err != nil || !ok {
			return err
		}
	}
	if a.Identity.Enrollment.FenceSequence > p.Head.Sequence {
		return codedError(CodeUnavailable)
	}
	if c.ProjectUID != "" && !liveIdentity(p.Identity.Project, c.ClusterUID, "project", c.ProjectUID) {
		return codedError(CodeUnavailable)
	}
	old := p.Identity.Alias
	if old != nil {
		if old.ClusterUID != c.ClusterUID || old.ProjectUID != c.ProjectUID || old.Kind != b.Kind || old.Alias != b.Alias || old.UID == "" || old.Generation == 0 {
			return codedError(CodeUnavailable)
		}
		if old.Witness == b.Witness {
			if old.Retired {
				rejectReduction(out, CodeRetired)
				return nil
			}
			if b.Kind == "vm" {
				resource := p.Identity.Resource
				if resource == nil || resource.UID != old.UID || resource.ClusterUID != c.ClusterUID || resource.ProjectUID != c.ProjectUID || resource.Name != b.Alias || resource.Retired || resource.DomainUUID != a.Identity.Enrollment.VM.DomainUUID || resource.Incarnation != a.Identity.Enrollment.VM.Incarnation || p.Identity.Name == nil || p.Identity.Name.ResourceUID != old.UID || p.Identity.Name.Generation != old.Generation {
					return codedError(CodeUnavailable)
				}
			}
			out.Receipt.ResourceUID = old.UID
			out.Receipt.Generation = old.Generation
			return nil
		}
		if !old.Retired {
			rejectReduction(out, CodeOwnershipConflict)
			return nil
		}
		if old.Generation != b.ExpectedGeneration {
			rejectReduction(out, CodeRevisionConflict)
			return nil
		}
	} else if b.ExpectedGeneration != 0 {
		return codedError(CodeUnavailable)
	}
	if b.Kind == "vm" {
		if p.Identity.AssignedResource != nil {
			rejectReduction(out, CodeValidation)
			return nil
		}
		name := p.Identity.Name
		if name != nil {
			if old == nil || !old.Retired || name.ResourceUID != old.UID || name.ClusterUID != c.ClusterUID || name.Name != b.Alias || name.Generation != old.Generation || name.Disposition != "reusable" || name.RetirementOperationID == "" || p.Identity.Resource == nil || !p.Identity.Resource.Retired {
				return codedError(CodeUnavailable)
			}
		} else if old != nil || p.Identity.Resource != nil {
			return codedError(CodeUnavailable)
		}
	}
	if p.Identity.Assigned != nil {
		rejectReduction(out, CodeValidation)
		return nil
	}
	out.IdentityEffect = &IdentityRecord{ClusterUID: c.ClusterUID, ProjectUID: c.ProjectUID, Kind: b.Kind, UID: a.Identity.UID, Alias: b.Alias, Witness: b.Witness, Generation: a.Identity.Generation}
	if b.Kind == "vm" {
		vm := a.Identity.Enrollment.VM
		out.ResourceEffect = &ResourceRecord{ClusterUID: c.ClusterUID, ProjectUID: c.ProjectUID, UID: a.Identity.UID, Name: b.Alias, DomainUUID: vm.DomainUUID, Incarnation: vm.Incarnation, Revision: vm.Revision, LastOperationID: a.OperationID, AppliedSequence: d.Sequence}
		out.NameEffect = &NameRecord{ClusterUID: c.ClusterUID, Name: b.Alias, ResourceUID: a.Identity.UID, Generation: a.Identity.Generation, Disposition: "live"}
		out.Receipt.ResourceRevision = vm.Revision
	}
	out.Receipt.ResourceUID = a.Identity.UID
	out.Receipt.Generation = a.Identity.Generation
	return nil
}

func rejectReduction(out *Reduction, code string) {
	out.Receipt.Code = code
	out.Receipt.State = "rejected"
	out.Receipt.ResourceUID = ""
	out.Receipt.Generation = 0
	out.Receipt.Revision = 0
	out.Receipt.ResourceRevision = ""
}

// Zero-valued fields still carry explicit schema meaning. encoding/json alone
// cannot distinguish absent/null generation or global scope from explicit zero.
func requiredIdentityFields(b []byte, fields ...string) bool {
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil {
		return false
	}
	for _, field := range fields {
		value, ok := raw[field]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}
