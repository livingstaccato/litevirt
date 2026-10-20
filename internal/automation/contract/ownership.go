package contract

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"strings"
)

type BindingKey struct {
	ClusterUID    string `json:"cluster_uid"`
	ProjectUID    string `json:"project_uid"`
	OwnerID       string `json:"owner_id"`
	ManagementKey string `json:"management_key"`
}
type BindingReference struct {
	Key        BindingKey `json:"key"`
	Generation uint64     `json:"generation"`
}
type OwnershipBody struct {
	Version                  int               `json:"version"`
	Resource                 ResourceReference `json:"resource"`
	ExpectedRevision         string            `json:"expected_revision"`
	Source                   *BindingReference `json:"source,omitempty"`
	Target                   BindingKey        `json:"target"`
	ExpectedTargetGeneration uint64            `json:"expected_target_generation"`
}
type RecordedOwnerSession struct {
	ID           string `json:"id"`
	Activation   uint64 `json:"activation"`
	PrincipalUID string `json:"principal_uid"`
}

// QuiescenceFacts records the exact frontier authenticated before choice. It
// is replay data, not a permit, status guess, or absence-based journal check.
type QuiescenceFacts struct {
	Version           int    `json:"version"`
	ResourceUID       string `json:"resource_uid"`
	Revision          string `json:"revision"`
	Incarnation       string `json:"incarnation"`
	LastOperationID   string `json:"last_operation_id"`
	RuntimeOwnerEpoch uint64 `json:"runtime_owner_epoch"`
	FenceSequence     uint64 `json:"fence_sequence"`
	EvidenceID        string `json:"evidence_id"`
	CoverageDigest    string `json:"coverage_digest"`
}

// PermissionFacts is an immutable scoped check by the authenticated command
// principal. The fresh provider must check existing vm.update permissions using
// the authoritative raw project name and injectively encoded owner path.
type PermissionFacts struct {
	Purpose        string `json:"purpose"`
	PrincipalUID   string `json:"principal_uid"`
	ClusterUID     string `json:"cluster_uid"`
	ProjectUID     string `json:"project_uid"`
	ProjectName    string `json:"project_name"`
	OwnerID        string `json:"owner_id,omitempty"`
	ResourceUID    string `json:"resource_uid,omitempty"`
	ResourceName   string `json:"resource_name,omitempty"`
	Verb           string `json:"verb"`
	EvidenceID     string `json:"evidence_id"`
	CoverageDigest string `json:"coverage_digest"`
	FenceSequence  uint64 `json:"fence_sequence"`
}
type OwnershipAssignment struct {
	Version            int                  `json:"version"`
	TargetSession      RecordedOwnerSession `json:"target_session"`
	TargetGeneration   uint64               `json:"target_generation"`
	Revision           string               `json:"revision"`
	AdmittedGeneration uint64               `json:"admitted_generation"`
	Quiescence         QuiescenceFacts      `json:"quiescence"`
	Permissions        []PermissionFacts    `json:"permissions"`
}

func validBindingKey(k BindingKey, cluster, project string) bool {
	return k.ClusterUID == cluster && k.ProjectUID == project && k.OwnerID != "" && k.ManagementKey != ""
}
func DecodeOwnershipBody(c Command) (OwnershipBody, error) {
	var b OwnershipBody
	if strictBindingObject(c.Body, &b) != nil || b.Version != 1 {
		return b, codedError(CodeValidation)
	}
	for _, v := range []string{c.ClusterUID, c.ProjectUID, c.PrincipalID, c.OwnerID, c.ManagementKey, c.RequestID, c.ResourceUID, c.SessionID} {
		if v == "" || len(v) > MaxStringBytes {
			return b, codedError(CodeValidation)
		}
	}
	if c.ExpectedRevision != 0 || c.Session == 0 || c.Session > math.MaxInt64 || len(c.Ciphertext) != 0 || len(c.SecretIntentTag) != 0 || c.SecretKeyEpoch != "" || !validResourceRef(b.Resource, c.ClusterUID) || b.Resource.ProjectUID != c.ProjectUID || b.Resource.UID != c.ResourceUID || b.ExpectedRevision == "" || !validBindingKey(b.Target, c.ClusterUID, c.ProjectUID) || b.ExpectedTargetGeneration >= math.MaxInt64 {
		return b, codedError(CodeValidation)
	}
	current := BindingKey{c.ClusterUID, c.ProjectUID, c.OwnerID, c.ManagementKey}
	switch c.Kind {
	case "adopt_resource":
		if b.Source != nil || b.Target != current || c.Generation != 0 {
			return b, codedError(CodeValidation)
		}
	case "transfer_owner":
		if b.Source == nil || b.Source.Key != current || b.Source.Generation == 0 || b.Source.Generation > math.MaxInt64 || b.Source.Generation != c.Generation || b.Target == current {
			return b, codedError(CodeValidation)
		}
	default:
		return b, codedError(CodeUnsupported)
	}
	return b, nil
}
func validFactsDigest(d string) bool {
	b, err := hex.DecodeString(d)
	return err == nil && len(b) == 32 && d == strings.ToLower(d)
}
func validateOwnershipAssignment(d Decision, a Assignment) error {
	body, err := DecodeOwnershipBody(d.Command)
	if err != nil {
		return err
	}
	o := a.Ownership
	c := d.Command
	if o == nil || a.ClusterUID != c.ClusterUID {
		return codedError(CodeValidation)
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(d.Assignment, &raw) != nil || exactBindingJSON(raw["ownership"], reflect.TypeOf(OwnershipAssignment{})) != nil {
		return codedError(CodeValidation)
	}
	if o.Version != 1 || o.TargetSession.ID == "" || o.TargetSession.PrincipalUID == "" || o.TargetSession.Activation == 0 || o.TargetSession.Activation > math.MaxInt64 || o.TargetGeneration != body.ExpectedTargetGeneration+1 || o.Revision == "" || o.Revision == body.ExpectedRevision || o.AdmittedGeneration == 0 || o.AdmittedGeneration > math.MaxInt64 {
		return codedError(CodeValidation)
	}
	q := o.Quiescence
	if q.Version != 1 || q.ResourceUID != body.Resource.UID || q.Revision != body.ExpectedRevision || q.Incarnation == "" || q.RuntimeOwnerEpoch > math.MaxInt64 || q.FenceSequence == 0 || q.FenceSequence >= d.Sequence || q.EvidenceID == "" || !validFactsDigest(q.CoverageDigest) {
		return codedError(CodeValidation)
	}
	want := map[string]bool{"target_owner": true, "resource": true}
	if c.Kind == "transfer_owner" {
		want["source_owner"] = true
	}
	if len(o.Permissions) != len(want) {
		return codedError(CodeValidation)
	}
	for _, p := range o.Permissions {
		if !want[p.Purpose] || p.PrincipalUID != c.PrincipalID || p.ClusterUID != c.ClusterUID || p.ProjectUID != c.ProjectUID || p.ProjectName == "" || p.Verb != "vm.update" || p.EvidenceID == "" || !validFactsDigest(p.CoverageDigest) || p.FenceSequence == 0 || p.FenceSequence >= d.Sequence {
			return codedError(CodeValidation)
		}
		delete(want, p.Purpose)
		switch p.Purpose {
		case "source_owner":
			if p.OwnerID != c.OwnerID || p.ResourceUID != "" || p.ResourceName != "" {
				return codedError(CodeValidation)
			}
		case "target_owner":
			if p.OwnerID != body.Target.OwnerID || p.ResourceUID != "" || p.ResourceName != "" {
				return codedError(CodeValidation)
			}
		case "resource":
			if p.OwnerID != "" || p.ResourceUID != c.ResourceUID || p.ResourceName == "" {
				return codedError(CodeValidation)
			}
		}
	}
	return nil
}

func reduceOwnership(out *Reduction, p Projection, d Decision, a Assignment) error {
	c, o, f := d.Command, a.Ownership, p.Binding
	body, err := DecodeOwnershipBody(c)
	if err != nil {
		return err
	}
	if p.Head.Sequence == 0 || p.Head.ClusterUID != c.ClusterUID || f == nil || !liveIdentity(f.Project, c.ClusterUID, "project", c.ProjectUID) || !liveIdentity(f.Principal, c.ClusterUID, "principal", c.PrincipalID) {
		return codedError(CodeUnavailable)
	}
	if !currentBindingOwner(f.Owner, c) {
		rejectReduction(out, CodeOwnershipConflict)
		return nil
	}
	v := f.Resource
	if v == nil {
		return codedError(CodeUnavailable)
	}
	if ok, err := guardTargetReservation(out, p, c.ClusterUID, v.Name); err != nil || !ok {
		return err
	}
	if v.ClusterUID != body.Resource.ClusterUID || v.ProjectUID != body.Resource.ProjectUID || v.UID != body.Resource.UID {
		rejectReduction(out, CodeValidation)
		return nil
	}
	if v.Retired {
		rejectReduction(out, CodeRetired)
		return nil
	}
	if v.Revision != body.ExpectedRevision {
		rejectReduction(out, CodeRevisionConflict)
		return nil
	}
	if f.NameIdentity == nil || f.NameIdentity.Retired || f.NameIdentity.Kind != "vm" || f.NameIdentity.ClusterUID != v.ClusterUID || f.NameIdentity.ProjectUID != v.ProjectUID || f.NameIdentity.UID != v.UID || f.NameIdentity.Alias != v.Name || f.Name == nil || f.Name.ClusterUID != v.ClusterUID || f.Name.Name != v.Name || f.Name.ResourceUID != v.UID || f.Name.Generation != f.NameIdentity.Generation || (f.Name.Disposition != "live" && f.Name.Disposition != "reserved") {
		return codedError(CodeUnavailable)
	}
	if f.OriginalAdmission != nil && f.OriginalTarget != nil {
		return codedError(CodeUnavailable)
	}
	if v.OriginalOperationID != "" && f.OriginalTarget != nil {
		if !validOrdinaryTargetOrigin(f.OriginalTarget, *v, *f.NameIdentity, *f.Name) {
			return codedError(CodeUnavailable)
		}
	} else if v.OriginalOperationID != "" {
		original := f.OriginalAdmission
		if original == nil || original.OperationID != v.OriginalOperationID || original.ClusterUID != v.ClusterUID || original.ProjectUID != v.ProjectUID || original.ResourceUID != v.UID || original.Method != "admit_create" || original.Sequence == 0 || original.Sequence > v.AppliedSequence || original.AdmittedGeneration == 0 {
			return codedError(CodeUnavailable)
		}
	} else if f.OriginalAdmission != nil || f.OriginalTarget != nil {
		return codedError(CodeUnavailable)
	}
	q := o.Quiescence
	if q.Incarnation != v.Incarnation || q.LastOperationID != v.LastOperationID || q.FenceSequence < v.AppliedSequence || q.FenceSequence > p.Head.Sequence {
		return codedError(CodeUnavailable)
	}
	for _, permission := range o.Permissions {
		if permission.ProjectName != f.Project.Alias || (permission.Purpose == "resource" && permission.ResourceName != v.Name) {
			return codedError(CodeUnavailable)
		}
	}
	target := f.TargetOwner
	if target == nil || target.ClusterUID != body.Target.ClusterUID || target.ProjectUID != body.Target.ProjectUID || target.OwnerID != body.Target.OwnerID || target.SessionID != o.TargetSession.ID || target.Activation != o.TargetSession.Activation || target.SessionPrincipalUID != o.TargetSession.PrincipalUID || !liveIdentity(f.TargetPrincipal, c.ClusterUID, "principal", o.TargetSession.PrincipalUID) {
		rejectReduction(out, CodeOwnershipConflict)
		return nil
	}
	if last := f.TargetLast; last != nil {
		if last.ClusterUID != body.Target.ClusterUID || last.ProjectUID != body.Target.ProjectUID || last.OwnerID != body.Target.OwnerID || last.ManagementKey != body.Target.ManagementKey || last.Generation == 0 {
			return codedError(CodeUnavailable)
		}
		if !last.Retired {
			rejectReduction(out, CodeOwnershipConflict)
			return nil
		}
		if last.Generation != body.ExpectedTargetGeneration {
			rejectReduction(out, CodeRevisionConflict)
			return nil
		}
	} else if body.ExpectedTargetGeneration != 0 {
		return codedError(CodeUnavailable)
	}
	var bindings []BindingRecord
	if c.Kind == "transfer_owner" {
		source := f.Last
		if source == nil {
			return codedError(CodeUnavailable)
		}
		if source.Generation != body.Source.Generation || v.BindingGeneration != body.Source.Generation {
			rejectReduction(out, CodeRevisionConflict)
			return nil
		}
		if source.Retired || source.ClusterUID != c.ClusterUID || source.ProjectUID != c.ProjectUID || source.OwnerID != c.OwnerID || source.ManagementKey != c.ManagementKey || source.ResourceUID != v.UID || v.OwnerID != c.OwnerID || v.ManagementKey != c.ManagementKey {
			rejectReduction(out, CodeOwnershipConflict)
			return nil
		}
		if source.Revision != v.Revision {
			return codedError(CodeUnavailable)
		}
		retired := *source
		retired.Retired = true
		bindings = append(bindings, retired)
	} else if v.OwnerID != "" || v.ManagementKey != "" || v.BindingGeneration != 0 {
		rejectReduction(out, CodeOwnershipConflict)
		return nil
	}
	next := *v
	next.OwnerID = body.Target.OwnerID
	next.ManagementKey = body.Target.ManagementKey
	next.BindingGeneration = o.TargetGeneration
	next.Revision = o.Revision
	next.LastOperationID = a.OperationID
	next.AppliedSequence = d.Sequence
	previous := *v
	out.ResourcePrevious = &previous
	out.ResourceEffect = &next
	out.BindingEffects = append(bindings, BindingRecord{ClusterUID: v.ClusterUID, ProjectUID: v.ProjectUID, OwnerID: body.Target.OwnerID, ManagementKey: body.Target.ManagementKey, ResourceUID: v.UID, OperationID: a.OperationID, Generation: o.TargetGeneration, Revision: o.Revision})
	out.AdmissionEffect = &AdmissionRecord{ClusterUID: c.ClusterUID, ProjectUID: c.ProjectUID, OwnerID: c.OwnerID, ManagementKey: c.ManagementKey, ResourceUID: v.UID, OperationID: a.OperationID, RequestID: c.RequestID, PrincipalUID: c.PrincipalID, Method: c.Kind, BindingGeneration: o.TargetGeneration, AdmittedGeneration: o.AdmittedGeneration, Sequence: d.Sequence}
	out.Receipt.ResourceUID = v.UID
	out.Receipt.Generation = o.TargetGeneration
	out.Receipt.ResourceRevision = o.Revision
	out.Receipt.State = "succeeded"
	return nil
}

// Origin is immutable certified birth provenance, not a native execution grant.
// Managed ownership changes retain the ordinary allocation without fabricating
// a managed-create AdmissionRecord.
func validOrdinaryTargetOrigin(o *TargetOperationRecord, v ResourceRecord, id IdentityRecord, n NameRecord) bool {
	if o == nil || o.Kind != OrdinaryCreateCommand || o.OperationID != v.OriginalOperationID || o.ResourceUID != v.UID || o.TargetName != v.Name || o.ClusterUID != v.ClusterUID || o.ProjectUID != v.ProjectUID || o.Sequence == 0 || o.Sequence > v.AppliedSequence || !keyDigest(o.DecisionDigest) {
		return false
	}
	var a Assignment
	if json.Unmarshal(o.Assignment, &a) != nil || a.Target == nil || a.Target.Allocation == nil {
		return false
	}
	d := Decision{Sequence: o.Sequence, ParentDigest: a.Target.ParentDigest, Command: Command{Kind: o.Kind, ClusterUID: o.ClusterUID, ProjectUID: o.ProjectUID, PrincipalID: o.PrincipalUID, RequestID: o.RequestID, Body: o.Body}, Assignment: o.Assignment}
	if ValidateSupportedDecision(d) != nil || a.OperationID != o.OperationID {
		return false
	}
	b, e := DecodeOrdinaryCreateBody(d.Command)
	if e != nil || b.Desired.Name != v.Name {
		return false
	}
	allocation := a.Target.Allocation
	return allocation.ResourceUID == v.UID && allocation.DomainUUID == v.DomainUUID && allocation.Incarnation == v.Incarnation && allocation.NameGeneration == id.Generation && id.Witness == allocation.Incarnation && n.Generation == allocation.NameGeneration
}
