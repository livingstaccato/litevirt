package contract

import (
	"bytes"
	"encoding/json"
	"io"
	"maps"
	"math"
	"reflect"
	"unicode/utf8"
)

// Update records nonsecret desired intent and immutable preflight observations.
// None of these facts issue native admission or runtime authority.
type UpdateBindingBody struct {
	Version             int               `json:"version"`
	Resource            ResourceReference `json:"resource"`
	ExpectedRevision    string            `json:"expected_revision"`
	Patch               VMUpdatePatch     `json:"patch"`
	PermittedDisruption string            `json:"permitted_disruption"`
}
type VMUpdatePatch struct {
	CPU       *uint32          `json:"cpu,omitempty"`
	MemoryMiB *uint64          `json:"memory_mib,omitempty"`
	Labels    *UpdateLabelSet  `json:"labels,omitempty"`
	Placement *PlacementIntent `json:"placement,omitempty"`
}
type UpdateLabelSet struct {
	Values map[string]string `json:"values"`
}
type UpdateApplicability struct {
	Version           int    `json:"version"`
	ResourceUID       string `json:"resource_uid"`
	DomainUUID        string `json:"domain_uuid"`
	Incarnation       string `json:"incarnation"`
	PreviousRevision  string `json:"previous_revision"`
	PreviousOperation string `json:"previous_operation"`
	HostUID           string `json:"host_uid"`
	HostIncarnation   string `json:"host_incarnation"`
	RuntimeOwnerEpoch uint64 `json:"runtime_owner_epoch"`
	FenceSequence     uint64 `json:"fence_sequence"`
	EvidenceID        string `json:"evidence_id"`
	CoverageDigest    string `json:"coverage_digest"`
	Mechanism         string `json:"mechanism"`
	CPULiveMin        uint32 `json:"cpu_live_min"`
	CPULiveMax        uint32 `json:"cpu_live_max"`
	MemoryLiveMinMiB  uint64 `json:"memory_live_min_mib"`
	MemoryLiveMaxMiB  uint64 `json:"memory_live_max_mib"`
	MemoryMode        string `json:"memory_mode"`
	CPUPinned         bool   `json:"cpu_pinned"`
	RuntimeState      string `json:"runtime_state"`
}
type UpdateAssignment struct {
	Version            int                 `json:"version"`
	PreviousDesired    HistoryReference    `json:"previous_desired"`
	PreviousOperation  HistoryReference    `json:"previous_operation"`
	Origin             HistoryReference    `json:"origin"`
	Revision           string              `json:"revision"`
	AdmittedGeneration uint64              `json:"admitted_generation"`
	Configuration      VMIntent            `json:"configuration"`
	PayloadID          string              `json:"payload_id"`
	Quiescence         QuiescenceFacts     `json:"quiescence"`
	Permissions        []PermissionFacts   `json:"permissions"`
	Applicability      UpdateApplicability `json:"applicability"`
}

// References are in the certified ClaimValue domain, not envelope digests.
// The storage owner authenticates all three originals and their inverse closure.
type UpdateProjection struct {
	PreviousDesired, PreviousOperation, Origin                            *AdmissionRecord
	PreviousDesiredReference, PreviousOperationReference, OriginReference HistoryReference
	OriginResource                                                        *ResourceRecord
}

func DecodeUpdateBindingBody(c Command) (UpdateBindingBody, error) {
	var b UpdateBindingBody
	if c.Kind != "admit_update" {
		return b, codedError(CodeUnsupported)
	}
	if strictBindingObject(c.Body, &b) != nil || b.Version != 1 {
		return b, codedError(CodeValidation)
	}
	for _, s := range []string{c.ClusterUID, c.ProjectUID, c.PrincipalID, c.OwnerID, c.ManagementKey, c.RequestID, c.ResourceUID, c.SessionID, b.ExpectedRevision} {
		if !keyText(s) {
			return b, codedError(CodeValidation)
		}
	}
	if !keyNumber(c.Generation) || !keyNumber(c.Session) || c.ExpectedRevision != 0 || len(c.Ciphertext) != 0 || len(c.SecretIntentTag) != 0 || c.SecretKeyEpoch != "" || !validResourceRef(b.Resource, c.ClusterUID) || b.Resource.UID != c.ResourceUID || b.Resource.ProjectUID != c.ProjectUID || (b.PermittedDisruption != "live" && b.PermittedDisruption != "restart") {
		return b, codedError(CodeValidation)
	}
	if b.Patch.CPU != nil && (*b.Patch.CPU == 0 || *b.Patch.CPU > math.MaxInt32) || b.Patch.MemoryMiB != nil && (*b.Patch.MemoryMiB == 0 || *b.Patch.MemoryMiB > math.MaxInt32) || !validPlacement(b.Patch.Placement, c.ClusterUID) || b.Patch.Labels != nil && b.Patch.Labels.Values == nil {
		return b, codedError(CodeValidation)
	}
	return b, nil
}
func validateUpdateAssignment(d Decision, a Assignment) error {
	b, e := DecodeUpdateBindingBody(d.Command)
	if e != nil {
		return e
	}
	u := a.Update
	c := d.Command
	if a.Version != 3 || a.ClusterUID != c.ClusterUID || u == nil {
		return codedError(CodeValidation)
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(d.Assignment, &raw) != nil || exactBindingJSON(raw["update"], reflect.TypeOf(UpdateAssignment{})) != nil || u.Version != 1 || !keyText(u.Revision) || !keyNumber(u.AdmittedGeneration) {
		return codedError(CodeValidation)
	}
	for _, r := range []HistoryReference{u.PreviousDesired, u.PreviousOperation, u.Origin} {
		if !keyReference(r) || r.Sequence >= d.Sequence {
			return codedError(CodeValidation)
		}
	}
	if u.Origin.Sequence > u.PreviousDesired.Sequence || u.PreviousDesired.Sequence > u.PreviousOperation.Sequence {
		return codedError(CodeValidation)
	}
	if validateVMIntent(u.Configuration, c.ClusterUID) != nil || u.Configuration.CPU > math.MaxInt32 || u.Configuration.MemoryMiB > math.MaxInt32 || u.Configuration.MaxCPU == nil || u.Configuration.MemoryHotplugMaxMiB == nil || !keyText(u.Configuration.Name) || len(u.PayloadID) > MaxStringBytes {
		return codedError(CodeValidation)
	}
	q, x := u.Quiescence, u.Applicability
	if q.Version != 1 || q.ResourceUID != c.ResourceUID || q.Revision != b.ExpectedRevision || !keyText(q.Incarnation) || !keyText(q.LastOperationID) || q.RuntimeOwnerEpoch > math.MaxInt64 || q.FenceSequence == 0 || q.FenceSequence >= d.Sequence || !keyText(q.EvidenceID) || !validFactsDigest(q.CoverageDigest) {
		return codedError(CodeValidation)
	}
	if x.Version != 1 || x.ResourceUID != c.ResourceUID || !keyText(x.DomainUUID) || x.Incarnation != q.Incarnation || x.PreviousRevision != b.ExpectedRevision || x.PreviousOperation != q.LastOperationID || !keyText(x.HostUID) || !keyText(x.HostIncarnation) || x.RuntimeOwnerEpoch != q.RuntimeOwnerEpoch || x.FenceSequence != q.FenceSequence || !keyText(x.EvidenceID) || !validFactsDigest(x.CoverageDigest) || x.CPULiveMin > x.CPULiveMax || x.MemoryLiveMinMiB > x.MemoryLiveMaxMiB || (x.RuntimeState != "running" && x.RuntimeState != "stopped") || (x.MemoryMode != "none" && x.MemoryMode != "balloon" && x.MemoryMode != "virtio_mem") {
		return codedError(CodeValidation)
	}
	switch x.Mechanism {
	case "none", "metadata", "live_resize":
	case "restart":
		if b.PermittedDisruption != "restart" {
			return codedError(CodeValidation)
		}
	default:
		return codedError(CodeValidation)
	}
	if len(u.Permissions) != 1 {
		return codedError(CodeValidation)
	}
	p := u.Permissions[0]
	if p.Purpose != "resource" || p.PrincipalUID != c.PrincipalID || p.ClusterUID != c.ClusterUID || p.ProjectUID != c.ProjectUID || !keyText(p.ProjectName) || p.OwnerID != c.OwnerID || p.ResourceUID != c.ResourceUID || p.ResourceName != u.Configuration.Name || p.Verb != "vm.update" || !keyText(p.EvidenceID) || !validFactsDigest(p.CoverageDigest) || p.FenceSequence == 0 || p.FenceSequence >= d.Sequence {
		return codedError(CodeValidation)
	}
	return nil
}
func updateClone(v VMIntent) VMIntent {
	raw, _ := json.Marshal(v)
	var out VMIntent
	_ = json.Unmarshal(raw, &out)
	return out
}
func updateEqual(a, b VMIntent) bool {
	aa, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return bytes.Equal(aa, bb)
}
func updateDesired(old VMIntent, b UpdateBindingBody, assigned VMIntent, cluster string) (VMIntent, error) {
	v := updateClone(old)
	if b.Patch.CPU != nil {
		v.CPU = *b.Patch.CPU
	}
	if b.Patch.MemoryMiB != nil {
		v.MemoryMiB = *b.Patch.MemoryMiB
	}
	if b.Patch.Labels != nil {
		v.Labels = maps.Clone(b.Patch.Labels.Values)
	}
	if b.Patch.Placement != nil {
		if !placementMatches(b.Patch.Placement, assigned.Placement, cluster) {
			return v, codedError(CodeValidation)
		}
		// Only the explicitly patched policy may resolve a selector to its recorded UID.
		v.Placement = updateClone(assigned).Placement
	}
	if validateVMIntent(v, cluster) != nil || !updateEqual(v, assigned) {
		return v, codedError(CodeValidation)
	}
	return v, nil
}
func reduceUpdateBinding(out *Reduction, p Projection, d Decision, a Assignment) error {
	c, u, f, g := d.Command, a.Update, p.Binding, p.Update
	b, e := DecodeUpdateBindingBody(c)
	if e != nil {
		return e
	}
	if p.Head.Sequence == 0 || p.Head.ClusterUID != c.ClusterUID || f == nil || g == nil || !liveIdentity(f.Project, c.ClusterUID, "project", c.ProjectUID) || !liveIdentity(f.Principal, c.ClusterUID, "principal", c.PrincipalID) {
		return codedError(CodeUnavailable)
	}
	if !currentBindingOwner(f.Owner, c) {
		rejectReduction(out, CodeOwnershipConflict)
		return nil
	}
	v, last := f.Resource, f.Last
	if v == nil || last == nil || g.PreviousDesired == nil || g.PreviousOperation == nil || g.Origin == nil || g.OriginResource == nil {
		return codedError(CodeUnavailable)
	}
	if v.ClusterUID != c.ClusterUID || v.ProjectUID != c.ProjectUID || v.UID != c.ResourceUID {
		return codedError(CodeUnavailable)
	}
	if v.Retired {
		rejectReduction(out, CodeRetired)
		return nil
	}
	if v.Revision != b.ExpectedRevision || v.BindingGeneration != c.Generation || last.Generation != c.Generation {
		rejectReduction(out, CodeRevisionConflict)
		return nil
	}
	if v.OwnerID != c.OwnerID || v.ManagementKey != c.ManagementKey || last.Retired || last.ClusterUID != c.ClusterUID || last.ProjectUID != c.ProjectUID || last.OwnerID != c.OwnerID || last.ManagementKey != c.ManagementKey || last.ResourceUID != v.UID {
		rejectReduction(out, CodeOwnershipConflict)
		return nil
	}
	if last.OperationID != v.LastOperationID || last.Revision != v.Revision || v.AppliedSequence > p.Head.Sequence {
		return codedError(CodeUnavailable)
	}
	if ok, e := guardTargetReservation(out, p, c.ClusterUID, v.Name); e != nil || !ok {
		return e
	}
	i, n := f.NameIdentity, f.Name
	if i == nil || i.Retired || i.ClusterUID != v.ClusterUID || i.ProjectUID != v.ProjectUID || i.Kind != "vm" || i.UID != v.UID || i.Alias != v.Name || i.Witness != v.Incarnation || n == nil || n.ClusterUID != v.ClusterUID || n.Name != v.Name || n.ResourceUID != v.UID || n.Generation != i.Generation || (n.Disposition != "live" && n.Disposition != "reserved") {
		return codedError(CodeUnavailable)
	}
	if u.PreviousDesired != g.PreviousDesiredReference || u.PreviousOperation != g.PreviousOperationReference || u.Origin != g.OriginReference || g.PreviousOperationReference.Sequence != v.AppliedSequence || g.PreviousOperation.OperationID != v.LastOperationID || g.Origin.OperationID != v.OriginalOperationID {
		return codedError(CodeUnavailable)
	}
	for _, r := range []*AdmissionRecord{g.PreviousDesired, g.PreviousOperation, g.Origin} {
		if r.ClusterUID != c.ClusterUID || r.ProjectUID != c.ProjectUID || r.ResourceUID != v.UID || r.Sequence == 0 || r.Sequence > p.Head.Sequence || r.OperationID == "" {
			return codedError(CodeUnavailable)
		}
	}
	origin, old := g.Origin, g.PreviousDesired
	if (origin.Method != "admit_create" && origin.Method != OrdinaryCreateCommand) || origin.PinnedConfiguration == nil || old.PinnedConfiguration == nil || (old.Method != "admit_create" && old.Method != "admit_update" && old.Method != OrdinaryCreateCommand) || origin.Sequence != g.OriginReference.Sequence || old.Sequence != g.PreviousDesiredReference.Sequence || g.PreviousOperation.Sequence != g.PreviousOperationReference.Sequence || u.PayloadID != origin.PayloadID || old.PayloadID != origin.PayloadID {
		return codedError(CodeUnavailable)
	}
	if origin.Method == OrdinaryCreateCommand {
		if f.OriginalAdmission != nil || !validOrdinaryTargetOrigin(f.OriginalTarget, *v, *i, *n) {
			return codedError(CodeUnavailable)
		}
		if old.Method == OrdinaryCreateCommand && (g.PreviousDesiredReference != g.OriginReference || old.OperationID != origin.OperationID) {
			return codedError(CodeUnavailable)
		}
	} else if old.Method == OrdinaryCreateCommand {
		return codedError(CodeUnavailable)
	}
	birth := g.OriginResource
	if birth.ClusterUID != v.ClusterUID || birth.ProjectUID != v.ProjectUID || birth.UID != v.UID || birth.Name != v.Name || birth.DomainUUID != v.DomainUUID || birth.Incarnation != v.Incarnation || birth.OriginalOperationID != v.OriginalOperationID {
		return codedError(CodeUnavailable)
	}
	q, x := u.Quiescence, u.Applicability
	if q.Incarnation != v.Incarnation || q.LastOperationID != v.LastOperationID || q.FenceSequence < v.AppliedSequence || q.FenceSequence > p.Head.Sequence || x.DomainUUID != v.DomainUUID || u.Permissions[0].ProjectName != f.Project.Alias || u.Permissions[0].FenceSequence < v.AppliedSequence || u.Permissions[0].FenceSequence > p.Head.Sequence {
		return codedError(CodeUnavailable)
	}
	wanted, e := updateDesired(*old.PinnedConfiguration, b, u.Configuration, c.ClusterUID)
	if e != nil {
		return e
	}
	changed := !updateEqual(*old.PinnedConfiguration, wanted)
	if changed == (u.Revision == v.Revision) {
		return codedError(CodeValidation)
	}
	cpu, memory := wanted.CPU != old.PinnedConfiguration.CPU, wanted.MemoryMiB != old.PinnedConfiguration.MemoryMiB
	switch x.Mechanism {
	case "none":
		if changed {
			return codedError(CodeValidation)
		}
	case "metadata":
		if !changed || cpu || memory {
			return codedError(CodeValidation)
		}
	case "restart":
		if !changed || (!cpu && !memory) {
			return codedError(CodeValidation)
		}
	case "live_resize":
		if x.RuntimeState != "running" || (!cpu && !memory) {
			return codedError(CodeValidation)
		}
		if cpu && (wanted.CPU <= old.PinnedConfiguration.CPU || x.CPUPinned || x.CPULiveMin == 0 || wanted.CPU < x.CPULiveMin || wanted.CPU > x.CPULiveMax) {
			return codedError(CodeValidation)
		}
		if memory && (x.MemoryLiveMinMiB == 0 || wanted.MemoryMiB < x.MemoryLiveMinMiB || wanted.MemoryMiB > x.MemoryLiveMaxMiB || x.MemoryMode == "none" || (x.MemoryMode == "virtio_mem" && (wanted.MemoryMiB-x.MemoryLiveMinMiB)%2 != 0)) {
			return codedError(CodeValidation)
		}
	}
	deps := map[string]*IdentityRecord{}
	for _, r := range f.Dependencies {
		if r != nil {
			deps[r.UID] = r
		}
	}
	for _, ref := range BindingDependencies(wanted) {
		r := deps[ref.UID]
		if r == nil || r.ClusterUID != ref.ClusterUID || r.ProjectUID != ref.ProjectUID || r.Kind != ref.Kind || r.Generation == 0 {
			return codedError(CodeUnavailable)
		}
		if r.Retired {
			rejectReduction(out, CodeRetired)
			return nil
		}
	}
	if wanted.Placement != nil && wanted.Placement.Host != nil && wanted.Placement.Host.Pinned != nil {
		pin := wanted.Placement.Host.Pinned
		enrolled := deps[pin.UID]
		if enrolled == nil || enrolled.Alias != pin.Name {
			return codedError(CodeUnavailable)
		}
	}
	host := deps[x.HostUID]
	if !liveIdentity(host, c.ClusterUID, "host", x.HostUID) || host.Witness != x.HostIncarnation {
		return codedError(CodeUnavailable)
	}
	before, after := *v, *v
	after.Revision = u.Revision
	after.LastOperationID = a.OperationID
	after.AppliedSequence = d.Sequence
	binding := *last
	binding.OperationID = a.OperationID
	binding.Revision = u.Revision
	out.ResourcePrevious = &before
	out.ResourceEffect = &after
	out.BindingEffects = []BindingRecord{binding}
	out.AdmissionEffect = &AdmissionRecord{ClusterUID: c.ClusterUID, ProjectUID: c.ProjectUID, OwnerID: c.OwnerID, ManagementKey: c.ManagementKey, ResourceUID: c.ResourceUID, OperationID: a.OperationID, RequestID: c.RequestID, PrincipalUID: c.PrincipalID, Method: "admit_update", PayloadID: u.PayloadID, BindingGeneration: c.Generation, AdmittedGeneration: u.AdmittedGeneration, Sequence: d.Sequence, PinnedConfiguration: &wanted}
	out.Receipt.ResourceUID = c.ResourceUID
	out.Receipt.Generation = c.Generation
	out.Receipt.ResourceRevision = u.Revision
	out.Receipt.State = "accepted"
	return nil
}

// Old assignment bodies keep the original v1 validator and bytes. The distinct
// update envelope uses the same bounded duplicate-aware parser under version3.
func validateAssignmentBody(d Decision) error {
	if d.Command.Kind != "admit_update" {
		_, e := canonicalBody(d.Assignment)
		return e
	}
	raw := d.Assignment
	if len(raw) == 0 || len(raw) > 1<<20 || !utf8.Valid(raw) || !validSurrogates(raw) {
		return codedError(CodeValidation)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	v, e := jsonValue(decoder, 0)
	if e != nil {
		return codedError(CodeValidation)
	}
	if _, e = decoder.Token(); e != io.EOF {
		return codedError(CodeValidation)
	}
	object, ok := v.(map[string]any)
	if !ok || object["version"] != json.Number("3") {
		return codedError(CodeValidation)
	}
	return nil
}

func validateDecisionAssignment(d Decision) error {
	if d.Command.Kind != "admit_update" {
		_, e := canonicalBody(d.Assignment)
		return e
	}
	a, e := DecodeAssignment(d)
	if e != nil {
		return e
	}
	return validateUpdateAssignment(d, a)
}
