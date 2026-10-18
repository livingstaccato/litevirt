package contract

import (
	"encoding/json"
	"maps"
	"math"
	"reflect"
	"slices"
)

// BindingAssignment records preparation once. Counters identify distinct things:
// binding lifetime, global name lifetime, desired revision and original voters.
// Prepared facts grant no authority without the fresh storage-owned class permit.
type BindingAssignment struct {
	ResourceUID        string   `json:"resource_uid"`
	BindingGeneration  uint64   `json:"binding_generation"`
	NameGeneration     uint64   `json:"name_generation"`
	Revision           string   `json:"revision"`
	DomainUUID         string   `json:"domain_uuid"`
	Incarnation        string   `json:"incarnation"`
	AdmittedGeneration uint64   `json:"admitted_generation"`
	Configuration      VMIntent `json:"configuration"`
	PayloadID          string   `json:"payload_id,omitempty"`
}
type BindingRecord struct {
	ClusterUID, ProjectUID, OwnerID, ManagementKey, ResourceUID, OperationID string
	Generation                                                               uint64
	Revision                                                                 string
	Retired                                                                  bool
}
type ResourceRecord struct {
	AppliedSequence                                              uint64
	ClusterUID, ProjectUID, UID, Name, DomainUUID, Incarnation   string
	OwnerID, ManagementKey, LastOperationID, OriginalOperationID string
	BindingGeneration                                            uint64
	Revision                                                     string
	Retired                                                      bool
}
type NameRecord struct {
	ClusterUID, Name, ResourceUID string
	Generation                    uint64
	// Only an ordered retirement with actual cleanup authority may make a name
	// reusable. No timer, failed RPC or missing VM projection does that.
	Disposition, RetirementOperationID string
}
type AdmissionRecord struct {
	ClusterUID, ProjectUID, OwnerID, ManagementKey, ResourceUID string
	OperationID, RequestID, PrincipalUID, Method, PayloadID     string
	BindingGeneration, AdmittedGeneration, Sequence             uint64
	// PinnedConfiguration is nonsecret admitted configuration, never an envelope
	// or operation execution journal. Its original bytes live in certified history.
	PinnedConfiguration *VMIntent
}
type BindingProjection struct {
	TargetOwner                                        *OwnerRecord
	TargetPrincipal                                    *IdentityRecord
	TargetLast                                         *BindingRecord
	OriginalAdmission                                  *AdmissionRecord
	Project, Principal, AssignedIdentity, NameIdentity *IdentityRecord
	Owner                                              *OwnerRecord
	Last                                               *BindingRecord
	Name                                               *NameRecord
	Resource, AssignedResource                         *ResourceRecord
	Dependencies                                       []*IdentityRecord
}

func validateBindingAssignment(d Decision, a Assignment) error {
	body, err := DecodeCreateBindingBody(d.Command)
	if err != nil {
		return err
	}
	b := a.Binding
	if a.ClusterUID != d.Command.ClusterUID || b == nil || b.ResourceUID == "" || b.DomainUUID == "" || b.Incarnation == "" || b.BindingGeneration != d.Command.Generation+1 || b.NameGeneration == 0 || b.NameGeneration > math.MaxInt64 || b.Revision == "" || len(b.Revision) > MaxStringBytes || b.AdmittedGeneration == 0 || b.AdmittedGeneration > math.MaxInt64 {
		return codedError(CodeValidation)
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(d.Assignment, &raw) != nil || exactBindingJSON(raw["binding"], reflect.TypeOf(BindingAssignment{})) != nil {
		return codedError(CodeValidation)
	}
	if (len(d.Command.Ciphertext) > 0) != (b.PayloadID != "") || (b.PayloadID != "" && (len(d.Command.SecretIntentTag) == 0 || d.Command.SecretKeyEpoch == "")) {
		return codedError(CodeValidation)
	}
	prepared := d.Command
	prepared.Body, _ = json.Marshal(CreateBindingBody{Version: 1, Desired: b.Configuration})
	if _, err := DecodeCreateBindingBody(prepared); err != nil {
		return err
	}
	if !configurationMatches(body.Desired, b.Configuration, d.Command.ClusterUID) {
		return codedError(CodeValidation)
	}
	return nil
}
func resolvedReference(input, actual *ReferenceInput, cluster, kind string) bool {
	if actual == nil {
		return input == nil
	}
	if actual.Selector != nil || actual.Pinned == nil || !validPinned(*actual.Pinned, cluster, kind) {
		return false
	}
	if input == nil {
		return true
	}
	if input.Pinned != nil {
		return *input.Pinned == *actual.Pinned
	}
	return input.Selector != nil && input.Selector.Scope == actual.Pinned.Scope && input.Selector.Name == actual.Pinned.Name
}
func defaultPolicy(s string) string {
	if s == "" {
		return "balanced"
	}
	return s
}
func defaultState(s string) string {
	if s == "" {
		return "running"
	}
	return s
}
func defaultDiskBus(s string) string {
	if s == "" {
		return "virtio"
	}
	return s
}
func defaultNICModel(s string) string {
	if s == "" {
		return "virtio"
	}
	return s
}
func placementMatches(input, actual *PlacementIntent, cluster string) bool {
	if actual == nil || actual.Policy == "" {
		return false
	}
	if input == nil {
		input = &PlacementIntent{}
	}
	if defaultPolicy(input.Policy) != actual.Policy || input.MaxPerHost != actual.MaxPerHost || !maps.Equal(input.RequiredLabels, actual.RequiredLabels) || !maps.Equal(input.PreferredLabels, actual.PreferredLabels) || !slices.Equal(input.Affinity, actual.Affinity) || !slices.Equal(input.AntiAffinity, actual.AntiAffinity) {
		return false
	}
	if input.Host == nil {
		return actual.Host == nil
	}
	if actual.Host == nil || actual.Host.Name != "" || actual.Host.Pinned == nil || actual.Host.Pinned.ClusterUID != cluster {
		return false
	}
	if input.Host.Pinned != nil {
		return *input.Host.Pinned == *actual.Host.Pinned
	}
	return input.Host.Name == actual.Host.Pinned.Name
}
func optionalStringPreserved(input, actual *string) bool {
	return input == nil || (actual != nil && *input == *actual)
}
func configurationMatches(input, actual VMIntent, cluster string) bool {
	if input.Name != actual.Name || input.CPU != actual.CPU || input.MemoryMiB != actual.MemoryMiB || !maps.Equal(input.Labels, actual.Labels) || defaultState(input.RequestedState) != actual.RequestedState || actual.MaxCPU == nil || actual.MemoryHotplugMaxMiB == nil {
		return false
	}
	if input.MaxCPU != nil && *input.MaxCPU != *actual.MaxCPU {
		return false
	}
	if input.MemoryHotplugMaxMiB != nil && *input.MemoryHotplugMaxMiB != *actual.MemoryHotplugMaxMiB {
		return false
	}
	if !placementMatches(input.Placement, actual.Placement, cluster) || !resolvedReference(input.Image, actual.Image, cluster, "image") {
		return false
	}
	disks := map[string]DiskIntent{}
	for _, disk := range input.Disks {
		disks[disk.Key] = disk
	}
	for _, disk := range actual.Disks {
		original, ok := disks[disk.Key]
		if !ok {
			// The default root disk may be materialized from the top-level image.
			if disk.Key != "root" || input.Image == nil {
				return false
			}
			original = DiskIntent{Key: "root", Image: input.Image}
		} else {
			delete(disks, disk.Key)
			if original.SizeBytes != disk.SizeBytes {
				return false
			}
		}
		if disk.Bus != defaultDiskBus(original.Bus) || disk.Pool == nil || !resolvedReference(original.Pool, disk.Pool, cluster, "pool") || !resolvedReference(original.Image, disk.Image, cluster, "image") {
			return false
		}
		if disk.Key == "root" && actual.Image != nil && (disk.Image == nil || *actual.Image.Pinned != *disk.Image.Pinned) {
			return false
		}
	}
	if len(disks) != 0 {
		return false
	}
	if actual.Image != nil {
		hasRoot := false
		for _, disk := range actual.Disks {
			hasRoot = hasRoot || disk.Key == "root"
		}
		if !hasRoot {
			return false
		}
	}
	if len(input.NICs) != len(actual.NICs) {
		return false
	}
	nics := map[string]NICIntent{}
	for _, nic := range input.NICs {
		nics[nic.Key] = nic
	}
	for _, nic := range actual.NICs {
		original, ok := nics[nic.Key]
		if !ok || nic.Model != defaultNICModel(original.Model) || nic.MAC == nil || !resolvedReference(&original.Network, &nic.Network, cluster, "network") || !optionalStringPreserved(original.MAC, nic.MAC) || !optionalStringPreserved(original.IPv4CIDR, nic.IPv4CIDR) || !optionalStringPreserved(original.IPv4Gateway, nic.IPv4Gateway) || !optionalStringPreserved(original.IPv6CIDR, nic.IPv6CIDR) || !optionalStringPreserved(original.IPv6Gateway, nic.IPv6Gateway) {
			return false
		}
		delete(nics, nic.Key)
	}
	return len(nics) == 0
}

type BindingDependency struct {
	Kind, ClusterUID, ProjectUID, UID string
}

// BindingDependencies enumerates bounded immutable references from prepared
// configuration; the storage adapter reads these exact UIDs, never selectors.
func BindingDependencies(v VMIntent) []BindingDependency {
	var out []BindingDependency
	add := func(r *ReferenceInput, kind string) {
		if r != nil && r.Pinned != nil {
			p := r.Pinned
			out = append(out, BindingDependency{kind, p.Scope.ClusterUID, p.Scope.ProjectUID, p.UID})
		}
	}
	add(v.Image, "image")
	for _, disk := range v.Disks {
		add(disk.Pool, "pool")
		add(disk.Image, "image")
	}
	for _, nic := range v.NICs {
		add(&nic.Network, "network")
	}
	if v.Placement != nil {
		if v.Placement.Host != nil && v.Placement.Host.Pinned != nil {
			h := v.Placement.Host.Pinned
			out = append(out, BindingDependency{"host", h.ClusterUID, "", h.UID})
		}
		for _, set := range [][]ResourceReference{v.Placement.Affinity, v.Placement.AntiAffinity} {
			for _, r := range set {
				out = append(out, BindingDependency{r.Kind, r.ClusterUID, r.ProjectUID, r.UID})
			}
		}
	}
	return out
}
func currentBindingOwner(owner *OwnerRecord, c Command) bool {
	return owner != nil && owner.ClusterUID == c.ClusterUID && owner.ProjectUID == c.ProjectUID && owner.OwnerID == c.OwnerID && owner.SessionPrincipalUID == c.PrincipalID && owner.SessionID == c.SessionID && owner.Activation == c.Session && owner.Activation > 0
}
func reduceCreateBinding(out *Reduction, p Projection, d Decision, a Assignment) error {
	c := d.Command
	b := a.Binding
	facts := p.Binding
	if p.Head.Sequence == 0 || p.Head.ClusterUID != c.ClusterUID || facts == nil {
		return codedError(CodeUnavailable)
	}
	if !liveIdentity(facts.Project, c.ClusterUID, "project", c.ProjectUID) || !liveIdentity(facts.Principal, c.ClusterUID, "principal", c.PrincipalID) {
		return codedError(CodeUnavailable)
	}
	if !currentBindingOwner(facts.Owner, c) {
		rejectReduction(out, CodeOwnershipConflict)
		return nil
	}
	if last := facts.Last; last != nil {
		if last.ClusterUID != c.ClusterUID || last.ProjectUID != c.ProjectUID || last.OwnerID != c.OwnerID || last.ManagementKey != c.ManagementKey || last.Generation == 0 || last.ResourceUID == "" {
			return codedError(CodeUnavailable)
		}
		if !last.Retired {
			rejectReduction(out, CodeOwnershipConflict)
			return nil
		}
		if last.Generation != c.Generation {
			rejectReduction(out, CodeRevisionConflict)
			return nil
		}
	} else if c.Generation != 0 {
		return codedError(CodeUnavailable)
	}
	if name := facts.Name; name != nil {
		if name.ClusterUID != c.ClusterUID || name.Name != b.Configuration.Name || name.ResourceUID == "" || name.Generation == 0 {
			return codedError(CodeUnavailable)
		}
		if name.Disposition != "reusable" {
			rejectReduction(out, CodeOwnershipConflict)
			return nil
		}
		if name.RetirementOperationID == "" || facts.Resource == nil || facts.Resource.UID != name.ResourceUID || !facts.Resource.Retired || facts.NameIdentity == nil || facts.NameIdentity.UID != name.ResourceUID || !facts.NameIdentity.Retired || facts.NameIdentity.Generation != name.Generation {
			return codedError(CodeUnavailable)
		}
		if name.Generation >= math.MaxInt64 || b.NameGeneration != name.Generation+1 {
			rejectReduction(out, CodeRevisionConflict)
			return nil
		}
		if facts.Resource.Incarnation == b.Incarnation {
			rejectReduction(out, CodeValidation)
			return nil
		}
	} else {
		if facts.NameIdentity != nil || facts.Resource != nil {
			return codedError(CodeUnavailable)
		}
		if b.NameGeneration != 1 {
			rejectReduction(out, CodeRevisionConflict)
			return nil
		}
	}
	if facts.AssignedIdentity != nil || facts.AssignedResource != nil {
		rejectReduction(out, CodeValidation)
		return nil
	}
	deps := map[string]*IdentityRecord{}
	for _, r := range facts.Dependencies {
		if r == nil {
			return codedError(CodeUnavailable)
		}
		deps[r.UID] = r
	}
	for _, ref := range BindingDependencies(b.Configuration) {
		actual := deps[ref.UID]
		if actual == nil || actual.ClusterUID != ref.ClusterUID || actual.ProjectUID != ref.ProjectUID || actual.Kind != ref.Kind || actual.Generation == 0 {
			return codedError(CodeUnavailable)
		}
		if actual.Retired {
			rejectReduction(out, CodeRetired)
			return nil
		}
	}
	out.IdentityEffect = &IdentityRecord{ClusterUID: c.ClusterUID, ProjectUID: c.ProjectUID, Kind: "vm", UID: b.ResourceUID, Alias: b.Configuration.Name, Witness: b.Incarnation, Generation: b.NameGeneration}
	out.ResourceEffect = &ResourceRecord{ClusterUID: c.ClusterUID, ProjectUID: c.ProjectUID, UID: b.ResourceUID, Name: b.Configuration.Name, DomainUUID: b.DomainUUID, Incarnation: b.Incarnation, OwnerID: c.OwnerID, ManagementKey: c.ManagementKey, LastOperationID: a.OperationID, OriginalOperationID: a.OperationID, AppliedSequence: d.Sequence, BindingGeneration: b.BindingGeneration, Revision: b.Revision}
	out.NameEffect = &NameRecord{ClusterUID: c.ClusterUID, Name: b.Configuration.Name, ResourceUID: b.ResourceUID, Generation: b.NameGeneration, Disposition: "reserved"}
	out.BindingEffects = []BindingRecord{{ClusterUID: c.ClusterUID, ProjectUID: c.ProjectUID, OwnerID: c.OwnerID, ManagementKey: c.ManagementKey, ResourceUID: b.ResourceUID, OperationID: a.OperationID, Generation: b.BindingGeneration, Revision: b.Revision}}
	out.AdmissionEffect = &AdmissionRecord{ClusterUID: c.ClusterUID, ProjectUID: c.ProjectUID, OwnerID: c.OwnerID, ManagementKey: c.ManagementKey, ResourceUID: b.ResourceUID, OperationID: a.OperationID, RequestID: c.RequestID, PrincipalUID: c.PrincipalID, Method: c.Kind, PayloadID: b.PayloadID, BindingGeneration: b.BindingGeneration, AdmittedGeneration: b.AdmittedGeneration, Sequence: d.Sequence, PinnedConfiguration: &b.Configuration}
	out.Receipt.ResourceUID = b.ResourceUID
	out.Receipt.Generation = b.BindingGeneration
	out.Receipt.ResourceRevision = b.Revision
	out.Receipt.State = "accepted"
	return nil
}
