package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
)

// ExecutionBody describes already-admitted work. It is never a runtime permit.
// Binding generation, executor generation and admitted voter generation remain
// separate identities. The native issuer and FULL projection adapter are not
// supplied by this pure contract.
type ExecutionBody struct {
	Version          int                `json:"version"`
	OperationID      string             `json:"operation_id"`
	Admission        HistoryReference   `json:"admission"`
	ResourceRevision string             `json:"resource_revision"`
	DomainUUID       string             `json:"domain_uuid"`
	Incarnation      string             `json:"incarnation"`
	HostUID          string             `json:"host_uid"`
	HostIncarnation  string             `json:"host_incarnation"`
	Previous         *ExecutorReference `json:"previous,omitempty"`
	Exclusion        *HistoryReference  `json:"exclusion,omitempty"`
	Grant            *ExecutorReference `json:"grant,omitempty"`
	State            string             `json:"state,omitempty"`
	Reason           string             `json:"reason,omitempty"`
	NextAction       string             `json:"next_action,omitempty"`
	Artifacts        []ArtifactRecord   `json:"artifacts,omitempty"`
	Result           *ExecutionResult   `json:"result,omitempty"`
}

type ExecutionAssignment struct {
	Version            int    `json:"version"`
	ExecutorGeneration uint64 `json:"executor_generation"`
	// Requirements adds explicitly declared firmware/backend obligations to
	// those derived from pinned admission. A native producer must declare its
	// complete journal plan before effects; it cannot omit disk/domain/seed.
	Requirements []ArtifactRequirement `json:"requirements,omitempty"`
}
type ExecutorReference struct {
	Generation uint64           `json:"generation"`
	Decision   HistoryReference `json:"decision"`
}
type ExecutionTarget struct {
	ClusterUID        string           `json:"cluster_uid"`
	ProjectUID        string           `json:"project_uid"`
	ResourceUID       string           `json:"resource_uid"`
	OwnerID           string           `json:"owner_id"`
	ManagementKey     string           `json:"management_key"`
	BindingGeneration uint64           `json:"binding_generation"`
	OperationID       string           `json:"operation_id"`
	Admission         HistoryReference `json:"admission"`
	ResourceRevision  string           `json:"resource_revision"`
	DomainUUID        string           `json:"domain_uuid"`
	Incarnation       string           `json:"incarnation"`
	HostUID           string           `json:"host_uid"`
	HostIncarnation   string           `json:"host_incarnation"`
	// Only normalized nonsecret configuration is hashed. PayloadID is opaque;
	// neither effective bootstrap bytes nor their digest belongs in this record.
	ConfigurationDigest string `json:"configuration_digest"`
	PayloadID           string `json:"payload_id,omitempty"`
}
type ExecutorGrant struct {
	Target       ExecutionTarget       `json:"target"`
	Generation   uint64                `json:"generation"`
	Reference    HistoryReference      `json:"reference"`
	Requirements []ArtifactRequirement `json:"requirements"`
}

// ExecutorExclusion is a projection of an ALREADY certified, scope-bound fact
// supplied by its existing exclusion owner. It cannot be constructed from a
// timeout, boolean, row absence, PID death, local close or caller assertion.
// No fresh producer or persistence adapter is enabled by defining this type.
type ExecutorExclusion struct {
	Reference   HistoryReference
	Predecessor ExecutorGrant
}
type ExecutionProgress struct {
	OperationID               string
	Grant                     ExecutorReference
	State, Reason, NextAction string
	Sequence                  uint64
}
type ExecutionResult struct {
	Outcome       string                `json:"outcome"`
	Code          string                `json:"code"`
	ObservedState string                `json:"observed_state"`
	Artifacts     []ArtifactDisposition `json:"artifacts"`
}
type ExecutionTerminal struct {
	Target    ExecutionTarget
	Grant     ExecutorReference
	Result    ExecutionResult
	Artifacts []ArtifactRecord
	Sequence  uint64
}
type ExecutionProjection struct {
	Admission  HistoryReference
	Grant      *ExecutorGrant
	Progress   *ExecutionProgress
	Terminal   *ExecutionTerminal
	Artifacts  []ArtifactRecord
	Exclusions []ExecutorExclusion
}

func executionKind(kind string) bool {
	switch kind {
	case "claim_executor", "record_progress", "complete_operation", "retire_artifact":
		return true
	}
	return false
}
func validExecutorReference(r ExecutorReference) bool {
	return keyNumber(r.Generation) && keyReference(r.Decision)
}
func DecodeExecutionBody(c Command) (ExecutionBody, error) {
	var b ExecutionBody
	if !executionKind(c.Kind) || strictBindingObject(c.Body, &b) != nil || b.Version != 1 {
		return b, codedError(CodeValidation)
	}
	for _, s := range []string{c.ClusterUID, c.ProjectUID, c.PrincipalID, c.OwnerID, c.ManagementKey, c.RequestID, c.ResourceUID, c.SessionID, b.OperationID, b.ResourceRevision, b.DomainUUID, b.Incarnation, b.HostUID, b.HostIncarnation} {
		if !keyText(s) {
			return b, codedError(CodeValidation)
		}
	}
	if !keyNumber(c.Generation) || !keyNumber(c.Session) || c.ExpectedRevision != 0 ||
		len(c.Ciphertext) != 0 || len(c.SecretIntentTag) != 0 || c.SecretKeyEpoch != "" || !keyReference(b.Admission) {
		return b, codedError(CodeValidation)
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(c.Body, &raw) != nil {
		return b, codedError(CodeValidation)
	}
	allowed := map[string]bool{}
	switch c.Kind {
	case "claim_executor":
		allowed["previous"], allowed["exclusion"] = true, true
		if (b.Previous == nil) != (b.Exclusion == nil) ||
			(b.Previous != nil && (!validExecutorReference(*b.Previous) || !keyReference(*b.Exclusion))) {
			return b, codedError(CodeValidation)
		}
	case "record_progress":
		for _, n := range []string{"grant", "state", "reason", "next_action", "artifacts"} {
			allowed[n] = true
		}
		if b.State != "running" && b.State != "recovering" && b.State != "blocked" {
			return b, codedError(CodeValidation)
		}
		if (b.State == "blocked" || b.State == "recovering") && (!keyText(b.Reason) || !keyText(b.NextAction)) {
			return b, codedError(CodeValidation)
		}
		if (b.Reason != "" && !keyText(b.Reason)) || (b.NextAction != "" && !keyText(b.NextAction)) {
			return b, codedError(CodeValidation)
		}
	case "complete_operation":
		allowed["grant"], allowed["result"] = true, true
		if b.Result == nil || !validExecutionResult(*b.Result) {
			return b, codedError(CodeValidation)
		}
	case "retire_artifact":
		allowed["grant"], allowed["artifacts"] = true, true
		if len(b.Artifacts) != 1 || b.Artifacts[0].State != "deleted" {
			return b, codedError(CodeValidation)
		}
	}
	for _, n := range []string{"previous", "exclusion", "grant", "state", "reason", "next_action", "artifacts", "result"} {
		if _, present := raw[n]; present && !allowed[n] {
			return b, codedError(CodeValidation)
		}
	}
	if c.Kind != "claim_executor" && (b.Grant == nil || !validExecutorReference(*b.Grant)) {
		return b, codedError(CodeValidation)
	}
	for _, a := range b.Artifacts {
		if !validArtifactRecord(a) {
			return b, codedError(CodeValidation)
		}
	}
	return b, nil
}

func validateExecutionAssignment(d Decision, a Assignment) error {
	b, err := DecodeExecutionBody(d.Command)
	if err != nil {
		return err
	}
	if a.ClusterUID != d.Command.ClusterUID || a.OperationID == b.OperationID {
		return codedError(CodeValidation)
	}
	if d.Command.Kind == "claim_executor" {
		if a.Execution == nil || a.Execution.Version != 1 || !keyNumber(a.Execution.ExecutorGeneration) {
			return codedError(CodeValidation)
		}
		var raw map[string]json.RawMessage
		if json.Unmarshal(d.Assignment, &raw) != nil || exactBindingJSON(raw["execution"], reflect.TypeOf(ExecutionAssignment{})) != nil {
			return codedError(CodeValidation)
		}
		if b.Previous == nil {
			if a.Execution.ExecutorGeneration != 1 {
				return codedError(CodeValidation)
			}
		} else if b.Previous.Generation >= math.MaxInt64 || a.Execution.ExecutorGeneration != b.Previous.Generation+1 {
			return codedError(CodeValidation)
		}
		if !validArtifactRequirements(a.Execution.Requirements) {
			return codedError(CodeValidation)
		}
	} else if a.Execution != nil {
		return codedError(CodeValidation)
	}
	return nil
}

func executionTarget(p Projection, d Decision, b ExecutionBody) (ExecutionTarget, error) {
	c := d.Command
	f := p.Binding
	if p.Head.ClusterUID != c.ClusterUID || p.Head.Sequence == 0 || p.Head.Sequence >= math.MaxInt64 ||
		d.Sequence != p.Head.Sequence+1 || d.ParentDigest != p.Head.Digest || !keyDigest(p.Head.Digest) ||
		f == nil || f.Resource == nil || f.OriginalAdmission == nil {
		return ExecutionTarget{}, codedError(CodeUnavailable)
	}
	r, a := f.Resource, f.OriginalAdmission
	if r.Retired {
		return ExecutionTarget{}, codedError(CodeRetired)
	}
	if f.Last == nil || f.Last.Retired || f.Last.ClusterUID != c.ClusterUID ||
		f.Last.ProjectUID != c.ProjectUID || f.Last.OwnerID != c.OwnerID || f.Last.ManagementKey != c.ManagementKey ||
		f.Last.ResourceUID != c.ResourceUID || f.Last.Generation != c.Generation || f.Last.Revision != b.ResourceRevision ||
		f.Name == nil || f.Name.ClusterUID != c.ClusterUID || f.Name.ResourceUID != c.ResourceUID ||
		f.Name.Name != r.Name || !keyNumber(f.Name.Generation) || (f.Name.Disposition != "reserved" && f.Name.Disposition != "live") {
		return ExecutionTarget{}, codedError(CodeUnavailable)
	}
	if r.ClusterUID != c.ClusterUID || r.ProjectUID != c.ProjectUID || r.UID != c.ResourceUID ||
		r.OwnerID != c.OwnerID || r.ManagementKey != c.ManagementKey || r.BindingGeneration != c.Generation ||
		r.Revision != b.ResourceRevision || r.DomainUUID != b.DomainUUID || r.Incarnation != b.Incarnation ||
		r.LastOperationID != b.OperationID || r.AppliedSequence > p.Head.Sequence || r.AppliedSequence < a.Sequence ||
		a.ClusterUID != c.ClusterUID || a.ProjectUID != c.ProjectUID || a.ResourceUID != c.ResourceUID ||
		a.OwnerID != c.OwnerID || a.ManagementKey != c.ManagementKey || a.OperationID != b.OperationID ||
		a.BindingGeneration != c.Generation || a.Sequence != b.Admission.Sequence ||
		!keyNumber(a.AdmittedGeneration) || a.PinnedConfiguration == nil {
		return ExecutionTarget{}, codedError(CodeUnavailable)
	}
	// The immediate admission is the only predecessor whose reference can be
	// obtained directly from Head. Later commands require the history projection.
	ref := HistoryReference{Sequence: p.Head.Sequence, Digest: p.Head.Digest}
	if p.Execution != nil {
		ref = p.Execution.Admission
	}
	if ref != b.Admission || b.Admission.Sequence > p.Head.Sequence {
		return ExecutionTarget{}, codedError(CodeUnavailable)
	}
	hosts := 0
	for _, host := range f.Dependencies {
		if host != nil && host.UID == b.HostUID {
			hosts++
			if !liveIdentity(host, c.ClusterUID, "host", b.HostUID) || !keyNumber(host.Generation) || host.Witness != b.HostIncarnation {
				return ExecutionTarget{}, codedError(CodeUnavailable)
			}
		}
	}
	if hosts != 1 {
		return ExecutionTarget{}, codedError(CodeUnavailable)
	}
	config := a.PinnedConfiguration
	prepared := c
	prepared.ResourceUID = ""
	prepared.Generation = 0
	preparedBody, err := json.Marshal(CreateBindingBody{Version: 1, Desired: *config})
	if err != nil {
		return ExecutionTarget{}, codedError(CodeUnavailable)
	}
	prepared.Body = preparedBody
	if _, err := DecodeCreateBindingBody(prepared); err != nil {
		return ExecutionTarget{}, codedError(CodeUnavailable)
	}
	if config.Placement == nil || config.Placement.Policy == "" || config.RequestedState == "" ||
		config.MaxCPU == nil || config.MemoryHotplugMaxMiB == nil || config.Name != r.Name {
		return ExecutionTarget{}, codedError(CodeUnavailable)
	}
	// Reject unresolved configuration rather than resolving a mutable alias.
	for _, disk := range config.Disks {
		if disk.Pool == nil || disk.Pool.Pinned == nil || disk.Pool.Selector != nil ||
			(disk.Image != nil && (disk.Image.Pinned == nil || disk.Image.Selector != nil)) {
			return ExecutionTarget{}, codedError(CodeUnavailable)
		}
	}
	for _, nic := range config.NICs {
		if nic.Network.Pinned == nil || nic.Network.Selector != nil {
			return ExecutionTarget{}, codedError(CodeUnavailable)
		}
	}
	if config.Image != nil && (config.Image.Pinned == nil || config.Image.Selector != nil) {
		return ExecutionTarget{}, codedError(CodeUnavailable)
	}
	raw, err := json.Marshal(config)
	if err != nil {
		return ExecutionTarget{}, codedError(CodeUnavailable)
	}
	sum := sha256.Sum256(raw)
	return ExecutionTarget{ClusterUID: c.ClusterUID, ProjectUID: c.ProjectUID, ResourceUID: c.ResourceUID,
		OwnerID: c.OwnerID, ManagementKey: c.ManagementKey, BindingGeneration: c.Generation,
		OperationID: b.OperationID, Admission: b.Admission, ResourceRevision: b.ResourceRevision,
		DomainUUID: b.DomainUUID, Incarnation: b.Incarnation, HostUID: b.HostUID,
		HostIncarnation: b.HostIncarnation, ConfigurationDigest: hex.EncodeToString(sum[:]), PayloadID: a.PayloadID}, nil
}

func grantMatches(g *ExecutorGrant, target ExecutionTarget, head uint64) bool {
	return g != nil && g.Target == target && keyNumber(g.Generation) && keyReference(g.Reference) &&
		g.Reference.Sequence <= head && g.Reference.Sequence > target.Admission.Sequence &&
		len(g.Requirements) > 0 && validArtifactRequirements(g.Requirements)
}
func grantReference(g *ExecutorGrant) ExecutorReference {
	return ExecutorReference{Generation: g.Generation, Decision: g.Reference}
}
func reduceExecution(out *Reduction, p Projection, d Decision, a Assignment) error {
	b, err := DecodeExecutionBody(d.Command)
	if err != nil {
		return err
	}
	target, err := executionTarget(p, d, b)
	if err != nil {
		return err
	}
	out.Receipt.ResourceUID = target.ResourceUID
	out.Receipt.Generation = target.BindingGeneration
	out.Receipt.ResourceRevision = target.ResourceRevision
	f := p.Execution
	if d.Command.Kind == "claim_executor" {
		if !currentBindingOwner(p.Binding.Owner, d.Command) {
			return codedError(CodeOwnershipConflict)
		}
		if f != nil && f.Terminal != nil {
			return codedError(CodeUnavailable)
		}
		requirements, err := executionRequirements(p.Binding.OriginalAdmission, a.Execution.Requirements)
		if err != nil {
			return err
		}
		if b.Previous == nil {
			if f != nil && (f.Grant != nil || len(f.Artifacts) != 0 || f.Progress != nil) {
				return codedError(CodeUnavailable)
			}
			placement := p.Binding.OriginalAdmission.PinnedConfiguration.Placement
			if placement != nil && placement.Host != nil && (placement.Host.Pinned == nil || placement.Host.Pinned.UID != target.HostUID) {
				return codedError(CodeUnavailable)
			}
		} else {
			if f == nil || f.Grant == nil {
				return codedError(CodeUnavailable)
			}
			oldTarget := target
			oldTarget.HostUID, oldTarget.HostIncarnation = f.Grant.Target.HostUID, f.Grant.Target.HostIncarnation
			if !grantMatches(f.Grant, oldTarget, p.Head.Sequence) || *b.Previous != grantReference(f.Grant) ||
				!reflect.DeepEqual(requirements, f.Grant.Requirements) {
				return codedError(CodeUnavailable)
			}
			matches := 0
			for _, fact := range f.Exclusions {
				if fact.Reference == *b.Exclusion {
					matches++
					if !keyReference(fact.Reference) || fact.Reference.Sequence <= f.Grant.Reference.Sequence ||
						fact.Reference.Sequence > p.Head.Sequence || !reflect.DeepEqual(fact.Predecessor, *f.Grant) {
						return codedError(CodeUnavailable)
					}
				}
			}
			if matches != 1 {
				return codedError(CodeUnavailable)
			}
		}
		raw, err := EncodeDecision(d)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		out.ExecutorEffect = &ExecutorGrant{Target: target, Generation: a.Execution.ExecutorGeneration,
			Reference: HistoryReference{Sequence: d.Sequence, Digest: hex.EncodeToString(sum[:])}, Requirements: requirements}
		out.Receipt.State = "accepted"
		return nil
	}
	if f == nil || !grantMatches(f.Grant, target, p.Head.Sequence) || *b.Grant != grantReference(f.Grant) {
		return codedError(CodeUnavailable)
	}
	requirements, err := executionRequirements(p.Binding.OriginalAdmission, f.Grant.Requirements)
	if err != nil || !reflect.DeepEqual(requirements, f.Grant.Requirements) {
		return codedError(CodeUnavailable)
	}
	// Terminal facts are permanent. A different request cannot overwrite them;
	// identical semantic terminal replay remains stable after progress compaction.
	if f.Terminal != nil {
		if d.Command.Kind != "complete_operation" || f.Terminal.Target != target ||
			f.Terminal.Grant != *b.Grant || !reflect.DeepEqual(f.Terminal.Result, *b.Result) {
			return codedError(CodeUnavailable)
		}
		out.Receipt.State = f.Terminal.Result.Outcome
		return nil
	}
	switch d.Command.Kind {
	case "record_progress", "retire_artifact":
		changes, err := reduceArtifacts(p, b, d.Command.Kind == "retire_artifact")
		if err != nil {
			return err
		}
		out.ArtifactEffects = changes
		if d.Command.Kind == "record_progress" {
			out.ProgressEffect = &ExecutionProgress{OperationID: b.OperationID, Grant: *b.Grant, State: b.State, Reason: b.Reason, NextAction: b.NextAction, Sequence: d.Sequence}
			out.Receipt.State = b.State
		}
	case "complete_operation":
		terminal, err := reduceExecutionTerminal(p, b, d.Sequence)
		if err != nil {
			return err
		}
		out.TerminalEffect = terminal
		out.Receipt.State = b.Result.Outcome
	}
	return nil
}
