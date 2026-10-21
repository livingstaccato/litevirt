package contract

import "sort"

type ArtifactRequirement struct {
	Key  string `json:"key"`
	Kind string `json:"kind"`
}

// ArtifactRecord names a backend object independently of its locator. The
// origin is immutable across executor takeover and path reuse. PayloadID is an
// opaque association with the admitted effective bootstrap, never secret bytes
// or a public digest of those bytes.
type ArtifactRecord struct {
	ID              string            `json:"id"`
	Key             string            `json:"key"`
	Kind            string            `json:"kind"`
	Backend         string            `json:"backend"`
	ObjectID        string            `json:"object_id"`
	ResourceUID     string            `json:"resource_uid"`
	Incarnation     string            `json:"incarnation"`
	OperationID     string            `json:"operation_id"`
	Origin          ExecutorReference `json:"origin"`
	HostUID         string            `json:"host_uid"`
	HostIncarnation string            `json:"host_incarnation"`
	PoolUID         string            `json:"pool_uid,omitempty"`
	ImageDigest     string            `json:"image_digest,omitempty"`
	PayloadID       string            `json:"payload_id,omitempty"`
	Locator         string            `json:"locator,omitempty"`
	State           string            `json:"state"`
}
type ArtifactDisposition struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

func artifactKind(kind string) bool {
	return kind == "domain" || kind == "disk" || kind == "seed" || kind == "firmware"
}
func artifactState(state string) bool {
	switch state {
	case "planned", "active", "unknown", "retained", "deleted", "absent", "pending_cleanup":
		return true
	}
	return false
}
func validArtifactRequirements(rows []ArtifactRequirement) bool {
	if len(rows) > 128 {
		return false
	}
	seen := map[ArtifactRequirement]bool{}
	for _, r := range rows {
		if !keyText(r.Key) || !artifactKind(r.Kind) || seen[r] {
			return false
		}
		seen[r] = true
	}
	return true
}
func executionRequirements(a *AdmissionRecord, declared []ArtifactRequirement) ([]ArtifactRequirement, error) {
	if a == nil || a.PinnedConfiguration == nil {
		return nil, codedError(CodeUnavailable)
	}
	required := []ArtifactRequirement{{Key: "domain", Kind: "domain"}}
	for _, disk := range a.PinnedConfiguration.Disks {
		required = append(required, ArtifactRequirement{Key: disk.Key, Kind: "disk"})
	}
	if a.PayloadID != "" {
		required = append(required, ArtifactRequirement{Key: "bootstrap", Kind: "seed"})
	}
	if !validArtifactRequirements(required) {
		return nil, codedError(CodeUnavailable)
	}
	if len(declared) != 0 {
		if !validArtifactRequirements(declared) {
			return nil, codedError(CodeValidation)
		}
		set := map[ArtifactRequirement]bool{}
		for _, r := range required {
			set[r] = true
		}
		for _, r := range declared {
			if !set[r] && r.Kind != "firmware" {
				return nil, codedError(CodeValidation)
			}
			delete(set, r)
		}
		if len(set) != 0 {
			return nil, codedError(CodeValidation)
		}
		required = append([]ArtifactRequirement(nil), declared...)
	}
	sort.Slice(required, func(i, j int) bool {
		if required[i].Kind == required[j].Kind {
			return required[i].Key < required[j].Key
		}
		return required[i].Kind < required[j].Kind
	})
	return required, nil
}
func validArtifactRecord(a ArtifactRecord) bool {
	for _, s := range []string{a.ID, a.Key, a.Backend, a.ObjectID, a.ResourceUID, a.Incarnation, a.OperationID, a.HostUID, a.HostIncarnation} {
		if !keyText(s) {
			return false
		}
	}
	if !artifactKind(a.Kind) || !artifactState(a.State) || !validExecutorReference(a.Origin) {
		return false
	}
	for _, s := range []string{a.PoolUID, a.PayloadID, a.Locator} {
		if s != "" && !keyText(s) {
			return false
		}
	}
	return a.ImageDigest == "" || keyDigest(a.ImageDigest)
}
func immutableArtifact(a ArtifactRecord) ArtifactRecord {
	a.State, a.Locator = "", ""
	return a
}
func artifactPinned(p Projection, a ArtifactRecord) bool {
	g := p.Execution.Grant
	target := g.Target
	if !validArtifactRecord(a) || a.ResourceUID != target.ResourceUID || a.Incarnation != target.Incarnation ||
		a.OperationID != target.OperationID || a.Origin.Generation > g.Generation || a.Origin.Decision.Sequence > g.Reference.Sequence {
		return false
	}
	required := false
	for _, r := range g.Requirements {
		if r.Key == a.Key && r.Kind == a.Kind {
			required = true
		}
	}
	if !required {
		return false
	}
	switch a.Kind {
	case "domain":
		return a.ObjectID == target.DomainUUID && a.PoolUID == "" && a.ImageDigest == "" && a.PayloadID == ""
	case "seed":
		return target.PayloadID != "" && a.PayloadID == target.PayloadID && a.PoolUID == "" && a.ImageDigest == ""
	case "firmware":
		return a.PayloadID == "" && a.ImageDigest == "" && a.PoolUID == ""
	case "disk":
		for _, d := range p.Binding.OriginalAdmission.PinnedConfiguration.Disks {
			if d.Key == a.Key {
				image := ""
				if d.Image != nil {
					if d.Image.Pinned == nil {
						return false
					}
					image = d.Image.Pinned.ContentDigest
				}
				return d.Pool != nil && d.Pool.Pinned != nil && a.PoolUID == d.Pool.Pinned.UID &&
					a.ImageDigest == image && a.PayloadID == ""
			}
		}
	}
	return false
}

func artifactInventory(p Projection) (map[string]ArtifactRecord, map[ArtifactRequirement]string, error) {
	byID := map[string]ArtifactRecord{}
	byKey := map[ArtifactRequirement]string{}
	if len(p.Execution.Artifacts) > 128 {
		return nil, nil, codedError(CodeUnavailable)
	}
	objects := map[[2]string]bool{}
	for _, a := range p.Execution.Artifacts {
		k := ArtifactRequirement{Key: a.Key, Kind: a.Kind}
		object := [2]string{a.Backend, a.ObjectID}
		if _, exists := byID[a.ID]; exists {
			return nil, nil, codedError(CodeUnavailable)
		}
		if !artifactPinned(p, a) || byKey[k] != "" || objects[object] {
			return nil, nil, codedError(CodeUnavailable)
		}
		byID[a.ID], byKey[k], objects[object] = a, a.ID, true
	}
	return byID, byKey, nil
}

func reduceArtifacts(p Projection, b ExecutionBody, retirement bool) ([]ArtifactRecord, error) {
	byID, byKey, err := artifactInventory(p)
	if err != nil {
		return nil, err
	}
	seenID := map[string]bool{}
	seenKey := map[ArtifactRequirement]bool{}
	out := make([]ArtifactRecord, 0, len(b.Artifacts))
	for _, a := range b.Artifacts {
		key := ArtifactRequirement{Key: a.Key, Kind: a.Kind}
		if seenID[a.ID] || seenKey[key] || !artifactPinned(p, a) {
			return nil, codedError(CodeUnavailable)
		}
		seenID[a.ID], seenKey[key] = true, true
		if old, exists := byID[a.ID]; exists {
			if immutableArtifact(old) != immutableArtifact(a) ||
				((old.State == "deleted" || old.State == "absent") && a.State != old.State) {
				return nil, codedError(CodeUnavailable)
			}
		} else {
			if retirement || byKey[key] != "" || a.Origin != grantReference(p.Execution.Grant) ||
				a.HostUID != p.Execution.Grant.Target.HostUID || a.HostIncarnation != p.Execution.Grant.Target.HostIncarnation {
				return nil, codedError(CodeUnavailable)
			}
		}
		// Even distinct artifact IDs cannot claim one backend object twice.
		for id, old := range byID {
			if id != a.ID && old.Backend == a.Backend && old.ObjectID == a.ObjectID {
				return nil, codedError(CodeUnavailable)
			}
		}
		byID[a.ID], byKey[key] = a, a.ID
		out = append(out, a)
	}
	return out, nil
}

func validExecutionResult(r ExecutionResult) bool {
	if (r.Outcome != "succeeded" && r.Outcome != "failed") || !keyText(r.Code) ||
		(r.ObservedState != "running" && r.ObservedState != "stopped" && r.ObservedState != "absent") ||
		len(r.Artifacts) == 0 || len(r.Artifacts) > 128 {
		return false
	}
	last := ""
	for _, a := range r.Artifacts {
		if !keyText(a.ID) || a.ID <= last || !artifactState(a.State) {
			return false
		}
		last = a.ID
	}
	return true
}

func reduceExecutionTerminal(p Projection, b ExecutionBody, sequence uint64) (*ExecutionTerminal, error) {
	byID, byKey, err := artifactInventory(p)
	if err != nil {
		return nil, err
	}
	g := p.Execution.Grant
	if len(byKey) != len(g.Requirements) || len(b.Result.Artifacts) != len(byID) {
		return nil, codedError(CodeUnavailable)
	}
	for _, required := range g.Requirements {
		if byKey[required] == "" {
			return nil, codedError(CodeUnavailable)
		}
	}
	var artifacts []ArtifactRecord
	for _, disposition := range b.Result.Artifacts {
		a, exists := byID[disposition.ID]
		if !exists || a.State != disposition.State {
			return nil, codedError(CodeUnavailable)
		}
		if b.Result.Outcome == "succeeded" {
			// Current admitted create cannot succeed with unknown/retained or
			// uncreated required objects. Deletion has its separate retirement
			// owner and is not inferred from completion here.
			if a.State != "active" {
				return nil, codedError(CodeUnavailable)
			}
		} else {
			if a.State != "deleted" && a.State != "absent" && a.State != "retained" {
				return nil, codedError(CodeUnavailable)
			}
			if (a.Kind == "domain" || a.Kind == "seed") && a.State == "retained" {
				return nil, codedError(CodeUnavailable)
			}
		}
		artifacts = append(artifacts, a)
	}
	if b.Result.Outcome == "succeeded" {
		if b.Result.ObservedState != p.Binding.OriginalAdmission.PinnedConfiguration.RequestedState {
			return nil, codedError(CodeUnavailable)
		}
	} else if b.Result.ObservedState != "absent" {
		return nil, codedError(CodeUnavailable)
	}
	result := *b.Result
	result.Artifacts = append([]ArtifactDisposition(nil), result.Artifacts...)
	terminal := &ExecutionTerminal{Target: g.Target, Grant: *b.Grant, Result: result, Artifacts: artifacts, Sequence: sequence}
	// Preserve independent permanent copies; future verbose progress compaction
	// cannot erase or alias the terminal artifact ownership record.
	return terminal, nil
}
