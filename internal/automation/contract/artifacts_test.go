package contract

import (
	"reflect"
	"strings"
	"testing"
)

func executionArtifactsFixture(t *testing.T) (Projection, Decision) {
	t.Helper()
	p, d := executionGrantedFixture(t)
	b, _ := DecodeExecutionBody(d.Command)
	g := p.Execution.Grant
	b.Artifacts = []ArtifactRecord{
		{ID: "domain-artifact", Key: "domain", Kind: "domain", Backend: "libvirt", ObjectID: "domain-uuid", ResourceUID: "resource-uid", Incarnation: "runtime-incarnation", OperationID: "create-operation", Origin: ExecutorReference{Generation: 1, Decision: g.Reference}, HostUID: "host-uid", HostIncarnation: "positive-host-uid", State: "active"},
		{ID: "disk-artifact", Key: "root", Kind: "disk", Backend: "pool", ObjectID: "immutable-volume-id", ResourceUID: "resource-uid", Incarnation: "runtime-incarnation", OperationID: "create-operation", Origin: ExecutorReference{Generation: 1, Decision: g.Reference}, HostUID: "host-uid", HostIncarnation: "positive-host-uid", PoolUID: "pool-uid", ImageDigest: strings.Repeat("a", 64), Locator: "/volumes/machine", State: "active"},
	}
	d.Command.Body = executionJSON(t, b)
	r, err := Reduce(p, d)
	if err != nil || len(r.ArtifactEffects) != 2 || r.ProgressEffect == nil {
		t.Fatal("artifact fixture", r, err)
	}
	p.Execution.Artifacts = r.ArtifactEffects
	p.Execution.Progress = r.ProgressEffect
	p.Head = Prefix{ClusterUID: "cluster", Sequence: 9, Digest: strings.Repeat("b", 64)}
	d.Sequence = 10
	d.ParentDigest = p.Head.Digest
	d.Command.RequestID = "complete-request"
	d.Command.Kind = "complete_operation"
	b.State = ""
	b.Artifacts = nil
	b.Result = &ExecutionResult{Outcome: "succeeded", Code: "created", ObservedState: "running", Artifacts: []ArtifactDisposition{{ID: "disk-artifact", State: "active"}, {ID: "domain-artifact", State: "active"}}}
	d.Command.Body = executionJSON(t, b)
	d.Assignment = []byte(`{"version":1,"cluster_uid":"cluster","operation_id":"complete-operation","recorded_at":"2026-10-20T00:00:03Z"}`)
	return p, d
}

func TestAutomationArtifactImmutableBackendIdentity(t *testing.T) {
	for _, mode := range []string{"object", "backend", "id", "path-only", "operation", "resource", "incarnation", "generation", "image", "pool", "payload", "host", "duplicate-id", "duplicate-key"} {
		t.Run(mode, func(t *testing.T) {
			p, d := executionArtifactsFixture(t)
			b, _ := DecodeExecutionBody(d.Command)
			b.Result = nil
			b.State = "running"
			b.Artifacts = append([]ArtifactRecord(nil), p.Execution.Artifacts...)
			a := &b.Artifacts[1]
			switch mode {
			case "object":
				a.ObjectID = "successor-volume"
			case "backend":
				a.Backend = "other-backend"
			case "id":
				a.ID = "same-path-successor"
			case "path-only":
				a.ObjectID = ""
			case "operation":
				a.OperationID = "other"
			case "resource":
				a.ResourceUID = "other"
			case "incarnation":
				a.Incarnation = "other"
			case "generation":
				a.Origin.Generation = 2
			case "image":
				a.ImageDigest = strings.Repeat("f", 64)
			case "pool":
				a.PoolUID = "other"
			case "payload":
				a.PayloadID = "invented"
			case "host":
				a.HostIncarnation = "other"
			case "duplicate-id":
				a.ID = b.Artifacts[0].ID
			case "duplicate-key":
				a.Key = b.Artifacts[0].Key
				a.Kind = b.Artifacts[0].Kind
			}
			d.Command.Kind = "record_progress"
			d.Command.Body = executionJSON(t, b)
			executionRequireRefusal(t, p, d)
		})
	}
	p, d := executionArtifactsFixture(t)
	b, _ := DecodeExecutionBody(d.Command)
	b.Result = nil
	b.State = "recovering"
	b.Reason = "relocated"
	b.NextAction = "reconcile"
	b.Artifacts = append([]ArtifactRecord(nil), p.Execution.Artifacts...)
	b.Artifacts[1].Locator = "/volumes/relocated"
	d.Command.Kind = "record_progress"
	d.Command.Body = executionJSON(t, b)
	r, err := Reduce(p, d)
	if err != nil || len(r.ArtifactEffects) != 2 || r.ArtifactEffects[1].ObjectID != "immutable-volume-id" {
		t.Fatal("locator became ownership", r, err)
	}
}

func TestAutomationTerminalCompleteDispositionAndReplay(t *testing.T) {
	p, d := executionArtifactsFixture(t)
	r, err := Reduce(p, d)
	if err != nil || r.TerminalEffect == nil || r.Receipt.State != "succeeded" ||
		r.TerminalEffect.Grant.Generation != 1 || !noBindingEffects(r) || len(r.TerminalEffect.Artifacts) != 2 {
		t.Fatal("terminal lost permanent resource/artifact accounting", r, err)
	}
	p.Execution.Terminal = r.TerminalEffect
	// Verbose progress may be compacted independently of the terminal record.
	p.Execution.Progress = nil
	same, err := Reduce(p, d)
	if err != nil || !executionNoEffects(same) || same.Receipt.State != "succeeded" {
		t.Fatal("identical terminal replay was unstable after progress compaction", same, err)
	}
	for _, mode := range []string{"missing", "duplicate", "unknown", "wrong-disposition", "wrong-result", "wrong-observation", "conflicting-outcome", "stale-generation"} {
		t.Run(mode, func(t *testing.T) {
			p, d := executionArtifactsFixture(t)
			b, _ := DecodeExecutionBody(d.Command)
			switch mode {
			case "missing":
				b.Result.Artifacts = b.Result.Artifacts[:1]
			case "duplicate":
				b.Result.Artifacts[1] = b.Result.Artifacts[0]
			case "unknown":
				p.Execution.Artifacts[0].State = "unknown"
			case "wrong-disposition":
				b.Result.Artifacts[0].State = "retained"
			case "wrong-result":
				old, _ := Reduce(p, d)
				p.Execution.Terminal = old.TerminalEffect
				b.Result.Code = "other"
			case "wrong-observation":
				b.Result.ObservedState = "stopped"
			case "conflicting-outcome":
				old, _ := Reduce(p, d)
				p.Execution.Terminal = old.TerminalEffect
				b.Result.Outcome = "failed"
			case "stale-generation":
				b.Grant.Generation = 2
			}
			d.Command.Body = executionJSON(t, b)
			executionRequireRefusal(t, p, d)
		})
	}
}

func TestAutomationTerminalFailureRequiresAccountedOwnership(t *testing.T) {
	p, d := executionArtifactsFixture(t)
	b, _ := DecodeExecutionBody(d.Command)
	b.Result.Outcome = "failed"
	b.Result.Code = "create_failed"
	b.Result.ObservedState = "absent"
	b.Result.Artifacts = []ArtifactDisposition{{ID: "disk-artifact", State: "retained"}, {ID: "domain-artifact", State: "deleted"}}
	p.Execution.Artifacts[0].State = "deleted"
	p.Execution.Artifacts[1].State = "retained"
	d.Command.Body = executionJSON(t, b)
	r, err := Reduce(p, d)
	if err != nil || r.TerminalEffect == nil || r.Receipt.State != "failed" || !noBindingEffects(r) {
		t.Fatal("accounted failure refused", r, err)
	}
	p.Execution.Artifacts[0].State = "active"
	executionRequireRefusal(t, p, d)
}

func TestAutomationArtifactRetirementKeepsIdentity(t *testing.T) {
	p, d := executionArtifactsFixture(t)
	b, _ := DecodeExecutionBody(d.Command)
	b.Result = nil
	a := p.Execution.Artifacts[1]
	a.State = "deleted"
	b.Artifacts = []ArtifactRecord{a}
	d.Command.Kind = "retire_artifact"
	d.Command.Body = executionJSON(t, b)
	r, err := Reduce(p, d)
	if err != nil || len(r.ArtifactEffects) != 1 || r.ArtifactEffects[0].ID != "disk-artifact" ||
		r.ArtifactEffects[0].State != "deleted" || !noBindingEffects(r) {
		t.Fatal("artifact tombstone lost immutable owner", r, err)
	}
	b.Artifacts[0].ObjectID = "successor-at-same-path"
	d.Command.Body = executionJSON(t, b)
	executionRequireRefusal(t, p, d)
}

func TestAutomationExecutionRetryHasNoNewEffects(t *testing.T) {
	p, d := executionArtifactsFixture(t)
	r, err := Reduce(p, d)
	if err != nil {
		t.Fatal(err)
	}
	p.Existing = &Request{Identity: r.Identity, Receipt: r.Receipt}
	p.Operation = &r.Receipt
	p.Execution.Grant.Generation = 99
	p.Binding.Resource.Retired = true
	d.Command.SessionID = "renewed"
	d.Command.Session = 7
	retry, err := Reduce(p, d)
	if err != nil || !reflect.DeepEqual(retry.Receipt, r.Receipt) || !executionNoEffects(retry) {
		t.Fatal("retry allocated new work", retry, err)
	}
	b, _ := DecodeExecutionBody(d.Command)
	b.Result.Code = "changed"
	d.Command.Body = executionJSON(t, b)
	conflict, err := Reduce(p, d)
	if err != nil || conflict.Receipt.Code != CodeIdempotencyConflict || !executionNoEffects(conflict) {
		t.Fatal("conflicting retry changed outcome", conflict, err)
	}
}

func TestAutomationArtifactRequirementsCannotOmitAdmittedObjects(t *testing.T) {
	for _, mode := range []string{"missing-disk", "missing-domain", "extra-disk", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			p, d := executionClaimFixture(t)
			a, _ := DecodeAssignment(d)
			switch mode {
			case "missing-disk":
				a.Execution.Requirements = []ArtifactRequirement{{Key: "domain", Kind: "domain"}}
			case "missing-domain":
				a.Execution.Requirements = []ArtifactRequirement{{Key: "root", Kind: "disk"}}
			case "extra-disk":
				a.Execution.Requirements = []ArtifactRequirement{{Key: "domain", Kind: "domain"}, {Key: "root", Kind: "disk"}, {Key: "extra", Kind: "disk"}}
			case "duplicate":
				a.Execution.Requirements = []ArtifactRequirement{{Key: "domain", Kind: "domain"}, {Key: "domain", Kind: "domain"}}
			}
			d.Assignment = executionJSON(t, a)
			executionRequireRefusal(t, p, d)
		})
	}
	p, d := executionClaimFixture(t)
	a, _ := DecodeAssignment(d)
	a.Execution.Requirements = []ArtifactRequirement{{Key: "domain", Kind: "domain"}, {Key: "root", Kind: "disk"}, {Key: "nvram", Kind: "firmware"}, {Key: "vtpm", Kind: "firmware"}}
	d.Assignment = executionJSON(t, a)
	r, err := Reduce(p, d)
	if err != nil || r.ExecutorEffect == nil || len(r.ExecutorEffect.Requirements) != 4 {
		t.Fatal("multi-effect plan refused", r, err)
	}
	// Missing firmware still blocks terminal even when every disk is accounted.
	p, d = executionArtifactsFixture(t)
	p.Execution.Grant.Requirements = append(p.Execution.Grant.Requirements, ArtifactRequirement{Key: "nvram", Kind: "firmware"})
	executionRequireRefusal(t, p, d)
	p, d = executionArtifactsFixture(t)
	p.Execution.Grant.Requirements = []ArtifactRequirement{{Key: "domain", Kind: "domain"}}
	p.Execution.Artifacts = p.Execution.Artifacts[:1]
	b, _ := DecodeExecutionBody(d.Command)
	b.Result.Artifacts = b.Result.Artifacts[1:]
	d.Command.Body = executionJSON(t, b)
	executionRequireRefusal(t, p, d)
}

func TestAutomationArtifactBootstrapAssociationIsOpaque(t *testing.T) {
	p, d := executionClaimFixture(t)
	// This is a private admitted-payload association supplied by the prior owner,
	// not bootstrap material or a fabricated custody/possession witness.
	p.Binding.OriginalAdmission.PayloadID = "effective-bootstrap"
	r, err := Reduce(p, d)
	if err != nil || r.ExecutorEffect == nil {
		t.Fatal(r, err)
	}
	p.Execution = &ExecutionProjection{Admission: r.ExecutorEffect.Target.Admission, Grant: r.ExecutorEffect}
	p.Head = Prefix{ClusterUID: "cluster", Sequence: 8, Digest: r.ExecutorEffect.Reference.Digest}
	b, _ := DecodeExecutionBody(d.Command)
	b.Grant = &ExecutorReference{Generation: 1, Decision: r.ExecutorEffect.Reference}
	b.State = "running"
	b.Artifacts = []ArtifactRecord{{ID: "seed-id", Key: "bootstrap", Kind: "seed", Backend: "seed-store", ObjectID: "seed-object", ResourceUID: "resource-uid", Incarnation: "runtime-incarnation", OperationID: "create-operation", Origin: *b.Grant, HostUID: "host-uid", HostIncarnation: "positive-host-uid", PayloadID: "effective-bootstrap", State: "active"}}
	d.Command.Kind = "record_progress"
	d.Command.RequestID = "seed-progress"
	d.Command.Body = executionJSON(t, b)
	d.Sequence = 9
	d.ParentDigest = p.Head.Digest
	d.Assignment = []byte(`{"version":1,"cluster_uid":"cluster","operation_id":"seed-progress-operation","recorded_at":"2026-10-20T00:00:01Z"}`)
	r, err = Reduce(p, d)
	if err != nil || len(r.ArtifactEffects) != 1 || r.ArtifactEffects[0].PayloadID != "effective-bootstrap" {
		t.Fatal("seed association lost", r, err)
	}
	b.Artifacts[0].PayloadID = "different-bootstrap"
	d.Command.Body = executionJSON(t, b)
	executionRequireRefusal(t, p, d)
	b.Artifacts[0].PayloadID = "effective-bootstrap"
	b.Artifacts[0].ImageDigest = strings.Repeat("c", 64)
	d.Command.Body = executionJSON(t, b)
	executionRequireRefusal(t, p, d)
}

func TestAutomationTerminalBlocksLaterMutationAndRetainsSnapshots(t *testing.T) {
	p, d := executionArtifactsFixture(t)
	r, err := Reduce(p, d)
	if err != nil || r.TerminalEffect == nil {
		t.Fatal(r, err)
	}
	p.Execution.Terminal = r.TerminalEffect
	snapshot := executionJSON(t, r.TerminalEffect)
	p.Execution.Artifacts[0].Locator = "later-locator"
	p.Execution.Progress.State = "later-observation"
	if string(snapshot) != string(executionJSON(t, r.TerminalEffect)) {
		t.Fatal("terminal aliases verbose or mutable projection")
	}
	b, _ := DecodeExecutionBody(d.Command)
	b.Result = nil
	b.State = "running"
	d.Command.Kind = "record_progress"
	d.Command.Body = executionJSON(t, b)
	executionRequireRefusal(t, p, d)
}

func TestAutomationArtifactsSurviveExecutorTakeover(t *testing.T) {
	prior, _ := executionArtifactsFixture(t)
	p, d := executionTakeoverFixture(t)
	p.Execution.Artifacts = prior.Execution.Artifacts
	r, err := Reduce(p, d)
	if err != nil || r.ExecutorEffect == nil {
		t.Fatal("takeover with existing objects", r, err)
	}
	p.Execution.Grant = r.ExecutorEffect
	p.Head = Prefix{ClusterUID: "cluster", Sequence: 10, Digest: r.ExecutorEffect.Reference.Digest}
	b, _ := DecodeExecutionBody(d.Command)
	b.Previous = nil
	b.Exclusion = nil
	b.Grant = &ExecutorReference{Generation: 2, Decision: r.ExecutorEffect.Reference}
	b.State = "recovering"
	b.Reason = "backend_unknown"
	b.NextAction = "reconcile"
	b.Artifacts = append([]ArtifactRecord(nil), p.Execution.Artifacts...)
	d.Command.Kind = "record_progress"
	d.Command.RequestID = "takeover-progress"
	d.Command.Body = executionJSON(t, b)
	d.Sequence = 11
	d.ParentDigest = p.Head.Digest
	d.Assignment = []byte(`{"version":1,"cluster_uid":"cluster","operation_id":"takeover-progress-operation","recorded_at":"2026-10-20T00:00:04Z"}`)
	r, err = Reduce(p, d)
	if err != nil || len(r.ArtifactEffects) != 2 || r.ArtifactEffects[1].Origin.Generation != 1 ||
		r.ArtifactEffects[1].ObjectID != "immutable-volume-id" || !noBindingEffects(r) {
		t.Fatal("new executor reassigned existing artifact identity", r, err)
	}
	b.Artifacts[1].Origin = *b.Grant
	d.Command.Body = executionJSON(t, b)
	executionRequireRefusal(t, p, d)
}
