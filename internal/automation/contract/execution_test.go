package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

// executionClaimFixture reaches the real dispatcher only after the real binding
// reducer has admitted the original pinned configuration. Its enrolled identity
// projection is deterministic unit-test input, not native admission, certified
// application, or proof of host/backend exclusion.
func executionClaimFixture(t *testing.T) (Projection, Decision) {
	t.Helper()
	p, admission := bindingPinnedFixture(t)
	admitted, err := Reduce(p, admission)
	if err != nil || admitted.Receipt.Code != "" || admitted.Receipt.State != "accepted" ||
		admitted.ResourceEffect == nil || admitted.AdmissionEffect == nil ||
		admitted.NameEffect == nil || len(admitted.BindingEffects) != 1 {
		t.Fatalf("execution prerequisite: original binding did not admit: %+v %v", admitted, err)
	}
	configuration := admitted.AdmissionEffect.PinnedConfiguration
	if configuration == nil || configuration.Image == nil || configuration.Image.Pinned == nil ||
		configuration.Image.Pinned.UID != "image-uid" ||
		len(configuration.Disks) != 1 || configuration.Disks[0].Pool.Pinned.UID != "pool-uid" ||
		len(configuration.NICs) != 1 || configuration.NICs[0].Network.Pinned.UID != "network-uid" ||
		configuration.Placement.Host.Pinned.UID != "host-uid" {
		t.Fatal("execution prerequisite: original immutable dependencies missing")
	}
	encoded, err := EncodeDecision(admission)
	if err != nil {
		t.Fatal("execution prerequisite: original decision encoding", err)
	}
	digest := sha256.Sum256(encoded)
	p.Head = Prefix{ClusterUID: "cluster", Sequence: 7, Digest: hex.EncodeToString(digest[:])}
	p.Binding.Resource = admitted.ResourceEffect
	p.Binding.OriginalAdmission = admitted.AdmissionEffect
	p.Binding.Name = admitted.NameEffect
	p.Binding.Last = &admitted.BindingEffects[0]
	p.Binding.AssignedIdentity = admitted.IdentityEffect
	// The host incarnation is the actual enrolled witness in the pinned fixture.
	// No owner epoch, spec generation or voter generation is substituted for it.
	body := struct {
		Version          int              `json:"version"`
		OperationID      string           `json:"operation_id"`
		Admission        HistoryReference `json:"admission"`
		ResourceRevision string           `json:"resource_revision"`
		DomainUUID       string           `json:"domain_uuid"`
		Incarnation      string           `json:"incarnation"`
		HostUID          string           `json:"host_uid"`
		HostIncarnation  string           `json:"host_incarnation"`
	}{
		1, "create-operation", HistoryReference{Sequence: 7, Digest: p.Head.Digest},
		"rev:opaque-alpha", "domain-uuid", "runtime-incarnation", "host-uid", "positive-host-uid",
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	d := Decision{
		Sequence: 8, ParentDigest: p.Head.Digest,
		Command: Command{
			Kind: "claim_executor", ClusterUID: "cluster", ProjectUID: "project",
			PrincipalID: "principal", OwnerID: "owner", ManagementKey: "machine",
			RequestID: "claim-request", ResourceUID: "resource-uid", Generation: 1,
			Session: 1, SessionID: "session", Body: raw,
		},
		Assignment: []byte(`{"version":1,"cluster_uid":"cluster","operation_id":"claim-operation","recorded_at":"2026-10-20T00:00:00Z","execution":{"version":1,"executor_generation":1}}`),
	}
	if _, err := EncodeDecision(d); err != nil {
		t.Fatal("execution prerequisite: canonical claim encoding", err)
	}
	return p, d
}

func executionJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func executionGrantedFixture(t *testing.T) (Projection, Decision) {
	t.Helper()
	p, d := executionClaimFixture(t)
	r, err := Reduce(p, d)
	if err != nil || r.ExecutorEffect == nil {
		t.Fatal("grant fixture", r, err)
	}
	p.Execution = &ExecutionProjection{Admission: r.ExecutorEffect.Target.Admission, Grant: r.ExecutorEffect}
	p.Head = Prefix{ClusterUID: "cluster", Sequence: 8, Digest: r.ExecutorEffect.Reference.Digest}
	b, err := DecodeExecutionBody(d.Command)
	if err != nil {
		t.Fatal(err)
	}
	b.Grant = &ExecutorReference{Generation: 1, Decision: r.ExecutorEffect.Reference}
	b.State = "running"
	d.Command.Kind = "record_progress"
	d.Command.RequestID = "progress-request"
	d.Command.Body = executionJSON(t, b)
	d.Sequence = 9
	d.ParentDigest = p.Head.Digest
	d.Assignment = []byte(`{"version":1,"cluster_uid":"cluster","operation_id":"progress-operation","recorded_at":"2026-10-20T00:00:01Z"}`)
	return p, d
}

func executionNoEffects(r Reduction) bool {
	return noBindingEffects(r) && r.OwnerEffect == nil && r.ExecutorEffect == nil &&
		r.ProgressEffect == nil && r.TerminalEffect == nil && len(r.ArtifactEffects) == 0
}

func executionRequireRefusal(t *testing.T, p Projection, d Decision) {
	t.Helper()
	before := executionJSON(t, p)
	r, err := Reduce(p, d)
	if (err == nil && r.Receipt.Code == "") || !executionNoEffects(r) {
		t.Fatalf("invalid execution produced effects: %+v %v", r, err)
	}
	if string(before) != string(executionJSON(t, p)) {
		t.Fatal("refusal mutated projection")
	}
}

func TestAutomationExecutionGrantAndProgress(t *testing.T) {
	p, d := executionClaimFixture(t)
	r, err := Reduce(p, d)
	if err != nil || r.ExecutorEffect == nil {
		t.Fatal(r, err)
	}
	g := r.ExecutorEffect
	if g.Generation != 1 || g.Target.OperationID != "create-operation" ||
		g.Target.ResourceUID != "resource-uid" || g.Target.DomainUUID != "domain-uuid" ||
		g.Target.HostIncarnation != "positive-host-uid" || g.Target.BindingGeneration != 1 ||
		g.Reference.Sequence != 8 || len(g.Requirements) != 2 {
		t.Fatal("incomplete original grant", g)
	}
	for _, state := range []string{"running", "recovering", "blocked"} {
		t.Run(state, func(t *testing.T) {
			p, d := executionGrantedFixture(t)
			b, _ := DecodeExecutionBody(d.Command)
			b.State = state
			if state != "running" {
				b.Reason = "backend_unknown"
				b.NextAction = "reconcile"
			}
			d.Command.Body = executionJSON(t, b)
			r, err := Reduce(p, d)
			if err != nil || r.ProgressEffect == nil || r.ProgressEffect.State != state ||
				r.TerminalEffect != nil || !noBindingEffects(r) || r.Receipt.ResourceRevision != "rev:opaque-alpha" {
				t.Fatalf("nonterminal progress changed intent or completed: %+v %v", r, err)
			}
		})
	}
}

// Removing the generation comparison must fail stale-generation after this
// same successful real first-grant setup, not at fixture construction.
func TestAutomationExecutionCurrentGrantBindings(t *testing.T) {
	for _, mode := range []string{"generation", "grant-digest", "operation", "admission", "host", "host-incarnation", "runtime", "domain", "resource", "revision", "binding-generation", "retired", "parent", "sequence", "future-grant", "missing-grant", "missing-admission", "missing-host", "foreign-admission", "changed-configuration", "binding-retired", "name-reused", "missing-binding", "sequence-overflow", "host-generation-overflow", "unapplied-resource"} {
		t.Run(mode, func(t *testing.T) {
			p, d := executionGrantedFixture(t)
			b, _ := DecodeExecutionBody(d.Command)
			switch mode {
			case "generation":
				b.Grant.Generation = 2
			case "grant-digest":
				b.Grant.Decision.Digest = strings.Repeat("f", 64)
			case "operation":
				b.OperationID = "other-operation"
			case "admission":
				b.Admission.Digest = strings.Repeat("f", 64)
			case "host":
				b.HostUID = "other-host"
			case "host-incarnation":
				b.HostIncarnation = "reinstalled-host"
			case "runtime":
				b.Incarnation = "successor-runtime"
			case "domain":
				b.DomainUUID = "successor-domain"
			case "resource":
				d.Command.ResourceUID = "successor-resource"
			case "revision":
				b.ResourceRevision = "later-revision"
			case "binding-generation":
				d.Command.Generation = 2
			case "retired":
				p.Binding.Resource.Retired = true
			case "parent":
				d.ParentDigest = strings.Repeat("f", 64)
			case "sequence":
				d.Sequence++
			case "future-grant":
				p.Execution.Grant.Reference.Sequence = 10
			case "missing-grant":
				p.Execution.Grant = nil
			case "missing-admission":
				p.Binding.OriginalAdmission = nil
			case "missing-host":
				p.Binding.Dependencies = p.Binding.Dependencies[:3]
			case "foreign-admission":
				p.Binding.OriginalAdmission.ResourceUID = "other"
			case "changed-configuration":
				p.Binding.OriginalAdmission.PinnedConfiguration.CPU++
			case "binding-retired":
				p.Binding.Last.Retired = true
			case "name-reused":
				p.Binding.Name.ResourceUID = "successor"
			case "missing-binding":
				p.Binding.Last = nil
			case "sequence-overflow":
				p.Head.Sequence = math.MaxInt64
			case "host-generation-overflow":
				p.Binding.Dependencies[3].Generation = uint64(math.MaxInt64) + 1
			case "unapplied-resource":
				p.Binding.Resource.AppliedSequence = 0
			}
			d.Command.Body = executionJSON(t, b)
			executionRequireRefusal(t, p, d)
		})
	}
}

func executionTakeoverFixture(t *testing.T) (Projection, Decision) {
	t.Helper()
	p, d := executionGrantedFixture(t)
	b, _ := DecodeExecutionBody(d.Command)
	b.State = ""
	b.Previous = b.Grant
	b.Grant = nil
	ref := HistoryReference{Sequence: 9, Digest: strings.Repeat("e", 64)}
	b.Exclusion = &ref
	b.HostUID = "next-host"
	b.HostIncarnation = "next-host-incarnation"
	p.Binding.Dependencies = append(p.Binding.Dependencies, &IdentityRecord{ClusterUID: "cluster", Kind: "host", UID: "next-host", Witness: "next-host-incarnation", Generation: 1})
	// Explicit already-certified projection fixture; no runtime/physical fence
	// producer exists in this component and this cannot serve as its witness.
	p.Execution.Exclusions = []ExecutorExclusion{{Reference: ref, Predecessor: *p.Execution.Grant}}
	p.Head.Sequence = 9
	p.Head.Digest = ref.Digest
	d.Sequence = 10
	d.ParentDigest = ref.Digest
	d.Command.Kind = "claim_executor"
	d.Command.RequestID = "takeover-request"
	d.Command.Body = executionJSON(t, b)
	d.Assignment = []byte(`{"version":1,"cluster_uid":"cluster","operation_id":"takeover-operation","recorded_at":"2026-10-20T00:00:02Z","execution":{"version":1,"executor_generation":2}}`)
	return p, d
}

func TestAutomationExecutionTakeoverRequiresExactExclusion(t *testing.T) {
	p, d := executionTakeoverFixture(t)
	r, err := Reduce(p, d)
	if err != nil || r.ExecutorEffect == nil || r.ExecutorEffect.Generation != 2 ||
		r.ExecutorEffect.Target.HostUID != "next-host" || !noBindingEffects(r) {
		t.Fatal("certified predecessor fixture did not advance exact executor", r, err)
	}
	for _, mode := range []string{"missing", "wrong-reference", "wrong-predecessor", "old-fact", "future-fact", "duplicate-fact", "no-previous", "no-exclusion", "overflow", "conflicting-first"} {
		t.Run(mode, func(t *testing.T) {
			p, d := executionTakeoverFixture(t)
			b, _ := DecodeExecutionBody(d.Command)
			switch mode {
			case "missing":
				p.Execution.Exclusions = nil
			case "wrong-reference":
				p.Execution.Exclusions[0].Reference.Digest = strings.Repeat("f", 64)
			case "wrong-predecessor":
				p.Execution.Exclusions[0].Predecessor.Target.DomainUUID = "wrong"
			case "old-fact":
				p.Execution.Exclusions[0].Reference.Sequence = 7
			case "future-fact":
				p.Execution.Exclusions[0].Reference.Sequence = 11
			case "duplicate-fact":
				p.Execution.Exclusions = append(p.Execution.Exclusions, p.Execution.Exclusions[0])
			case "no-previous":
				b.Previous = nil
			case "no-exclusion":
				b.Exclusion = nil
			case "overflow":
				p.Execution.Grant.Generation = math.MaxInt64
				b.Previous.Generation = math.MaxInt64
			case "conflicting-first":
				b.Previous = nil
				b.Exclusion = nil
			}
			d.Command.Body = executionJSON(t, b)
			executionRequireRefusal(t, p, d)
		})
	}
}

func TestAutomationExecutionStrictSchema(t *testing.T) {
	p, d := executionGrantedFixture(t)
	for _, change := range []struct{ from, to string }{
		{`"version":1`, `"version":2`}, {`"version":1`, `"Version":1`},
		{`"version":1`, `"version":1,"fenced":true`},
		{`"version":1`, `"version":1,"timeout":30`},
		{`"operation_id":"create-operation"`, `"operation_id":null`},
		{`"generation":1`, `"generation":0`},
		{`"generation":1`, `"generation":9223372036854775808`},
		{`"state":"running"`, `"state":"succeeded"`},
		{`"state":"running"`, `"state":"blocked"`},
		{`"state":"running"`, `"state":"running","result":null`},
	} {
		bad := d
		bad.Command.Body = []byte(strings.Replace(string(d.Command.Body), change.from, change.to, 1))
		if string(bad.Command.Body) == string(d.Command.Body) {
			t.Fatal("test mutation did not apply", change)
		}
		executionRequireRefusal(t, p, bad)
	}
	p, d = executionClaimFixture(t)
	for _, assignment := range []string{
		`{"version":1,"cluster_uid":"cluster","operation_id":"claim-operation","recorded_at":"2026-10-20T00:00:00Z"}`,
		strings.Replace(string(d.Assignment), `"executor_generation":1`, `"executor_generation":0`, 1),
		strings.Replace(string(d.Assignment), `"executor_generation":1`, `"executor_generation":9223372036854775808`, 1),
		strings.Replace(string(d.Assignment), `"executor_generation":1`, `"executor_generation":1,"physical_exclusion":true`, 1),
	} {
		bad := d
		bad.Assignment = []byte(assignment)
		executionRequireRefusal(t, p, bad)
	}
}

// The missing production branch is ValidateSupportedCommand/Reduce's typed
// claim_executor handler. The designated RED must be CodeUnsupported here,
// after the original admitted binding and canonical claim have succeeded.
func TestAutomationExecutionClaimAfterOriginalAdmission(t *testing.T) {
	p, d := executionClaimFixture(t)
	before, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Reduce(p, d)
	if err != nil {
		t.Fatalf("RED_EXECUTION_CLAIM_DISPATCH: valid original admission cannot claim executor: code=%s err=%v", Code(err), err)
	}
	if r.Receipt.Code != "" || r.Receipt.State == "rejected" ||
		r.Receipt.ResourceUID != "resource-uid" || r.Receipt.Generation != 1 ||
		r.Receipt.ResourceRevision != "rev:opaque-alpha" {
		t.Fatalf("claim lost original resource lifetime/revision: %+v", r.Receipt)
	}
	if !noBindingEffects(r) || r.OwnerEffect != nil {
		t.Fatalf("claim reassigned binding, desired intent or name: %+v", r)
	}
	after, err := json.Marshal(p)
	if err != nil || string(after) != string(before) {
		t.Fatal("pure executor dispatch mutated its predecessor input", err)
	}
	p.Existing = &Request{Identity: r.Identity, Receipt: r.Receipt}
	p.Operation = &r.Receipt
	d.Sequence = 9
	d.Command.Session = 2
	d.Command.SessionID = "successor-session"
	retry, err := Reduce(p, d)
	if err != nil || retry.Receipt != r.Receipt || retry.SaveRequest ||
		!noBindingEffects(retry) || retry.OwnerEffect != nil {
		t.Fatalf("executor request retry did not preserve original result: %+v %v", retry, err)
	}
}

func TestAutomationExecutionClaimHistoricalEncoding(t *testing.T) {
	_, d := executionClaimFixture(t)
	// The existing canonical spelling already round-trips through the historical
	// codec. Adding typed semantics must not rewrite these recovery bytes.
	checkDecisionEncoding(t, d, "")
	encoded, err := EncodeDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeDecision(encoded)
	if err != nil || !reflect.DeepEqual(decoded, d) {
		t.Fatal("execution claim lost original admitted fields in recovery", err)
	}
}

func TestAutomationExecutionAbsentAssignmentPreservesHistoricalBytes(t *testing.T) {
	const original = `{"version":1,"cluster_uid":"cluster","operation_id":"operation","recorded_at":"2026-10-20T00:00:00Z"}`
	a := Assignment{Version: 1, ClusterUID: "cluster", OperationID: "operation", RecordedAt: "2026-10-20T00:00:00Z"}
	if string(executionJSON(t, a)) != original {
		t.Fatal("absent executor extension changed historical control assignment")
	}
}

func TestAutomationExecutionOriginalReplayRecomputesGrant(t *testing.T) {
	p, d := executionClaimFixture(t)
	r, err := Reduce(p, d)
	if err != nil {
		t.Fatal(err)
	}
	p.Existing = &Request{Identity: r.Identity, Receipt: r.Receipt}
	p.Operation = &r.Receipt
	p.ReplayOriginal = true
	replay, err := Reduce(p, d)
	if err != nil || !reflect.DeepEqual(replay.ExecutorEffect, r.ExecutorEffect) || replay.Receipt != r.Receipt {
		t.Fatal("original replay lost grant derivation", replay, err)
	}
	p.Binding.Resource.Incarnation = "later-runtime"
	executionRequireRefusal(t, p, d)
	p, d = executionClaimFixture(t)
	r, err = Reduce(p, d)
	if err != nil {
		t.Fatal(err)
	}
	p.Existing = &Request{Identity: r.Identity, Receipt: r.Receipt}
	p.Existing.Receipt.ResourceRevision = "conflicting-retained-result"
	p.ReplayOriginal = true
	executionRequireRefusal(t, p, d)
}
