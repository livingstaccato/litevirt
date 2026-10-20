package contract

import (
	"encoding/json"
	"strings"
	"testing"
)

// Removing strict identity handler registration must reject these real wire
// bodies, and accepting unknown fields must fail the negative cases below.
func TestAutomationIdentityEnrollmentSchema(t *testing.T) {
	c := Command{Kind: "assign_identity", ClusterUID: "cluster", PrincipalID: "host", RequestID: "enroll-project", Body: []byte(`{"version":1,"kind":"project","alias":"acme","witness":"project-row-42","evidence_id":"closed-inventory","expected_generation":0}`)}
	if err := ValidateSupportedCommand(c); err != nil {
		t.Fatalf("valid positive enrollment command rejected: %v", err)
	}
	for _, body := range []string{
		`{"version":2,"kind":"project","alias":"acme","witness":"project-row-42","evidence_id":"closed-inventory","expected_generation":0}`,
		`{"version":1,"kind":"project","alias":"acme","witness":"","evidence_id":"closed-inventory","expected_generation":0}`,
		`{"version":1,"kind":"project","alias":"acme","witness":"project-row-42","evidence_id":"","expected_generation":0}`,
		`{"version":1,"kind":"project","alias":"acme","witness":"project-row-42","evidence_id":"closed-inventory","expected_generation":9223372036854775807}`,
		`{"version":1,"kind":"project","alias":"acme","witness":"project-row-42","evidence_id":"closed-inventory","expected_generation":0,"complete":true}`,
		`{"version":1,"kind":"unknown","alias":"acme","witness":"project-row-42","evidence_id":"closed-inventory","expected_generation":0}`,
	} {
		bad := c
		bad.Body = []byte(body)
		if err := ValidateSupportedCommand(bad); Code(err) != CodeValidation {
			t.Errorf("malformed identity accepted: %s: %v", body, err)
		}
	}
}

func unrecordedIdentityDecision(t *testing.T) Decision {
	t.Helper()
	return Decision{Sequence: 2, ParentDigest: strings.Repeat("a", 64), Command: Command{Kind: "assign_identity", ClusterUID: "cluster", PrincipalID: "host", RequestID: "enroll-project", Body: []byte(`{"version":1,"kind":"project","alias":"acme","witness":"project-row-42","evidence_id":"closed-inventory","expected_generation":0}`)}, Assignment: []byte(`{"version":1,"cluster_uid":"cluster","operation_id":"enrollment-operation","recorded_at":"2026-10-17T00:00:00Z","identity":{"uid":"project-uid","generation":1}}`)}
}

// A supplied evidence ID or a successful local absence read cannot replace
// the bounded authoritative predecessor projection.
func TestAutomationIdentityMissingPredecessorRefuses(t *testing.T) {
	d := identityDecision(t)
	p := Projection{Head: Prefix{ClusterUID: "cluster", Sequence: 1, Digest: d.ParentDigest}}
	_, err := Reduce(p, d)
	if Code(err) != CodeUnavailable {
		t.Fatalf("missing authoritative predecessor must be unavailable, got %v", err)
	}
}

func TestAutomationIdentityAssignmentSchema(t *testing.T) {
	d := identityDecision(t)
	if err := ValidateSupportedDecision(d); err != nil {
		t.Fatalf("valid identity assignment rejected: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(d.Assignment, &raw); err != nil {
		t.Fatal(err)
	}
	enrollment := raw["identity"].(map[string]any)["enrollment"]
	for _, assignment := range []any{
		map[string]any{"uid": "", "generation": 1},
		map[string]any{"uid": "project-uid", "generation": 0},
		map[string]any{"uid": "project-uid", "generation": 2},
		map[string]any{"uid": "project-uid", "generation": 1, "verified": true},
	} {
		assignment.(map[string]any)["enrollment"] = enrollment
		raw["identity"] = assignment
		b, _ := json.Marshal(raw)
		bad := d
		bad.Assignment = b
		if err := ValidateSupportedDecision(bad); Code(err) != CodeValidation {
			t.Errorf("invalid identity assignment accepted: %s: %v", b, err)
		}
	}
}

func enrollmentProjection(d Decision) Projection {
	return Projection{Head: Prefix{ClusterUID: "cluster", Sequence: 1, Digest: d.ParentDigest}, Identity: &IdentityProjection{}}
}

// These are pure semantic tests. Constructed inventory facts do not stand in for
// production migration, transport, writer-fence or quorum acceptance evidence.
func TestAutomationIdentityPositiveEnrollment(t *testing.T) {
	d := identityDecision(t)
	p := enrollmentProjection(d)
	got, err := Reduce(p, d)
	if err != nil {
		t.Fatalf("positive inventory did not enroll: %v", err)
	}
	want := IdentityRecord{ClusterUID: "cluster", Kind: "project", UID: "project-uid", Alias: "acme", Witness: "project-row-42", Generation: 1}
	if got.IdentityEffect == nil || *got.IdentityEffect != want || got.Receipt.ResourceUID != "project-uid" || got.Receipt.Generation != 1 || got.Receipt.Code != "" {
		t.Fatalf("incorrect lifetime or receipt: %+v effect=%+v", got.Receipt, got.IdentityEffect)
	}
	if p.Identity.Alias != nil {
		t.Fatal("pure reduction mutated predecessor")
	}
}

func TestAutomationIdentityConvergesWithoutRemint(t *testing.T) {
	d := identityDecision(t)
	p := enrollmentProjection(d)
	p.Identity.Alias = &IdentityRecord{ClusterUID: "cluster", Kind: "project", UID: "original-uid", Alias: "acme", Witness: "project-row-42", Generation: 1}
	got, err := Reduce(p, d)
	if err != nil || got.Receipt.Code != "" || got.Receipt.ResourceUID != "original-uid" || got.Receipt.Generation != 1 || got.IdentityEffect != nil {
		t.Fatalf("same positive lifetime did not converge: %+v %v", got.Receipt, err)
	}
}

func TestAutomationIdentityConflictBlocks(t *testing.T) {
	d := identityDecision(t)
	p := enrollmentProjection(d)
	p.Identity.Alias = &IdentityRecord{ClusterUID: "cluster", Kind: "project", UID: "other-uid", Alias: "acme", Witness: "different-row", Generation: 1}
	got, err := Reduce(p, d)
	if err != nil || got.Receipt.Code != CodeOwnershipConflict || got.Receipt.State != "rejected" || got.IdentityEffect != nil {
		t.Fatalf("conflicting positive lifetime was not rejected: %+v %v", got.Receipt, err)
	}
}

func TestAutomationIdentityEvidenceCannotChangeScope(t *testing.T) {
	for _, field := range []string{"cluster_uid", "project_uid", "kind", "alias", "witness", "coverage_digest", "fence_sequence", "previous_generation"} {
		t.Run(field, func(t *testing.T) {
			d := identityDecision(t)
			var raw map[string]any
			_ = json.Unmarshal(d.Assignment, &raw)
			facts := raw["identity"].(map[string]any)["enrollment"].(map[string]any)
			if field == "fence_sequence" {
				facts[field] = 0
			} else if field == "previous_generation" {
				facts[field] = 1
			} else {
				facts[field] = "other"
			}
			d.Assignment, _ = json.Marshal(raw)
			got, err := Reduce(enrollmentProjection(d), d)
			if Code(err) != CodeValidation || got.IdentityEffect != nil {
				t.Fatalf("altered certified enrollment facts accepted: %+v %v", got.Receipt, err)
			}
		})
	}
}

func identityDecision(t *testing.T) Decision { return recordedIdentityDecision(t) }

func recordedIdentityDecision(t *testing.T) Decision {
	t.Helper()
	d := unrecordedIdentityDecision(t)
	var raw map[string]any
	if err := json.Unmarshal(d.Assignment, &raw); err != nil {
		t.Fatal(err)
	}
	raw["identity"].(map[string]any)["enrollment"] = map[string]any{"version": 1, "evidence_id": "closed-inventory", "cluster_uid": "cluster", "project_uid": "", "kind": "project", "alias": "acme", "witness": "project-row-42", "previous_generation": 0, "coverage_digest": strings.Repeat("c", 64), "fence_sequence": 1}
	d.Assignment, _ = json.Marshal(raw)
	return d
}

func TestAutomationIdentityReplayUsesRecordedWitness(t *testing.T) {
	d := recordedIdentityDecision(t)
	// No current migration inventory/provider exists in this predecessor. The
	// already-certified immutable assignment must suffice for semantic replay.
	p := Projection{Head: Prefix{ClusterUID: "cluster", Sequence: 1, Digest: d.ParentDigest}, Identity: &IdentityProjection{}}
	original, err := Reduce(p, d)
	if err != nil || original.IdentityEffect == nil || original.IdentityEffect.UID != "project-uid" {
		t.Fatalf("recorded witness could not reconstruct without current provider: %+v %v", original.Receipt, err)
	}
	p.Existing = &Request{Identity: original.Identity, Receipt: original.Receipt}
	p.Operation = &original.Receipt
	p.ReplayOriginal = true
	replay, err := Reduce(p, d)
	if err != nil || replay.Receipt != original.Receipt || replay.IdentityEffect == nil || replay.IdentityEffect.UID != "project-uid" {
		t.Fatalf("original replay drift: %+v %v", replay.Receipt, err)
	}
}

func TestAutomationIdentityCannotDiscardRecordedWitness(t *testing.T) {
	d := unrecordedIdentityDecision(t)
	if err := ValidateSupportedDecision(d); Code(err) != CodeValidation {
		t.Fatalf("enrollment assignment without recorded witness accepted: %v", err)
	}
}

func TestAutomationIdentityRequiredZeroFields(t *testing.T) {
	for _, field := range []string{"expected_generation", "previous_generation", "project_uid"} {
		for _, form := range []string{"missing", "null"} {
			t.Run(field+"/"+form, func(t *testing.T) {
				d := identityDecision(t)
				var body, assignment map[string]any
				if err := json.Unmarshal(d.Command.Body, &body); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(d.Assignment, &assignment); err != nil {
					t.Fatal(err)
				}
				target := body
				if field != "expected_generation" {
					target = assignment["identity"].(map[string]any)["enrollment"].(map[string]any)
				}
				if form == "missing" {
					delete(target, field)
				} else {
					target[field] = nil
				}
				d.Command.Body, _ = json.Marshal(body)
				d.Assignment, _ = json.Marshal(assignment)
				if err := ValidateSupportedDecision(d); Code(err) != CodeValidation {
					t.Fatalf("required field %s %s defaulted to zero: %v", field, form, err)
				}
			})
		}
	}
}

func TestAutomationIdentityVMEnrollmentCreatesUnownedFacts(t *testing.T) {
	d := Decision{Sequence: 3, ParentDigest: strings.Repeat("a", 64), Command: Command{Kind: "assign_identity", ClusterUID: "cluster", ProjectUID: "project", PrincipalID: "host", RequestID: "migration-request", Body: []byte(`{"version":1,"kind":"vm","alias":"legacy-machine","witness":"positive-source-witness","evidence_id":"closed-cutover","expected_generation":0}`)}, Assignment: []byte(`{"version":1,"cluster_uid":"cluster","operation_id":"migration-operation","recorded_at":"2026-10-18T00:00:00Z","identity":{"uid":"legacy-resource","generation":1,"enrollment":{"version":1,"evidence_id":"closed-cutover","cluster_uid":"cluster","project_uid":"project","kind":"vm","alias":"legacy-machine","witness":"positive-source-witness","previous_generation":0,"coverage_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","fence_sequence":1,"vm":{"version":1,"domain_uuid":"legacy-domain","incarnation":"legacy-runtime-incarnation","revision":"legacy-opaque-revision"}}}}`)}
	p := Projection{Target: &TargetProjection{}, Head: Prefix{ClusterUID: "cluster", Sequence: 2}, Identity: &IdentityProjection{Project: &IdentityRecord{ClusterUID: "cluster", Kind: "project", UID: "project", Generation: 1, Witness: "project-lifetime"}}}
	r, err := Reduce(p, d)
	if err != nil || r.Receipt.Code != "" || r.ResourceEffect == nil || r.NameEffect == nil || r.IdentityEffect == nil {
		t.Fatalf("positive VM enrollment omitted unowned resource/name: receipt=%+v error=%v", r.Receipt, err)
	}
	if r.ResourceEffect.OwnerID != "" || r.ResourceEffect.BindingGeneration != 0 || r.ResourceEffect.OriginalOperationID != "" || r.ResourceEffect.LastOperationID != "migration-operation" || r.ResourceEffect.Incarnation != "legacy-runtime-incarnation" || r.IdentityEffect.Witness != "positive-source-witness" || r.AdmissionEffect != nil || len(r.BindingEffects) != 0 || r.NameEffect.Disposition != "live" {
		t.Fatal("VM migration fabricated create admission or conflated source/runtime lifetime")
	}
}
