package contract

import (
	"encoding/json"
	"strings"
	"testing"
)

func transferDecision() Decision {
	return Decision{Sequence: 8, ParentDigest: strings.Repeat("a", 64), Command: Command{Kind: "transfer_owner", ClusterUID: "cluster", ProjectUID: "project", PrincipalID: "principal", OwnerID: "owner", ManagementKey: "machine", ResourceUID: "resource-uid", Generation: 1, Session: 1, SessionID: "session", RequestID: "transfer-request", Body: []byte(`{"version":1,"resource":{"cluster_uid":"cluster","project_uid":"project","kind":"vm","uid":"resource-uid"},"expected_revision":"rev:opaque-alpha","source":{"key":{"cluster_uid":"cluster","project_uid":"project","owner_id":"owner","management_key":"machine"},"generation":1},"target":{"cluster_uid":"cluster","project_uid":"project","owner_id":"target-owner","management_key":"target-key"},"expected_target_generation":0}`)}, Assignment: []byte(`{"version":1,"cluster_uid":"cluster","operation_id":"transfer-operation","recorded_at":"2026-10-18T00:00:00Z","ownership":{"version":1,"target_session":{"id":"target-session","activation":3,"principal_uid":"target-principal"},"target_generation":1,"revision":"rev:opaque-beta","admitted_generation":1,"quiescence":{"version":1,"resource_uid":"resource-uid","revision":"rev:opaque-alpha","incarnation":"runtime-incarnation","last_operation_id":"create-operation","runtime_owner_epoch":0,"fence_sequence":7,"evidence_id":"quiescence-evidence","coverage_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"permissions":[{"purpose":"source_owner","principal_uid":"principal","cluster_uid":"cluster","project_uid":"project","owner_id":"owner","project_name":"acme","verb":"vm.update","evidence_id":"authorization-evidence","coverage_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","fence_sequence":7},{"purpose":"target_owner","principal_uid":"principal","cluster_uid":"cluster","project_uid":"project","owner_id":"target-owner","project_name":"acme","verb":"vm.update","evidence_id":"authorization-evidence","coverage_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","fence_sequence":7},{"purpose":"resource","principal_uid":"principal","cluster_uid":"cluster","project_uid":"project","resource_uid":"resource-uid","resource_name":"machine","project_name":"acme","verb":"vm.update","evidence_id":"authorization-evidence","coverage_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","fence_sequence":7}]}}`)}
}
func TestAutomationOwnershipStrictContract(t *testing.T) {
	d := transferDecision()
	if err := ValidateSupportedDecision(d); err != nil {
		t.Fatal("valid strict ownership packet refused", err)
	}
}

func TestAutomationOwnershipRejectsConfusedFacts(t *testing.T) {
	for _, change := range []struct{ from, to string }{
		{`"expected_target_generation":0`, `"expected_target_generation":null`},
		{`,"expected_target_generation":0`, ``},
		{`"expected_revision":"rev:opaque-alpha"`, `"expected_revision":1`},
		{`"target":{"cluster_uid":"cluster","project_uid":"project"`, `"target":{"cluster_uid":"cluster","project_uid":"another-project"`},
	} {
		d := transferDecision()
		d.Command.Body = []byte(strings.Replace(string(d.Command.Body), change.from, change.to, 1))
		if err := ValidateSupportedDecision(d); Code(err) != CodeValidation {
			t.Fatalf("invalid ownership body accepted: %s %v", d.Command.Body, err)
		}
	}
	for _, change := range []struct{ from, to string }{
		{`"runtime_owner_epoch":0`, `"runtime_owner_epoch":null`},
		{`"purpose":"source_owner"`, `"purpose":"target_owner"`},
		{`"verb":"vm.update"`, `"verb":"perm.modify"`},
		{`"revision":"rev:opaque-beta"`, `"revision":"rev:opaque-alpha"`},
		{`"activation":3`, `"activation":0`},
		{`"resource_name":"machine"`, `"resource_name":""`},
	} {
		d := transferDecision()
		d.Assignment = []byte(strings.Replace(string(d.Assignment), change.from, change.to, 1))
		if err := ValidateSupportedDecision(d); Code(err) != CodeValidation {
			t.Fatalf("invalid ownership assignment accepted: %s %v", change.from, err)
		}
	}
	d := transferDecision()
	d.Command.ExpectedRevision = 1
	if err := ValidateSupportedDecision(d); Code(err) != CodeValidation {
		t.Fatal("legacy numeric revision accepted", err)
	}
}

func ownershipProjection(t *testing.T) Projection {
	t.Helper()
	p := createBindingProjection()
	r, err := Reduce(p, createBindingDecision())
	if err != nil {
		t.Fatal(err)
	}
	p.Head.Sequence = 7
	p.Binding.Resource = r.ResourceEffect
	p.Binding.Name = r.NameEffect
	p.Binding.NameIdentity = r.IdentityEffect
	p.Binding.Last = &r.BindingEffects[0]
	p.Binding.OriginalAdmission = r.AdmissionEffect
	p.Binding.TargetOwner = &OwnerRecord{ClusterUID: "cluster", ProjectUID: "project", OwnerID: "target-owner", FounderPrincipalUID: "target-principal", SessionID: "target-session", SessionPrincipalUID: "target-principal", Activation: 3}
	p.Binding.TargetPrincipal = &IdentityRecord{ClusterUID: "cluster", Kind: "principal", UID: "target-principal", Witness: "target-lifetime", Generation: 1}
	return p
}
func TestAutomationOwnershipTransferPreservesIdentity(t *testing.T) {
	p := ownershipProjection(t)
	d := transferDecision()
	r, err := Reduce(p, d)
	if err != nil || r.Receipt.Code != "" || r.Receipt.State != "succeeded" || r.ResourceEffect == nil || len(r.BindingEffects) != 2 || r.AdmissionEffect == nil {
		t.Fatalf("transfer did not produce full typed ownership effects: %+v %v", r, err)
	}
	resource := r.ResourceEffect
	if resource.UID != p.Binding.Resource.UID || resource.ProjectUID != p.Binding.Resource.ProjectUID || resource.Name != p.Binding.Resource.Name || resource.DomainUUID != p.Binding.Resource.DomainUUID || resource.Incarnation != p.Binding.Resource.Incarnation || resource.OriginalOperationID != "create-operation" || resource.LastOperationID != "transfer-operation" || resource.OwnerID != "target-owner" || resource.Revision != "rev:opaque-beta" || resource.AppliedSequence != 8 {
		t.Fatal("transfer rewrote immutable resource/original admission", resource)
	}
	if !r.BindingEffects[0].Retired || r.BindingEffects[0].Revision != "rev:opaque-alpha" || r.BindingEffects[1].Retired || r.BindingEffects[1].OwnerID != "target-owner" || r.BindingEffects[1].Generation != 1 || r.Receipt.ResourceRevision != "rev:opaque-beta" || r.NameEffect != nil || r.IdentityEffect != nil {
		t.Fatal("transfer confused binding generations/revision/name", r)
	}
	p.Existing = &Request{Identity: r.Identity, Receipt: r.Receipt}
	p.Operation = &r.Receipt
	d.Command.SessionID = "successor"
	d.Command.Session = 2
	d.Assignment = []byte(strings.Replace(string(d.Assignment), `"id":"target-session"`, `"id":"new-target-session"`, 1))
	retry, err := Reduce(p, d)
	if err != nil || retry.Receipt != r.Receipt || !noBindingEffects(retry) {
		t.Fatal("successor rebound immutable ownership receipt", retry, err)
	}
}
func TestAutomationOwnershipRejectsStalePredecessors(t *testing.T) {
	for _, mode := range []string{"resource-revision", "source-generation", "target-generation", "target-session", "project", "incarnation", "last-operation", "fence", "original-admission"} {
		t.Run(mode, func(t *testing.T) {
			p := ownershipProjection(t)
			d := transferDecision()
			want := CodeRevisionConflict
			switch mode {
			case "resource-revision":
				p.Binding.Resource.Revision = "another-revision"
			case "source-generation":
				p.Binding.Last.Generation = 2
			case "target-generation":
				p.Binding.TargetLast = &BindingRecord{ClusterUID: "cluster", ProjectUID: "project", OwnerID: "target-owner", ManagementKey: "target-key", ResourceUID: "retired", OperationID: "retired-op", Generation: 3, Revision: "retired-rev", Retired: true}
			case "target-session":
				p.Binding.TargetOwner.Activation = 4
				want = CodeOwnershipConflict
			case "project":
				p.Binding.Resource.ProjectUID = "other-project"
				want = CodeValidation
			case "incarnation":
				p.Binding.Resource.Incarnation = "other-incarnation"
				want = CodeUnavailable
			case "last-operation":
				p.Binding.Resource.LastOperationID = "other-operation"
				want = CodeUnavailable
			case "fence":
				p.Binding.Resource.AppliedSequence = 8
				want = CodeUnavailable
			case "original-admission":
				p.Binding.OriginalAdmission = nil
				want = CodeUnavailable
			}
			r, err := Reduce(p, d)
			code := r.Receipt.Code
			if err != nil {
				code = Code(err)
			}
			if code != want || !noBindingEffects(r) {
				t.Fatalf("stale predecessor %s accepted: %+v %v want %s", mode, r, err, want)
			}
		})
	}
}
func TestAutomationOwnershipAdoptsUnownedWithoutInventingCreate(t *testing.T) {
	p := ownershipProjection(t)
	p.Binding.Resource.OwnerID = ""
	p.Binding.Resource.ManagementKey = ""
	p.Binding.Resource.BindingGeneration = 0
	p.Binding.Resource.OriginalOperationID = ""
	p.Binding.Resource.LastOperationID = "migration-operation"
	p.Binding.OriginalAdmission = nil
	p.Binding.Last = nil
	d := transferDecision()
	d.Command.Kind = "adopt_resource"
	d.Command.OwnerID = "target-owner"
	d.Command.ManagementKey = "target-key"
	d.Command.Generation = 0
	d.Command.PrincipalID = "target-principal"
	d.Command.SessionID = "target-session"
	d.Command.Session = 3
	body, _ := DecodeOwnershipBody(transferDecision().Command)
	body.Source = nil
	d.Command.Body, _ = json.Marshal(body)
	assigned, _ := DecodeAssignment(transferDecision())
	assigned.OperationID = "adopt-operation"
	assigned.Ownership.Quiescence.LastOperationID = "migration-operation"
	assigned.Ownership.Permissions = assigned.Ownership.Permissions[1:]
	for i := range assigned.Ownership.Permissions {
		assigned.Ownership.Permissions[i].PrincipalUID = "target-principal"
	}
	d.Assignment, _ = json.Marshal(assigned)
	p.Binding.Owner = p.Binding.TargetOwner
	p.Binding.Principal = p.Binding.TargetPrincipal
	r, err := Reduce(p, d)
	if err != nil || r.Receipt.Code != "" || r.ResourceEffect == nil || r.ResourceEffect.OriginalOperationID != "" || r.ResourceEffect.LastOperationID != "adopt-operation" || r.ResourceEffect.UID != "resource-uid" || len(r.BindingEffects) != 1 || r.AdmissionEffect == nil || r.AdmissionEffect.Method != "adopt_resource" {
		t.Fatalf("adoption invented create admission or omitted ownership effects: %+v %v", r, err)
	}
}
