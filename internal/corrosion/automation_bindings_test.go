package corrosion

import (
	"context"
	"errors"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"reflect"
	"testing"
)

// Storage-effect fixtures are not fresh migration, runtime or admission permits.
func TestAutomationBindingEffectsPersistAtomically(t *testing.T) {
	c := NewTestClientT(t)
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	r := automationCreateStorageFixture()
	if err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		return automationApplySemanticEffectsTx(ctx, tx, "", contract.Prefix{}, contract.Prefix{ClusterUID: "cluster", Sequence: 1, Digest: "digest"}, r)
	}); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`SELECT uid FROM local_automation_resources WHERE stage=''`,
		`SELECT resource_uid FROM local_automation_names WHERE stage=''`,
		`SELECT resource_uid FROM local_automation_bindings WHERE stage=''`,
		`SELECT resource_uid FROM local_automation_admissions WHERE stage=''`,
	} {
		rows, err := c.Query(ctx, query)
		if err != nil || len(rows) != 1 {
			t.Errorf("complete typed effect missing: %s rows=%+v err=%v", query, rows, err)
		}
	}
}
func TestAutomationBindingCallbackCannotEraseEffects(t *testing.T) {
	for _, kind := range []string{"resource", "resource_previous", "name", "binding", "admission"} {
		t.Run(kind, func(t *testing.T) {
			r := contract.Reduction{}
			switch kind {
			case "resource_previous":
				r.ResourcePrevious = &contract.ResourceRecord{UID: "resource"}
			case "resource":
				r.ResourceEffect = &contract.ResourceRecord{UID: "resource"}
			case "name":
				r.NameEffect = &contract.NameRecord{Name: "machine"}
			case "binding":
				r.BindingEffects = []contract.BindingRecord{{ResourceUID: "resource"}}
			case "admission":
				r.AdmissionEffect = &contract.AdmissionRecord{OperationID: "operation"}
			}
			if err := validateAutomationCallback(r, contract.Reduction{}); err == nil {
				t.Fatal("callback erased typed binding effect")
			}
		})
	}
}

func TestAutomationBindingCallbackCannotMutatePredecessor(t *testing.T) {
	original := contract.Projection{Binding: &contract.BindingProjection{Project: &contract.IdentityRecord{UID: "project"}, Principal: &contract.IdentityRecord{UID: "principal"}, AssignedIdentity: &contract.IdentityRecord{UID: "assigned"}, NameIdentity: &contract.IdentityRecord{UID: "named"}, Owner: &contract.OwnerRecord{Activation: 1}, Last: &contract.BindingRecord{Generation: 1}, Name: &contract.NameRecord{Generation: 1}, Resource: &contract.ResourceRecord{Revision: "rev:opaque-alpha"}, AssignedResource: &contract.ResourceRecord{Revision: "rev:opaque-alpha"}, Dependencies: []*contract.IdentityRecord{{UID: "dependency"}}}}
	original.Binding.TargetOwner = &contract.OwnerRecord{Activation: 3}
	original.Binding.TargetPrincipal = &contract.IdentityRecord{UID: "target-principal"}
	original.Binding.TargetLast = &contract.BindingRecord{Generation: 4}
	original.Binding.OriginalAdmission = &contract.AdmissionRecord{OperationID: "original-create", PinnedConfiguration: &contract.VMIntent{Labels: map[string]string{"original": "label"}, Image: &contract.ReferenceInput{Pinned: &contract.PinnedReference{UID: "original-image"}}, Disks: []contract.DiskIntent{{Pool: &contract.ReferenceInput{Pinned: &contract.PinnedReference{UID: "original-pool"}}}}, NICs: []contract.NICIntent{{Network: contract.ReferenceInput{Pinned: &contract.PinnedReference{UID: "original-network"}}}}, Placement: &contract.PlacementIntent{Host: &contract.HostInput{Pinned: &contract.HostReference{UID: "original-host"}}}}}
	copy := cloneAutomationProjection(original)
	copy.Binding.Project.UID = "changed"
	copy.Binding.Principal.UID = "changed"
	copy.Binding.AssignedIdentity.UID = "changed"
	copy.Binding.NameIdentity.UID = "changed"
	copy.Binding.Owner.Activation = 2
	copy.Binding.Last.Generation = 2
	copy.Binding.Name.Generation = 2
	copy.Binding.Resource.Revision = "rev:opaque-beta"
	copy.Binding.AssignedResource.Revision = "rev:opaque-beta"
	copy.Binding.Dependencies[0].UID = "changed"
	copy.Binding.TargetOwner.Activation = 99
	copy.Binding.TargetPrincipal.UID = "changed"
	copy.Binding.TargetLast.Generation = 99
	copy.Binding.OriginalAdmission.OperationID = "changed"
	config := copy.Binding.OriginalAdmission.PinnedConfiguration
	config.Labels["original"] = "changed"
	config.Image.Pinned.UID = "changed"
	config.Disks[0].Pool.Pinned.UID = "changed"
	config.NICs[0].Network.Pinned.UID = "changed"
	config.Placement.Host.Pinned.UID = "changed"
	b := original.Binding
	pinned := b.OriginalAdmission.PinnedConfiguration
	if b.TargetOwner.Activation != 3 || b.TargetPrincipal.UID != "target-principal" || b.TargetLast.Generation != 4 || b.OriginalAdmission.OperationID != "original-create" || pinned.Labels["original"] != "label" || pinned.Image.Pinned.UID != "original-image" || pinned.Disks[0].Pool.Pinned.UID != "original-pool" || pinned.NICs[0].Network.Pinned.UID != "original-network" || pinned.Placement.Host.Pinned.UID != "original-host" {
		t.Fatal("callback mutated target ownership or nested original admission")
	}

	if b.Project.UID != "project" || b.Principal.UID != "principal" || b.AssignedIdentity.UID != "assigned" || b.NameIdentity.UID != "named" || b.Owner.Activation != 1 || b.Last.Generation != 1 || b.Name.Generation != 1 || b.Resource.Revision != "rev:opaque-alpha" || b.AssignedResource.Revision != "rev:opaque-alpha" || b.Dependencies[0].UID != "dependency" {
		t.Fatal("callback mutated authoritative binding predecessor")
	}
}

func automationCreateStorageFixture() contract.Reduction {
	return contract.Reduction{
		Receipt:         contract.Receipt{ResourceUID: "resource", State: "accepted"},
		IdentityEffect:  &contract.IdentityRecord{ClusterUID: "cluster", ProjectUID: "project", Kind: "vm", UID: "resource", Alias: "machine", Witness: "incarnation", Generation: 1},
		ResourceEffect:  &contract.ResourceRecord{ClusterUID: "cluster", ProjectUID: "project", UID: "resource", Name: "machine", DomainUUID: "domain", Incarnation: "incarnation", OwnerID: "owner", ManagementKey: "key", BindingGeneration: 1, Revision: "rev:opaque-alpha", LastOperationID: "operation", OriginalOperationID: "operation", AppliedSequence: 1},
		NameEffect:      &contract.NameRecord{ClusterUID: "cluster", Name: "machine", ResourceUID: "resource", Generation: 1, Disposition: "reserved"},
		BindingEffects:  []contract.BindingRecord{{ClusterUID: "cluster", ProjectUID: "project", OwnerID: "owner", ManagementKey: "key", ResourceUID: "resource", OperationID: "operation", Generation: 1, Revision: "rev:opaque-alpha"}},
		AdmissionEffect: &contract.AdmissionRecord{ClusterUID: "cluster", ProjectUID: "project", OwnerID: "owner", ManagementKey: "key", ResourceUID: "resource", OperationID: "operation", RequestID: "request", PrincipalUID: "principal", Method: "admit_create", BindingGeneration: 1, AdmittedGeneration: 1, Sequence: 1, PinnedConfiguration: &contract.VMIntent{Name: "machine", CPU: 2, MemoryMiB: 1024}},
	}
}

func TestAutomationOwnershipStorageRollbackIsAtomic(t *testing.T) {
	c := NewTestClientT(t)
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	create := automationCreateStorageFixture()
	head := contract.Prefix{ClusterUID: "cluster", Sequence: 1, Digest: "create-digest"}
	if err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		return automationApplySemanticEffectsTx(ctx, tx, "", contract.Prefix{}, head, create)
	}); err != nil {
		t.Fatal(err)
	}
	before := automationTypedSnapshot(t, c)
	previous := *create.ResourceEffect
	resource := previous
	resource.OwnerID = "target-owner"
	resource.ManagementKey = "target-key"
	resource.Revision = "opaque-next"
	resource.LastOperationID = "transfer-operation"
	resource.AppliedSequence = 2
	retired := create.BindingEffects[0]
	retired.Retired = true
	transfer := contract.Reduction{ResourcePrevious: &previous, ResourceEffect: &resource, BindingEffects: []contract.BindingRecord{retired, {ClusterUID: "cluster", ProjectUID: "project", OwnerID: "target-owner", ManagementKey: "target-key", ResourceUID: "resource", OperationID: "transfer-operation", Generation: 1, Revision: "opaque-next"}}, AdmissionEffect: &contract.AdmissionRecord{ClusterUID: "cluster", ProjectUID: "project", OwnerID: "owner", ManagementKey: "key", ResourceUID: "resource", OperationID: "transfer-operation", RequestID: "transfer-request", PrincipalUID: "principal", Method: "transfer_owner", BindingGeneration: 1, AdmittedGeneration: 1, Sequence: 2}}
	abort := errors.New("injected post-effect failure")
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		if err := automationApplySemanticEffectsTx(ctx, tx, "", head, contract.Prefix{ClusterUID: "cluster", Sequence: 2, Digest: "transfer-digest"}, transfer); err != nil {
			return err
		}
		return abort
	})
	if !errors.Is(err, abort) {
		t.Fatal("did not reach complete ownership writes", err)
	}
	if !reflect.DeepEqual(before, automationTypedSnapshot(t, c)) {
		t.Fatal("ownership rollback left partial resource/binding/admission/name effects")
	}
}
