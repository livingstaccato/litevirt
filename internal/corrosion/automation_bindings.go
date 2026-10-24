package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// These are derived effects of the one concrete evaluator, applied under the
// same FULL transaction and semantic predecessor as the certified history.
// Neither these records nor an operation pointer grants admission or quiescence.
func automationApplyBindingEffectsTx(ctx context.Context, tx *LocalTx, stage string, next contract.Prefix, r contract.Reduction) error {
	if r.ResourcePrevious == nil && r.ResourceEffect == nil && r.NameEffect == nil && len(r.BindingEffects) == 0 && r.AdmissionEffect == nil {
		return nil
	}
	if r.TargetEffect != nil && r.TargetEffect.Kind == contract.OrdinaryCreateCommand {
		return automationApplyOrdinaryAllocationEffectsTx(ctx, tx, stage, next, r)
	}
	if r.AdmissionEffect == nil {
		return automationApplyVMEnrollmentEffectsTx(ctx, tx, stage, next, r)
	}
	if r.AdmissionEffect.Method == "admit_update" {
		return automationApplyUpdateEffectsTx(ctx, tx, stage, next, r)
	}
	if r.AdmissionEffect.Method == "adopt_resource" || r.AdmissionEffect.Method == "transfer_owner" {
		return automationApplyOwnershipEffectsTx(ctx, tx, stage, next, r)
	}
	v, n, a := r.ResourceEffect, r.NameEffect, r.AdmissionEffect
	if r.ResourcePrevious != nil || v == nil || n == nil || a == nil || r.IdentityEffect == nil || len(r.BindingEffects) != 1 {
		return fmt.Errorf("incomplete create binding effects")
	}
	b := r.BindingEffects[0]
	i := r.IdentityEffect
	if v.ClusterUID != next.ClusterUID || v.ProjectUID == "" || v.UID == "" || v.Name == "" || v.DomainUUID == "" || v.Incarnation == "" || v.OwnerID == "" || v.ManagementKey == "" || v.Retired || v.Revision == "" || len(v.Revision) > contract.MaxStringBytes || v.BindingGeneration == 0 || v.BindingGeneration > math.MaxInt64 || v.AppliedSequence != next.Sequence || v.LastOperationID == "" || v.OriginalOperationID != v.LastOperationID {
		return fmt.Errorf("invalid create resource effect")
	}
	if i.ClusterUID != v.ClusterUID || i.ProjectUID != v.ProjectUID || i.Kind != "vm" || i.UID != v.UID || i.Alias != v.Name || i.Witness != v.Incarnation || i.Retired || n.ClusterUID != v.ClusterUID || n.Name != v.Name || n.ResourceUID != v.UID || n.Generation != i.Generation || n.Disposition != "reserved" || n.RetirementOperationID != "" {
		return fmt.Errorf("incoherent create name effect")
	}
	if b.ClusterUID != v.ClusterUID || b.ProjectUID != v.ProjectUID || b.OwnerID != v.OwnerID || b.ManagementKey != v.ManagementKey || b.ResourceUID != v.UID || b.OperationID != v.LastOperationID || b.Generation != v.BindingGeneration || b.Revision != v.Revision || b.Retired {
		return fmt.Errorf("incoherent create binding effect")
	}
	if a.ClusterUID != v.ClusterUID || a.ProjectUID != v.ProjectUID || a.OwnerID != v.OwnerID || a.ManagementKey != v.ManagementKey || a.ResourceUID != v.UID || a.OperationID != v.LastOperationID || a.RequestID == "" || a.PrincipalUID == "" || a.Method != "admit_create" || a.BindingGeneration != v.BindingGeneration || a.AdmittedGeneration == 0 || a.AdmittedGeneration > math.MaxInt64 || a.Sequence != next.Sequence || a.PinnedConfiguration == nil || a.PinnedConfiguration.Name != v.Name {
		return fmt.Errorf("incoherent create admission effect")
	}
	configuration, err := json.Marshal(a.PinnedConfiguration)
	if err != nil || len(configuration) > (1<<20) {
		return fmt.Errorf("invalid admission configuration size")
	}
	if _, err = tx.Exec(ctx, `INSERT INTO local_automation_resources(stage,uid,cluster_uid,project_uid,name,domain_uuid,incarnation,owner_id,management_key,binding_generation,revision,retired,last_operation_id,original_operation_id,applied_sequence) VALUES(?,?,?,?,?,?,?,?,?,?,?,0,?,?,?)`, stage, v.UID, v.ClusterUID, v.ProjectUID, v.Name, v.DomainUUID, v.Incarnation, v.OwnerID, v.ManagementKey, v.BindingGeneration, v.Revision, v.LastOperationID, v.OriginalOperationID, v.AppliedSequence); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `INSERT INTO local_automation_names(stage,cluster_uid,name,resource_uid,generation,disposition,retirement_operation_id) VALUES(?,?,?,?,?,?,?) ON CONFLICT(stage,cluster_uid,name) DO UPDATE SET resource_uid=excluded.resource_uid,generation=excluded.generation,disposition=excluded.disposition,retirement_operation_id=excluded.retirement_operation_id WHERE disposition='reusable' AND retirement_operation_id<>'' AND generation=excluded.generation-1`, stage, n.ClusterUID, n.Name, n.ResourceUID, n.Generation, n.Disposition, n.RetirementOperationID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("name lifetime did not advance")
	}
	if _, err = tx.Exec(ctx, `INSERT INTO local_automation_bindings(stage,cluster_uid,project_uid,owner_id,management_key,creation_generation,resource_uid,operation_id,revision,retired) VALUES(?,?,?,?,?,?,?,?,?,0)`, stage, b.ClusterUID, b.ProjectUID, b.OwnerID, b.ManagementKey, b.Generation, b.ResourceUID, b.OperationID, b.Revision); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO local_automation_admissions(stage,operation_id,cluster_uid,project_uid,owner_id,management_key,resource_uid,request_id,principal_uid,method,payload_id,binding_generation,admitted_generation,sequence,configuration_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, stage, a.OperationID, a.ClusterUID, a.ProjectUID, a.OwnerID, a.ManagementKey, a.ResourceUID, a.RequestID, a.PrincipalUID, a.Method, a.PayloadID, a.BindingGeneration, a.AdmittedGeneration, a.Sequence, string(configuration))
	return err
}

func automationResourceRecordTx(ctx context.Context, tx *LocalTx, stage, uid string) (*contract.ResourceRecord, error) {
	if uid == "" {
		return nil, nil
	}
	sizes, err := tx.Query(ctx, `SELECT length(CAST(revision AS BLOB))+length(CAST(cluster_uid AS BLOB))+length(CAST(project_uid AS BLOB))+length(CAST(name AS BLOB))+length(CAST(domain_uuid AS BLOB))+length(CAST(incarnation AS BLOB))+length(CAST(owner_id AS BLOB))+length(CAST(management_key AS BLOB))+length(CAST(last_operation_id AS BLOB))+length(CAST(original_operation_id AS BLOB)) AS bytes FROM local_automation_resources WHERE stage=? AND uid=? LIMIT 1`, stage, uid)
	if err != nil || len(sizes) == 0 {
		return nil, err
	}
	if sizes[0].Int64("bytes") > 10*contract.MaxStringBytes {
		return nil, fmt.Errorf("oversized resource projection")
	}
	rows, err := tx.Query(ctx, `SELECT cluster_uid,project_uid,name,domain_uuid,incarnation,owner_id,management_key,binding_generation,revision,retired,last_operation_id,original_operation_id,applied_sequence FROM local_automation_resources WHERE stage=? AND uid=? LIMIT 1`, stage, uid)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, fmt.Errorf("resource projection disappeared")
	}
	r := rows[0]
	if r.String("cluster_uid") == "" || r.String("project_uid") == "" || r.String("name") == "" || r.String("domain_uuid") == "" || r.String("incarnation") == "" || r.Int64("binding_generation") < 0 || r.String("revision") == "" || len(r.String("revision")) > contract.MaxStringBytes || r.Int64("applied_sequence") <= 0 || r.Int64("retired") < 0 || r.Int64("retired") > 1 || (r.String("owner_id") == "") != (r.String("management_key") == "") || (r.String("owner_id") == "") != (r.Int64("binding_generation") == 0) {
		return nil, fmt.Errorf("invalid resource projection")
	}
	return &contract.ResourceRecord{ClusterUID: r.String("cluster_uid"), ProjectUID: r.String("project_uid"), UID: uid, Name: r.String("name"), DomainUUID: r.String("domain_uuid"), Incarnation: r.String("incarnation"), OwnerID: r.String("owner_id"), ManagementKey: r.String("management_key"), BindingGeneration: uint64(r.Int64("binding_generation")), Revision: r.String("revision"), Retired: r.Int64("retired") == 1, LastOperationID: r.String("last_operation_id"), OriginalOperationID: r.String("original_operation_id"), AppliedSequence: uint64(r.Int64("applied_sequence"))}, nil
}
func automationLastBindingTx(ctx context.Context, tx *LocalTx, stage, cluster, project, owner, key string) (*contract.BindingRecord, error) {
	sizes, err := tx.Query(ctx, `SELECT length(CAST(revision AS BLOB))+length(CAST(resource_uid AS BLOB))+length(CAST(operation_id AS BLOB)) AS bytes FROM local_automation_bindings WHERE stage=? AND cluster_uid=? AND project_uid=? AND owner_id=? AND management_key=? ORDER BY creation_generation DESC LIMIT 1`, stage, cluster, project, owner, key)
	if err != nil || len(sizes) == 0 {
		return nil, err
	}
	if sizes[0].Int64("bytes") > 3*contract.MaxStringBytes {
		return nil, fmt.Errorf("oversized binding projection")
	}
	rows, err := tx.Query(ctx, `SELECT creation_generation,resource_uid,operation_id,revision,retired FROM local_automation_bindings WHERE stage=? AND cluster_uid=? AND project_uid=? AND owner_id=? AND management_key=? ORDER BY creation_generation DESC LIMIT 1`, stage, cluster, project, owner, key)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, fmt.Errorf("binding projection disappeared")
	}
	r := rows[0]
	if r.Int64("creation_generation") <= 0 || r.String("revision") == "" || len(r.String("revision")) > contract.MaxStringBytes || r.String("resource_uid") == "" || r.String("operation_id") == "" || r.Int64("retired") < 0 || r.Int64("retired") > 1 {
		return nil, fmt.Errorf("invalid binding projection")
	}
	return &contract.BindingRecord{ClusterUID: cluster, ProjectUID: project, OwnerID: owner, ManagementKey: key, ResourceUID: r.String("resource_uid"), OperationID: r.String("operation_id"), Generation: uint64(r.Int64("creation_generation")), Revision: r.String("revision"), Retired: r.Int64("retired") == 1}, nil
}
func automationNameRecordTx(ctx context.Context, tx *LocalTx, stage, cluster, name string) (*contract.NameRecord, error) {
	sizes, err := tx.Query(ctx, `SELECT length(CAST(resource_uid AS BLOB))+length(CAST(retirement_operation_id AS BLOB)) AS bytes FROM local_automation_names WHERE stage=? AND cluster_uid=? AND name=? LIMIT 1`, stage, cluster, name)
	if err != nil || len(sizes) == 0 {
		return nil, err
	}
	if sizes[0].Int64("bytes") > 2*contract.MaxStringBytes {
		return nil, fmt.Errorf("oversized name projection")
	}
	rows, err := tx.Query(ctx, `SELECT resource_uid,generation,disposition,retirement_operation_id FROM local_automation_names WHERE stage=? AND cluster_uid=? AND name=? LIMIT 1`, stage, cluster, name)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, fmt.Errorf("name projection disappeared")
	}
	r := rows[0]
	disposition := r.String("disposition")
	if r.String("resource_uid") == "" || r.Int64("generation") <= 0 || (disposition != "reserved" && disposition != "live" && disposition != "reusable") || (disposition == "reusable" && r.String("retirement_operation_id") == "") {
		return nil, fmt.Errorf("invalid name projection")
	}
	return &contract.NameRecord{ClusterUID: cluster, Name: name, ResourceUID: r.String("resource_uid"), Generation: uint64(r.Int64("generation")), Disposition: disposition, RetirementOperationID: r.String("retirement_operation_id")}, nil
}
func automationBindingProjectionTx(ctx context.Context, tx *LocalTx, stage string, p *contract.Projection, d contract.Decision) error {
	a, err := contract.DecodeAssignment(d)
	if err != nil {
		return err
	}
	if a.Binding == nil {
		return fmt.Errorf("missing create assignment")
	}
	c, b := d.Command, a.Binding
	facts := &contract.BindingProjection{}
	if facts.Project, err = automationIdentityRecordTx(ctx, tx, stage, c.ProjectUID); err != nil {
		return err
	}
	if facts.Principal, err = automationIdentityRecordTx(ctx, tx, stage, c.PrincipalID); err != nil {
		return err
	}
	if facts.Owner, err = automationOwnerRecordTx(ctx, tx, stage, c.ClusterUID, c.ProjectUID, c.OwnerID); err != nil {
		return err
	}
	if facts.Last, err = automationLastBindingTx(ctx, tx, stage, c.ClusterUID, c.ProjectUID, c.OwnerID, c.ManagementKey); err != nil {
		return err
	}
	if facts.Name, err = automationNameRecordTx(ctx, tx, stage, c.ClusterUID, b.Configuration.Name); err != nil {
		return err
	}
	if facts.AssignedIdentity, err = automationIdentityRecordTx(ctx, tx, stage, b.ResourceUID); err != nil {
		return err
	}
	if facts.AssignedResource, err = automationResourceRecordTx(ctx, tx, stage, b.ResourceUID); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT uid,generation FROM local_automation_aliases WHERE stage=? AND cluster_uid=? AND project_scope='' AND kind='vm' AND alias=? LIMIT 1`, stage, c.ClusterUID, b.Configuration.Name)
	if err != nil {
		return err
	}
	if len(rows) > 0 {
		if len(rows[0].String("uid")) > contract.MaxStringBytes {
			return fmt.Errorf("oversized alias projection")
		}
		facts.NameIdentity, err = automationIdentityRecordTx(ctx, tx, stage, rows[0].String("uid"))
		if err != nil {
			return err
		}
		if facts.NameIdentity == nil || facts.NameIdentity.Generation != uint64(rows[0].Int64("generation")) {
			return fmt.Errorf("name identity lifetime missing or inconsistent")
		}
	}
	if facts.Name != nil {
		if facts.Resource, err = automationResourceRecordTx(ctx, tx, stage, facts.Name.ResourceUID); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, dependency := range contract.BindingDependencies(b.Configuration) {
		if seen[dependency.UID] {
			continue
		}
		seen[dependency.UID] = true
		record, err := automationIdentityRecordTx(ctx, tx, stage, dependency.UID)
		if err != nil {
			return err
		}
		facts.Dependencies = append(facts.Dependencies, record)
	}
	p.Binding = facts
	return nil
}

func automationAdmissionRecordTx(ctx context.Context, tx *LocalTx, stage, operation string) (*contract.AdmissionRecord, error) {
	if operation == "" {
		return nil, nil
	}
	var bad []string
	for _, column := range []string{"operation_id", "cluster_uid", "project_uid", "owner_id", "management_key", "resource_uid", "request_id", "principal_uid", "method", "payload_id", "configuration_json"} {
		bad = append(bad, "typeof("+column+")<>'text'")
	}
	for _, column := range []string{"binding_generation", "admitted_generation", "sequence"} {
		bad = append(bad, "typeof("+column+")<>'integer' OR "+column+"<=0")
	}
	types, err := tx.Query(ctx, "SELECT CASE WHEN "+strings.Join(bad, " OR ")+" THEN 1 ELSE 0 END AS bad FROM local_automation_admissions WHERE stage=? AND operation_id=? LIMIT 1", stage, operation)
	if err != nil {
		return nil, err
	}
	if len(types) == 0 {
		return nil, nil
	}
	if len(types) != 1 || types[0].Int64("bad") != 0 {
		return nil, fmt.Errorf("invalid typed admission columns")
	}
	sizes, err := tx.Query(ctx, `SELECT length(CAST(configuration_json AS BLOB)) AS config_bytes,length(CAST(cluster_uid AS BLOB))+length(CAST(project_uid AS BLOB))+length(CAST(owner_id AS BLOB))+length(CAST(management_key AS BLOB))+length(CAST(resource_uid AS BLOB))+length(CAST(request_id AS BLOB))+length(CAST(principal_uid AS BLOB))+length(CAST(method AS BLOB))+length(CAST(payload_id AS BLOB)) AS bytes FROM local_automation_admissions WHERE stage=? AND operation_id=? LIMIT 1`, stage, operation)
	if err != nil || len(sizes) == 0 {
		return nil, err
	}
	if sizes[0].Int64("config_bytes") > 1<<20 || sizes[0].Int64("bytes") > 9*contract.MaxStringBytes {
		return nil, fmt.Errorf("oversized original admission")
	}
	rows, err := tx.Query(ctx, `SELECT cluster_uid,project_uid,owner_id,management_key,resource_uid,request_id,principal_uid,method,payload_id,binding_generation,admitted_generation,sequence,configuration_json FROM local_automation_admissions WHERE stage=? AND operation_id=? LIMIT 1`, stage, operation)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, fmt.Errorf("original admission disappeared")
	}
	v := rows[0]
	if v.Int64("sequence") <= 0 || v.Int64("binding_generation") <= 0 || v.Int64("admitted_generation") <= 0 || v.String("cluster_uid") == "" || v.String("project_uid") == "" || v.String("owner_id") == "" || v.String("management_key") == "" || v.String("resource_uid") == "" || v.String("request_id") == "" || v.String("principal_uid") == "" {
		return nil, fmt.Errorf("invalid original admission")
	}
	r := &contract.AdmissionRecord{ClusterUID: v.String("cluster_uid"), ProjectUID: v.String("project_uid"), OwnerID: v.String("owner_id"), ManagementKey: v.String("management_key"), ResourceUID: v.String("resource_uid"), OperationID: operation, RequestID: v.String("request_id"), PrincipalUID: v.String("principal_uid"), Method: v.String("method"), PayloadID: v.String("payload_id"), BindingGeneration: uint64(v.Int64("binding_generation")), AdmittedGeneration: uint64(v.Int64("admitted_generation")), Sequence: uint64(v.Int64("sequence"))}
	encoded := []byte(v.String("configuration_json"))
	if json.Unmarshal(encoded, &r.PinnedConfiguration) != nil {
		return nil, fmt.Errorf("invalid admitted configuration")
	}
	canonical, err := json.Marshal(r.PinnedConfiguration)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return nil, fmt.Errorf("noncanonical admitted configuration")
	}
	if (r.Method == "admit_create" || r.Method == "admit_update") != (r.PinnedConfiguration != nil) || (r.Method != "admit_create" && r.Method != "admit_update" && r.Method != "adopt_resource" && r.Method != "transfer_owner") {
		return nil, fmt.Errorf("invalid admission method/configuration")
	}
	return r, nil
}
func automationOwnershipProjectionTx(ctx context.Context, tx *LocalTx, stage string, p *contract.Projection, d contract.Decision) error {
	body, err := contract.DecodeOwnershipBody(d.Command)
	if err != nil {
		return err
	}
	a, err := contract.DecodeAssignment(d)
	if err != nil {
		return err
	}
	if a.Ownership == nil {
		return fmt.Errorf("missing ownership assignment")
	}
	c := d.Command
	f := &contract.BindingProjection{}
	if f.Project, err = automationIdentityRecordTx(ctx, tx, stage, c.ProjectUID); err != nil {
		return err
	}
	if f.Principal, err = automationIdentityRecordTx(ctx, tx, stage, c.PrincipalID); err != nil {
		return err
	}
	if f.Owner, err = automationOwnerRecordTx(ctx, tx, stage, c.ClusterUID, c.ProjectUID, c.OwnerID); err != nil {
		return err
	}
	if f.TargetOwner, err = automationOwnerRecordTx(ctx, tx, stage, body.Target.ClusterUID, body.Target.ProjectUID, body.Target.OwnerID); err != nil {
		return err
	}
	if f.TargetPrincipal, err = automationIdentityRecordTx(ctx, tx, stage, a.Ownership.TargetSession.PrincipalUID); err != nil {
		return err
	}
	if f.TargetLast, err = automationLastBindingTx(ctx, tx, stage, body.Target.ClusterUID, body.Target.ProjectUID, body.Target.OwnerID, body.Target.ManagementKey); err != nil {
		return err
	}
	if body.Source != nil {
		if f.Last, err = automationLastBindingTx(ctx, tx, stage, c.ClusterUID, c.ProjectUID, c.OwnerID, c.ManagementKey); err != nil {
			return err
		}
	}
	if f.Resource, err = automationResourceRecordTx(ctx, tx, stage, body.Resource.UID); err != nil {
		return err
	}
	if f.NameIdentity, err = automationIdentityRecordTx(ctx, tx, stage, body.Resource.UID); err != nil {
		return err
	}
	if f.Resource != nil {
		if f.Name, err = automationNameRecordTx(ctx, tx, stage, c.ClusterUID, f.Resource.Name); err != nil {
			return err
		}
		if f.OriginalAdmission, err = automationAdmissionRecordTx(ctx, tx, stage, f.Resource.OriginalOperationID); err != nil {
			return err
		}
	}
	p.Binding = f
	return nil
}
func automationApplyVMEnrollmentEffectsTx(ctx context.Context, tx *LocalTx, stage string, next contract.Prefix, r contract.Reduction) error {
	v, n, i := r.ResourceEffect, r.NameEffect, r.IdentityEffect
	if v == nil || n == nil || i == nil || r.ResourcePrevious != nil || len(r.BindingEffects) != 0 || i.Kind != "vm" || v.ClusterUID != next.ClusterUID || v.ProjectUID == "" || v.UID == "" || v.Name == "" || v.DomainUUID == "" || v.Incarnation == "" || v.Revision == "" || v.Retired || v.OwnerID != "" || v.ManagementKey != "" || v.BindingGeneration != 0 || v.OriginalOperationID != "" || v.LastOperationID == "" || v.AppliedSequence != next.Sequence || i.UID != v.UID || i.ClusterUID != v.ClusterUID || i.ProjectUID != v.ProjectUID || i.Alias != v.Name || i.Retired || n.ClusterUID != v.ClusterUID || n.Name != v.Name || n.ResourceUID != v.UID || n.Generation != i.Generation || n.Disposition != "live" || n.RetirementOperationID != "" {
		return fmt.Errorf("incoherent VM enrollment effects")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO local_automation_resources(stage,uid,cluster_uid,project_uid,name,domain_uuid,incarnation,owner_id,management_key,binding_generation,revision,retired,last_operation_id,original_operation_id,applied_sequence) VALUES(?,?,?,?,?,?,?,'','',0,?,0,?,'',?)`, stage, v.UID, v.ClusterUID, v.ProjectUID, v.Name, v.DomainUUID, v.Incarnation, v.Revision, v.LastOperationID, v.AppliedSequence); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `INSERT INTO local_automation_names(stage,cluster_uid,name,resource_uid,generation,disposition,retirement_operation_id) VALUES(?,?,?,?,?,'live','') ON CONFLICT(stage,cluster_uid,name) DO UPDATE SET resource_uid=excluded.resource_uid,generation=excluded.generation,disposition=excluded.disposition,retirement_operation_id='' WHERE disposition='reusable' AND retirement_operation_id<>'' AND generation=excluded.generation-1`, stage, n.ClusterUID, n.Name, n.ResourceUID, n.Generation)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("enrollment name lifetime did not advance")
	}
	return nil
}
func automationApplyOwnershipEffectsTx(ctx context.Context, tx *LocalTx, stage string, next contract.Prefix, r contract.Reduction) error {
	before, v, a := r.ResourcePrevious, r.ResourceEffect, r.AdmissionEffect
	if before == nil || v == nil || a == nil || r.NameEffect != nil || r.IdentityEffect != nil || v.ClusterUID != next.ClusterUID || v.UID != before.UID || v.ClusterUID != before.ClusterUID || v.ProjectUID != before.ProjectUID || v.Name != before.Name || v.DomainUUID != before.DomainUUID || v.Incarnation != before.Incarnation || v.OriginalOperationID != before.OriginalOperationID || v.Retired || before.Retired || v.Revision == "" || v.Revision == before.Revision || v.OwnerID == "" || v.ManagementKey == "" || v.BindingGeneration == 0 || v.BindingGeneration > math.MaxInt64 || v.AppliedSequence != next.Sequence || v.LastOperationID != a.OperationID || a.OperationID == "" || a.ClusterUID != v.ClusterUID || a.ProjectUID != v.ProjectUID || a.ResourceUID != v.UID || a.BindingGeneration != v.BindingGeneration || a.Sequence != next.Sequence || a.AdmittedGeneration == 0 || a.AdmittedGeneration > math.MaxInt64 || a.RequestID == "" || a.PrincipalUID == "" || a.PinnedConfiguration != nil || a.PayloadID != "" {
		return fmt.Errorf("incoherent ownership effects")
	}
	stored, err := automationResourceRecordTx(ctx, tx, stage, before.UID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(stored, before) {
		return fmt.Errorf("ownership resource predecessor changed")
	}
	effects := r.BindingEffects
	if a.Method == "transfer_owner" {
		if len(effects) != 2 || before.OwnerID == "" || a.OwnerID != before.OwnerID || a.ManagementKey != before.ManagementKey {
			return fmt.Errorf("incomplete transfer effects")
		}
		retired := effects[0]
		if !retired.Retired || retired.ClusterUID != before.ClusterUID || retired.ProjectUID != before.ProjectUID || retired.OwnerID != before.OwnerID || retired.ManagementKey != before.ManagementKey || retired.ResourceUID != before.UID || retired.Generation != before.BindingGeneration || retired.Revision != before.Revision {
			return fmt.Errorf("incoherent source retirement")
		}
		actual, err := automationLastBindingTx(ctx, tx, stage, retired.ClusterUID, retired.ProjectUID, retired.OwnerID, retired.ManagementKey)
		if err != nil {
			return err
		}
		expected := retired
		expected.Retired = false
		if actual == nil || *actual != expected {
			return fmt.Errorf("source binding predecessor changed")
		}
		result, err := tx.Exec(ctx, `UPDATE local_automation_bindings SET retired=1 WHERE stage=? AND cluster_uid=? AND project_uid=? AND owner_id=? AND management_key=? AND creation_generation=? AND retired=0`, stage, retired.ClusterUID, retired.ProjectUID, retired.OwnerID, retired.ManagementKey, retired.Generation)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if count != 1 {
			return fmt.Errorf("source binding not retired")
		}
		effects = effects[1:]
	} else if a.Method != "adopt_resource" || len(effects) != 1 || before.OwnerID != "" || before.ManagementKey != "" || before.BindingGeneration != 0 || a.OwnerID != v.OwnerID || a.ManagementKey != v.ManagementKey {
		return fmt.Errorf("incomplete adoption effects")
	}
	b := effects[0]
	if b.Retired || b.ClusterUID != v.ClusterUID || b.ProjectUID != v.ProjectUID || b.OwnerID != v.OwnerID || b.ManagementKey != v.ManagementKey || b.Generation != v.BindingGeneration || b.Revision != v.Revision || b.ResourceUID != v.UID || b.OperationID != a.OperationID {
		return fmt.Errorf("incoherent target binding")
	}
	previous, err := automationLastBindingTx(ctx, tx, stage, b.ClusterUID, b.ProjectUID, b.OwnerID, b.ManagementKey)
	if err != nil {
		return err
	}
	if (previous == nil && b.Generation != 1) || (previous != nil && (!previous.Retired || previous.Generation+1 != b.Generation)) {
		return fmt.Errorf("target binding predecessor changed")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO local_automation_bindings(stage,cluster_uid,project_uid,owner_id,management_key,creation_generation,resource_uid,operation_id,revision,retired) VALUES(?,?,?,?,?,?,?,?,?,0)`, stage, b.ClusterUID, b.ProjectUID, b.OwnerID, b.ManagementKey, b.Generation, b.ResourceUID, b.OperationID, b.Revision); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `UPDATE local_automation_resources SET owner_id=?,management_key=?,binding_generation=?,revision=?,last_operation_id=?,applied_sequence=? WHERE stage=? AND uid=? AND revision=? AND applied_sequence=?`, v.OwnerID, v.ManagementKey, v.BindingGeneration, v.Revision, v.LastOperationID, v.AppliedSequence, stage, v.UID, before.Revision, before.AppliedSequence)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("resource ownership did not advance")
	}
	_, err = tx.Exec(ctx, `INSERT INTO local_automation_admissions(stage,operation_id,cluster_uid,project_uid,owner_id,management_key,resource_uid,request_id,principal_uid,method,payload_id,binding_generation,admitted_generation,sequence,configuration_json) VALUES(?,?,?,?,?,?,?,?,?,?,?, ?,?,?,?)`, stage, a.OperationID, a.ClusterUID, a.ProjectUID, a.OwnerID, a.ManagementKey, a.ResourceUID, a.RequestID, a.PrincipalUID, a.Method, "", a.BindingGeneration, a.AdmittedGeneration, a.Sequence, "null")
	return err
}
