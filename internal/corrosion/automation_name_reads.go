package corrosion

import (
	"context"
	"math"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/safename"
)

type AutomationNameState uint8

const (
	AutomationNameUnavailable AutomationNameState = iota
	AutomationNamePresent
	AutomationNameAbsent
)

type AutomationNameRecord struct {
	Name       contract.NameRecord
	Resource   contract.ResourceRecord
	VMIdentity contract.IdentityRecord
	Project    contract.IdentityRecord
	Owner      *contract.OwnerRecord
	Binding    *contract.BindingRecord
}

type AutomationNameObservation struct {
	State  AutomationNameState
	Prefix AutomationPrefix
	Name   string
	Record *AutomationNameRecord
}

// AutomationObserveName reads one active projection snapshot. Even a complete
// absence is only a certified namespace observation, never effect authority.
func (c *Client) AutomationObserveName(ctx context.Context, cluster, name string, barrier uint64) (AutomationNameObservation, error) {
	if !automationReadString(cluster, false) || !automationReadString(name, false) || safename.ValidateVMName(name) != nil || barrier == 0 || barrier > math.MaxInt64 {
		return AutomationNameObservation{}, automationReadError(contract.CodeValidation)
	}
	var result AutomationNameObservation
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		var err error
		result, err = automationObserveNameTx(ctx, tx, cluster, name, barrier)
		return err
	})
	if err != nil {
		// ExecuteLocal may fail after the callback, including at commit.
		return AutomationNameObservation{}, err
	}
	return result, nil
}

func automationObserveNameTx(ctx context.Context, tx *LocalTx, cluster, name string, barrier uint64) (AutomationNameObservation, error) {
	unavailable := automationReadError(contract.CodeUnavailable)
	head, err := automationReadFrontierTx(ctx, tx, cluster, barrier)
	if err != nil {
		return AutomationNameObservation{}, err
	}
	// Do not materialize an unchecked UID merely to find the scalar probe's
	// scope. This query returns only counts; scalar validation follows first.
	rows, err := tx.Query(ctx, `SELECT count(*) AS n FROM local_automation_names WHERE stage='' AND name=?`, name)
	if err != nil {
		return AutomationNameObservation{}, err
	}
	if len(rows) != 1 || rows[0].Int64("n") > 1 {
		return AutomationNameObservation{}, unavailable
	}
	// Probe the fixed scalar inventory before materialization. Bindings and
	// admissions have no recoverable name once resource and identity disappear.
	if err := automationNameScalarsTx(ctx, tx); err != nil {
		return AutomationNameObservation{}, err
	}
	n, err := automationNameRecordTx(ctx, tx, "", cluster, name)
	if err != nil {
		return AutomationNameObservation{}, err
	}
	if n == nil {
		if rows[0].Int64("n") != 0 {
			return AutomationNameObservation{}, unavailable
		}
		if err := automationNameAbsentClosureTx(ctx, tx, cluster, name); err != nil {
			return AutomationNameObservation{}, err
		}
		return AutomationNameObservation{State: AutomationNameAbsent, Prefix: head, Name: name}, nil
	}
	r, err := automationNameResourceTx(ctx, tx, head, n.ResourceUID, name)
	if err != nil {
		return AutomationNameObservation{}, err
	}
	identity, err := automationNameIdentityTx(ctx, tx, cluster, "vm", r.UID)
	if err != nil {
		return AutomationNameObservation{}, err
	}
	if identity.ProjectUID != r.ProjectUID || identity.Alias != name || identity.Generation != n.Generation || identity.Retired != r.Retired {
		return AutomationNameObservation{}, unavailable
	}
	if err := automationNameAliasTx(ctx, tx, *identity); err != nil {
		return AutomationNameObservation{}, err
	}
	project, err := automationNameIdentityTx(ctx, tx, cluster, "project", r.ProjectUID)
	if err != nil {
		return AutomationNameObservation{}, err
	}
	if project.ProjectUID != "" || (!r.Retired && project.Retired) {
		return AutomationNameObservation{}, unavailable
	}
	if err := automationNameAliasTx(ctx, tx, *project); err != nil {
		return AutomationNameObservation{}, err
	}
	// No genuine retirement producer exists in this version. A synthetic
	// retirement operation must not be promoted into completed provenance.
	if r.Retired || n.Disposition == "reusable" || n.RetirementOperationID != "" {
		return AutomationNameObservation{}, unavailable
	}
	if err := automationNameCandidatesTx(ctx, tx, head, *n, *r); err != nil {
		return AutomationNameObservation{}, err
	}
	result := &AutomationNameRecord{Name: *n, Resource: *r, VMIdentity: *identity, Project: *project}
	if r.OwnerID == "" && r.OriginalOperationID != "" {
		if err := automationNameOrdinaryOriginTx(ctx, tx, head, *r, *n, *identity); err != nil {
			return AutomationNameObservation{}, unavailable
		}
		refs, err := tx.Query(ctx, `SELECT EXISTS(SELECT 1 FROM local_automation_bindings WHERE stage='' AND resource_uid=?) OR EXISTS(SELECT 1 FROM local_automation_admissions WHERE stage='' AND resource_uid=?) AS bad`, r.UID, r.UID)
		if err != nil {
			return AutomationNameObservation{}, err
		}
		if len(refs) != 1 || refs[0].Int64("bad") != 0 {
			return AutomationNameObservation{}, unavailable
		}
	} else if r.OwnerID == "" {
		if r.OriginalOperationID != "" || n.Disposition != "live" {
			return AutomationNameObservation{}, unavailable
		}
		refs, err := tx.Query(ctx, `SELECT EXISTS(SELECT 1 FROM local_automation_bindings WHERE stage='' AND resource_uid=? AND retired=0) OR EXISTS(SELECT 1 FROM local_automation_admissions WHERE stage='' AND resource_uid=?) AS bad`, r.UID, r.UID)
		if err != nil {
			return AutomationNameObservation{}, err
		}
		if len(refs) != 1 || refs[0].Int64("bad") != 0 {
			return AutomationNameObservation{}, unavailable
		}
		d, a, err := automationNameOperationTx(ctx, tx, head, r.LastOperationID, r.AppliedSequence)
		if err != nil {
			return AutomationNameObservation{}, err
		}
		if d.Command.Kind != "assign_identity" || d.Command.ProjectUID != r.ProjectUID || a.Identity == nil || a.Identity.UID != r.UID || a.Identity.Enrollment == nil || a.Identity.Enrollment.VM == nil {
			return AutomationNameObservation{}, unavailable
		}
		f := a.Identity.Enrollment
		vm := f.VM
		if f.Alias != name || f.Witness != identity.Witness || f.Kind != "vm" || f.ClusterUID != cluster || f.ProjectUID != r.ProjectUID || a.Identity.Generation != identity.Generation || vm.DomainUUID != r.DomainUUID || vm.Incarnation != r.Incarnation || vm.Revision != r.Revision {
			return AutomationNameObservation{}, unavailable
		}
	} else {
		owner, err := automationNameOwnerTx(ctx, tx, cluster, r.ProjectUID, r.OwnerID)
		if err != nil {
			return AutomationNameObservation{}, err
		}
		binding, err := automationNameBindingTx(ctx, tx, cluster, r.ProjectUID, r.OwnerID, r.ManagementKey, r.BindingGeneration)
		if err != nil {
			return AutomationNameObservation{}, err
		}
		if binding.ResourceUID != r.UID || binding.Retired || binding.Revision != r.Revision || binding.OperationID != r.LastOperationID {
			return AutomationNameObservation{}, unavailable
		}
		refs, err := tx.Query(ctx, `SELECT count(*) AS n FROM local_automation_bindings WHERE stage='' AND resource_uid=? AND retired=0`, r.UID)
		if err != nil {
			return AutomationNameObservation{}, err
		}
		if len(refs) != 1 || refs[0].Int64("n") != 1 {
			return AutomationNameObservation{}, unavailable
		}
		latest, err := tx.Query(ctx, `SELECT EXISTS(SELECT 1 FROM local_automation_bindings WHERE stage='' AND cluster_uid=? AND project_uid=? AND owner_id=? AND management_key=? AND creation_generation>?) AS bad`, cluster, r.ProjectUID, r.OwnerID, r.ManagementKey, r.BindingGeneration)
		if err != nil {
			return AutomationNameObservation{}, err
		}
		if len(latest) != 1 || latest[0].Int64("bad") != 0 {
			return AutomationNameObservation{}, unavailable
		}
		if err := automationNameAdmissionTx(ctx, tx, head, *r, *binding, true); err != nil {
			return AutomationNameObservation{}, err
		}
		// Each retained source binding has its own operation and owner. A
		// transfer-back must not compare that older generation to the latest.
		cursor := int64(math.MinInt64)
		comparison := ">="
		for {
			bindings, err := tx.Query(ctx, `SELECT rowid AS cursor,cluster_uid,project_uid,owner_id,management_key,creation_generation FROM local_automation_bindings WHERE stage='' AND resource_uid=? AND rowid`+comparison+`? ORDER BY rowid LIMIT 64`, r.UID, cursor)
			comparison = ">"
			if err != nil {
				return AutomationNameObservation{}, err
			}
			for _, row := range bindings {
				cursor = row.Int64("cursor")
				if row.String("cluster_uid") != cluster || row.String("project_uid") != r.ProjectUID {
					return AutomationNameObservation{}, unavailable
				}
				b, err := automationNameBindingTx(ctx, tx, cluster, r.ProjectUID, row.String("owner_id"), row.String("management_key"), uint64(row.Int64("creation_generation")))
				if err != nil {
					return AutomationNameObservation{}, err
				}
				if err := automationNameAdmissionTx(ctx, tx, head, *r, *b, false); err != nil {
					return AutomationNameObservation{}, err
				}
			}
			if len(bindings) < 64 {
				break
			}
		}
		if r.OriginalOperationID != "" {
			target, err := automationTargetOperationRecordTx(ctx, tx, "", r.ClusterUID, r.OriginalOperationID)
			if err != nil {
				return AutomationNameObservation{}, err
			}
			if target != nil {
				if err := automationNameOrdinaryOriginTx(ctx, tx, head, *r, *n, *identity); err != nil {
					return AutomationNameObservation{}, unavailable
				}
			} else {
				original, err := tx.Query(ctx, `SELECT owner_id,management_key,creation_generation FROM local_automation_bindings WHERE stage='' AND resource_uid=? AND operation_id=? LIMIT 2`, r.UID, r.OriginalOperationID)
				if err != nil {
					return AutomationNameObservation{}, err
				}
				if len(original) != 1 {
					return AutomationNameObservation{}, unavailable
				}
				b, err := automationNameBindingTx(ctx, tx, cluster, r.ProjectUID, original[0].String("owner_id"), original[0].String("management_key"), uint64(original[0].Int64("creation_generation")))
				if err != nil {
					return AutomationNameObservation{}, err
				}
				if err := automationNameAdmissionTx(ctx, tx, head, *r, *b, false); err != nil {
					return AutomationNameObservation{}, err
				}
			}
		}
		result.Owner, result.Binding = owner, binding
	}
	return AutomationNameObservation{State: AutomationNamePresent, Prefix: head, Name: name, Record: result}, nil
}

// This is the finite scalar inventory of this reader, not a storage abstraction
// or history decoder. SQL rejects types and per-field sizes before any text is
// materialized. Paging then validates UTF-8/NUL with fixed memory. Work can scan
// the projection and is bounded by caller cancellation, not a latency promise.
func automationNameScalarsTx(ctx context.Context, tx *LocalTx) error {
	checks := []struct{ table, text, integer string }{
		{"local_automation_names", "cluster_uid,name,resource_uid,disposition,retirement_operation_id", "typeof(generation)='integer' AND generation>0"},
		{"local_automation_resources", "uid,cluster_uid,project_uid,name,domain_uuid,incarnation,owner_id,management_key,revision,last_operation_id,original_operation_id", "typeof(binding_generation)='integer' AND binding_generation>=0 AND typeof(retired)='integer' AND retired IN (0,1) AND typeof(applied_sequence)='integer' AND applied_sequence>0"},
		{"local_automation_identities", "uid,cluster_uid,project_uid,kind,alias,witness", "kind IN ('project','principal','vm','pool','network','image','host') AND typeof(generation)='integer' AND generation>0 AND typeof(retired)='integer' AND retired IN (0,1)"},
		{"local_automation_aliases", "cluster_uid,project_scope,kind,alias,uid", "kind IN ('project','principal','vm','pool','network','image','host') AND typeof(generation)='integer' AND generation>0"},
		{"local_automation_owners", "cluster_uid,project_uid,owner_id,founder_principal_uid,session_id,session_principal_uid", "typeof(activation)='integer' AND activation>=0"},
		{"local_automation_bindings", "cluster_uid,project_uid,owner_id,management_key,resource_uid,operation_id,revision", "typeof(creation_generation)='integer' AND creation_generation>0 AND typeof(retired)='integer' AND retired IN (0,1)"},
		{"local_automation_admissions", "operation_id,cluster_uid,project_uid,owner_id,management_key,resource_uid,request_id,principal_uid,method,payload_id", "typeof(binding_generation)='integer' AND binding_generation>0 AND typeof(admitted_generation)='integer' AND admitted_generation>0 AND typeof(sequence)='integer' AND sequence>0 AND typeof(configuration_json)='text' AND length(CAST(configuration_json AS BLOB))<=1048576"},
	}
	optional := map[string]map[string]bool{
		"local_automation_names":      {"retirement_operation_id": true},
		"local_automation_resources":  {"owner_id": true, "management_key": true, "original_operation_id": true},
		"local_automation_identities": {"project_uid": true},
		"local_automation_aliases":    {"project_scope": true},
		"local_automation_owners":     {"session_id": true, "session_principal_uid": true},
		"local_automation_admissions": {"payload_id": true},
	}
	for _, check := range checks {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Every identifier here is a literal in the fixed inventory above.
		predicate := check.integer
		columns := strings.Split(check.text, ",")
		for _, col := range columns {
			predicate += " AND typeof(" + col + ")='text' AND length(CAST(" + col + " AS BLOB))<=4096"
		}
		rows, err := tx.Query(ctx, "SELECT EXISTS(SELECT 1 FROM "+check.table+" WHERE stage='' AND NOT ("+predicate+")) AS bad")
		if err != nil {
			return err
		}
		if len(rows) != 1 || rows[0].Int64("bad") != 0 {
			return automationReadError(contract.CodeUnavailable)
		}
		cursor := int64(math.MinInt64)
		comparison := ">="
		for {
			rows, err := tx.Query(ctx, "SELECT rowid AS cursor,"+check.text+" FROM "+check.table+" WHERE stage='' AND rowid"+comparison+"? ORDER BY rowid LIMIT 64", cursor)
			comparison = ">"
			if err != nil {
				return err
			}
			for _, row := range rows {
				for _, col := range columns {
					if !automationReadString(row.String(col), optional[check.table][col]) {
						return automationReadError(contract.CodeUnavailable)
					}
				}
				cursor = row.Int64("cursor")
			}
			if len(rows) < 64 {
				break
			}
		}
	}
	return nil
}

func automationNameIdentityTx(ctx context.Context, tx *LocalTx, cluster, kind, uid string) (*contract.IdentityRecord, error) {
	r, err := automationIdentityRecordTx(ctx, tx, "", uid)
	if err != nil {
		return nil, err
	}
	if r == nil || r.ClusterUID != cluster || r.Kind != kind || !automationReadString(r.UID, false) || !automationReadString(r.Alias, false) || !automationReadString(r.Witness, false) || (kind != "vm" && r.ProjectUID != "") {
		return nil, automationReadError(contract.CodeUnavailable)
	}
	return r, nil
}

func automationNameAliasTx(ctx context.Context, tx *LocalTx, r contract.IdentityRecord) error {
	rows, err := tx.Query(ctx, `SELECT cluster_uid,project_scope,kind,alias,uid,generation FROM local_automation_aliases WHERE stage='' AND kind=? AND alias=? LIMIT 2`, r.Kind, r.Alias)
	if err != nil {
		return err
	}
	if len(rows) != 1 || rows[0].String("cluster_uid") != r.ClusterUID || rows[0].String("project_scope") != "" || rows[0].String("uid") != r.UID || uint64(rows[0].Int64("generation")) != r.Generation {
		return automationReadError(contract.CodeUnavailable)
	}
	return nil
}

func automationNameOwnerTx(ctx context.Context, tx *LocalTx, cluster, project, owner string) (*contract.OwnerRecord, error) {
	r, err := automationOwnerRecordTx(ctx, tx, "", cluster, project, owner)
	if err != nil {
		return nil, err
	}
	if r == nil || !automationReadString(r.FounderPrincipalUID, false) {
		return nil, automationReadError(contract.CodeUnavailable)
	}
	for _, uid := range []string{r.FounderPrincipalUID, r.SessionPrincipalUID} {
		if uid == "" && r.Activation == 0 {
			continue
		}
		if _, err := automationNameIdentityTx(ctx, tx, cluster, "principal", uid); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func automationNameResourceTx(ctx context.Context, tx *LocalTx, head AutomationPrefix, uid, name string) (*contract.ResourceRecord, error) {
	r, err := automationResourceRecordTx(ctx, tx, "", uid)
	if err != nil {
		return nil, err
	}
	if r == nil || r.ClusterUID != head.ClusterUID || r.Name != name || r.AppliedSequence > head.Sequence || !automationReadString(r.LastOperationID, false) {
		return nil, automationReadError(contract.CodeUnavailable)
	}
	return r, nil
}

func automationNameBindingTx(ctx context.Context, tx *LocalTx, cluster, project, owner, key string, generation uint64) (*contract.BindingRecord, error) {
	rows, err := tx.Query(ctx, `SELECT resource_uid,operation_id,revision,retired FROM local_automation_bindings WHERE stage='' AND cluster_uid=? AND project_uid=? AND owner_id=? AND management_key=? AND creation_generation=?`, cluster, project, owner, key, generation)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 || !automationReadString(rows[0].String("resource_uid"), false) || !automationReadString(rows[0].String("operation_id"), false) || !automationReadString(rows[0].String("revision"), false) {
		return nil, automationReadError(contract.CodeUnavailable)
	}
	row := rows[0]
	return &contract.BindingRecord{ClusterUID: cluster, ProjectUID: project, OwnerID: owner, ManagementKey: key, Generation: generation, ResourceUID: row.String("resource_uid"), OperationID: row.String("operation_id"), Revision: row.String("revision"), Retired: row.Int64("retired") == 1}, nil
}

// Resolve only the exact relevant retained operation, with the existing bounded
// canonical history decoder and trusted digest owner. No general history scan.
func automationNameOperationTx(ctx context.Context, tx *LocalTx, head AutomationPrefix, operation string, sequence uint64) (contract.Decision, contract.Assignment, error) {
	bad := automationReadError(contract.CodeUnavailable)
	if !automationReadString(operation, false) || sequence == 0 || sequence > head.Sequence {
		return contract.Decision{}, contract.Assignment{}, bad
	}
	summary, found, err := automationTrustedSummaryTx(ctx, tx, sequence)
	if err != nil {
		return contract.Decision{}, contract.Assignment{}, err
	}
	if !found || summary.ClusterUID != head.ClusterUID {
		return contract.Decision{}, contract.Assignment{}, bad
	}
	rows, err := tx.Query(ctx, `SELECT value_json FROM local_automation_history WHERE sequence=? AND typeof(value_json)='text' AND length(CAST(value_json AS BLOB))<=?`, sequence, MaxAutomationClaimBytes)
	if err != nil {
		return contract.Decision{}, contract.Assignment{}, err
	}
	if len(rows) != 1 {
		return contract.Decision{}, contract.Assignment{}, bad
	}
	var value ClaimValue
	key, _ := AutomationClaimKey(sequence)
	if err := decodeClaimValue(key, rows[0].String("value_json"), &value); err != nil {
		return contract.Decision{}, contract.Assignment{}, err
	}
	if value.Automation == nil || value.MustDigest() != summary.Digest {
		return contract.Decision{}, contract.Assignment{}, bad
	}
	d, err := contract.DecodeDecision(value.Automation.Envelope)
	if err != nil {
		return contract.Decision{}, contract.Assignment{}, err
	}
	a, err := contract.DecodeAssignment(d)
	if err != nil {
		return contract.Decision{}, contract.Assignment{}, err
	}
	if a.OperationID != operation || d.Sequence != sequence || d.Command.ClusterUID != head.ClusterUID {
		return contract.Decision{}, contract.Assignment{}, bad
	}
	return d, a, nil
}

func automationNameAdmissionTx(ctx context.Context, tx *LocalTx, head AutomationPrefix, r contract.ResourceRecord, b contract.BindingRecord, current bool) error {
	bad := automationReadError(contract.CodeUnavailable)
	config, err := tx.Query(ctx, `SELECT configuration_json FROM local_automation_admissions WHERE stage='' AND operation_id=?`, b.OperationID)
	if err != nil {
		return err
	}
	if len(config) != 1 || !utf8.ValidString(config[0].String("configuration_json")) || strings.IndexByte(config[0].String("configuration_json"), 0) >= 0 {
		return bad
	}
	a, err := automationAdmissionRecordTx(ctx, tx, "", b.OperationID)
	if err != nil {
		return err
	}
	if a == nil || a.ClusterUID != r.ClusterUID || a.ProjectUID != r.ProjectUID || a.ResourceUID != r.UID || a.BindingGeneration != b.Generation || (current && (a.Sequence != r.AppliedSequence || a.OperationID != r.LastOperationID)) {
		return bad
	}
	d, assigned, err := automationNameOperationTx(ctx, tx, head, a.OperationID, a.Sequence)
	if err != nil {
		return err
	}
	c := d.Command
	if c.Kind != a.Method || c.ProjectUID != a.ProjectUID || c.OwnerID != a.OwnerID || c.ManagementKey != a.ManagementKey || c.RequestID != a.RequestID || c.PrincipalID != a.PrincipalUID {
		return bad
	}
	if _, err := automationNameOwnerTx(ctx, tx, r.ClusterUID, r.ProjectUID, a.OwnerID); err != nil {
		return err
	}
	if a.Method == "admit_create" {
		v := assigned.Binding
		if v == nil || a.PinnedConfiguration == nil || a.PinnedConfiguration.Name != r.Name || !reflect.DeepEqual(*a.PinnedConfiguration, v.Configuration) || v.ResourceUID != r.UID || v.DomainUUID != r.DomainUUID || v.Incarnation != r.Incarnation || v.Revision != b.Revision || v.BindingGeneration != b.Generation || v.AdmittedGeneration != a.AdmittedGeneration || v.PayloadID != a.PayloadID || c.OwnerID != b.OwnerID || c.ManagementKey != b.ManagementKey || a.OperationID != r.OriginalOperationID {
			return bad
		}
		i, err := automationNameIdentityTx(ctx, tx, r.ClusterUID, "vm", r.UID)
		if err != nil {
			return err
		}
		if i.Generation != v.NameGeneration || i.Witness != v.Incarnation {
			return bad
		}
		return nil
	}
	if !current && a.OperationID == r.OriginalOperationID {
		return bad
	}
	body, err := contract.DecodeOwnershipBody(c)
	if err != nil {
		return err
	}
	v := assigned.Ownership
	if v == nil || body.Resource.UID != r.UID || body.Resource.ProjectUID != r.ProjectUID || body.Resource.ClusterUID != r.ClusterUID || body.Target.OwnerID != b.OwnerID || body.Target.ManagementKey != b.ManagementKey || body.Target.ProjectUID != r.ProjectUID || body.Target.ClusterUID != r.ClusterUID || v.TargetGeneration != b.Generation || v.Revision != b.Revision || v.AdmittedGeneration != a.AdmittedGeneration || c.ResourceUID != r.UID || a.PayloadID != "" || v.Quiescence.Incarnation != r.Incarnation {
		return bad
	}
	if a.Method == "adopt_resource" {
		if body.Source != nil || a.OwnerID != b.OwnerID || a.ManagementKey != b.ManagementKey {
			return bad
		}
		return nil
	}
	if a.Method != "transfer_owner" || body.Source == nil {
		return bad
	}
	source := body.Source
	if source.Key.ClusterUID != r.ClusterUID || source.Key.ProjectUID != r.ProjectUID || source.Key.OwnerID != a.OwnerID || source.Key.ManagementKey != a.ManagementKey || source.Generation != c.Generation {
		return bad
	}
	old, err := automationNameBindingTx(ctx, tx, r.ClusterUID, r.ProjectUID, source.Key.OwnerID, source.Key.ManagementKey, source.Generation)
	if err != nil {
		return err
	}
	if !old.Retired || old.ResourceUID != r.UID || old.Revision != body.ExpectedRevision || old.OperationID == b.OperationID {
		return bad
	}
	// The source binding can be an older generation of the current target
	// owner/key after transfer-back. Its own operation/revision stay historical.
	return nil
}

func automationNameCandidatesTx(ctx context.Context, tx *LocalTx, head AutomationPrefix, n contract.NameRecord, current contract.ResourceRecord) error {
	if err := automationNameTargetClosureTx(ctx, tx, head, n.Name); err != nil {
		return automationReadError(contract.CodeUnavailable)
	}
	bad := automationReadError(contract.CodeUnavailable)
	cursor := int64(math.MinInt64)
	comparison := ">="
	for {
		rows, err := tx.Query(ctx, `SELECT r.rowid AS cursor,r.uid,r.incarnation,r.retired,i.generation,i.retired AS identity_retired,i.cluster_uid,i.project_uid,i.kind,i.alias FROM local_automation_resources r LEFT JOIN local_automation_identities i ON i.stage=r.stage AND i.uid=r.uid WHERE r.stage='' AND r.name=? AND r.uid<>? AND r.rowid`+comparison+`? ORDER BY r.rowid LIMIT 64`, n.Name, current.UID, cursor)
		comparison = ">"
		if err != nil {
			return err
		}
		for _, row := range rows {
			cursor = row.Int64("cursor")
			if row.Int64("retired") != 1 || row.Int64("identity_retired") != 1 || row.Int64("generation") <= 0 || uint64(row.Int64("generation")) >= n.Generation || row.String("cluster_uid") != head.ClusterUID || row.String("kind") != "vm" || row.String("alias") != n.Name || row.String("incarnation") == current.Incarnation {
				return bad
			}
			old, err := automationNameResourceTx(ctx, tx, head, row.String("uid"), n.Name)
			if err != nil {
				return err
			}
			if old.ProjectUID != row.String("project_uid") {
				return bad
			}
			project, err := automationNameIdentityTx(ctx, tx, head.ClusterUID, "project", old.ProjectUID)
			if err != nil {
				return err
			}
			// The old lifetime may be retired, but its certified identity remains.
			// Its alias may now select a newer project lifetime.
			if project.ProjectUID != "" {
				return bad
			}

			refs, err := tx.Query(ctx, `SELECT EXISTS(SELECT 1 FROM local_automation_bindings WHERE stage='' AND resource_uid=? AND retired=0) OR EXISTS(SELECT 1 FROM local_automation_names WHERE stage='' AND resource_uid=?) OR EXISTS(SELECT 1 FROM local_automation_aliases WHERE stage='' AND kind='vm' AND uid=?) AS bad`, old.UID, old.UID, old.UID)
			if err != nil {
				return err
			}
			if len(refs) != 1 || refs[0].Int64("bad") != 0 {
				return bad
			}
			if old.OwnerID != "" {
				b, err := automationNameBindingTx(ctx, tx, old.ClusterUID, old.ProjectUID, old.OwnerID, old.ManagementKey, old.BindingGeneration)
				if err != nil {
					return err
				}
				if !b.Retired || b.ResourceUID != old.UID || b.Revision != old.Revision || b.OperationID != old.LastOperationID {
					return bad
				}
				if err := automationNameAdmissionTx(ctx, tx, head, *old, *b, true); err != nil {
					return err
				}
			}
		}
		if len(rows) < 64 {
			break
		}
	}
	refs, err := tx.Query(ctx, `SELECT EXISTS(SELECT 1 FROM local_automation_identities i WHERE i.stage='' AND i.kind='vm' AND i.alias=? AND NOT EXISTS(SELECT 1 FROM local_automation_resources r WHERE r.stage=i.stage AND r.uid=i.uid AND r.name=i.alias AND r.cluster_uid=i.cluster_uid AND r.project_uid=i.project_uid AND r.retired=i.retired)) OR EXISTS(SELECT 1 FROM local_automation_aliases WHERE stage='' AND kind='vm' AND uid=? AND (alias<>? OR project_scope<>'' OR cluster_uid<>?)) AS bad`, n.Name, current.UID, n.Name, head.ClusterUID)
	if err != nil {
		return err
	}
	if len(refs) != 1 || refs[0].Int64("bad") != 0 {
		return bad
	}
	inverse, err := tx.Query(ctx, `SELECT EXISTS(SELECT 1 FROM local_automation_names WHERE stage='' AND resource_uid=? AND (cluster_uid<>? OR name<>? OR generation<>?)) AS bad`, current.UID, head.ClusterUID, n.Name, n.Generation)
	if err != nil {
		return err
	}
	if len(inverse) != 1 || inverse[0].Int64("bad") != 0 {
		return bad
	}
	return nil
}

func automationNameAbsentClosureTx(ctx context.Context, tx *LocalTx, cluster, name string) error {
	head, err := automationSemanticHeadTx(ctx, tx, "")
	if err != nil {
		return err
	}
	if head.ClusterUID != cluster {
		return automationReadError(contract.CodeUnavailable)
	}
	if err := automationNameTargetClosureTx(ctx, tx, head, name); err != nil {
		return automationReadError(contract.CodeUnavailable)
	}
	// Fixed anti-joins cover missing counterparts before any configuration or
	// historical envelope could be considered. Unrelated coherent graphs pass.
	queries := []string{
		`SELECT EXISTS(SELECT 1 FROM local_automation_resources WHERE stage='' AND name=?) OR EXISTS(SELECT 1 FROM local_automation_identities WHERE stage='' AND kind='vm' AND alias=?) OR EXISTS(SELECT 1 FROM local_automation_aliases WHERE stage='' AND kind='vm' AND alias=?) AS bad`,
		`SELECT EXISTS(SELECT 1 FROM local_automation_names n WHERE n.stage='' AND (n.cluster_uid<>? OR n.name='' OR n.resource_uid='' OR NOT EXISTS(SELECT 1 FROM local_automation_resources r JOIN local_automation_identities i ON i.stage=r.stage AND i.uid=r.uid WHERE r.stage=n.stage AND r.uid=n.resource_uid AND r.cluster_uid=n.cluster_uid AND r.name=n.name AND i.kind='vm' AND i.cluster_uid=r.cluster_uid AND i.project_uid=r.project_uid AND i.alias=n.name AND i.generation=n.generation AND i.retired=r.retired))) AS bad`,
		`SELECT EXISTS(SELECT 1 FROM local_automation_aliases a WHERE a.stage='' AND a.kind='vm' AND (a.cluster_uid<>? OR a.project_scope<>'' OR a.alias='' OR NOT EXISTS(SELECT 1 FROM local_automation_identities i JOIN local_automation_resources r ON r.stage=i.stage AND r.uid=i.uid WHERE i.stage=a.stage AND i.uid=a.uid AND i.kind='vm' AND i.cluster_uid=a.cluster_uid AND i.alias=a.alias AND i.generation=a.generation AND r.name=i.alias AND r.project_uid=i.project_uid AND r.cluster_uid=i.cluster_uid AND r.retired=i.retired))) AS bad`,
		`SELECT EXISTS(SELECT 1 FROM local_automation_resources r WHERE r.stage='' AND (r.cluster_uid<>? OR r.uid='' OR r.name='' OR r.incarnation='' OR r.domain_uuid='' OR r.revision='' OR r.last_operation_id='' OR (r.owner_id='')<>(r.management_key='') OR (r.owner_id='')<>(r.binding_generation=0) OR NOT EXISTS(SELECT 1 FROM local_automation_identities i WHERE i.stage=r.stage AND i.uid=r.uid AND i.kind='vm' AND i.alias=r.name AND i.cluster_uid=r.cluster_uid AND i.project_uid=r.project_uid AND i.retired=r.retired) OR NOT EXISTS(SELECT 1 FROM local_automation_identities p WHERE p.stage=r.stage AND p.uid=r.project_uid AND p.kind='project' AND p.cluster_uid=r.cluster_uid AND p.project_uid=''))) AS bad`,
		`SELECT EXISTS(SELECT 1 FROM local_automation_identities i WHERE i.stage='' AND i.kind='vm' AND (i.cluster_uid<>? OR i.uid='' OR i.alias='' OR i.witness='' OR NOT EXISTS(SELECT 1 FROM local_automation_resources r WHERE r.stage=i.stage AND r.uid=i.uid AND r.name=i.alias AND r.project_uid=i.project_uid AND r.cluster_uid=i.cluster_uid AND r.retired=i.retired))) AS bad`,
		`SELECT EXISTS(SELECT 1 FROM local_automation_bindings b WHERE b.stage='' AND (b.cluster_uid<>? OR b.owner_id='' OR b.management_key='' OR b.resource_uid='' OR b.operation_id='' OR b.revision='' OR NOT EXISTS(SELECT 1 FROM local_automation_resources r WHERE r.stage=b.stage AND r.uid=b.resource_uid AND r.cluster_uid=b.cluster_uid AND r.project_uid=b.project_uid AND (b.retired=1 OR (r.retired=0 AND r.owner_id=b.owner_id AND r.management_key=b.management_key AND r.binding_generation=b.creation_generation AND r.revision=b.revision AND r.last_operation_id=b.operation_id))) OR NOT EXISTS(SELECT 1 FROM local_automation_owners o WHERE o.stage=b.stage AND o.cluster_uid=b.cluster_uid AND o.project_uid=b.project_uid AND o.owner_id=b.owner_id) OR NOT EXISTS(SELECT 1 FROM local_automation_admissions a WHERE a.stage=b.stage AND a.operation_id=b.operation_id AND a.resource_uid=b.resource_uid AND a.project_uid=b.project_uid AND a.cluster_uid=b.cluster_uid AND a.binding_generation=b.creation_generation))) AS bad`,
		`SELECT EXISTS(SELECT 1 FROM local_automation_admissions a WHERE a.stage='' AND (a.cluster_uid<>? OR a.owner_id='' OR a.management_key='' OR a.principal_uid='' OR a.request_id='' OR a.method NOT IN ('admit_create','adopt_resource','transfer_owner') OR NOT EXISTS(SELECT 1 FROM local_automation_resources r WHERE r.stage=a.stage AND r.uid=a.resource_uid AND r.cluster_uid=a.cluster_uid AND r.project_uid=a.project_uid) OR NOT EXISTS(SELECT 1 FROM local_automation_owners o WHERE o.stage=a.stage AND o.cluster_uid=a.cluster_uid AND o.project_uid=a.project_uid AND o.owner_id=a.owner_id) OR NOT EXISTS(SELECT 1 FROM local_automation_identities p WHERE p.stage=a.stage AND p.uid=a.principal_uid AND p.kind='principal' AND p.cluster_uid=a.cluster_uid))) AS bad`,
		`SELECT EXISTS(SELECT 1 FROM local_automation_resources r WHERE r.stage='' AND r.cluster_uid=? AND ((r.retired=0 AND NOT EXISTS(SELECT 1 FROM local_automation_names n JOIN local_automation_aliases a ON a.stage=n.stage AND a.cluster_uid=n.cluster_uid AND a.kind='vm' AND a.project_scope='' AND a.alias=n.name AND a.uid=n.resource_uid AND a.generation=n.generation WHERE n.stage=r.stage AND n.resource_uid=r.uid AND n.name=r.name AND n.cluster_uid=r.cluster_uid)) OR (r.retired=0 AND NOT EXISTS(SELECT 1 FROM local_automation_identities p JOIN local_automation_aliases a ON a.stage=p.stage AND a.uid=p.uid AND a.cluster_uid=p.cluster_uid AND a.kind='project' AND a.project_scope='' AND a.alias=p.alias AND a.generation=p.generation WHERE p.stage=r.stage AND p.uid=r.project_uid AND p.kind='project' AND p.cluster_uid=r.cluster_uid AND p.project_uid='')) OR (r.owner_id<>'' AND NOT EXISTS(SELECT 1 FROM local_automation_bindings b WHERE b.stage=r.stage AND b.resource_uid=r.uid AND b.cluster_uid=r.cluster_uid AND b.project_uid=r.project_uid AND b.owner_id=r.owner_id AND b.management_key=r.management_key AND b.creation_generation=r.binding_generation AND b.revision=r.revision AND b.operation_id=r.last_operation_id AND b.retired=r.retired)))) AS bad`,
		// Follow recorded principal/session facts only for owners referenced by
		// resources, bindings or admissions. Owner-only rows reserve no name.
		`SELECT EXISTS(SELECT 1 FROM local_automation_owners o
          WHERE o.stage='' AND o.cluster_uid=?
          AND (EXISTS(SELECT 1 FROM local_automation_resources r WHERE r.stage=o.stage AND r.cluster_uid=o.cluster_uid AND r.project_uid=o.project_uid AND r.owner_id=o.owner_id)
            OR EXISTS(SELECT 1 FROM local_automation_bindings b WHERE b.stage=o.stage AND b.cluster_uid=o.cluster_uid AND b.project_uid=o.project_uid AND b.owner_id=o.owner_id)
            OR EXISTS(SELECT 1 FROM local_automation_admissions a WHERE a.stage=o.stage AND a.cluster_uid=o.cluster_uid AND a.project_uid=o.project_uid AND a.owner_id=o.owner_id))
          AND ((o.activation=0)<>(o.session_id='')
            OR (o.session_id='')<>(o.session_principal_uid='')
            OR NOT EXISTS(SELECT 1 FROM local_automation_identities p WHERE p.stage=o.stage AND p.uid=o.founder_principal_uid AND p.cluster_uid=o.cluster_uid AND p.project_uid='' AND p.kind='principal')
            OR (o.session_id<>'' AND NOT EXISTS(SELECT 1 FROM local_automation_identities p WHERE p.stage=o.stage AND p.uid=o.session_principal_uid AND p.cluster_uid=o.cluster_uid AND p.project_uid='' AND p.kind='principal')))) AS bad`,
	}
	for i, query := range queries {
		args := []any{cluster}
		if i == 0 {
			args = []any{name, name, name}
		}
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		if len(rows) != 1 || rows[0].Int64("bad") != 0 {
			return automationReadError(contract.CodeUnavailable)
		}
	}
	return nil
}
