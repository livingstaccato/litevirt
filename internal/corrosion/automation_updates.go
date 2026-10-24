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

const automationUpdateIndexSQL = "CREATE INDEX automation_admission_resource_desired ON local_automation_admissions(stage,cluster_uid,resource_uid,sequence DESC,operation_id) WHERE method IN ('admit_create','admit_update')"

// Invalid key rows remain visible as typed/length metadata, but SQLite never
// returns their unbounded TEXT/BLOB cells to the eager LocalTx.Query reader.
const automationUpdateKeyColumns = "typeof(operation_id) AS key_type,length(CAST(operation_id AS BLOB)) AS key_bytes,CASE WHEN typeof(operation_id)='text' AND length(CAST(operation_id AS BLOB)) BETWEEN 1 AND ? THEN operation_id ELSE NULL END AS operation_id"
const automationDesiredLookupSQL = "SELECT " + automationUpdateKeyColumns + ",sequence FROM local_automation_admissions WHERE stage=? AND cluster_uid=? AND resource_uid=? AND method IN ('admit_create','admit_update') AND sequence<=? ORDER BY sequence DESC,local_automation_admissions.operation_id LIMIT 2"

type updateLineage struct {
	facts    contract.UpdateProjection
	resource *contract.ResourceRecord
}

func automationVerifyUpdateIndexesTx(ctx context.Context, tx *LocalTx) error {
	rows, e := tx.Query(ctx, `SELECT name,"unique" AS uq,partial FROM pragma_index_list('local_automation_admissions')`)
	if e != nil {
		return e
	}
	if len(rows) != 3 {
		return fmt.Errorf("update admission index inventory differs")
	}
	found := false
	for _, r := range rows {
		switch r.String("name") {
		case "automation_admission_resource_desired":
			if r.Int64("uq") != 0 || r.Int64("partial") != 1 {
				return fmt.Errorf("update desired index uniqueness/predicate differs")
			}
			found = true
		case "sqlite_autoindex_local_automation_admissions_1", "automation_admission_inventory":
		default:
			return fmt.Errorf("unexpected admission index")
		}
	}
	if !found {
		return fmt.Errorf("update desired index missing")
	}
	return automationVerifyUpdateIndexShapeTx(ctx, tx)
}

// The caller MUST authenticate two-way closure before this derived lookup.
// Select scalar candidates before loading one bounded canonical configuration.
func automationLatestDesiredAdmissionTx(ctx context.Context, tx *LocalTx, stage string, head contract.Prefix, ref contract.ResourceReference) (*contract.AdmissionRecord, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if head.Sequence > math.MaxInt64 {
		return nil, fmt.Errorf("desired frontier overflows")
	}
	if e := automationVerifyUpdateIndexesTx(ctx, tx); e != nil {
		return nil, e
	}
	rows, e := tx.Query(ctx, automationDesiredLookupSQL, contract.MaxStringBytes, stage, ref.ClusterUID, ref.UID, head.Sequence)
	if e != nil {
		return nil, e
	}
	if len(rows) == 0 {
		return nil, nil
	}
	for _, r := range rows {
		if _, e := automationUpdateBoundedKey(r); e != nil {
			return nil, e
		}
		if _, ok := r.get("sequence").(int64); !ok || r.Int64("sequence") <= 0 || r.Int64("sequence") > int64(head.Sequence) {
			return nil, fmt.Errorf("invalid desired candidate")
		}
	}
	if len(rows) == 2 && rows[0].Int64("sequence") == rows[1].Int64("sequence") {
		return nil, fmt.Errorf("duplicate greatest desired sequence")
	}
	a, e := automationAdmissionRecordTx(ctx, tx, stage, rows[0].String("operation_id"))
	if e != nil {
		return nil, e
	}
	if a == nil || a.ClusterUID != ref.ClusterUID || a.ProjectUID != ref.ProjectUID || a.ResourceUID != ref.UID || a.Sequence != uint64(rows[0].Int64("sequence")) || a.PinnedConfiguration == nil {
		return nil, fmt.Errorf("desired candidate scope differs")
	}
	return a, nil
}

func automationUpdateHistoryTx(ctx context.Context, tx *LocalTx, source automationKeyHistorySource, sequence uint64) (automationExecutionHistory, error) {
	if e := ctx.Err(); e != nil {
		return automationExecutionHistory{}, e
	}
	automationObserveKeyBody(ctx, sequence, nil)
	h, e := automationExecutionHistoryReadTx(ctx, tx, source, sequence)
	if e != nil {
		return h, e
	}
	if h.receipt.Sequence < sequence {
		original, e := automationExecutionHistoryReadTx(ctx, tx, source, h.receipt.Sequence)
		if e != nil {
			return h, e
		}
		if original.receipt.Sequence != original.decision.Sequence || original.receipt != h.receipt {
			return h, fmt.Errorf("update retained retry receipt differs")
		}
		first, e := contract.CanonicalCommand(original.decision.Command)
		if e != nil {
			return h, e
		}
		again, e := contract.CanonicalCommand(h.decision.Command)
		if e != nil || !bytes.Equal(first, again) {
			return h, fmt.Errorf("update retained retry request differs")
		}
	}
	return h, nil
}

// Reconstruct stored effects from their immutable accepted original. This is an
// integrity decoder only; contract.Reduce is the sole business evaluator.
func automationUpdateAdmission(h automationExecutionHistory) (*contract.AdmissionRecord, *contract.ResourceRecord, error) {
	c, a, r := h.decision.Command, h.assignment, h.receipt
	if r.Code != "" || r.Sequence != h.decision.Sequence || r.OperationID != a.OperationID || r.RequestID != c.RequestID {
		return nil, nil, fmt.Errorf("not an accepted original mutation")
	}
	out := &contract.AdmissionRecord{ClusterUID: c.ClusterUID, ProjectUID: c.ProjectUID, OwnerID: c.OwnerID, ManagementKey: c.ManagementKey, ResourceUID: c.ResourceUID, OperationID: a.OperationID, RequestID: c.RequestID, PrincipalUID: c.PrincipalID, Method: c.Kind, Sequence: r.Sequence}
	v := &contract.ResourceRecord{AppliedSequence: r.Sequence, ClusterUID: c.ClusterUID, ProjectUID: c.ProjectUID, UID: c.ResourceUID, OwnerID: c.OwnerID, ManagementKey: c.ManagementKey, LastOperationID: a.OperationID}
	expected := contract.Receipt{RequestID: c.RequestID, OperationID: a.OperationID, ResourceUID: c.ResourceUID, Sequence: r.Sequence, State: "accepted"}
	switch c.Kind {
	case contract.OrdinaryCreateCommand:
		target := a.Target
		if target == nil || target.Allocation == nil {
			return nil, nil, fmt.Errorf("ordinary complete desired origin unavailable")
		}
		allocation := target.Allocation
		out.ResourceUID = allocation.ResourceUID
		out.AdmittedGeneration = target.MembershipGeneration
		out.PayloadID = target.PayloadID
		out.PinnedConfiguration = &target.Configuration
		v.UID = allocation.ResourceUID
		v.Name = target.Configuration.Name
		v.DomainUUID = allocation.DomainUUID
		v.Incarnation = allocation.Incarnation
		v.OriginalOperationID = a.OperationID
		v.Revision = allocation.Revision
	case "admit_create":
		b := a.Binding
		if b == nil {
			return nil, nil, fmt.Errorf("missing original create")
		}
		out.ResourceUID = b.ResourceUID
		out.BindingGeneration = b.BindingGeneration
		out.AdmittedGeneration = b.AdmittedGeneration
		out.PayloadID = b.PayloadID
		out.PinnedConfiguration = &b.Configuration
		v.UID = b.ResourceUID
		v.Name = b.Configuration.Name
		v.DomainUUID = b.DomainUUID
		v.Incarnation = b.Incarnation
		v.OriginalOperationID = a.OperationID
		v.BindingGeneration = b.BindingGeneration
		v.Revision = b.Revision
	case "admit_update":
		b := a.Update
		if b == nil {
			return nil, nil, fmt.Errorf("missing original update")
		}
		out.BindingGeneration = c.Generation
		out.AdmittedGeneration = b.AdmittedGeneration
		out.PayloadID = b.PayloadID
		out.PinnedConfiguration = &b.Configuration
		v.BindingGeneration = c.Generation
		v.Revision = b.Revision
	case "adopt_resource", "transfer_owner":
		b, e := contract.DecodeOwnershipBody(c)
		if e != nil {
			return nil, nil, e
		}
		o := a.Ownership
		if o == nil {
			return nil, nil, fmt.Errorf("missing original ownership")
		}
		out.BindingGeneration = o.TargetGeneration
		out.AdmittedGeneration = o.AdmittedGeneration
		v.OwnerID = b.Target.OwnerID
		v.ManagementKey = b.Target.ManagementKey
		v.BindingGeneration = o.TargetGeneration
		v.Revision = o.Revision
		expected.State = "succeeded"
	default:
		return nil, nil, fmt.Errorf("unsupported admission method")
	}
	expected.ResourceUID = v.UID
	expected.Generation = v.BindingGeneration
	expected.ResourceRevision = v.Revision
	if r != expected {
		return nil, nil, fmt.Errorf("update original accepted receipt differs")
	}
	return out, v, nil
}

// This traversal is linear in the authenticated prefix and reverse admission
// rows. Memory remains one bounded frame, bounded lineage and <=64 scalar rows.
// A desired index cannot substitute for history-to-row completeness.
func automationUpdateInverseClosureTx(ctx context.Context, tx *LocalTx, stage string, head contract.Prefix, ref contract.ResourceReference, source automationKeyHistorySource) (updateLineage, error) {
	var out updateLineage
	if e := ctx.Err(); e != nil {
		return out, e
	}
	if head.Sequence == 0 || head.Sequence > math.MaxInt64 || ref.ClusterUID != head.ClusterUID || ref.ProjectUID == "" || ref.Kind != "vm" || ref.UID == "" {
		return out, fmt.Errorf("invalid update scope/frontier")
	}
	actual, e := automationSemanticHeadTx(ctx, tx, stage)
	if e != nil {
		return out, e
	}
	if actual != head {
		return out, fmt.Errorf("update semantic predecessor differs")
	}
	switch source.(type) {
	case nil:
		source = localAutomationKeySource{tx}
	case localAutomationKeySource, receiverAutomationKeySource:
	default:
		return out, fmt.Errorf("unsupported update history owner")
	}
	if e = automationVerifyUpdateIndexesTx(ctx, tx); e != nil {
		return out, e
	}
	running := contract.Prefix{}
	for window := uint64(1); window <= head.Sequence; {
		if e = ctx.Err(); e != nil {
			return out, e
		}
		end := min(window+63, head.Sequence)
		for sequence := window; sequence <= end; sequence++ {
			if e = ctx.Err(); e != nil {
				return out, e
			}
			h, e := automationUpdateHistoryTx(ctx, tx, source, sequence)
			if e != nil {
				return out, e
			}
			if h.decision.ParentDigest != running.Digest || h.decision.Sequence != sequence || (sequence > 1 && h.decision.Command.ClusterUID != head.ClusterUID) || (sequence == 1 && h.assignment.ClusterUID != head.ClusterUID) {
				return out, fmt.Errorf("update history predecessor continuity differs")
			}
			running = contract.Prefix{ClusterUID: head.ClusterUID, Sequence: sequence, Digest: h.value.MustDigest()}
			c := h.decision.Command
			if h.receipt.Code != "" || h.receipt.Sequence != sequence {
				continue
			}
			relevant := c.ResourceUID == ref.UID
			if c.Kind == "admit_create" && h.assignment.Binding != nil {
				relevant = h.assignment.Binding.ResourceUID == ref.UID
			}
			if c.Kind == contract.OrdinaryCreateCommand && h.assignment.Target != nil && h.assignment.Target.Allocation != nil {
				relevant = h.assignment.Target.Allocation.ResourceUID == ref.UID
			}
			if !relevant {
				continue
			}
			if c.Kind != contract.OrdinaryCreateCommand && c.Kind != "admit_create" && c.Kind != "admit_update" && c.Kind != "adopt_resource" && c.Kind != "transfer_owner" {
				continue
			}
			a, v, e := automationUpdateAdmission(h)
			if e != nil {
				return out, e
			}
			if a.ClusterUID != ref.ClusterUID || a.ProjectUID != ref.ProjectUID {
				return out, fmt.Errorf("update original resource scope differs")
			}
			if c.Kind == contract.OrdinaryCreateCommand {
				op, e := automationTargetOperationRecordTx(ctx, tx, stage, ref.ClusterUID, a.OperationID)
				if e != nil {
					return out, e
				}
				if op == nil || op.ResourceUID != ref.UID || op.Sequence != sequence {
					return out, fmt.Errorf("ordinary desired origin missing")
				}
				if e = automationValidateTargetOriginTx(ctx, tx, source, running, op); e != nil {
					return out, e
				}
			} else {
				materialized, e := automationAdmissionRecordTx(ctx, tx, stage, a.OperationID)
				if e != nil {
					return out, e
				}
				if !reflect.DeepEqual(a, materialized) {
					return out, fmt.Errorf("update accepted original admission missing or differs")
				}
			}
			reference := contract.HistoryReference{Sequence: sequence, Digest: running.Digest}
			switch c.Kind {
			case contract.OrdinaryCreateCommand, "admit_create":
				if out.facts.Origin != nil {
					return out, fmt.Errorf("duplicate resource birth")
				}
				out.facts.Origin = a
				birth := *v
				out.facts.OriginResource = &birth
				out.facts.OriginReference = reference
				out.facts.PreviousDesired = a
				out.facts.PreviousDesiredReference = reference
			case "admit_update":
				u := h.assignment.Update
				if out.facts.Origin == nil || out.facts.PreviousDesired == nil || out.facts.PreviousOperation == nil || u.Origin != out.facts.OriginReference || u.PreviousDesired != out.facts.PreviousDesiredReference || u.PreviousOperation != out.facts.PreviousOperationReference || u.PayloadID != out.facts.Origin.PayloadID {
					return out, fmt.Errorf("update historical lineage differs")
				}
				out.facts.PreviousDesired = a
				out.facts.PreviousDesiredReference = reference
			}
			if out.facts.Origin == nil {
				return out, fmt.Errorf("certified complete desired origin unavailable")
			}
			birth := out.facts.OriginResource
			v.Name = birth.Name
			v.DomainUUID = birth.DomainUUID
			v.Incarnation = birth.Incarnation
			v.OriginalOperationID = birth.OriginalOperationID
			out.facts.PreviousOperation = a
			out.facts.PreviousOperationReference = reference
			out.resource = v
		}
		window = end + 1
	}
	if running != head || out.resource == nil || out.facts.PreviousDesired == nil {
		return out, fmt.Errorf("update authenticated frontier/origin unavailable")
	}
	current, e := automationResourceRecordTx(ctx, tx, stage, ref.UID)
	if e != nil {
		return out, e
	}
	if !reflect.DeepEqual(current, out.resource) {
		return out, fmt.Errorf("update resource frontier differs")
	}
	binding, e := automationLastBindingTx(ctx, tx, stage, ref.ClusterUID, ref.ProjectUID, current.OwnerID, current.ManagementKey)
	if e != nil {
		return out, e
	}
	expected := contract.BindingRecord{ClusterUID: current.ClusterUID, ProjectUID: current.ProjectUID, OwnerID: current.OwnerID, ManagementKey: current.ManagementKey, ResourceUID: current.UID, OperationID: current.LastOperationID, Generation: current.BindingGeneration, Revision: current.Revision}
	if binding == nil || *binding != expected {
		return out, fmt.Errorf("update binding frontier differs")
	}
	cursor := int64(math.MinInt64)
	comparison := ">="
	for {
		if e = ctx.Err(); e != nil {
			return out, e
		}
		rows, e := automationUpdateAdmissionKeyWindowTx(ctx, tx, stage, cursor, comparison == ">=")
		if e != nil {
			return out, e
		}
		comparison = ">"
		for _, r := range rows {
			if e = ctx.Err(); e != nil {
				return out, e
			}
			cursor = r.Int64("cursor")
			operation, e := automationUpdateBoundedKey(r)
			if e != nil {
				return out, e
			}
			a, e := automationAdmissionRecordTx(ctx, tx, stage, operation)
			if e != nil {
				return out, e
			}
			if a == nil || a.Sequence > head.Sequence {
				return out, fmt.Errorf("reverse admission outside frontier")
			}
			h, e := automationUpdateHistoryTx(ctx, tx, source, a.Sequence)
			if e != nil {
				return out, e
			}
			original, _, e := automationUpdateAdmission(h)
			if e != nil || !reflect.DeepEqual(a, original) {
				return out, fmt.Errorf("reverse admission is not its accepted original")
			}
		}
		if len(rows) < 64 {
			break
		}
	}
	return out, nil
}

func automationUpdateProjectionTx(ctx context.Context, tx *LocalTx, stage string, p *contract.Projection, d contract.Decision, source automationKeyHistorySource) error {
	// Retained receipt authentication/retry handling is owned by the caller and
	// Reduce. Current lineage must not turn a retry after handoff into fresh work.
	if p.Existing != nil && !p.ReplayOriginal {
		return nil
	}
	body, e := contract.DecodeUpdateBindingBody(d.Command)
	if e != nil {
		return e
	}
	a, e := contract.DecodeAssignment(d)
	if e != nil {
		return e
	}
	if a.Update == nil {
		return fmt.Errorf("missing update assignment")
	}
	lineage, e := automationUpdateInverseClosureTx(ctx, tx, stage, p.Head, body.Resource, source)
	if e != nil {
		return e
	}
	desired, e := automationLatestDesiredAdmissionTx(ctx, tx, stage, p.Head, body.Resource)
	if e != nil {
		return e
	}
	// The first ordinary-origin update has no managed desired row. Only the
	// complete authenticated prefix can prove that no later desired exists.
	if desired == nil && lineage.facts.PreviousDesired.Method == contract.OrdinaryCreateCommand && lineage.facts.PreviousDesiredReference == lineage.facts.OriginReference {
		desired = lineage.facts.PreviousDesired
	}
	if !reflect.DeepEqual(desired, lineage.facts.PreviousDesired) {
		return fmt.Errorf("indexed desired differs from authenticated lineage")
	}
	f := &contract.BindingProjection{Resource: lineage.resource}
	if lineage.facts.Origin.Method == "admit_create" {
		f.OriginalAdmission = lineage.facts.Origin
	}
	c := d.Command
	if f.Project, e = automationIdentityRecordTx(ctx, tx, stage, c.ProjectUID); e != nil {
		return e
	}
	if f.Principal, e = automationIdentityRecordTx(ctx, tx, stage, c.PrincipalID); e != nil {
		return e
	}
	if f.Owner, e = automationOwnerRecordTx(ctx, tx, stage, c.ClusterUID, c.ProjectUID, c.OwnerID); e != nil {
		return e
	}
	if f.Last, e = automationLastBindingTx(ctx, tx, stage, c.ClusterUID, c.ProjectUID, c.OwnerID, c.ManagementKey); e != nil {
		return e
	}
	if f.NameIdentity, e = automationIdentityRecordTx(ctx, tx, stage, c.ResourceUID); e != nil {
		return e
	}
	if f.Name, e = automationNameRecordTx(ctx, tx, stage, c.ClusterUID, lineage.resource.Name); e != nil {
		return e
	}
	seen := map[string]bool{}
	dependencies := append(contract.BindingDependencies(a.Update.Configuration), contract.BindingDependency{Kind: "host", ClusterUID: c.ClusterUID, UID: a.Update.Applicability.HostUID})
	for _, dep := range dependencies {
		if seen[dep.UID] {
			continue
		}
		seen[dep.UID] = true
		r, e := automationIdentityRecordTx(ctx, tx, stage, dep.UID)
		if e != nil {
			return e
		}
		f.Dependencies = append(f.Dependencies, r)
	}
	p.Binding = f
	p.Update = &lineage.facts
	return nil
}

func automationApplyUpdateEffectsTx(ctx context.Context, tx *LocalTx, stage string, next contract.Prefix, r contract.Reduction) error {
	if e := requireAutomationFull(ctx, tx); e != nil {
		return e
	}
	before, v, a := r.ResourcePrevious, r.ResourceEffect, r.AdmissionEffect
	if before == nil || v == nil || a == nil || a.Method != "admit_update" || a.PinnedConfiguration == nil || r.IdentityEffect != nil || r.NameEffect != nil || len(r.BindingEffects) != 1 || len(r.TargetReservations) != 0 || r.ExecutorEffect != nil || r.TerminalEffect != nil || r.WrappingEffect != nil || len(r.ArtifactEffects) != 0 {
		return fmt.Errorf("incomplete update effect set")
	}
	expected := *before
	expected.Revision = v.Revision
	expected.LastOperationID = v.LastOperationID
	expected.AppliedSequence = next.Sequence
	if *v != expected || before.Retired || v.Revision == "" || v.LastOperationID != a.OperationID || v.ClusterUID != next.ClusterUID || v.AppliedSequence != next.Sequence || a.Sequence != next.Sequence || a.ClusterUID != v.ClusterUID || a.ProjectUID != v.ProjectUID || a.OwnerID != v.OwnerID || a.ManagementKey != v.ManagementKey || a.ResourceUID != v.UID || a.BindingGeneration != v.BindingGeneration || a.AdmittedGeneration == 0 || a.AdmittedGeneration > math.MaxInt64 || a.PinnedConfiguration.Name != v.Name || a.OperationID == before.LastOperationID || a.RequestID == "" || a.PrincipalUID == "" {
		return fmt.Errorf("incoherent update effects")
	}
	actual, e := automationResourceRecordTx(ctx, tx, stage, v.UID)
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(actual, before) {
		return fmt.Errorf("update resource predecessor changed")
	}
	binding, e := automationLastBindingTx(ctx, tx, stage, v.ClusterUID, v.ProjectUID, v.OwnerID, v.ManagementKey)
	if e != nil {
		return e
	}
	expectedBinding := contract.BindingRecord{ClusterUID: v.ClusterUID, ProjectUID: v.ProjectUID, OwnerID: v.OwnerID, ManagementKey: v.ManagementKey, ResourceUID: v.UID, OperationID: before.LastOperationID, Generation: v.BindingGeneration, Revision: before.Revision}
	if binding == nil || *binding != expectedBinding {
		return fmt.Errorf("update binding predecessor changed")
	}
	nextBinding := expectedBinding
	nextBinding.OperationID = a.OperationID
	nextBinding.Revision = v.Revision
	if r.BindingEffects[0] != nextBinding {
		return fmt.Errorf("update binding effect differs")
	}
	original, e := automationAdmissionRecordTx(ctx, tx, stage, before.LastOperationID)
	if e != nil {
		return e
	}
	if original == nil || original.Sequence != before.AppliedSequence || original.ResourceUID != v.UID || original.ClusterUID != v.ClusterUID || original.ProjectUID != v.ProjectUID {
		return fmt.Errorf("update predecessor admission changed")
	}
	encoded, e := json.Marshal(a.PinnedConfiguration)
	if e != nil || len(encoded) > 1<<20 {
		return fmt.Errorf("update configuration exceeds bounds")
	}
	result, e := tx.Exec(ctx, `UPDATE local_automation_resources SET revision=?,last_operation_id=?,applied_sequence=? WHERE stage=? AND uid=? AND cluster_uid=? AND project_uid=? AND name=? AND domain_uuid=? AND incarnation=? AND owner_id=? AND management_key=? AND binding_generation=? AND revision=? AND retired=0 AND last_operation_id=? AND original_operation_id=? AND applied_sequence=?`, v.Revision, v.LastOperationID, v.AppliedSequence, stage, before.UID, before.ClusterUID, before.ProjectUID, before.Name, before.DomainUUID, before.Incarnation, before.OwnerID, before.ManagementKey, before.BindingGeneration, before.Revision, before.LastOperationID, before.OriginalOperationID, before.AppliedSequence)
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return fmt.Errorf("update resource CAS failed")
	}
	result, e = tx.Exec(ctx, `UPDATE local_automation_bindings SET operation_id=?,revision=? WHERE stage=? AND cluster_uid=? AND project_uid=? AND owner_id=? AND management_key=? AND creation_generation=? AND resource_uid=? AND operation_id=? AND revision=? AND retired=0`, a.OperationID, v.Revision, stage, before.ClusterUID, before.ProjectUID, before.OwnerID, before.ManagementKey, before.BindingGeneration, before.UID, before.LastOperationID, before.Revision)
	if e != nil {
		return e
	}
	n, e = result.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return fmt.Errorf("update binding CAS failed")
	}
	_, e = tx.Exec(ctx, `INSERT INTO local_automation_admissions(stage,operation_id,cluster_uid,project_uid,owner_id,management_key,resource_uid,request_id,principal_uid,method,payload_id,binding_generation,admitted_generation,sequence,configuration_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, stage, a.OperationID, a.ClusterUID, a.ProjectUID, a.OwnerID, a.ManagementKey, a.ResourceUID, a.RequestID, a.PrincipalUID, a.Method, a.PayloadID, a.BindingGeneration, a.AdmittedGeneration, a.Sequence, string(encoded))
	return e
}

func automationUpdateBoundedKey(row Row) (string, error) {
	kind, kindOK := row.get("key_type").(string)
	size, sizeOK := row.get("key_bytes").(int64)
	if !kindOK || kind != "text" || !sizeOK || size <= 0 || size > contract.MaxStringBytes {
		return "", fmt.Errorf("invalid admission key type/length")
	}
	key, keyOK := row.get("operation_id").(string)
	if !keyOK || len(key) != int(size) {
		return "", fmt.Errorf("bounded admission key differs")
	}
	return key, nil
}
func automationUpdateAdmissionKeyWindowTx(ctx context.Context, tx *LocalTx, stage string, cursor int64, inclusive bool) ([]Row, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	comparison := ">"
	if inclusive {
		comparison = ">="
	}
	rows, e := tx.Query(ctx, "SELECT rowid AS cursor,"+automationUpdateKeyColumns+" FROM local_automation_admissions WHERE stage=? AND rowid"+comparison+"? ORDER BY rowid LIMIT 64", contract.MaxStringBytes, stage, cursor)
	if e != nil {
		return nil, e
	}
	for _, row := range rows {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		if _, e = automationUpdateBoundedKey(row); e != nil {
			return nil, e
		}
	}
	return rows, nil
}

// The migration verifies this required physical index and its scoped query plan
// before recording90. The FULL owner additionally verifies its complete
// three-index inventory; neither check grants business authority.
func automationVerifyUpdateIndexShapeTx(ctx context.Context, tx *LocalTx) error {
	rows, e := tx.Query(ctx, `SELECT "unique" AS uq,partial FROM pragma_index_list('local_automation_admissions') WHERE name='automation_admission_resource_desired'`)
	if e != nil {
		return e
	}
	if len(rows) != 1 || rows[0].Int64("uq") != 0 || rows[0].Int64("partial") != 1 {
		return fmt.Errorf("required update index uniqueness/predicate differs")
	}
	rows, e = tx.Query(ctx, `SELECT name,coll,"desc" AS descending FROM pragma_index_xinfo('automation_admission_resource_desired') WHERE "key"=1 ORDER BY seqno`)
	if e != nil {
		return e
	}
	columns := []string{"stage", "cluster_uid", "resource_uid", "sequence", "operation_id"}
	if len(rows) != len(columns) {
		return fmt.Errorf("update desired index key count differs")
	}
	for i, c := range columns {
		descending := int64(0)
		if i == 3 {
			descending = 1
		}
		if rows[i].String("name") != c || rows[i].String("coll") != "BINARY" || rows[i].Int64("descending") != descending {
			return fmt.Errorf("update desired index order differs")
		}
	}
	rows, e = tx.Query(ctx, `SELECT sql FROM sqlite_master WHERE type='index' AND name='automation_admission_resource_desired'`)
	if e != nil {
		return e
	}
	normalized := func(s string) string {
		return strings.ReplaceAll(strings.ToLower(strings.Join(strings.Fields(s), "")), "ifnotexists", "")
	}
	if len(rows) != 1 || normalized(rows[0].String("sql")) != normalized(automationUpdateIndexSQL) {
		return fmt.Errorf("update desired index predicate differs")
	}
	rows, e = tx.Query(ctx, "EXPLAIN QUERY PLAN "+automationDesiredLookupSQL, contract.MaxStringBytes, "", "cluster", "resource", int64(1))
	if e != nil {
		return e
	}
	seek := false
	for _, r := range rows {
		detail := strings.ToUpper(r.String("detail"))
		if strings.Contains(detail, "TEMP") || strings.Contains(detail, "SCAN ") {
			return fmt.Errorf("update desired lookup sorts or scans")
		}
		if strings.Contains(detail, "SEARCH LOCAL_AUTOMATION_ADMISSIONS USING") && strings.Contains(detail, "AUTOMATION_ADMISSION_RESOURCE_DESIRED") && strings.Contains(detail, "STAGE=? AND CLUSTER_UID=? AND RESOURCE_UID=? AND SEQUENCE<") {
			seek = true
		}
	}
	if !seek {
		return fmt.Errorf("update desired lookup lacks scoped bounded seek")
	}
	return nil
}

func automationUpdateIndexPresentTx(ctx context.Context, tx *LocalTx) (bool, error) {
	rows, err := tx.Query(ctx, `SELECT name FROM sqlite_master WHERE name='automation_admission_resource_desired'`)
	if err != nil || len(rows) == 0 {
		return false, err
	}
	if len(rows) != 1 {
		return false, fmt.Errorf("required update index identity differs")
	}
	if err := automationVerifyUpdateIndexShapeTx(ctx, tx); err != nil {
		return false, err
	}
	return true, nil
}
