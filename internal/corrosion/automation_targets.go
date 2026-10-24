package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"reflect"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// Target rows are derived, stage-local certified-history projections. Neither
// these readers nor successful reduction provide native execution authority.
func automationTargetOperationRecordTx(ctx context.Context, tx *LocalTx, stage, cluster, operation string) (*contract.TargetOperationRecord, error) {
	if operation == "" {
		return nil, nil
	}
	probe, err := tx.Query(ctx, `SELECT typeof(body_json) AS bt,typeof(assignment_json) AS at,length(CAST(body_json AS BLOB)) AS bn,length(CAST(assignment_json AS BLOB)) AS an FROM local_automation_target_operations WHERE stage=? AND cluster_uid=? AND operation_id=? LIMIT 2`, stage, cluster, operation)
	if err != nil {
		return nil, err
	}
	if len(probe) == 0 {
		return nil, nil
	}
	if len(probe) != 1 || probe[0].String("bt") != "text" || probe[0].String("at") != "text" || probe[0].Int64("bn") > 1<<20 || probe[0].Int64("an") > 1<<20 {
		return nil, fmt.Errorf("oversized target operation")
	}
	rows, err := tx.Query(ctx, `SELECT cluster_uid,operation_id,kind,project_uid,principal_uid,request_id,resource_uid,target_name,sequence,decision_digest,body_json,assignment_json FROM local_automation_target_operations WHERE stage=? AND cluster_uid=? AND operation_id=? LIMIT 2`, stage, cluster, operation)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	if len(rows) != 1 {
		return nil, fmt.Errorf("ambiguous target operation")
	}
	r := rows[0]
	for _, column := range []string{"cluster_uid", "operation_id", "kind", "project_uid", "principal_uid", "request_id", "resource_uid", "target_name", "decision_digest", "body_json", "assignment_json"} {
		s, ok := r.get(column).(string)
		bound := contract.MaxStringBytes
		if column == "body_json" || column == "assignment_json" {
			bound = 1 << 20
		}
		if !ok || len(s) > bound {
			return nil, fmt.Errorf("malformed target operation field")
		}
	}
	sequence, ok := r.get("sequence").(int64)
	if !ok || sequence <= 0 || r.String("cluster_uid") != cluster || r.String("operation_id") != operation || !receiverDigest(r.String("decision_digest")) {
		return nil, fmt.Errorf("malformed target operation identity")
	}
	kind := r.String("kind")
	if kind != contract.LegacyRebuildCommand && kind != contract.OrdinaryCreateCommand {
		return nil, fmt.Errorf("unknown target operation kind")
	}
	if !json.Valid([]byte(r.String("body_json"))) || !json.Valid([]byte(r.String("assignment_json"))) {
		return nil, fmt.Errorf("malformed retained target bytes")
	}
	return &contract.TargetOperationRecord{ClusterUID: cluster, OperationID: operation, Kind: kind, ProjectUID: r.String("project_uid"), PrincipalUID: r.String("principal_uid"), RequestID: r.String("request_id"), ResourceUID: r.String("resource_uid"), TargetName: r.String("target_name"), Sequence: uint64(sequence), DecisionDigest: r.String("decision_digest"), Body: []byte(r.String("body_json")), Assignment: []byte(r.String("assignment_json"))}, nil
}

// The source must be the same immutable history owner used by staged replay;
// a receiver never falls back to the local active history.
func automationTargetHistoryRecordTx(ctx context.Context, tx *LocalTx, source automationKeyHistorySource, sequence uint64) (ClaimValue, contract.Receipt, error) {
	if sequence == 0 || sequence > math.MaxInt64 {
		return ClaimValue{}, contract.Receipt{}, fmt.Errorf("invalid target history sequence")
	}
	var rows []Row
	var err error
	local := false
	switch s := source.(type) {
	case receiverAutomationKeySource:
		row, e := s.store.sequence(ctx, 5, int64(sequence))
		if e != nil {
			return ClaimValue{}, contract.Receipt{}, e
		}
		rows = []Row{row}
	case nil, localAutomationKeySource:
		local = true
		rows, err = tx.Query(ctx, `SELECT value_json,digest,receipt_json FROM local_automation_history WHERE sequence=? LIMIT 2`, sequence)
	default:
		return ClaimValue{}, contract.Receipt{}, fmt.Errorf("unsupported target history owner")
	}
	if err != nil {
		return ClaimValue{}, contract.Receipt{}, err
	}
	if len(rows) != 1 {
		return ClaimValue{}, contract.Receipt{}, fmt.Errorf("target history unavailable")
	}
	key, _ := AutomationClaimKey(sequence)
	var v ClaimValue
	if err := decodeClaimValue(key, rows[0].String("value_json"), &v); err != nil {
		return ClaimValue{}, contract.Receipt{}, err
	}
	if v.Automation == nil || v.MustDigest() != rows[0].String("digest") {
		return ClaimValue{}, contract.Receipt{}, fmt.Errorf("target history digest mismatch")
	}
	if local {
		summary, found, err := automationTrustedSummaryTx(ctx, tx, sequence)
		if err != nil {
			return ClaimValue{}, contract.Receipt{}, err
		}
		if !found || summary.Digest != v.MustDigest() {
			return ClaimValue{}, contract.Receipt{}, fmt.Errorf("target history anchor mismatch")
		}
	}
	d, e := contract.DecodeDecision(v.Automation.Envelope)
	if e != nil {
		return ClaimValue{}, contract.Receipt{}, e
	}
	var receipt contract.Receipt
	if json.Unmarshal([]byte(rows[0].String("receipt_json")), &receipt) != nil || receipt.RequestID != d.Command.RequestID || receipt.Sequence == 0 || receipt.Sequence > d.Sequence {
		return ClaimValue{}, contract.Receipt{}, fmt.Errorf("target certified receipt mismatch")
	}
	// An assigned-operation collision is a permanent validation rejection with
	// no operation ID. A retained retry keeps that rejection's earlier sequence.
	// Only accepted origins require a nonempty operation; their first-accept
	// assignment and sequence binding remain enforced by automationTargetHistoryTx.
	if receipt.Code != "" {
		if receipt.State != "rejected" || (receipt.OperationID == "" && receipt.Code != contract.CodeValidation) {
			return ClaimValue{}, contract.Receipt{}, fmt.Errorf("target certified receipt mismatch")
		}
	} else if receipt.State != "accepted" || receipt.OperationID == "" {
		return ClaimValue{}, contract.Receipt{}, fmt.Errorf("target certified receipt mismatch")
	}
	return v, receipt, nil
}
func automationTargetHistoryTx(ctx context.Context, tx *LocalTx, source automationKeyHistorySource, sequence uint64) (ClaimValue, error) {
	value, receipt, err := automationTargetHistoryRecordTx(ctx, tx, source, sequence)
	if err != nil {
		return ClaimValue{}, err
	}
	d, err := contract.DecodeDecision(value.Automation.Envelope)
	if err != nil {
		return ClaimValue{}, err
	}
	a, err := contract.DecodeAssignment(d)
	if err != nil {
		return ClaimValue{}, err
	}
	if receipt.Code != "" || receipt.State != "accepted" || receipt.OperationID != a.OperationID || receipt.Sequence != sequence {
		return ClaimValue{}, fmt.Errorf("target certified receipt mismatch")
	}
	return value, nil
}
func automationValidateTargetOriginTx(ctx context.Context, tx *LocalTx, source automationKeyHistorySource, head contract.Prefix, r *contract.TargetOperationRecord) error {
	if r == nil || r.ClusterUID != head.ClusterUID || r.Sequence == 0 || r.Sequence > head.Sequence {
		return fmt.Errorf("target origin frontier mismatch")
	}
	value, err := automationTargetHistoryTx(ctx, tx, source, r.Sequence)
	if err != nil {
		return err
	}
	d, err := contract.DecodeDecision(value.Automation.Envelope)
	if err != nil {
		return err
	}
	a, err := contract.DecodeAssignment(d)
	if err != nil {
		return err
	}
	if value.MustDigest() != r.DecisionDigest || d.Command.Kind != r.Kind || d.Command.ClusterUID != r.ClusterUID || d.Command.ProjectUID != r.ProjectUID || d.Command.PrincipalID != r.PrincipalUID || d.Command.RequestID != r.RequestID || a.OperationID != r.OperationID || a.Target == nil || !bytes.Equal(d.Command.Body, r.Body) || !bytes.Equal(d.Assignment, r.Assignment) {
		return fmt.Errorf("target origin differs from certified history")
	}
	var name, uid string
	if r.Kind == contract.LegacyRebuildCommand {
		b, e := contract.DecodeLegacyRebuildBody(d.Command)
		if e != nil {
			return e
		}
		name = b.Name
		uid = b.Expected.ResourceUID
	} else {
		b, e := contract.DecodeOrdinaryCreateBody(d.Command)
		if e != nil {
			return e
		}
		name = b.Desired.Name
		if a.Target.Allocation == nil {
			return fmt.Errorf("ordinary target allocation missing")
		}
		uid = a.Target.Allocation.ResourceUID
	}
	if r.TargetName != name || r.ResourceUID != uid {
		return fmt.Errorf("target origin resource mismatch")
	}
	return nil
}
func automationTargetKeyProjectionTx(ctx context.Context, tx *LocalTx, stage, cluster string, head contract.Prefix, key contract.TargetKey, source automationKeyHistorySource) (contract.TargetKeyProjection, error) {
	out := contract.TargetKeyProjection{Key: key}
	encoded, err := contract.TargetKeyEncoding(key)
	if err != nil {
		return out, err
	}
	rows, err := tx.Query(ctx, `SELECT operation_id,sequence FROM local_automation_target_reservations WHERE stage=? AND cluster_uid=? AND target_key=? LIMIT 2`, stage, cluster, encoded)
	if err != nil {
		return out, err
	}
	if len(rows) > 1 {
		return out, fmt.Errorf("ambiguous target key")
	}
	if len(rows) == 1 {
		seq, ok := rows[0].get("sequence").(int64)
		if !ok || seq <= 0 || uint64(seq) > head.Sequence || !automationReadString(rows[0].String("operation_id"), false) {
			return out, fmt.Errorf("malformed target reservation")
		}
		operation, err := automationTargetOperationRecordTx(ctx, tx, stage, cluster, rows[0].String("operation_id"))
		if err != nil {
			return out, err
		}
		if operation == nil || operation.Sequence != uint64(seq) {
			return out, fmt.Errorf("orphan target reservation")
		}
		if err := automationValidateTargetOriginTx(ctx, tx, source, head, operation); err != nil {
			return out, err
		}
		var a contract.Assignment
		if err := json.Unmarshal(operation.Assignment, &a); err != nil || a.Target == nil {
			return out, fmt.Errorf("target reservation assignment unavailable")
		}
		matched := false
		for _, p := range a.Target.Preparations {
			k, e := contract.TargetKeyEncoding(p.Key)
			if e != nil {
				return out, e
			}
			if k == encoded {
				matched = true
			}
		}
		if !matched {
			return out, fmt.Errorf("target reservation not in retained key set")
		}
		out.Reservation = &contract.TargetReservation{ClusterUID: cluster, Key: encoded, OperationID: operation.OperationID, Sequence: uint64(seq)}
	}
	if key.Kind != "vm_name" {
		return out, nil
	}
	out.Name, err = automationNameRecordTx(ctx, tx, stage, cluster, key.Name)
	if err != nil {
		return out, err
	}
	aliases, err := tx.Query(ctx, `SELECT uid,generation FROM local_automation_aliases WHERE stage=? AND cluster_uid=? AND project_scope='' AND kind='vm' AND alias=? LIMIT 2`, stage, cluster, key.Name)
	if err != nil {
		return out, err
	}
	if len(aliases) > 1 {
		return out, fmt.Errorf("ambiguous target alias")
	}
	uid := ""
	if out.Name != nil {
		uid = out.Name.ResourceUID
	}
	if len(aliases) == 1 {
		out.Identity, err = automationIdentityRecordTx(ctx, tx, stage, aliases[0].String("uid"))
		if err != nil {
			return out, err
		}
		if out.Identity == nil || out.Identity.Generation != uint64(aliases[0].Int64("generation")) || out.Identity.ClusterUID != cluster || out.Identity.Kind != "vm" || out.Identity.Alias != key.Name {
			return out, fmt.Errorf("incoherent target alias")
		}
		if uid != "" && uid != out.Identity.UID {
			return out, fmt.Errorf("target name alias disagree")
		}
		uid = out.Identity.UID
	}
	out.Resource, err = automationResourceRecordTx(ctx, tx, stage, uid)
	if err != nil {
		return out, err
	}
	inverse, err := tx.Query(ctx, `SELECT EXISTS(SELECT 1 FROM local_automation_resources WHERE stage=? AND cluster_uid=? AND name=? AND (?='' OR (uid<>? AND (typeof(retired)<>'integer' OR retired<>1)))) AS bad`, stage, cluster, key.Name, uid, uid)
	if err != nil {
		return out, err
	}
	if len(inverse) != 1 || inverse[0].Int64("bad") != 0 {
		return out, fmt.Errorf("orphan target resource")
	}

	// Partial rows are corruption, never the explicit empty predecessor.
	if (out.Name == nil) != (out.Identity == nil) || (out.Name == nil) != (out.Resource == nil) {
		return out, fmt.Errorf("partial target name predecessor")
	}
	return out, nil
}
func automationTargetProjectionTx(ctx context.Context, tx *LocalTx, stage string, p *contract.Projection, d contract.Decision, source automationKeyHistorySource) error {
	if d.Command.Kind == "admit_update" && p.Existing != nil && !p.ReplayOriginal {
		return nil
	}
	var keys []contract.TargetKey
	var intent *contract.VMIntent
	switch d.Command.Kind {
	case contract.LegacyRebuildCommand:
		b, e := contract.DecodeLegacyRebuildBody(d.Command)
		if e != nil {
			return e
		}
		keys = b.Keys
	case contract.OrdinaryCreateCommand:
		b, e := contract.DecodeOrdinaryCreateBody(d.Command)
		if e != nil {
			return e
		}
		keys = b.Keys
	case "assign_identity":
		b, e := contract.DecodeIdentityEnrollment(d.Command)
		if e != nil {
			return e
		}
		if b.Kind != "vm" {
			return nil
		}
		keys = []contract.TargetKey{{Kind: "vm_name", Name: b.Alias}}
	case "admit_create":
		a, e := contract.DecodeAssignment(d)
		if e != nil {
			return e
		}
		if a.Binding == nil {
			return fmt.Errorf("missing binding target")
		}
		keys = []contract.TargetKey{{Kind: "vm_name", Name: a.Binding.Configuration.Name}}
	case "admit_update", "adopt_resource", "transfer_owner":
		if p.Binding == nil || p.Binding.Resource == nil {
			return fmt.Errorf("missing ownership target")
		}
		keys = []contract.TargetKey{{Kind: "vm_name", Name: p.Binding.Resource.Name}}
	default:
		return nil
	}
	if err := automationTargetInverseClosureTx(ctx, tx, stage, p.Head, source); err != nil {
		return err
	}
	facts := &contract.TargetProjection{}
	for _, key := range keys {
		row, e := automationTargetKeyProjectionTx(ctx, tx, stage, d.Command.ClusterUID, p.Head, key, source)
		if e != nil {
			return e
		}
		facts.Keys = append(facts.Keys, row)
	}
	if d.Command.Kind == contract.LegacyRebuildCommand || d.Command.Kind == contract.OrdinaryCreateCommand {
		a, e := contract.DecodeAssignment(d)
		if e != nil {
			return e
		}
		if a.Target == nil {
			return fmt.Errorf("missing target assignment")
		}
		intent = &a.Target.Configuration
		facts.Project, e = automationIdentityRecordTx(ctx, tx, stage, d.Command.ProjectUID)
		if e != nil {
			return e
		}
		facts.Principal, e = automationIdentityRecordTx(ctx, tx, stage, d.Command.PrincipalID)
		if e != nil {
			return e
		}
		if a.Target.Allocation != nil {
			facts.AssignedIdentity, e = automationIdentityRecordTx(ctx, tx, stage, a.Target.Allocation.ResourceUID)
			if e != nil {
				return e
			}
			facts.AssignedResource, e = automationResourceRecordTx(ctx, tx, stage, a.Target.Allocation.ResourceUID)
			if e != nil {
				return e
			}
		}
		seen := map[string]bool{}
		for _, dep := range contract.BindingDependencies(*intent) {
			if seen[dep.UID] {
				continue
			}
			seen[dep.UID] = true
			id, e := automationIdentityRecordTx(ctx, tx, stage, dep.UID)
			if e != nil {
				return e
			}
			facts.Dependencies = append(facts.Dependencies, id)
		}
	}
	p.Target = facts
	if p.Binding != nil && p.Binding.Resource != nil && p.Binding.Resource.OriginalOperationID != "" {
		v := p.Binding.Resource
		origin, e := automationTargetOperationRecordTx(ctx, tx, stage, v.ClusterUID, v.OriginalOperationID)
		if e != nil {
			return e
		}
		if origin != nil {
			if p.Binding.OriginalAdmission != nil {
				return fmt.Errorf("ambiguous ordinary and managed origin")
			}
			if e := automationValidateTargetOriginTx(ctx, tx, source, p.Head, origin); e != nil {
				return e
			}
			p.Binding.OriginalTarget = origin
		}
	}
	return nil
}

func automationApplyTargetEffectsTx(ctx context.Context, tx *LocalTx, stage string, next contract.Prefix, r contract.Reduction) error {
	if err := requireAutomationFull(ctx, tx); err != nil {
		return err
	}
	op := r.TargetEffect
	if op == nil {
		if len(r.TargetReservations) != 0 {
			return fmt.Errorf("target keys without operation")
		}
		return nil
	}
	if r.Receipt.Code != "" || r.Receipt.State != "accepted" || r.Receipt.OperationID != op.OperationID || r.Receipt.Sequence != next.Sequence || op.ClusterUID != next.ClusterUID || op.Sequence != next.Sequence || op.OperationID == "" || op.TargetName == "" || (op.DecisionDigest != "" && op.DecisionDigest != next.Digest) {
		return fmt.Errorf("invalid target operation effect")
	}
	var a contract.Assignment
	if err := json.Unmarshal(op.Assignment, &a); err != nil || a.Target == nil {
		return fmt.Errorf("invalid target retained assignment")
	}
	d := contract.Decision{Sequence: op.Sequence, ParentDigest: a.Target.ParentDigest, Command: contract.Command{Kind: op.Kind, ClusterUID: op.ClusterUID, ProjectUID: op.ProjectUID, PrincipalID: op.PrincipalUID, RequestID: op.RequestID, Body: op.Body}, Assignment: op.Assignment}
	if err := contract.ValidateSupportedDecision(d); err != nil {
		return err
	}
	if a.OperationID != op.OperationID {
		return fmt.Errorf("target operation assignment mismatch")
	}
	var keys []contract.TargetKey
	var name, uid string
	if op.Kind == contract.LegacyRebuildCommand {
		b, e := contract.DecodeLegacyRebuildBody(d.Command)
		if e != nil {
			return e
		}
		keys = b.Keys
		name = b.Name
		uid = b.Expected.ResourceUID
	} else if op.Kind == contract.OrdinaryCreateCommand {
		b, e := contract.DecodeOrdinaryCreateBody(d.Command)
		if e != nil {
			return e
		}
		keys = b.Keys
		name = b.Desired.Name
		uid = a.Target.Allocation.ResourceUID
	} else {
		return fmt.Errorf("invalid target kind")
	}
	if name != op.TargetName || uid != op.ResourceUID || len(keys) != len(r.TargetReservations) || r.Receipt.ResourceUID != uid {
		return fmt.Errorf("incomplete target effect set")
	}
	for i, key := range keys {
		encoded, e := contract.TargetKeyEncoding(key)
		if e != nil {
			return e
		}
		want := contract.TargetReservation{ClusterUID: op.ClusterUID, Key: encoded, OperationID: op.OperationID, Sequence: op.Sequence}
		if r.TargetReservations[i] != want {
			return fmt.Errorf("target key effect differs")
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO local_automation_target_operations(stage,cluster_uid,operation_id,kind,project_uid,principal_uid,request_id,resource_uid,target_name,sequence,decision_digest,body_json,assignment_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, stage, op.ClusterUID, op.OperationID, op.Kind, op.ProjectUID, op.PrincipalUID, op.RequestID, op.ResourceUID, op.TargetName, op.Sequence, next.Digest, string(op.Body), string(op.Assignment)); err != nil {
		return err
	}
	for _, key := range r.TargetReservations {
		res, err := tx.Exec(ctx, `INSERT INTO local_automation_target_reservations(stage,cluster_uid,target_key,operation_id,sequence) VALUES(?,?,?,?,?)`, stage, key.ClusterUID, key.Key, key.OperationID, key.Sequence)
		if err != nil {
			return err
		}
		n, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return fmt.Errorf("target key was not acquired")
		}
	}
	return nil
}
func automationApplyOrdinaryAllocationEffectsTx(ctx context.Context, tx *LocalTx, stage string, next contract.Prefix, r contract.Reduction) error {
	op := r.TargetEffect
	if op == nil || op.Kind != contract.OrdinaryCreateCommand {
		return fmt.Errorf("ordinary allocation origin missing")
	}
	var a contract.Assignment
	if err := json.Unmarshal(op.Assignment, &a); err != nil || a.Target == nil || a.Target.Allocation == nil {
		return fmt.Errorf("ordinary allocation missing")
	}
	v, n, i := r.ResourceEffect, r.NameEffect, r.IdentityEffect
	alloc := a.Target.Allocation
	expected := contract.ResourceRecord{ClusterUID: op.ClusterUID, ProjectUID: op.ProjectUID, UID: alloc.ResourceUID, Name: op.TargetName, DomainUUID: alloc.DomainUUID, Incarnation: alloc.Incarnation, LastOperationID: op.OperationID, OriginalOperationID: op.OperationID, AppliedSequence: next.Sequence, Revision: alloc.Revision}
	if v == nil || n == nil || i == nil || !reflect.DeepEqual(*v, expected) || r.ResourcePrevious != nil || r.OwnerEffect != nil || r.AdmissionEffect != nil || len(r.BindingEffects) != 0 || i.Witness != v.Incarnation || i.UID != v.UID || i.ProjectUID != v.ProjectUID || i.ClusterUID != v.ClusterUID || i.Kind != "vm" || i.Alias != v.Name || i.Generation != alloc.NameGeneration || i.Retired || n.ClusterUID != v.ClusterUID || n.ResourceUID != v.UID || n.Name != v.Name || n.Generation != i.Generation || n.Disposition != "reserved" || n.RetirementOperationID != "" {
		return fmt.Errorf("incoherent ordinary allocation")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO local_automation_resources(stage,uid,cluster_uid,project_uid,name,domain_uuid,incarnation,owner_id,management_key,binding_generation,revision,retired,last_operation_id,original_operation_id,applied_sequence) VALUES(?,?,?,?,?,?,?,'','',0,?,0,?,?,?)`, stage, v.UID, v.ClusterUID, v.ProjectUID, v.Name, v.DomainUUID, v.Incarnation, v.Revision, v.LastOperationID, v.OriginalOperationID, v.AppliedSequence); err != nil {
		return err
	}
	res, err := tx.Exec(ctx, `INSERT INTO local_automation_names(stage,cluster_uid,name,resource_uid,generation,disposition,retirement_operation_id) VALUES(?,?,?,?,?,'reserved','') ON CONFLICT(stage,cluster_uid,name) DO UPDATE SET resource_uid=excluded.resource_uid,generation=excluded.generation,disposition='reserved',retirement_operation_id='' WHERE disposition='reusable' AND retirement_operation_id<>'' AND generation=excluded.generation-1`, stage, n.ClusterUID, n.Name, n.ResourceUID, n.Generation)
	if err != nil {
		return err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("ordinary name lifetime did not advance")
	}
	return nil
}

// Strict ordinary-origin observation may be reused after real managed adoption;
// it never substitutes a target record for the current managed admission.
func automationNameOrdinaryOriginTx(ctx context.Context, tx *LocalTx, head contract.Prefix, r contract.ResourceRecord, n contract.NameRecord, id contract.IdentityRecord) error {
	origin, err := automationTargetOperationRecordTx(ctx, tx, "", r.ClusterUID, r.OriginalOperationID)
	if err != nil {
		return err
	}
	if origin == nil || origin.Kind != contract.OrdinaryCreateCommand || origin.ResourceUID != r.UID || origin.TargetName != r.Name || origin.ProjectUID != r.ProjectUID || origin.Sequence > r.AppliedSequence {
		return fmt.Errorf("ordinary name origin unavailable")
	}
	if err := automationValidateTargetOriginTx(ctx, tx, nil, head, origin); err != nil {
		return err
	}
	var a contract.Assignment
	if json.Unmarshal(origin.Assignment, &a) != nil || a.Target == nil || a.Target.Allocation == nil {
		return fmt.Errorf("ordinary name allocation unavailable")
	}
	v := a.Target.Allocation
	if v.ResourceUID != r.UID || v.DomainUUID != r.DomainUUID || v.Incarnation != r.Incarnation || v.NameGeneration != n.Generation || id.Generation != v.NameGeneration || id.Witness != v.Incarnation {
		return fmt.Errorf("ordinary name birth differs")
	}
	if r.OwnerID == "" && (origin.OperationID != r.LastOperationID || origin.Sequence != r.AppliedSequence || v.Revision != r.Revision || n.Disposition != "reserved") {
		return fmt.Errorf("ordinary unowned name changed without provenance")
	}
	return nil
}

// Absence is closed over all target allocation rows as well as identity/name
// rows. A no-binding L has no allocation and does not invent a namespace row.
func automationNameTargetClosureTx(ctx context.Context, tx *LocalTx, head contract.Prefix, name string) error {
	if err := automationTargetScalarsTx(ctx, tx, ""); err != nil {
		return err
	}
	bad, err := tx.Query(ctx, `SELECT EXISTS(SELECT 1 FROM local_automation_target_reservations k WHERE k.stage='' AND (typeof(k.target_key)<>'text' OR typeof(k.operation_id)<>'text' OR typeof(k.sequence)<>'integer' OR k.sequence<=0 OR NOT EXISTS(SELECT 1 FROM local_automation_target_operations o WHERE o.stage=k.stage AND o.cluster_uid=k.cluster_uid AND o.operation_id=k.operation_id AND o.sequence=k.sequence))) AS bad`)
	if err != nil {
		return err
	}
	if len(bad) != 1 || bad[0].Int64("bad") != 0 {
		return fmt.Errorf("orphan target reservation")
	}
	cursor := int64(math.MinInt64)
	comparison := ">="
	for {
		rows, err := tx.Query(ctx, "SELECT rowid AS cursor,operation_id,cluster_uid FROM local_automation_target_operations WHERE stage='' AND rowid"+comparison+"? ORDER BY rowid LIMIT 64", cursor)
		if err != nil {
			return err
		}
		comparison = ">"
		for _, row := range rows {
			cursor = row.Int64("cursor")
			origin, err := automationTargetOperationRecordTx(ctx, tx, "", row.String("cluster_uid"), row.String("operation_id"))
			if err != nil {
				return err
			}
			if err := automationValidateTargetOriginTx(ctx, tx, nil, head, origin); err != nil {
				return err
			}
			var a contract.Assignment
			if json.Unmarshal(origin.Assignment, &a) != nil || a.Target == nil {
				return fmt.Errorf("target closure assignment missing")
			}
			keys, err := tx.Query(ctx, `SELECT target_key,sequence FROM local_automation_target_reservations WHERE stage='' AND cluster_uid=? AND operation_id=? ORDER BY target_key LIMIT 65`, origin.ClusterUID, origin.OperationID)
			if err != nil {
				return err
			}
			if len(keys) != len(a.Target.Preparations) {
				return fmt.Errorf("target closure key set incomplete")
			}
			for i, p := range a.Target.Preparations {
				key, e := contract.TargetKeyEncoding(p.Key)
				if e != nil {
					return e
				}
				if keys[i].String("target_key") != key || keys[i].Int64("sequence") != int64(origin.Sequence) {
					return fmt.Errorf("target closure key differs")
				}
			}
			if origin.Kind == contract.OrdinaryCreateCommand {
				resource, err := automationResourceRecordTx(ctx, tx, "", origin.ResourceUID)
				if err != nil {
					return err
				}
				if resource == nil || resource.Name != origin.TargetName || resource.ClusterUID != head.ClusterUID || resource.ProjectUID != origin.ProjectUID || resource.OriginalOperationID != origin.OperationID {
					return fmt.Errorf("orphan ordinary allocation")
				}
			}
		}
		if len(rows) < 64 {
			break
		}
	}
	return nil
}

// Scalar probes bound text before materialization, including corrupt rows that
// no longer carry a recoverable name. Stage ownership remains explicit.
func automationTargetScalarsTx(ctx context.Context, tx *LocalTx, stage string) error {
	checks := []struct{ table, predicate string }{
		{"local_automation_target_operations", "typeof(sequence)<>'integer' OR sequence<=0 OR typeof(body_json)<>'text' OR length(CAST(body_json AS BLOB))>1048576 OR typeof(assignment_json)<>'text' OR length(CAST(assignment_json AS BLOB))>1048576"},
		{"local_automation_target_reservations", "typeof(sequence)<>'integer' OR sequence<=0 OR typeof(target_key)<>'text' OR length(CAST(target_key AS BLOB))>98368"},
	}
	for _, check := range checks {
		predicate := check.predicate
		columns := []string{"cluster_uid", "operation_id"}
		if check.table == "local_automation_target_operations" {
			columns = append(columns, "kind", "project_uid", "principal_uid", "request_id", "resource_uid", "target_name", "decision_digest")
		}
		for _, column := range columns {
			predicate += " OR typeof(" + column + ")<>'text' OR length(CAST(" + column + " AS BLOB))>4096"
		}
		rows, err := tx.Query(ctx, "SELECT EXISTS(SELECT 1 FROM "+check.table+" WHERE stage=? AND ("+predicate+")) AS bad", stage)
		if err != nil {
			return err
		}
		if len(rows) != 1 || rows[0].Int64("bad") != 0 {
			return fmt.Errorf("malformed target projection scalars")
		}
	}
	return nil
}

// An empty forward key lookup is meaningful only after every retained operation
// at this exact stage/head has its complete original reservation set. Missing or
// moved rows are corruption, not an implicit terminal release. This deliberately
// uses the caller's immutable history owner, including receiver source rows.
func automationTargetInverseClosureTx(ctx context.Context, tx *LocalTx, stage string, head contract.Prefix, source automationKeyHistorySource) (result error) {
	defer func() {
		if result != nil {
			result = fmt.Errorf("target inverse: %w", result)
		}
	}()
	actual, err := automationSemanticHeadTx(ctx, tx, stage)
	if err != nil {
		return err
	}
	if actual != head {
		return fmt.Errorf("semantic predecessor differs")
	}
	switch source.(type) {
	case nil, localAutomationKeySource, receiverAutomationKeySource:
	default:
		return fmt.Errorf("unsupported history owner")
	}
	if err := automationTargetScalarsTx(ctx, tx, stage); err != nil {
		return err
	}
	// Include the immutable prefix inverse: deleting both an operation row and
	// all its keys must not turn retained accepted work into coherent emptiness.
	history := source
	if history == nil {
		history = localAutomationKeySource{tx}
	}
	for sequence := uint64(1); sequence <= head.Sequence; sequence++ {
		summary, err := history.keyHistory(ctx, sequence)
		if err != nil {
			return err
		}
		if summary.Kind != contract.LegacyRebuildCommand && summary.Kind != contract.OrdinaryCreateCommand {
			continue
		}
		value, receipt, err := automationTargetHistoryRecordTx(ctx, tx, source, sequence)
		if err != nil {
			return err
		}
		if receipt.Code != "" {
			continue
		}
		if receipt.State != "accepted" {
			return fmt.Errorf("unknown retained target result")
		}
		op, err := automationTargetOperationRecordTx(ctx, tx, stage, head.ClusterUID, receipt.OperationID)
		if err != nil {
			return err
		}
		if op == nil || op.Sequence != receipt.Sequence {
			return fmt.Errorf("retained accepted operation missing")
		}
		if err := automationValidateTargetOriginTx(ctx, tx, source, head, op); err != nil {
			return err
		}
		current, err := contract.DecodeDecision(value.Automation.Envelope)
		if err != nil {
			return err
		}
		origin := contract.Command{Kind: op.Kind, ClusterUID: op.ClusterUID, ProjectUID: op.ProjectUID, PrincipalID: op.PrincipalUID, RequestID: op.RequestID, Body: op.Body}
		originalIdentity, err := contract.CanonicalCommand(origin)
		if err != nil {
			return err
		}
		currentIdentity, err := contract.CanonicalCommand(current.Command)
		if err != nil {
			return err
		}
		if !bytes.Equal(originalIdentity, currentIdentity) {
			return fmt.Errorf("retained target retry identity differs")
		}
	}
	orphan, err := tx.Query(ctx, `SELECT EXISTS(SELECT 1 FROM local_automation_target_reservations k WHERE k.stage=? AND NOT EXISTS(SELECT 1 FROM local_automation_target_operations o WHERE o.stage=k.stage AND o.cluster_uid=k.cluster_uid AND o.operation_id=k.operation_id AND o.sequence=k.sequence)) AS bad`, stage)
	if err != nil {
		return err
	}
	if len(orphan) != 1 || orphan[0].Int64("bad") != 0 {
		return fmt.Errorf("orphan reservation")
	}
	cursor := int64(math.MinInt64)
	comparison := ">="
	for {
		rows, err := tx.Query(ctx, "SELECT rowid AS cursor,cluster_uid,operation_id FROM local_automation_target_operations WHERE stage=? AND rowid"+comparison+"? ORDER BY rowid LIMIT 64", stage, cursor)
		if err != nil {
			return err
		}
		comparison = ">"
		for _, row := range rows {
			cursor = row.Int64("cursor")
			op, err := automationTargetOperationRecordTx(ctx, tx, stage, row.String("cluster_uid"), row.String("operation_id"))
			if err != nil {
				return err
			}
			if err := automationValidateTargetOriginTx(ctx, tx, source, head, op); err != nil {
				return err
			}
			var a contract.Assignment
			if json.Unmarshal(op.Assignment, &a) != nil || a.Target == nil {
				return fmt.Errorf("retained preparation unavailable")
			}
			keys, err := tx.Query(ctx, `SELECT target_key,sequence FROM local_automation_target_reservations WHERE stage=? AND cluster_uid=? AND operation_id=? ORDER BY target_key LIMIT 65`, stage, op.ClusterUID, op.OperationID)
			if err != nil {
				return err
			}
			if len(keys) != len(a.Target.Preparations) {
				return fmt.Errorf("retained key set incomplete")
			}
			for i, preparation := range a.Target.Preparations {
				encoded, err := contract.TargetKeyEncoding(preparation.Key)
				if err != nil {
					return err
				}
				if keys[i].String("target_key") != encoded || keys[i].Int64("sequence") != int64(op.Sequence) {
					return fmt.Errorf("retained key tuple differs")
				}
			}
		}
		if len(rows) < 64 {
			break
		}
	}
	return nil
}
