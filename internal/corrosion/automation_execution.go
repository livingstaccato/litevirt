package corrosion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"reflect"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// Execution is a derived projection of the existing certified FULL history.
// These tables confer no permission to issue effects, exclude a worker, retire
// a resource/name, or release an original target reservation.
const automationExecutionTableStart = 13

type automationExecutionHistory struct {
	value      ClaimValue
	decision   contract.Decision
	assignment contract.Assignment
	receipt    contract.Receipt
}

// Decode a single canonical typed object; unknown fields, trailing values,
// duplicate fields and coercions cannot become materialized state. Comparing
// typed re-encoding also rejects alternate escaping/order and omitted fields.
func automationExecutionDecodeJSON(raw string, out any) error {
	if len(raw) == 0 || len(raw) > MaxAutomationClaimBytes {
		return fmt.Errorf("execution JSON exceeds bounds")
	}
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return fmt.Errorf("invalid execution JSON: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("trailing execution JSON")
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(canonical, []byte(raw)) {
		return fmt.Errorf("noncanonical execution JSON")
	}
	return nil
}

func automationExecutionHistoryReadTx(ctx context.Context, tx *LocalTx, source automationKeyHistorySource, sequence uint64) (automationExecutionHistory, error) {
	var out automationExecutionHistory
	if sequence == 0 || sequence > math.MaxInt64 {
		return out, fmt.Errorf("invalid execution original sequence")
	}
	var row Row
	local := false
	switch s := source.(type) {
	case receiverAutomationKeySource:
		var err error
		row, err = s.store.sequence(ctx, 5, int64(sequence))
		if err != nil {
			return out, err
		}
	case nil, localAutomationKeySource:
		local = true
		probe, err := tx.Query(ctx, `SELECT typeof(value_json) AS vt,length(CAST(value_json AS BLOB)) AS vn,typeof(digest) AS dt,length(CAST(digest AS BLOB)) AS dn,typeof(certificate) AS ct,length(CAST(certificate AS BLOB)) AS cn,typeof(receipt_json) AS rt,length(CAST(receipt_json AS BLOB)) AS rn FROM local_automation_history WHERE sequence=? LIMIT 1`, sequence)
		if err != nil {
			return out, err
		}
		if len(probe) != 1 || probe[0].String("vt") != "text" || probe[0].Int64("vn") <= 0 || probe[0].Int64("vn") > MaxAutomationClaimBytes || probe[0].String("dt") != "text" || probe[0].Int64("dn") != 64 || probe[0].String("ct") != "text" || probe[0].Int64("cn") <= 0 || probe[0].Int64("cn") > maxSourceCertificateBytes || probe[0].String("rt") != "text" || probe[0].Int64("rn") <= 0 || probe[0].Int64("rn") > MaxAutomationClaimBytes {
			return out, fmt.Errorf("execution original history missing or malformed")
		}
		rows, err := tx.Query(ctx, `SELECT value_json,digest,certificate,receipt_json FROM local_automation_history WHERE sequence=? LIMIT 1`, sequence)
		if err != nil {
			return out, err
		}
		if len(rows) != 1 {
			return out, fmt.Errorf("execution original disappeared")
		}
		row = rows[0]
	default:
		return out, fmt.Errorf("unsupported execution history owner")
	}
	key, err := AutomationClaimKey(sequence)
	if err != nil {
		return out, err
	}
	if err = decodeClaimValue(key, row.String("value_json"), &out.value); err != nil {
		return out, err
	}
	digest, err := out.value.Digest()
	if err != nil || out.value.Automation == nil || digest != row.String("digest") {
		return out, fmt.Errorf("execution original claim digest differs")
	}
	cert, err := sourceCertificate(row.String("certificate"))
	if err != nil || cert.ConfigGeneration <= 0 {
		return out, fmt.Errorf("execution original certificate unavailable")
	}
	if local {
		summary, found, err := automationTrustedSummaryTx(ctx, tx, sequence)
		if err != nil {
			return out, err
		}
		if !found || summary.Digest != digest {
			return out, fmt.Errorf("execution original trusted anchor differs")
		}
	}
	out.decision, err = automationDecision(out.value)
	if err != nil {
		return out, err
	}
	if out.decision.Sequence != sequence {
		return out, fmt.Errorf("execution original envelope sequence differs")
	}
	if err := contract.ValidateSupportedDecision(out.decision); err != nil {
		return out, err
	}
	out.assignment, err = contract.DecodeAssignment(out.decision)
	if err != nil {
		return out, err
	}
	if err = automationExecutionDecodeJSON(row.String("receipt_json"), &out.receipt); err != nil {
		return out, err
	}
	r := out.receipt
	if r.RequestID != out.decision.Command.RequestID || r.Sequence == 0 || r.Sequence > sequence || (r.Code != "" && r.State != "rejected") {
		return out, fmt.Errorf("execution original receipt differs")
	}
	if r.Code == "" && r.Sequence == sequence {
		if err := automationExecutionAcceptedReceipt(out); err != nil {
			return out, err
		}
	}
	return out, nil
}

// Compare the whole receipt of an accepted original to its fixed reducer
// encoding, including zero legacy Revision and retire_artifact's succeeded
// state. A retained retry is checked at its earlier original instead: its
// receipt must not be reconstructed from the retry's later assignment.
func automationExecutionAcceptedReceipt(h automationExecutionHistory) error {
	c, a := h.decision.Command, h.assignment
	expected := contract.Receipt{RequestID: c.RequestID, OperationID: a.OperationID, Sequence: h.decision.Sequence, Revision: 0, Code: "", State: "accepted"}
	switch c.Kind {
	case "admit_create":
		if a.Binding == nil {
			return fmt.Errorf("execution original admission assignment missing")
		}
		expected.ResourceUID, expected.Generation, expected.ResourceRevision = a.Binding.ResourceUID, a.Binding.BindingGeneration, a.Binding.Revision
	case "claim_executor", "record_progress", "complete_operation", "retire_artifact":
		b, err := contract.DecodeExecutionBody(c)
		if err != nil {
			return err
		}
		expected.ResourceUID, expected.Generation, expected.ResourceRevision = c.ResourceUID, c.Generation, b.ResourceRevision
		switch c.Kind {
		case "record_progress":
			expected.State = b.State
		case "complete_operation":
			if b.Result == nil {
				return fmt.Errorf("execution original terminal result missing")
			}
			expected.State = b.Result.Outcome
		case "retire_artifact":
			expected.State = "succeeded"
		}
	default:
		return nil
	}
	if h.receipt != expected {
		return fmt.Errorf("execution original accepted receipt differs")
	}
	return nil
}

func automationExecutionHistoryTx(ctx context.Context, tx *LocalTx, source automationKeyHistorySource, sequence uint64) (automationExecutionHistory, error) {
	h, err := automationExecutionHistoryReadTx(ctx, tx, source, sequence)
	if err != nil {
		return h, err
	}
	// A retry carries the exact earlier permanent receipt, not a new execution
	// operation. One decreasing lookup is enough: the original must be original.
	if h.receipt.Sequence < sequence {
		original, err := automationExecutionHistoryReadTx(ctx, tx, source, h.receipt.Sequence)
		if err != nil {
			return h, err
		}
		if original.receipt != h.receipt || original.receipt.Sequence != original.decision.Sequence {
			return h, fmt.Errorf("execution retained retry differs from original receipt")
		}
	}
	return h, nil
}

func automationExecutionAccepted(h automationExecutionHistory, kind string) error {
	c, r := h.decision.Command, h.receipt
	if c.Kind != kind || r.Code != "" || r.Sequence != h.decision.Sequence || r.OperationID != h.assignment.OperationID {
		return fmt.Errorf("execution original is not an accepted %s", kind)
	}
	return nil
}

// The admission reference is in the ClaimValue domain. It is deliberately
// reconstructed from its original envelope, never from the current head.
func automationExecutionAdmissionTx(ctx context.Context, tx *LocalTx, source automationKeyHistorySource, head contract.Prefix, ref contract.HistoryReference) (*contract.AdmissionRecord, contract.BindingAssignment, error) {
	var zero contract.BindingAssignment
	if ref.Sequence == 0 || ref.Sequence > head.Sequence || !receiverDigest(ref.Digest) {
		return nil, zero, fmt.Errorf("execution admission frontier differs")
	}
	h, err := automationExecutionHistoryTx(ctx, tx, source, ref.Sequence)
	if err != nil {
		return nil, zero, err
	}
	if err := automationExecutionAccepted(h, "admit_create"); err != nil {
		return nil, zero, err
	}
	b := h.assignment.Binding
	c := h.decision.Command
	if h.value.MustDigest() != ref.Digest || c.ClusterUID != head.ClusterUID || b == nil || h.receipt.State != "accepted" || h.receipt.ResourceUID != b.ResourceUID || h.receipt.Generation != b.BindingGeneration || h.receipt.ResourceRevision != b.Revision {
		return nil, zero, fmt.Errorf("execution original admission identity differs")
	}
	a := &contract.AdmissionRecord{ClusterUID: c.ClusterUID, ProjectUID: c.ProjectUID, OwnerID: c.OwnerID, ManagementKey: c.ManagementKey, ResourceUID: b.ResourceUID, OperationID: h.assignment.OperationID, RequestID: c.RequestID, PrincipalUID: c.PrincipalID, Method: "admit_create", PayloadID: b.PayloadID, BindingGeneration: b.BindingGeneration, AdmittedGeneration: b.AdmittedGeneration, Sequence: ref.Sequence, PinnedConfiguration: &b.Configuration}
	return a, *b, nil
}

// This only reconstructs the bytes of an already accepted grant for integrity
// comparison. It is never used to accept a new decision or persist effects:
// contract.Reduce remains the sole evaluator at the FULL application owner.
func automationExecutionOriginalGrantTx(ctx context.Context, tx *LocalTx, source automationKeyHistorySource, head contract.Prefix, sequence uint64) (*contract.ExecutorGrant, error) {
	if sequence == 0 || sequence > head.Sequence {
		return nil, fmt.Errorf("execution grant is beyond frontier")
	}
	h, err := automationExecutionHistoryTx(ctx, tx, source, sequence)
	if err != nil {
		return nil, err
	}
	if err := automationExecutionAccepted(h, "claim_executor"); err != nil {
		return nil, err
	}
	d, c, a := h.decision, h.decision.Command, h.assignment
	b, err := contract.DecodeExecutionBody(c)
	if err != nil {
		return nil, err
	}
	// No exclusion owner/producer is installed by this migration.
	if c.ClusterUID != head.ClusterUID || h.receipt.State != "accepted" || a.Execution == nil || a.Execution.ExecutorGeneration != 1 || b.Previous != nil || b.Exclusion != nil {
		return nil, fmt.Errorf("execution original grant has unsupported predecessor")
	}
	admission, prepared, err := automationExecutionAdmissionTx(ctx, tx, source, head, b.Admission)
	if err != nil {
		return nil, err
	}
	if admission.OperationID != b.OperationID || admission.ResourceUID != c.ResourceUID || admission.ClusterUID != c.ClusterUID || admission.ProjectUID != c.ProjectUID || admission.OwnerID != c.OwnerID || admission.ManagementKey != c.ManagementKey || admission.BindingGeneration != c.Generation || prepared.DomainUUID != b.DomainUUID || prepared.Incarnation != b.Incarnation || prepared.Revision != b.ResourceRevision || sequence <= b.Admission.Sequence || h.receipt.ResourceUID != c.ResourceUID || h.receipt.Generation != c.Generation || h.receipt.ResourceRevision != b.ResourceRevision {
		return nil, fmt.Errorf("execution original grant differs from original admission")
	}
	requirements := []contract.ArtifactRequirement{{Key: "domain", Kind: "domain"}}
	for _, disk := range admission.PinnedConfiguration.Disks {
		requirements = append(requirements, contract.ArtifactRequirement{Key: disk.Key, Kind: "disk"})
	}
	if admission.PayloadID != "" {
		requirements = append(requirements, contract.ArtifactRequirement{Key: "bootstrap", Kind: "seed"})
	}
	if len(a.Execution.Requirements) != 0 {
		missing := map[contract.ArtifactRequirement]bool{}
		for _, r := range requirements {
			missing[r] = true
		}
		for _, r := range a.Execution.Requirements {
			if !missing[r] && r.Kind != "firmware" {
				return nil, fmt.Errorf("execution original requirements differ")
			}
			delete(missing, r)
		}
		if len(missing) != 0 {
			return nil, fmt.Errorf("execution original requirements incomplete")
		}
		requirements = append([]contract.ArtifactRequirement(nil), a.Execution.Requirements...)
	}
	if len(requirements) == 0 || len(requirements) > 128 {
		return nil, fmt.Errorf("execution requirements exceed bounds")
	}
	sort.Slice(requirements, func(i, j int) bool {
		if requirements[i].Kind == requirements[j].Kind {
			return requirements[i].Key < requirements[j].Key
		}
		return requirements[i].Kind < requirements[j].Kind
	})
	config, err := json.Marshal(admission.PinnedConfiguration)
	if err != nil {
		return nil, err
	}
	configSum := sha256.Sum256(config)
	// Executor references use the decision-envelope digest, not ClaimValue.Digest.
	envelope, err := contract.EncodeDecision(d)
	if err != nil {
		return nil, err
	}
	decisionSum := sha256.Sum256(envelope)
	target := contract.ExecutionTarget{ClusterUID: c.ClusterUID, ProjectUID: c.ProjectUID, ResourceUID: c.ResourceUID, OwnerID: c.OwnerID, ManagementKey: c.ManagementKey, BindingGeneration: c.Generation, OperationID: b.OperationID, Admission: b.Admission, ResourceRevision: b.ResourceRevision, DomainUUID: b.DomainUUID, Incarnation: b.Incarnation, HostUID: b.HostUID, HostIncarnation: b.HostIncarnation, ConfigurationDigest: hex.EncodeToString(configSum[:]), PayloadID: admission.PayloadID}
	return &contract.ExecutorGrant{Target: target, Generation: a.Execution.ExecutorGeneration, Reference: contract.HistoryReference{Sequence: sequence, Digest: hex.EncodeToString(decisionSum[:])}, Requirements: requirements}, nil
}

// Probe every scalar before loading any body or creating a cursor. Then page
// by the actual composite PK in groups of at most64. No invented lower bound
// can hide NULL, negative, foreign or malformed keys at the start of a scan.
func automationExecutionRowsTx(ctx context.Context, tx *LocalTx, stage, table string, visit func(Row) error) error {
	for _, d := range automationSemanticTables[automationExecutionTableStart:] {
		if d.table != table {
			continue
		}
		var bad []string
		for _, column := range strings.Split(d.columns, ",") {
			if strings.Contains(","+d.integers+",", ","+column+",") {
				bad = append(bad, "typeof("+column+")<>'integer' OR "+column+"<=0")
			} else {
				limit := contract.MaxStringBytes
				if strings.HasSuffix(column, "_json") {
					limit = MaxAutomationClaimBytes
				}
				condition := fmt.Sprintf("typeof(%s)<>'text' OR length(CAST(%s AS BLOB))>%d", column, column, limit)
				if column != "stage" {
					condition += " OR length(CAST(" + column + " AS BLOB))=0"
				}
				bad = append(bad, condition)
			}
		}
		probe, err := tx.Query(ctx, "SELECT 1 AS bad FROM "+table+" WHERE stage=? AND ("+strings.Join(bad, " OR ")+") LIMIT 1", stage)
		if err != nil {
			return err
		}
		if len(probe) != 0 {
			return fmt.Errorf("execution projection scalar shape differs: %s", table)
		}
		keys := strings.Split(d.primaryKey, ",")
		var after []any
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			where, args := "stage=?", []any{stage}
			if after != nil {
				where += " AND (" + d.primaryKey + ")>(" + strings.TrimSuffix(strings.Repeat("?,", len(keys)), ",") + ")"
				args = append(args, after...)
			}
			rows, err := tx.Query(ctx, "SELECT "+d.columns+" FROM "+table+" WHERE "+where+" ORDER BY "+d.primaryKey+" LIMIT 64", args...)
			if err != nil {
				return err
			}
			for _, row := range rows {
				if err := visit(row); err != nil {
					return err
				}
			}
			if len(rows) < 64 {
				return nil
			}
			after = make([]any, len(keys))
			for i, key := range keys {
				after[i] = rows[len(rows)-1].String(key)
			}
		}
	}
	return fmt.Errorf("unknown execution table")
}

func automationExecutionGrantRecordTx(ctx context.Context, tx *LocalTx, stage, cluster, operation string) (*contract.ExecutorGrant, error) {
	probe, err := tx.Query(ctx, `SELECT typeof(grant_json) AS t,length(CAST(grant_json AS BLOB)) AS n FROM local_automation_executors WHERE stage=? AND cluster_uid=? AND operation_id=? LIMIT 1`, stage, cluster, operation)
	if err != nil || len(probe) == 0 {
		return nil, err
	}
	if probe[0].String("t") != "text" || probe[0].Int64("n") <= 0 || probe[0].Int64("n") > MaxAutomationClaimBytes {
		return nil, fmt.Errorf("execution grant JSON exceeds bounds")
	}
	rows, err := tx.Query(ctx, `SELECT grant_json FROM local_automation_executors WHERE stage=? AND cluster_uid=? AND operation_id=? LIMIT 1`, stage, cluster, operation)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, fmt.Errorf("execution grant disappeared")
	}
	var g contract.ExecutorGrant
	if err := automationExecutionDecodeJSON(rows[0].String("grant_json"), &g); err != nil {
		return nil, err
	}
	return &g, nil
}

type automationExecutionTerminalWire struct {
	Target contract.ExecutionTarget
	Grant  contract.ExecutorReference
	Result contract.ExecutionResult
}

func automationExecutionReference(g *contract.ExecutorGrant) contract.ExecutorReference {
	return contract.ExecutorReference{Generation: g.Generation, Decision: g.Reference}
}

func automationVerifyExecutionIndexesTx(ctx context.Context, tx *LocalTx) error {
	type executionIndex struct{ name, columns string }
	for _, d := range automationSemanticTables[automationExecutionTableStart:] {
		indexes := []executionIndex{{"sqlite_autoindex_" + d.table + "_1", d.primaryKey}}
		if d.table == "local_automation_execution_artifacts" {
			indexes = append(indexes, executionIndex{"automation_execution_artifact_key", "stage,cluster_uid,operation_id,artifact_kind,artifact_key"}, executionIndex{"automation_execution_artifact_object", "stage,cluster_uid,operation_id,backend,object_id"})
		}
		rows, err := tx.Query(ctx, `SELECT count(*) AS n FROM pragma_index_list(?)`, d.table)
		if err != nil {
			return err
		}
		if len(rows) != 1 || rows[0].Int64("n") != int64(len(indexes)) {
			return fmt.Errorf("execution projection index inventory differs")
		}
		for _, index := range indexes {
			rows, err = tx.Query(ctx, `SELECT "unique" AS uq,partial FROM pragma_index_list(?) WHERE name=? LIMIT 1`, d.table, index.name)
			if err != nil {
				return err
			}
			if len(rows) != 1 || rows[0].Int64("uq") != 1 || rows[0].Int64("partial") != 0 {
				return fmt.Errorf("execution projection index shape differs")
			}
			columns := strings.Split(index.columns, ",")
			rows, err = tx.Query(ctx, `SELECT count(*) AS n FROM pragma_index_xinfo(?) WHERE "key"=1`, index.name)
			if err != nil {
				return err
			}
			if len(rows) != 1 || rows[0].Int64("n") != int64(len(columns)) {
				return fmt.Errorf("execution projection index key count differs")
			}
			for pos, column := range columns {
				rows, err = tx.Query(ctx, `SELECT 1 AS valid FROM pragma_index_xinfo(?) WHERE seqno=? AND name=? AND coll='BINARY' AND "desc"=0 AND "key"=1 LIMIT 1`, index.name, pos, column)
				if err != nil {
					return err
				}
				if len(rows) != 1 {
					return fmt.Errorf("execution projection index order differs")
				}
			}
		}
	}
	return nil
}

func automationExecutionCommandMatches(g *contract.ExecutorGrant, h automationExecutionHistory) (contract.ExecutionBody, error) {
	b, err := contract.DecodeExecutionBody(h.decision.Command)
	if err != nil {
		return b, err
	}
	c := h.decision.Command
	if g == nil || b.Grant == nil || *b.Grant != automationExecutionReference(g) || c.ClusterUID != g.Target.ClusterUID || c.ProjectUID != g.Target.ProjectUID || c.ResourceUID != g.Target.ResourceUID || c.OwnerID != g.Target.OwnerID || c.ManagementKey != g.Target.ManagementKey || c.Generation != g.Target.BindingGeneration || b.OperationID != g.Target.OperationID || b.Admission != g.Target.Admission || b.ResourceRevision != g.Target.ResourceRevision || b.DomainUUID != g.Target.DomainUUID || b.Incarnation != g.Target.Incarnation || b.HostUID != g.Target.HostUID || b.HostIncarnation != g.Target.HostIncarnation || h.receipt.ResourceUID != c.ResourceUID || h.receipt.Generation != c.Generation || h.receipt.ResourceRevision != b.ResourceRevision {
		return b, fmt.Errorf("execution original continuation differs from grant")
	}
	return b, nil
}

// Both directions of original-history closure are checked. Row authenticity
// alone cannot detect a deleted grant, deleted progress or a deleted terminal.
func automationVerifyExecutionStageTx(ctx context.Context, tx *LocalTx, stage string, head contract.Prefix, source automationKeyHistorySource) error {
	for _, descriptor := range automationSemanticTables[automationExecutionTableStart:] {
		err := automationExecutionRowsTx(ctx, tx, stage, descriptor.table, func(row Row) error {
			cluster, operation := row.String("cluster_uid"), row.String("operation_id")
			if cluster != head.ClusterUID || head.Sequence == 0 {
				return fmt.Errorf("execution row belongs to foreign frontier")
			}
			g, err := automationExecutionGrantRecordTx(ctx, tx, stage, cluster, operation)
			if err != nil {
				return err
			}
			if g == nil || g.Target.ClusterUID != cluster || g.Target.OperationID != operation || g.Target.ResourceUID != row.String("resource_uid") {
				return fmt.Errorf("execution row has no original grant")
			}
			if len(g.Requirements) == 0 || len(g.Requirements) > 128 {
				return fmt.Errorf("execution grant requirements exceed bounds")
			}
			if descriptor.table == "local_automation_executors" {
				expected, err := automationExecutionOriginalGrantTx(ctx, tx, source, head, uint64(row.Int64("grant_sequence")))
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(g, expected) || g.Generation != uint64(row.Int64("executor_generation")) || g.Reference.Digest != row.String("grant_digest") || g.Target.Admission.Sequence != uint64(row.Int64("admission_sequence")) || g.Target.Admission.Digest != row.String("admission_digest") {
					return fmt.Errorf("execution grant differs from certified original")
				}
				a, _, err := automationExecutionAdmissionTx(ctx, tx, source, head, g.Target.Admission)
				if err != nil {
					return err
				}
				stored, err := automationAdmissionRecordTx(ctx, tx, stage, operation)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(a, stored) {
					return fmt.Errorf("execution retained admission differs from original")
				}
				resource, err := automationResourceRecordTx(ctx, tx, stage, g.Target.ResourceUID)
				if err != nil {
					return err
				}
				if resource == nil || resource.ClusterUID != cluster || resource.OriginalOperationID != operation || resource.DomainUUID != g.Target.DomainUUID || resource.Incarnation != g.Target.Incarnation {
					return fmt.Errorf("execution original resource lineage differs")
				}
				count, err := tx.Query(ctx, `SELECT count(*) AS n FROM local_automation_execution_artifacts WHERE stage=? AND cluster_uid=? AND operation_id=?`, stage, cluster, operation)
				if err != nil {
					return err
				}
				if len(count) != 1 || count[0].Int64("n") > 128 {
					return fmt.Errorf("execution artifact inventory exceeds bounds")
				}
				return nil
			}
			sequence := uint64(row.Int64("applied_sequence"))
			if sequence <= g.Reference.Sequence || sequence > head.Sequence {
				return fmt.Errorf("execution effect is beyond grant frontier")
			}
			h, err := automationExecutionHistoryTx(ctx, tx, source, sequence)
			if err != nil {
				return err
			}
			if err := automationExecutionAccepted(h, h.decision.Command.Kind); err != nil {
				return err
			}
			b, err := automationExecutionCommandMatches(g, h)
			if err != nil {
				return err
			}
			switch descriptor.table {
			case "local_automation_execution_progress":
				var p contract.ExecutionProgress
				if err := automationExecutionDecodeJSON(row.String("progress_json"), &p); err != nil {
					return err
				}
				expected := contract.ExecutionProgress{OperationID: operation, Grant: *b.Grant, State: b.State, Reason: b.Reason, NextAction: b.NextAction, Sequence: sequence}
				if h.decision.Command.Kind != "record_progress" || p != expected || h.receipt.State != b.State {
					return fmt.Errorf("execution progress differs from certified original")
				}
			case "local_automation_execution_artifacts":
				var a contract.ArtifactRecord
				if err := automationExecutionDecodeJSON(row.String("artifact_json"), &a); err != nil {
					return err
				}
				if h.decision.Command.Kind != "record_progress" && h.decision.Command.Kind != "retire_artifact" {
					return fmt.Errorf("execution artifact origin kind differs")
				}
				matches := 0
				for _, original := range b.Artifacts {
					if original.ID == a.ID {
						matches++
						if original != a {
							return fmt.Errorf("execution artifact differs from original")
						}
					}
				}
				if matches != 1 || a.ID != row.String("artifact_id") || a.Key != row.String("artifact_key") || a.Kind != row.String("artifact_kind") || a.Backend != row.String("backend") || a.ObjectID != row.String("object_id") || a.ResourceUID != g.Target.ResourceUID || a.OperationID != operation || a.Incarnation != g.Target.Incarnation {
					return fmt.Errorf("execution artifact scalar closure differs")
				}
				terminal, err := tx.Query(ctx, `SELECT applied_sequence FROM local_automation_execution_terminals WHERE stage=? AND cluster_uid=? AND operation_id=? LIMIT 1`, stage, cluster, operation)
				if err != nil {
					return err
				}
				if len(terminal) != 0 && row.Int64("applied_sequence") > terminal[0].Int64("applied_sequence") {
					return fmt.Errorf("execution artifact changed after permanent terminal")
				}
			case "local_automation_execution_terminals":
				var terminal automationExecutionTerminalWire
				if err := automationExecutionDecodeJSON(row.String("terminal_json"), &terminal); err != nil {
					return err
				}
				if h.decision.Command.Kind != "complete_operation" || b.Result == nil || h.receipt.State != b.Result.Outcome || terminal.Target != g.Target || terminal.Grant != automationExecutionReference(g) || !reflect.DeepEqual(terminal.Result, *b.Result) {
					return fmt.Errorf("execution terminal differs from certified original")
				}
				artifacts, err := tx.Query(ctx, `SELECT artifact_id,artifact_json FROM local_automation_execution_artifacts WHERE stage=? AND cluster_uid=? AND operation_id=? ORDER BY artifact_id LIMIT 129`, stage, cluster, operation)
				if err != nil {
					return err
				}
				if len(artifacts) > 128 || len(artifacts) != len(terminal.Result.Artifacts) {
					return fmt.Errorf("execution terminal inventory incomplete")
				}
				for i, row := range artifacts {
					var a contract.ArtifactRecord
					if err := automationExecutionDecodeJSON(row.String("artifact_json"), &a); err != nil {
						return err
					}
					if a.ID != row.String("artifact_id") || a.ID != terminal.Result.Artifacts[i].ID || a.State != terminal.Result.Artifacts[i].State {
						return fmt.Errorf("execution terminal immutable artifact snapshot differs")
					}
				}
			default:
				return fmt.Errorf("unknown execution effect table")
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	// A bounded original read per sequence, in finite64-decision windows. This
	// reads the supplied source even when every derived row has been deleted.
	parent := ""
	for first := uint64(1); first <= head.Sequence; {
		last := head.Sequence
		if head.Sequence-first >= 64 {
			last = first + 63
		}
		for sequence := first; sequence <= last; sequence++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			h, err := automationExecutionHistoryTx(ctx, tx, source, sequence)
			if err != nil {
				return err
			}
			if h.decision.ParentDigest != parent || (h.decision.Command.ClusterUID != head.ClusterUID && sequence != 1) || (sequence == 1 && h.assignment.ClusterUID != head.ClusterUID) {
				return fmt.Errorf("execution original history lineage differs")
			}
			parent = h.value.MustDigest()
			if sequence == head.Sequence && parent != head.Digest {
				return fmt.Errorf("execution original history frontier differs")
			}
			kind := h.decision.Command.Kind
			if kind != "claim_executor" && kind != "record_progress" && kind != "retire_artifact" && kind != "complete_operation" {
				continue
			}
			if h.receipt.Code != "" || h.receipt.Sequence != sequence {
				continue
			}
			b, err := contract.DecodeExecutionBody(h.decision.Command)
			if err != nil {
				return err
			}
			g, err := automationExecutionGrantRecordTx(ctx, tx, stage, head.ClusterUID, b.OperationID)
			if err != nil {
				return err
			}
			if g == nil {
				return fmt.Errorf("certified execution grant projection missing")
			}
			if kind == "claim_executor" {
				if g.Reference.Sequence != sequence {
					return fmt.Errorf("certified execution grant reference missing")
				}
				continue
			}
			if _, err := automationExecutionCommandMatches(g, h); err != nil {
				return err
			}
			if kind == "record_progress" {
				rows, err := tx.Query(ctx, `SELECT applied_sequence FROM local_automation_execution_progress WHERE stage=? AND cluster_uid=? AND operation_id=? LIMIT 1`, stage, head.ClusterUID, b.OperationID)
				if err != nil {
					return err
				}
				if len(rows) != 1 || rows[0].Int64("applied_sequence") < int64(sequence) {
					return fmt.Errorf("certified execution progress projection missing")
				}
			}
			for _, a := range b.Artifacts {
				rows, err := tx.Query(ctx, `SELECT applied_sequence FROM local_automation_execution_artifacts WHERE stage=? AND cluster_uid=? AND operation_id=? AND artifact_id=? LIMIT 1`, stage, head.ClusterUID, b.OperationID, a.ID)
				if err != nil {
					return err
				}
				if len(rows) != 1 || rows[0].Int64("applied_sequence") < int64(sequence) {
					return fmt.Errorf("certified execution artifact projection missing")
				}
			}
			if kind == "complete_operation" {
				rows, err := tx.Query(ctx, `SELECT applied_sequence FROM local_automation_execution_terminals WHERE stage=? AND cluster_uid=? AND operation_id=? LIMIT 1`, stage, head.ClusterUID, b.OperationID)
				if err != nil {
					return err
				}
				if len(rows) != 1 || rows[0].Int64("applied_sequence") > int64(sequence) {
					return fmt.Errorf("certified execution terminal projection missing")
				}
			}
		}
		if last == head.Sequence {
			break
		}
		first = last + 1
	}
	return nil
}

func automationExecutionProjectionTx(ctx context.Context, tx *LocalTx, stage string, p *contract.Projection, d contract.Decision, source automationKeyHistorySource) error {
	head, err := automationSemanticHeadTx(ctx, tx, stage)
	if err != nil {
		return err
	}
	if head != p.Head {
		return fmt.Errorf("execution semantic predecessor unavailable")
	}
	if err := automationVerifyExecutionStageTx(ctx, tx, stage, head, source); err != nil {
		return err
	}
	b, err := contract.DecodeExecutionBody(d.Command)
	if err != nil {
		return err
	}
	c := d.Command
	f := &contract.BindingProjection{}
	if f.Resource, err = automationResourceRecordTx(ctx, tx, stage, c.ResourceUID); err != nil {
		return err
	}
	if f.Project, err = automationIdentityRecordTx(ctx, tx, stage, c.ProjectUID); err != nil {
		return err
	}
	if f.Principal, err = automationIdentityRecordTx(ctx, tx, stage, c.PrincipalID); err != nil {
		return err
	}
	if f.Owner, err = automationOwnerRecordTx(ctx, tx, stage, c.ClusterUID, c.ProjectUID, c.OwnerID); err != nil {
		return err
	}
	if f.Last, err = automationLastBindingTx(ctx, tx, stage, c.ClusterUID, c.ProjectUID, c.OwnerID, c.ManagementKey); err != nil {
		return err
	}
	if f.Resource == nil {
		return fmt.Errorf("execution original resource unavailable")
	}
	if f.Name, err = automationNameRecordTx(ctx, tx, stage, c.ClusterUID, f.Resource.Name); err != nil {
		return err
	}
	if f.OriginalAdmission, err = automationAdmissionRecordTx(ctx, tx, stage, f.Resource.OriginalOperationID); err != nil {
		return err
	}
	original, _, err := automationExecutionAdmissionTx(ctx, tx, source, head, b.Admission)
	if err != nil {
		return err
	}
	if f.Resource.OriginalOperationID != b.OperationID || !reflect.DeepEqual(original, f.OriginalAdmission) {
		return fmt.Errorf("execution original admission projection differs")
	}
	seen := map[string]bool{}
	for _, dependency := range contract.BindingDependencies(*original.PinnedConfiguration) {
		if seen[dependency.UID] {
			continue
		}
		seen[dependency.UID] = true
		identity, err := automationIdentityRecordTx(ctx, tx, stage, dependency.UID)
		if err != nil {
			return err
		}
		f.Dependencies = append(f.Dependencies, identity)
	}
	if !seen[b.HostUID] {
		host, err := automationIdentityRecordTx(ctx, tx, stage, b.HostUID)
		if err != nil {
			return err
		}
		f.Dependencies = append(f.Dependencies, host)
	}
	p.Binding = f
	e := &contract.ExecutionProjection{Admission: b.Admission}
	e.Grant, err = automationExecutionGrantRecordTx(ctx, tx, stage, c.ClusterUID, b.OperationID)
	if err != nil {
		return err
	}
	// Whole-stage closure has already checked scalar/body bounds and originals.
	progress, err := tx.Query(ctx, `SELECT progress_json FROM local_automation_execution_progress WHERE stage=? AND cluster_uid=? AND operation_id=? LIMIT 1`, stage, c.ClusterUID, b.OperationID)
	if err != nil {
		return err
	}
	if len(progress) != 0 {
		e.Progress = new(contract.ExecutionProgress)
		if err := automationExecutionDecodeJSON(progress[0].String("progress_json"), e.Progress); err != nil {
			return err
		}
	}
	artifacts, err := tx.Query(ctx, `SELECT artifact_json FROM local_automation_execution_artifacts WHERE stage=? AND cluster_uid=? AND operation_id=? ORDER BY artifact_id LIMIT 129`, stage, c.ClusterUID, b.OperationID)
	if err != nil {
		return err
	}
	if len(artifacts) > 128 {
		return fmt.Errorf("execution artifact inventory exceeds bounds")
	}
	for _, row := range artifacts {
		var a contract.ArtifactRecord
		if err := automationExecutionDecodeJSON(row.String("artifact_json"), &a); err != nil {
			return err
		}
		e.Artifacts = append(e.Artifacts, a)
	}
	terminal, err := tx.Query(ctx, `SELECT applied_sequence,terminal_json FROM local_automation_execution_terminals WHERE stage=? AND cluster_uid=? AND operation_id=? LIMIT 1`, stage, c.ClusterUID, b.OperationID)
	if err != nil {
		return err
	}
	if len(terminal) != 0 {
		var wire automationExecutionTerminalWire
		if err := automationExecutionDecodeJSON(terminal[0].String("terminal_json"), &wire); err != nil {
			return err
		}
		e.Terminal = &contract.ExecutionTerminal{Target: wire.Target, Grant: wire.Grant, Result: wire.Result, Sequence: uint64(terminal[0].Int64("applied_sequence")), Artifacts: append([]contract.ArtifactRecord(nil), e.Artifacts...)}
		if len(e.Artifacts) != len(wire.Result.Artifacts) {
			return fmt.Errorf("execution terminal inventory incomplete")
		}
		for i, a := range e.Artifacts {
			if a.ID != wire.Result.Artifacts[i].ID || a.State != wire.Result.Artifacts[i].State {
				return fmt.Errorf("execution terminal immutable artifact snapshot differs")
			}
		}
	}
	// Exclusions intentionally remains empty: no certified producer exists.
	p.Execution = e
	return nil
}

func automationExecutionWriteJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil || len(b) == 0 || len(b) > MaxAutomationClaimBytes {
		return "", fmt.Errorf("execution effect JSON exceeds bounds")
	}
	return string(b), nil
}

func automationApplyExecutionEffectsTx(ctx context.Context, tx *LocalTx, stage string, head, next contract.Prefix, r contract.Reduction) error {
	if r.ExecutorEffect == nil && r.ProgressEffect == nil && r.TerminalEffect == nil && len(r.ArtifactEffects) == 0 {
		return nil
	}
	if err := requireAutomationFull(ctx, tx); err != nil {
		return err
	}
	if r.Receipt.Code != "" || next.ClusterUID != head.ClusterUID || next.Sequence != head.Sequence+1 || next.Sequence > math.MaxInt64 {
		return fmt.Errorf("invalid execution effect successor")
	}
	var operation string
	if r.ExecutorEffect != nil {
		operation = r.ExecutorEffect.Target.OperationID
	}
	if r.ProgressEffect != nil {
		operation = r.ProgressEffect.OperationID
	}
	if r.TerminalEffect != nil {
		operation = r.TerminalEffect.Target.OperationID
	}
	if len(r.ArtifactEffects) != 0 {
		operation = r.ArtifactEffects[0].OperationID
	}
	if operation == "" {
		return fmt.Errorf("execution effect original operation missing")
	}
	g, err := automationExecutionGrantRecordTx(ctx, tx, stage, next.ClusterUID, operation)
	if err != nil {
		return err
	}
	terminal, err := tx.Query(ctx, `SELECT applied_sequence FROM local_automation_execution_terminals WHERE stage=? AND cluster_uid=? AND operation_id=? LIMIT 1`, stage, next.ClusterUID, operation)
	if err != nil {
		return err
	}
	if len(terminal) != 0 {
		return fmt.Errorf("execution effects cannot overwrite permanent terminal")
	}
	if v := r.ExecutorEffect; v != nil {
		if g != nil || v.Generation != 1 || v.Target.ClusterUID != next.ClusterUID || v.Target.OperationID != operation || v.Reference.Sequence != next.Sequence || !receiverDigest(v.Reference.Digest) || v.Target.Admission.Sequence == 0 || v.Target.Admission.Sequence > head.Sequence || !receiverDigest(v.Target.Admission.Digest) || len(v.Requirements) == 0 || len(v.Requirements) > 128 || r.ProgressEffect != nil || r.TerminalEffect != nil || len(r.ArtifactEffects) != 0 {
			return fmt.Errorf("invalid initial executor grant effect")
		}
		body, err := automationExecutionWriteJSON(v)
		if err != nil {
			return err
		}
		result, err := tx.Exec(ctx, `INSERT INTO local_automation_executors(stage,cluster_uid,operation_id,resource_uid,executor_generation,grant_sequence,grant_digest,admission_sequence,admission_digest,grant_json) VALUES(?,?,?,?,?,?,?,?,?,?)`, stage, next.ClusterUID, operation, v.Target.ResourceUID, v.Generation, v.Reference.Sequence, v.Reference.Digest, v.Target.Admission.Sequence, v.Target.Admission.Digest, body)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("executor grant was not inserted")
		}
		return nil
	}
	if g == nil || g.Target.ClusterUID != next.ClusterUID || g.Target.OperationID != operation || g.Reference.Sequence > head.Sequence {
		return fmt.Errorf("execution effect grant predecessor unavailable")
	}
	if len(r.ArtifactEffects) > 128 {
		return fmt.Errorf("execution artifact effects exceed bounds")
	}
	for _, v := range r.ArtifactEffects {
		if v.OperationID != operation || v.ResourceUID != g.Target.ResourceUID || v.Incarnation != g.Target.Incarnation {
			return fmt.Errorf("execution artifact effect lineage differs")
		}
		body, err := automationExecutionWriteJSON(v)
		if err != nil {
			return err
		}
		prior, err := tx.Query(ctx, `SELECT artifact_json FROM local_automation_execution_artifacts WHERE stage=? AND cluster_uid=? AND operation_id=? AND artifact_id=? LIMIT 1`, stage, next.ClusterUID, operation, v.ID)
		if err != nil {
			return err
		}
		if len(prior) != 0 {
			var old contract.ArtifactRecord
			if err := automationExecutionDecodeJSON(prior[0].String("artifact_json"), &old); err != nil {
				return err
			}
			before, after := old, v
			before.State, before.Locator, after.State, after.Locator = "", "", "", ""
			if before != after || ((old.State == "deleted" || old.State == "absent") && old.State != v.State) {
				return fmt.Errorf("execution artifact immutable identity differs")
			}
		} else if v.Origin != automationExecutionReference(g) || v.HostUID != g.Target.HostUID || v.HostIncarnation != g.Target.HostIncarnation {
			return fmt.Errorf("execution artifact initial origin differs")
		}
		result, err := tx.Exec(ctx, `INSERT INTO local_automation_execution_artifacts(stage,cluster_uid,operation_id,artifact_id,resource_uid,artifact_key,artifact_kind,backend,object_id,applied_sequence,artifact_json) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(stage,cluster_uid,operation_id,artifact_id) DO UPDATE SET applied_sequence=excluded.applied_sequence,artifact_json=excluded.artifact_json WHERE resource_uid=excluded.resource_uid AND artifact_key=excluded.artifact_key AND artifact_kind=excluded.artifact_kind AND backend=excluded.backend AND object_id=excluded.object_id AND applied_sequence<excluded.applied_sequence`, stage, next.ClusterUID, operation, v.ID, v.ResourceUID, v.Key, v.Kind, v.Backend, v.ObjectID, next.Sequence, body)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("execution artifact predecessor did not advance")
		}
	}
	count, err := tx.Query(ctx, `SELECT count(*) AS n FROM local_automation_execution_artifacts WHERE stage=? AND cluster_uid=? AND operation_id=?`, stage, next.ClusterUID, operation)
	if err != nil {
		return err
	}
	if len(count) != 1 || count[0].Int64("n") > 128 {
		return fmt.Errorf("execution artifact inventory exceeds bounds")
	}
	if v := r.ProgressEffect; v != nil {
		if v.OperationID != operation || v.Grant != automationExecutionReference(g) || v.Sequence != next.Sequence || (v.State != "running" && v.State != "recovering" && v.State != "blocked") || r.TerminalEffect != nil {
			return fmt.Errorf("execution progress effect differs from grant")
		}
		body, err := automationExecutionWriteJSON(v)
		if err != nil {
			return err
		}
		result, err := tx.Exec(ctx, `INSERT INTO local_automation_execution_progress(stage,cluster_uid,operation_id,resource_uid,applied_sequence,progress_json) VALUES(?,?,?,?,?,?) ON CONFLICT(stage,cluster_uid,operation_id) DO UPDATE SET applied_sequence=excluded.applied_sequence,progress_json=excluded.progress_json WHERE resource_uid=excluded.resource_uid AND applied_sequence<excluded.applied_sequence`, stage, next.ClusterUID, operation, g.Target.ResourceUID, next.Sequence, body)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("execution progress predecessor did not advance")
		}
	}
	if v := r.TerminalEffect; v != nil {
		if v.Target != g.Target || v.Grant != automationExecutionReference(g) || v.Sequence != next.Sequence || len(v.Artifacts) > 128 || len(v.Artifacts) != len(v.Result.Artifacts) || len(r.ArtifactEffects) != 0 {
			return fmt.Errorf("execution terminal effect differs from grant")
		}
		rows, err := tx.Query(ctx, `SELECT artifact_json FROM local_automation_execution_artifacts WHERE stage=? AND cluster_uid=? AND operation_id=? ORDER BY artifact_id LIMIT 129`, stage, next.ClusterUID, operation)
		if err != nil {
			return err
		}
		if len(rows) != len(v.Artifacts) {
			return fmt.Errorf("execution terminal inventory differs")
		}
		for i, row := range rows {
			var a contract.ArtifactRecord
			if err := automationExecutionDecodeJSON(row.String("artifact_json"), &a); err != nil {
				return err
			}
			if a != v.Artifacts[i] || a.ID != v.Result.Artifacts[i].ID || a.State != v.Result.Artifacts[i].State {
				return fmt.Errorf("execution terminal snapshot differs")
			}
		}
		body, err := automationExecutionWriteJSON(automationExecutionTerminalWire{Target: v.Target, Grant: v.Grant, Result: v.Result})
		if err != nil {
			return err
		}
		result, err := tx.Exec(ctx, `INSERT INTO local_automation_execution_terminals(stage,cluster_uid,operation_id,resource_uid,applied_sequence,terminal_json) VALUES(?,?,?,?,?,?)`, stage, next.ClusterUID, operation, g.Target.ResourceUID, next.Sequence, body)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("execution terminal was not inserted")
		}
	}
	return nil
}
