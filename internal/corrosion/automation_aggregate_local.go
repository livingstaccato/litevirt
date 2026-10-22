package corrosion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math"
	"strings"
	"unicode/utf8"
)

// aggregateLocalAudit is inert storage-derived evidence, never authority.
type aggregateLocalAudit struct {
	id, dependency, coverage string
	head                     AutomationPrefix
	records                  int64
	store                    receiverAuditStore
	attempt                  *AutomationReceiverAttempt
	retained                 *retainedLocalContext
}

type aggregateLocalTable struct {
	table, columns, keys, shape string
	stage                       bool
}

// The first nine descriptors preserve the archive's semantic column order;
// local-only timestamp suffixes are retained in the private framed snapshot.
// Immutable private layout from signed schema83 checkpoint4b30caf14d7d80a74049799606bf63638e28f003.
// Keep the archived literals independent of subsequent semantic schema changes.
var automationArchived83SemanticTables = []struct{ table, columns, integers, primaryKey, nullable string }{
	{"local_automation_identities", "stage,uid,cluster_uid,project_uid,kind,alias,witness,generation,retired", "generation,retired", "stage,uid", ""},
	{"local_automation_aliases", "stage,cluster_uid,project_scope,kind,alias,uid,generation", "generation", "stage,cluster_uid,project_scope,kind,alias", ""},
	{"local_automation_owners", "stage,cluster_uid,project_uid,owner_id,founder_principal_uid,session_id,session_principal_uid,activation", "activation", "stage,cluster_uid,project_uid,owner_id", ""},
	{"local_automation_semantic_heads", "stage,cluster_uid,sequence,digest", "sequence", "stage", "stage"},
	{"local_automation_resources", "stage,uid,cluster_uid,project_uid,name,domain_uuid,incarnation,owner_id,management_key,binding_generation,revision,retired,last_operation_id,original_operation_id,applied_sequence", "binding_generation,retired,applied_sequence", "stage,uid", ""},
	{"local_automation_names", "stage,cluster_uid,name,resource_uid,generation,disposition,retirement_operation_id", "generation", "stage,cluster_uid,name", ""},
	{"local_automation_bindings", "stage,cluster_uid,project_uid,owner_id,management_key,creation_generation,resource_uid,operation_id,revision,retired", "creation_generation,retired", "stage,cluster_uid,project_uid,owner_id,management_key,creation_generation", ""},
	{"local_automation_admissions", "stage,operation_id,cluster_uid,project_uid,owner_id,management_key,resource_uid,request_id,principal_uid,method,payload_id,binding_generation,admitted_generation,sequence,configuration_json", "binding_generation,admitted_generation,sequence", "stage,operation_id", ""},
	{"local_automation_key_epochs", "stage,cluster_uid,recipient_epoch,membership_generation,config_digest,equality_epoch,predecessor_activation_sequence,activation_sequence", "membership_generation,predecessor_activation_sequence,activation_sequence", "stage,cluster_uid,recipient_epoch", ""},
	{"local_automation_key_recipients", "stage,cluster_uid,recipient_epoch,membership_generation,config_digest,host,host_incarnation,admitted_at,admission_serial,voter_incarnation,key_id,recipient,enrollment_ref,recipient_ack_ref,equality_ack_ref,first_sequence", "membership_generation,host_incarnation,first_sequence", "stage,cluster_uid,recipient_epoch,host", ""},
	{"local_automation_payload_wrappings", "stage,cluster_uid,operation_id,payload_id,admission_sequence,wrapping_sequence,wrapping_digest,recipient_epoch,membership_generation,config_digest", "admission_sequence,wrapping_sequence,membership_generation", "stage,cluster_uid,operation_id,wrapping_sequence", ""},
}

func aggregateLocalTables83() []aggregateLocalTable {
	return []aggregateLocalTable{
		{"local_recovery_claims", "target_kind,target_name,owner_epoch,attempt,promised_round, promised_coord, promised_nonce, accepted_round, accepted_coord,\n\taccepted_nonce, value_json, value_digest, accept_json, config_generation,updated_at", "target_kind,target_name,owner_epoch,attempt", "ttiiitbitbtttit", false},
		{"local_incarnation_claims", "target_kind,target_name,incarnation,owner_epoch,attempt,promised_round, promised_coord, promised_nonce, accepted_round, accepted_coord,\n\taccepted_nonce, value_json, value_digest, accept_json, config_generation,updated_at", "target_kind,target_name,incarnation,owner_epoch,attempt", "tttiiitbitbtttit", false},
		{"local_automation_history", "sequence,digest,value_json,certificate,receipt_json,anchor_sequence", "sequence", "itttti", false},
		{"local_automation_anchors", "sequence,digest,generation,members_hash,certificate", "sequence", "ititt", false},
		{"local_automation_requests", "scope,request_id,identity,receipt_json,operation_id", "scope,request_id", "ttbtt", false},
		{"local_automation_authority", "id,generation,members_hash,incarnation,bootstrap_principal,bootstrap_request,provenance", "id", "iittttt", false},
		{"local_voter_adoption", "generation,imported_from,adopted_at", "generation", "itt", false},
		{"local_voter_seals", "generation,reason,sealed_at", "generation", "itt", false},
		{"voter_configs", "generation,members_json,members_hash,change,certificate,created_by,created_at,deleted_at,updated_at", "generation", "ittttttTt", false},
		{"local_automation_prefix", "id,cluster_uid,sequence,digest", "id", "itit", false},
		{"local_voter_incarnation", "id,incarnation,created_at", "id", "itt", false},
		{"local_automation_recovery", "id,sequence,digest,next_sequence,next_digest,base_sequence,base_digest,generation,members_hash,certificate", "id", "iititititt", false},
		{"local_automation_staging", "sequence,digest,value_json,certificate", "sequence", "ittt", false},
		{"reseed_in_progress", "id,started_at,source", "id", "itt", false},
		{"reseed_generation", "id,generation", "id", "ii", false},
		{"schema_state", "id,version,updated_at", "id", "iit", false},
		{"local_automation_cuts", "id,generation,incarnation,metadata,root", "id", "titbt", false},
		{"local_automation_cut_records", "cut_id,section,ordinal,record", "cut_id,section,ordinal", "tiib", false},
		{"local_automation_identities", "stage,uid,cluster_uid,project_uid,kind,alias,witness,generation,retired", "stage,uid", "tttttttii", true},
		{"local_automation_aliases", "stage,cluster_uid,project_scope,kind,alias,uid,generation", "stage,cluster_uid,project_scope,kind,alias", "tttttti", true},
		{"local_automation_owners", "stage,cluster_uid,project_uid,owner_id,founder_principal_uid,session_id,session_principal_uid,activation", "stage,cluster_uid,project_uid,owner_id", "ttttttti", true},
		{"local_automation_semantic_heads", "stage,cluster_uid,sequence,digest", "stage", "ttit", true},
		{"local_automation_resources", "stage,uid,cluster_uid,project_uid,name,domain_uuid,incarnation,owner_id,management_key,binding_generation,revision,retired,last_operation_id,original_operation_id,applied_sequence", "stage,uid", "tttttttttititti", true},
		{"local_automation_names", "stage,cluster_uid,name,resource_uid,generation,disposition,retirement_operation_id", "stage,cluster_uid,name", "ttttitt", true},
		{"local_automation_bindings", "stage,cluster_uid,project_uid,owner_id,management_key,creation_generation,resource_uid,operation_id,revision,retired", "stage,cluster_uid,project_uid,owner_id,management_key,creation_generation", "tttttittti", true},
		{"local_automation_admissions", "stage,operation_id,cluster_uid,project_uid,owner_id,management_key,resource_uid,request_id,principal_uid,method,payload_id,binding_generation,admitted_generation,sequence,configuration_json", "stage,operation_id", "tttttttttttiiit", true},
		{"local_automation_key_epochs", "stage,cluster_uid,recipient_epoch,membership_generation,config_digest,equality_epoch,predecessor_activation_sequence,activation_sequence", "stage,cluster_uid,recipient_epoch", "tttittii", true},
		{"local_automation_key_recipients", "stage,cluster_uid,recipient_epoch,membership_generation,config_digest,host,host_incarnation,admitted_at,admission_serial,voter_incarnation,key_id,recipient,enrollment_ref,recipient_ack_ref,equality_ack_ref,first_sequence", "stage,cluster_uid,recipient_epoch,host", "tttittitttttttti", true},
		{"local_automation_payload_wrappings", "stage,cluster_uid,operation_id,payload_id,admission_sequence,wrapping_sequence,wrapping_digest,recipient_epoch,membership_generation,config_digest", "stage,cluster_uid,operation_id,wrapping_sequence", "ttttiittit", true},
		{"local_automation_lifetimes", "kind,name,witness,origin,retired,valid", "kind,name,witness", "ttttii", false},
		{"local_automation_credential_issuance", "kind,credential_id,username,witness,principal_uid,cluster_uid,valid", "kind,credential_id", "tttttti", false},
	}
}

// Immutable private33 inventory from the accepted signed628 schema85 export.
// Schema84 shares these exact descriptors. Never derive archived offsets from
// the growing current semantic inventory or reinterpret its observation suffix.
func aggregateLocalTables85() []aggregateLocalTable {
	return []aggregateLocalTable{
		{"local_recovery_claims", "target_kind,target_name,owner_epoch,attempt,promised_round, promised_coord, promised_nonce, accepted_round, accepted_coord,\n\taccepted_nonce, value_json, value_digest, accept_json, config_generation,updated_at", "target_kind,target_name,owner_epoch,attempt", "ttiiitbitbtttit", false},
		{"local_incarnation_claims", "target_kind,target_name,incarnation,owner_epoch,attempt,promised_round, promised_coord, promised_nonce, accepted_round, accepted_coord,\n\taccepted_nonce, value_json, value_digest, accept_json, config_generation,updated_at", "target_kind,target_name,incarnation,owner_epoch,attempt", "tttiiitbitbtttit", false},
		{"local_automation_history", "sequence,digest,value_json,certificate,receipt_json,anchor_sequence", "sequence", "itttti", false},
		{"local_automation_anchors", "sequence,digest,generation,members_hash,certificate", "sequence", "ititt", false},
		{"local_automation_requests", "scope,request_id,identity,receipt_json,operation_id", "scope,request_id", "ttbtt", false},
		{"local_automation_authority", "id,generation,members_hash,incarnation,bootstrap_principal,bootstrap_request,provenance", "id", "iittttt", false},
		{"local_voter_adoption", "generation,imported_from,adopted_at", "generation", "itt", false},
		{"local_voter_seals", "generation,reason,sealed_at", "generation", "itt", false},
		{"voter_configs", "generation,members_json,members_hash,change,certificate,created_by,created_at,deleted_at,updated_at", "generation", "ittttttTt", false},
		{"local_automation_prefix", "id,cluster_uid,sequence,digest", "id", "itit", false},
		{"local_voter_incarnation", "id,incarnation,created_at", "id", "itt", false},
		{"local_automation_recovery", "id,sequence,digest,next_sequence,next_digest,base_sequence,base_digest,generation,members_hash,certificate", "id", "iititititt", false},
		{"local_automation_staging", "sequence,digest,value_json,certificate", "sequence", "ittt", false},
		{"reseed_in_progress", "id,started_at,source", "id", "itt", false},
		{"reseed_generation", "id,generation", "id", "ii", false},
		{"schema_state", "id,version,updated_at", "id", "iit", false},
		{"local_automation_cuts", "id,generation,incarnation,metadata,root", "id", "titbt", false},
		{"local_automation_cut_records", "cut_id,section,ordinal,record", "cut_id,section,ordinal", "tiib", false},
		{"local_automation_identities", "stage,uid,cluster_uid,project_uid,kind,alias,witness,generation,retired", "stage,uid", "tttttttii", true},
		{"local_automation_aliases", "stage,cluster_uid,project_scope,kind,alias,uid,generation", "stage,cluster_uid,project_scope,kind,alias", "tttttti", true},
		{"local_automation_owners", "stage,cluster_uid,project_uid,owner_id,founder_principal_uid,session_id,session_principal_uid,activation", "stage,cluster_uid,project_uid,owner_id", "ttttttti", true},
		{"local_automation_semantic_heads", "stage,cluster_uid,sequence,digest", "stage", "ttit", true},
		{"local_automation_resources", "stage,uid,cluster_uid,project_uid,name,domain_uuid,incarnation,owner_id,management_key,binding_generation,revision,retired,last_operation_id,original_operation_id,applied_sequence", "stage,uid", "tttttttttititti", true},
		{"local_automation_names", "stage,cluster_uid,name,resource_uid,generation,disposition,retirement_operation_id", "stage,cluster_uid,name", "ttttitt", true},
		{"local_automation_bindings", "stage,cluster_uid,project_uid,owner_id,management_key,creation_generation,resource_uid,operation_id,revision,retired", "stage,cluster_uid,project_uid,owner_id,management_key,creation_generation", "tttttittti", true},
		{"local_automation_admissions", "stage,operation_id,cluster_uid,project_uid,owner_id,management_key,resource_uid,request_id,principal_uid,method,payload_id,binding_generation,admitted_generation,sequence,configuration_json", "stage,operation_id", "tttttttttttiiit", true},
		{"local_automation_key_epochs", "stage,cluster_uid,recipient_epoch,membership_generation,config_digest,equality_epoch,predecessor_activation_sequence,activation_sequence", "stage,cluster_uid,recipient_epoch", "tttittii", true},
		{"local_automation_key_recipients", "stage,cluster_uid,recipient_epoch,membership_generation,config_digest,host,host_incarnation,admitted_at,admission_serial,voter_incarnation,key_id,recipient,enrollment_ref,recipient_ack_ref,equality_ack_ref,first_sequence", "stage,cluster_uid,recipient_epoch,host", "tttittitttttttti", true},
		{"local_automation_payload_wrappings", "stage,cluster_uid,operation_id,payload_id,admission_sequence,wrapping_sequence,wrapping_digest,recipient_epoch,membership_generation,config_digest", "stage,cluster_uid,operation_id,wrapping_sequence", "ttttiittit", true},
		{"local_automation_target_operations", "stage,cluster_uid,operation_id,kind,project_uid,principal_uid,request_id,resource_uid,target_name,sequence,decision_digest,body_json,assignment_json", "stage,cluster_uid,operation_id", "tttttttttittt", true},
		{"local_automation_target_reservations", "stage,cluster_uid,target_key,operation_id,sequence", "stage,cluster_uid,target_key", "tttti", true},
		{"local_automation_lifetimes", "kind,name,witness,origin,retired,valid", "kind,name,witness", "ttttii", false},
		{"local_automation_credential_issuance", "kind,credential_id,username,witness,principal_uid,cluster_uid,valid", "kind,credential_id", "tttttti", false},
	}
}

// Current86 preserves the old semantic prefix and adds target projections
// before the two private observation suffixes. Old frames use their own layout.
func aggregateLocalTables() []aggregateLocalTable {
	old := aggregateLocalTables83()
	boundary := 18 + len(automationArchived83SemanticTables)
	tables := append([]aggregateLocalTable(nil), old[:boundary]...)
	for _, d := range automationSemanticTables[len(automationArchived83SemanticTables):] {
		var shape strings.Builder
		for _, column := range strings.Split(d.columns, ",") {
			if strings.Contains(","+d.integers+",", ","+column+",") {
				shape.WriteByte('i')
			} else {
				shape.WriteByte('t')
			}
		}
		tables = append(tables, aggregateLocalTable{d.table, d.columns, d.primaryKey, shape.String(), true})
	}
	return append(tables, old[boundary:]...)
}

func (d aggregateLocalTable) descriptor() automationCutSection {
	return automationCutSection{"local-snapshot/v1/" + d.table, d.table, d.columns}
}
func aggregateLocalColumns(s string) []string {
	out := strings.Split(s, ",")
	for i := range out {
		out[i] = strings.TrimSpace(out[i])
	}
	return out
}
func aggregateLocalLimit(column string) int64 {
	switch column {
	case "record":
		return maxAutomationCutRecordBytes
	case "value_json":
		return MaxAutomationClaimBytes
	case "certificate", "accept_json":
		return maxSourceCertificateBytes
	case "identity":
		return MaxAutomationClaimBytes
	case "receipt_json", "metadata":
		return maxAutomationCutMetadataBytes
	case "members_json":
		return maxSourceConfigBytes
	case "configuration_json", "grant_json", "progress_json", "artifact_json", "terminal_json":
		return MaxAutomationClaimBytes
	case "promised_nonce", "accepted_nonce":
		return 256
	default:
		return maxSourceFieldBytes
	}
}

// walkAggregateLocalTable uses the actual PK tuple, including its TEXT/BLOB
// ordering. The first probe has no lower bound, so malformed negative, NULL or
// fractional keys cannot hide below an invented starting cursor. No raw key or
// body reaches Go until its type and length have been checked in this snapshot.
func walkAggregateLocalTable(ctx context.Context, tx *LocalTx, d aggregateLocalTable, stage string, visit func(int64, Row) error) error {
	return walkAggregateBoundedTable(ctx, tx, d, stage, aggregateLocalLimit, maxAutomationCutRecordBytes+maxSourceFieldBytes, visit)
}

// The common indexed reader probes types and lengths before loading one body.
func walkAggregateBoundedTable(ctx context.Context, tx *LocalTx, d aggregateLocalTable, stage string, limitFor func(string) int64, rowLimit int64, visit func(int64, Row) error) error {
	return walkAggregateBoundedTableFrom(ctx, tx, d, stage, limitFor, rowLimit, nil, visit)
}

// A private cursor may resume the same indexed one-body reader. The first probe
// remains unbounded below, so malformed keys cannot disappear before a cursor.
func walkAggregateBoundedTableFrom(ctx context.Context, tx *LocalTx, d aggregateLocalTable, stage string, limitFor func(string) int64, rowLimit int64, after []any, visit func(int64, Row) error) error {
	return walkAggregateBoundedTableFiltered(ctx, tx, d, stage, limitFor, rowLimit, after, "", nil, visit)
}

// Scope is supplied only by closed internal storage adapters, never an API or
// received descriptor. The ordinary stage/cursor path keeps its exact domain.
func walkAggregateBoundedTableFiltered(ctx context.Context, tx *LocalTx, d aggregateLocalTable, stage string, limitFor func(string) int64, rowLimit int64, after []any, scope string, scopeArgs []any, visit func(int64, Row) error) error {
	cols, keys := aggregateLocalColumns(d.columns), aggregateLocalColumns(d.keys)
	if len(cols) != len(d.shape) {
		return errors.New("local snapshot descriptor shape")
	}
	probes := make([]string, 0, len(cols)*3)
	for i, col := range cols {
		probes = append(probes, fmt.Sprintf("typeof(%s) AS t%d,length(CAST(%s AS BLOB)) AS l%d", col, i, col, i))
		if d.shape[i] == 'i' {
			probes = append(probes, fmt.Sprintf("CASE WHEN typeof(%s)='integer' THEN %s ELSE NULL END AS n%d", col, col, i))
		}
	}
	var ordinal int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		where := scope
		args := append([]any(nil), scopeArgs...)
		if d.stage {
			if where != "" {
				where += " AND "
			}
			where += "stage=?"
			args = append(args, stage)
		}
		if after != nil {
			if where != "" {
				where += " AND "
			}
			marks := strings.TrimSuffix(strings.Repeat("?,", len(keys)), ",")
			if len(keys) == 1 {
				where += keys[0] + ">?"
			} else {
				where += "(" + strings.Join(keys, ",") + ")>(" + marks + ")"
			}
			args = append(args, after...)
		}
		suffix := " FROM " + d.table
		if where != "" {
			suffix += " WHERE " + where
		}
		suffix += " ORDER BY " + strings.Join(keys, ",") + " LIMIT 1"
		rows, err := tx.Query(ctx, "SELECT "+strings.Join(probes, ",")+suffix, args...)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		var size int64
		for i, col := range cols {
			kind := rows[0].String(fmt.Sprintf("t%d", i))
			n := rows[0].Int64(fmt.Sprintf("l%d", i))
			shape := d.shape[i]
			nullable := shape == 'T'
			if nullable {
				shape = 't'
			}
			want := map[byte]string{'t': "text", 'i': "integer", 'b': "blob"}[shape]
			if kind == "null" && nullable {
				continue
			}
			limit := limitFor(col)
			if col == "value_json" && (d.table == "local_recovery_claims" || d.table == "local_incarnation_claims") {
				limit = maxAutomationCutRecordBytes
			}
			if kind != want || n < 0 || n > limit {
				return fmt.Errorf("local snapshot invalid type or bound: %s.%s", d.table, col)
			}
			if shape == 'i' && rows[0].Int64(fmt.Sprintf("n%d", i)) < 0 {
				return fmt.Errorf("local snapshot negative integer: %s.%s", d.table, col)
			}
			size += n
		}
		if d.table == "local_automation_cut_records" {
			rowLimit = maxAutomationCutRecordBytes + maxSourceFieldBytes + 32
		}
		if size > rowLimit {
			return fmt.Errorf("local snapshot row exceeds bound: %s", d.table)
		}
		rows, err = tx.Query(ctx, "SELECT "+strings.Join(keys, ",")+suffix, args...)
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			return errors.New("local snapshot key disappeared")
		}
		after = append([]any(nil), rows[0].Values...)
		predicates := make([]string, len(keys))
		for i, key := range keys {
			predicates[i] = key + "=?"
		}
		rows, err = tx.Query(ctx, "SELECT "+d.columns+" FROM "+d.table+" WHERE "+strings.Join(predicates, " AND ")+" LIMIT 1", after...)
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			return errors.New("local snapshot body disappeared")
		}
		if ordinal == math.MaxInt64 {
			return errors.New("local snapshot count overflow")
		}
		ordinal++
		if err = visit(ordinal, rows[0]); err != nil {
			return err
		}
	}
}

func aggregateLocalFreshScratch(ctx context.Context, tx *LocalTx, namespace string) error {
	if namespace == "" || len(namespace) > maxSourceFieldBytes {
		return errors.New("local scratch namespace invalid")
	}
	for _, d := range automationSemanticTables {
		rows, err := tx.Query(ctx, "SELECT 1 AS present FROM "+d.table+" WHERE stage=? LIMIT 1", "receiver-audit:"+namespace)
		if err != nil {
			return err
		}
		if len(rows) != 0 {
			return errors.New("local scratch stage already exists")
		}
	}
	rows, err := tx.Query(ctx, `SELECT 1 AS present FROM local_automation_receiver_requests WHERE audit=? LIMIT 1`, namespace)
	if err != nil {
		return err
	}
	if len(rows) != 0 {
		return errors.New("local scratch requests already exist")
	}
	return nil
}

func aggregateLocalCompareSemantic(ctx context.Context, tx *LocalTx, stage string) error {
	// A typed, bounded ordered digest on each side includes all exact bytes and
	// count/end markers, avoiding EXCEPT's history-sized intermediate material.
	for _, d := range aggregateLocalTables()[18 : 18+len(automationSemanticTables)] {
		digest := func(which string) (string, error) {
			h := sha256.New()
			sourceHash(h, []byte(d.table))
			var count int64
			err := walkAggregateLocalTable(ctx, tx, d, which, func(n int64, row Row) error {
				row.Values[0] = "" // Stage is the private namespace, not semantic content.
				raw, err := encodeAggregateLocalRecord(d.descriptor().name, n, row)
				if err != nil {
					return err
				}
				sourceHash(h, raw)
				count = n
				return nil
			})
			sourceHash(h, []byte("end"), automationCutInteger(count))
			return hex.EncodeToString(h.Sum(nil)), err
		}
		active, err := digest("")
		if err != nil {
			return err
		}
		scratch, err := digest(stage)
		if err != nil {
			return err
		}
		if active != scratch {
			return fmt.Errorf("active automation projection differs from certified history: %s", d.table)
		}
	}
	return nil
}

func aggregateLocalSnapshot(ctx context.Context, tx *LocalTx, a *AutomationReceiverAttempt, c *Client, visit func(int, int64, Row, []byte) error) (string, error) {
	if a == nil || c == nil {
		return "", errors.New("local snapshot attempt unavailable")
	}
	if err := automationVerifySemanticSchemaTx(ctx, tx); err != nil {
		return "", err
	}
	h := sha256.New()
	sourceHash(h, []byte("litevirt/local-dependencies/v1"), []byte(a.id), a.binding, []byte(c.hostName))
	for section, d := range aggregateLocalTables() {
		sourceHash(h, []byte("table"), []byte(d.table), []byte(d.columns), []byte(d.keys))
		var count int64
		err := walkAggregateLocalTable(ctx, tx, d, "", func(n int64, row Row) error {
			// Owned original frames remain in their immutable owner table. Bind
			// every exact byte here; persist only its bounded digest reference rather
			// than nesting a maximum-size original frame inside another frame.
			if d.table == "local_automation_cut_records" {
				original := row.Bytes("record")
				sourceHash(h, []byte("original-record-bytes"), original)
				row.Values = append([]any(nil), row.Values...)
				row.Values[len(row.Values)-1] = []byte(sourceDigest(original))
			}
			raw, err := encodeAggregateLocalRecord(d.descriptor().name, n, row)
			if err != nil {
				return err
			}
			sourceHash(h, raw)
			count = n
			if visit != nil {
				return visit(section, n, row, raw)
			}
			return nil
		})
		if err != nil {
			return "", err
		}
		sourceHash(h, []byte("end"), automationCutInteger(count))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func rehashAggregateLocalTx(ctx context.Context, tx *LocalTx, a *AutomationReceiverAttempt, c *Client) (string, error) {
	return aggregateLocalSnapshot(ctx, tx, a, c, nil)
}

func auditAggregateLocalTx(ctx context.Context, tx *LocalTx, a *AutomationReceiverAttempt, c *Client, namespace string) (aggregateLocalAudit, error) {
	var out aggregateLocalAudit
	out.attempt = a
	if err := aggregateLocalFreshScratch(ctx, tx, namespace); err != nil {
		return out, err
	}
	refs, err := tx.Query(ctx, `SELECT 1 AS present FROM local_automation_receiver_refs WHERE audit=? LIMIT 1`, namespace)
	if err != nil {
		return out, err
	}
	if len(refs) != 0 {
		return out, errors.New("local scratch index already exists")
	}
	out.dependency, err = rehashAggregateLocalTx(ctx, tx, a, c)
	if err != nil {
		return out, err
	}
	out.id = sourceDigest([]byte("litevirt/local-audit/v1"), []byte(a.id), []byte(out.dependency))
	var observation aggregateLocalObservation
	_, err = aggregateLocalSnapshot(ctx, tx, a, c, func(section int, n int64, row Row, raw []byte) error {
		if err := observation.observe(&out, section, n, row); err != nil {
			return err
		}
		return aggregateLocalSaveRow(ctx, tx, out.id, section, n, raw)
	})
	if err != nil {
		return out, err
	}
	if err = aggregateLocalStoredRows(ctx, tx, out.id, observation.counts); err != nil {
		return out, err
	}
	if err = observation.audit(ctx, tx, receiverAuditContext{a.id, a.request, a.facts}, c.hostName, namespace, out.id, false, &out); err != nil {
		return out, err
	}
	head, _ := json.Marshal(out.head)
	origin := []byte(`{"scope":"native-local-storage","lifecycle":"private-observations-only","custody":"unsupported-required-coverage-refused"}`)
	rows, err := tx.Query(ctx, `SELECT typeof(head) AS head_type,length(head) AS head_size,typeof(origin) AS origin_type,length(origin) AS origin_size FROM local_automation_local_audits WHERE id=? LIMIT 1`, out.id)
	if err != nil {
		return out, err
	}
	if len(rows) > 0 {
		if rows[0].String("head_type") != "blob" || rows[0].Int64("head_size") != int64(len(head)) || rows[0].String("origin_type") != "blob" || rows[0].Int64("origin_size") != int64(len(origin)) {
			return out, errors.New("local audit identity collision")
		}
		rows, err = tx.Query(ctx, `SELECT 1 AS same FROM local_automation_local_audits WHERE id=? AND attempt=? AND dependency=? AND head=? AND coverage=? AND records=? AND origin=? LIMIT 1`, out.id, a.id, out.dependency, head, out.coverage, out.records, origin)
		if err != nil {
			return out, err
		}
		if len(rows) != 1 {
			return out, errors.New("local audit identity collision")
		}
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO local_automation_local_audits(id,attempt,dependency,head,coverage,records,origin) VALUES(?,?,?,?,?,?,?)`, out.id, a.id, out.dependency, head, out.coverage, out.records, origin)
	}
	return out, err
}

func aggregateLocalSaveRow(ctx context.Context, tx *LocalTx, id string, section int, n int64, raw []byte) error {
	rows, err := tx.Query(ctx, `SELECT typeof(record) AS kind,length(record) AS size FROM local_automation_local_rows WHERE local_id=? AND section=? AND ordinal=? LIMIT 1`, id, section, n)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		_, err = tx.Exec(ctx, `INSERT INTO local_automation_local_rows(local_id,section,ordinal,record) VALUES(?,?,?,?)`, id, section, n, raw)
		return err
	}
	if rows[0].String("kind") != "blob" || rows[0].Int64("size") != int64(len(raw)) {
		return errors.New("local snapshot identity collision")
	}
	rows, err = tx.Query(ctx, `SELECT 1 AS same FROM local_automation_local_rows WHERE local_id=? AND section=? AND ordinal=? AND record=? LIMIT 1`, id, section, n, raw)
	if err != nil {
		return err
	}
	if len(rows) != 1 {
		return errors.New("local snapshot identity collision")
	}
	return nil
}

func (s receiverAuditStore) localRecord(ctx context.Context, component int, ordinal int64) (Row, error) {
	if component < 3 || component > 11 || ordinal <= 0 {
		return Row{}, errors.New("local record identity")
	}
	rows, err := s.query(ctx, `SELECT typeof(record) AS kind,length(record) AS size FROM local_automation_local_rows WHERE local_id=? AND section=? AND ordinal=? LIMIT 1`, s.localID, component-3, ordinal)
	if err != nil {
		return Row{}, err
	}
	if len(rows) != 1 || rows[0].String("kind") != "blob" || rows[0].Int64("size") <= 0 || rows[0].Int64("size") > maxAggregateLocalRecordBytes {
		return Row{}, errors.New("local record missing or over bound")
	}
	rows, err = s.query(ctx, `SELECT record FROM local_automation_local_rows WHERE local_id=? AND section=? AND ordinal=? LIMIT 1`, s.localID, component-3, ordinal)
	if err != nil {
		return Row{}, err
	}
	if len(rows) != 1 {
		return Row{}, errors.New("local record disappeared")
	}
	d := aggregateLocalTables()[component-3]
	row, err := decodeAutomationFramedRow(d.descriptor(), ordinal, rows[0].Bytes("record"), maxAggregateLocalRecordBytes)
	if err != nil {
		return Row{}, err
	}
	canonical, err := encodeAggregateLocalRecord(d.descriptor().name, ordinal, row)
	if err != nil || !bytes.Equal(canonical, rows[0].Bytes("record")) {
		return Row{}, errors.New("local record noncanonical")
	}
	count := len(aggregateLocalColumns(automationCutSections[component-3].columns))
	row.Columns = row.Columns[:count]
	row.Values = row.Values[:count]
	if err = receiverAuditRowTypes(component, row); err != nil {
		return Row{}, err
	}
	return row, nil
}

// Origin implementation below reuses the same source semantic adapter over the
// actual retained owned cut, never Freeze or a caller-authored source assertion.
func (s receiverAuditStore) ownedRecord(ctx context.Context, component int, ordinal int64) (Row, error) {
	if component < 3 || component > 11 || ordinal <= 0 {
		return Row{}, errors.New("owned cut record identity")
	}
	rows, err := s.query(ctx, `SELECT typeof(record) AS kind,length(record) AS size FROM local_automation_cut_records WHERE cut_id=? AND section=? AND ordinal=? LIMIT 1`, s.ownedCutID, component-3, ordinal)
	if err != nil {
		return Row{}, err
	}
	if len(rows) != 1 || rows[0].String("kind") != "blob" || rows[0].Int64("size") <= 0 || rows[0].Int64("size") > maxAutomationCutRecordBytes {
		return Row{}, errors.New("owned cut record missing or over bound")
	}
	rows, err = s.query(ctx, `SELECT record FROM local_automation_cut_records WHERE cut_id=? AND section=? AND ordinal=? LIMIT 1`, s.ownedCutID, component-3, ordinal)
	if err != nil {
		return Row{}, err
	}
	if len(rows) != 1 {
		return Row{}, errors.New("owned cut record disappeared")
	}
	raw := rows[0].Bytes("record")
	row, err := decodeSourceCutRow(component-3, ordinal, raw)
	if err != nil {
		return Row{}, err
	}
	canonical, err := encodeAutomationCutRecord(automationCutSections[component-3].name, ordinal, row)
	if err != nil || !bytes.Equal(canonical, raw) {
		return Row{}, errors.New("owned cut noncanonical")
	}
	if err = receiverAuditRowTypes(component, row); err != nil {
		return Row{}, err
	}
	return row, nil
}

// walkAggregateStoredFrames checks every actual tuple, not just expected
// sections. Its complete leading-key range rejects fractional/extra keys before
// either raw keys or bodies are materialized.
func walkAggregateStoredFrames(ctx context.Context, tx *LocalTx, table, idColumn, id string, visit func(int, int64, []byte) error) error {
	limit := int64(maxAutomationCutRecordBytes)
	if table == "local_automation_local_rows" {
		limit = maxAggregateLocalRecordBytes
	}
	return walkAutomationStoredFrames(ctx, tx, table, idColumn+"=?", []any{id}, "section", limit, visit)
}

// The concrete ordinary and retained address owners supply closed SQL names.
// Share the same length-first one-body keyset reader across both storage routes.
func walkAutomationStoredFrames(ctx context.Context, tx *LocalTx, table, scope string, scopeArgs []any, sectionColumn string, limit int64, visit func(int, int64, []byte) error) error {
	return walkAutomationStoredFramesBounded(ctx, tx, table, scope, scopeArgs, sectionColumn, limit, nil, visit)
}

// frameBound restricts a probed tuple before its body is materialized. It supplies
// only a numeric bound; semantic validation still belongs to the shared audits.
func walkAutomationStoredFramesBounded(ctx context.Context, tx *LocalTx, table, scope string, scopeArgs []any, sectionColumn string, limit int64, frameBound func(int, int64) int64, visit func(int, int64, []byte) error) error {
	var section, ordinal int64
	first := true
	for {
		where := scope
		args := append([]any(nil), scopeArgs...)
		if !first {
			where += " AND (" + sectionColumn + ",ordinal)>(?,?)"
			args = append(args, section, ordinal)
		}
		suffix := " FROM " + table + " WHERE " + where + " ORDER BY " + table + "." + sectionColumn + "," + table + ".ordinal LIMIT 1"
		rows, err := tx.Query(ctx, `SELECT typeof(`+sectionColumn+`) AS sk,typeof(ordinal) AS ok,typeof(record) AS rk,CASE WHEN typeof(`+sectionColumn+`)='integer' THEN `+sectionColumn+` ELSE NULL END AS section,CASE WHEN typeof(ordinal)='integer' THEN ordinal ELSE NULL END AS ordinal,length(record) AS size`+suffix, args...)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		if rows[0].String("sk") != "integer" || rows[0].String("ok") != "integer" || rows[0].String("rk") != "blob" || rows[0].Int64("section") < 0 || rows[0].Int64("ordinal") <= 0 || rows[0].Int64("size") <= 0 || rows[0].Int64("size") > limit {
			return errors.New("local snapshot invalid stored frame key or bound")
		}
		section, ordinal = rows[0].Int64("section"), rows[0].Int64("ordinal")
		if section > math.MaxInt32 {
			return errors.New("local snapshot stored section exceeds bound")
		}
		if frameBound != nil && rows[0].Int64("size") > frameBound(int(section), ordinal) {
			return errors.New("stored frame exceeds component or inventory bound")
		}
		first = false
		bodyArgs := append(append([]any(nil), scopeArgs...), section, ordinal, rows[0].Int64("size"))
		rows, err = tx.Query(ctx, "SELECT record FROM "+table+" WHERE "+scope+" AND "+sectionColumn+"=? AND ordinal=? AND typeof(record)='blob' AND length(CAST(record AS BLOB))=? LIMIT 1", bodyArgs...)
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			return errors.New("stored local frame disappeared")
		}
		if err = visit(int(section), ordinal, rows[0].Bytes("record")); err != nil {
			return err
		}
	}
}

func aggregateLocalStoredRows(ctx context.Context, tx *LocalTx, id string, counts []int64) error {
	seen := make([]int64, len(counts))
	err := walkAggregateStoredFrames(ctx, tx, "local_automation_local_rows", "local_id", id, func(section int, n int64, _ []byte) error {
		if section >= len(seen) || seen[section] == math.MaxInt64 || n != seen[section]+1 || n > counts[section] {
			return errors.New("local snapshot identity collision inventory")
		}
		seen[section] = n
		return nil
	})
	if err != nil {
		return err
	}
	for i, n := range seen {
		if n != counts[i] {
			return errors.New("local snapshot missing stored frame")
		}
	}
	return nil
}

func aggregateLocalVerifyCut(ctx context.Context, tx *LocalTx, m automationCutMetadata) error {
	// Inventory has exactly nine sections, established by readAutomationCutMetadata.
	hashes := make([]hash.Hash, len(m.Inventory))
	counts := make([]int64, len(hashes))
	sizes := make([]int64, len(hashes))
	for i, inv := range m.Inventory {
		h := sha256.New()
		prefix, _ := automationCutFrame("section/v1", []byte(inv.Section))
		h.Write(prefix)
		hashes[i] = h
	}
	err := walkAggregateStoredFrames(ctx, tx, "local_automation_cut_records", "cut_id", m.ID, func(section int, n int64, raw []byte) error {
		if section >= len(hashes) || counts[section] == math.MaxInt64 || n != counts[section]+1 || n > m.Inventory[section].Records {
			return errors.New("owned cut record inventory mismatch")
		}
		if sizes[section] > m.Inventory[section].Bytes-int64(len(raw)) {
			return errors.New("owned cut byte inventory mismatch")
		}
		counts[section] = n
		sizes[section] += int64(len(raw))
		hashes[section].Write(raw)
		return nil
	})
	if err != nil {
		return err
	}
	for i, inv := range m.Inventory {
		if counts[i] != inv.Records || sizes[i] != inv.Bytes || hex.EncodeToString(hashes[i].Sum(nil)) != inv.Digest {
			return errors.New("owned cut inventory mismatch")
		}
	}
	return nil
}

// aggregateLocalOriginsTx scopes one lazily reconstructed owned cut to this
// actual transaction and local contribution. The UNIQUE(generation,incarnation)
// lookup has exactly one candidate, even if unrelated cuts are retained. No
// reader, decoded record, or acceptance body is returned to the caller.
// On refusal the enclosing FULL transaction rolls back all fresh scratch rows.
func aggregateLocalOriginsTx(ctx context.Context, tx *LocalTx, local aggregateLocalAudit, visit func(func(int, int64) ([]byte, error)) error) error {
	var owned *receiverAuditStore
	err := visit(func(component int, ordinal int64) (origin []byte, err error) {
		// Every failure preserves the specific missing/unusable-origin obligation.
		defer func() {
			if err != nil {
				err = fmt.Errorf("local acceptance origin unavailable: %w", err)
			}
		}()
		if (local.attempt == nil && local.retained == nil) || component < 3 || component > 4 {
			return nil, errors.New("invalid local acceptance reference")
		}
		key, acceptedIdentity, err := aggregateLocalRetainedAcceptance(ctx, local.store, component, ordinal)
		if err != nil {
			return nil, err
		}

		if owned == nil {
			store, err := aggregateLocalOwnedStoreTx(ctx, tx, local)
			if err != nil {
				return nil, err
			}
			owned = &store
		}
		m := owned.publication.manifest.Cut
		root := owned.publication.manifest.Root
		namespace := owned.id
		encodedKey, _ := json.Marshal(key)
		rows, err := tx.Query(ctx, `SELECT ordinal FROM local_automation_receiver_refs WHERE audit=? AND component=? AND semantic_key=? LIMIT 1`, namespace, component, encodedKey)
		if err != nil {
			return nil, err
		}
		if len(rows) != 1 {
			return nil, errors.New("original acceptance missing from owned cut")
		}
		originalOrdinal := rows[0].Int64("ordinal")
		originalIdentity, originalDigest, err := aggregateLocalOriginalAcceptance(ctx, *owned, component, originalOrdinal)
		if err != nil {
			return nil, err
		}
		// Promise floors may have risen independently; the exact signed acceptance,
		// full value and full logical key must still be the retained original.
		if originalIdentity != acceptedIdentity {
			return nil, errors.New("owned cut acceptance bytes differ")
		}
		ref := struct {
			Version                                      int
			Kind, Source, Incarnation, Cut, Root, Record string
			Generation                                   int64
			Component                                    int
			Ordinal                                      int64
		}{1, "native-owned-cut", m.Source, m.Incarnation, m.ID, root, originalDigest, m.Generation, component, originalOrdinal}
		origin, err = json.Marshal(ref)
		if err != nil {
			return nil, err
		}
		return origin, nil
	})
	if err != nil {
		return err
	}
	if owned != nil {
		if err := aggregateCleanScratchTx(ctx, tx, owned.id); err != nil {
			return fmt.Errorf("local acceptance origin unavailable: %w", err)
		}
	}
	return nil
}

func aggregateLocalOwnedStoreTx(ctx context.Context, tx *LocalTx, local aggregateLocalAudit) (receiverAuditStore, error) {
	if local.retained != nil {
		return retainedLocalOwnedStoreTx(ctx, tx, local)
	}
	a := local.attempt
	// UNIQUE(generation,incarnation) is the actual owned-cut lookup index.
	rows, err := tx.Query(ctx, `SELECT typeof(id) AS ik,length(CAST(id AS BLOB)) AS il,typeof(metadata) AS mk,length(metadata) AS ml,typeof(root) AS rk,length(CAST(root AS BLOB)) AS rl FROM local_automation_cuts WHERE generation=? AND incarnation=? LIMIT 1`, a.request.Generation, a.facts.Incarnation)
	if err != nil {
		return receiverAuditStore{}, err
	}
	if len(rows) != 1 || rows[0].String("ik") != "text" || rows[0].Int64("il") <= 0 || rows[0].Int64("il") > 128 || rows[0].String("mk") != "blob" || rows[0].Int64("ml") <= 0 || rows[0].Int64("ml") > maxAutomationCutMetadataBytes || rows[0].String("rk") != "text" || rows[0].Int64("rl") != 64 {
		return receiverAuditStore{}, errors.New("completed native cut missing or over bound")
	}
	rows, err = tx.Query(ctx, `SELECT id,metadata,root FROM local_automation_cuts WHERE generation=? AND incarnation=? LIMIT 1`, a.request.Generation, a.facts.Incarnation)
	if err != nil {
		return receiverAuditStore{}, err
	}
	if len(rows) != 1 {
		return receiverAuditStore{}, errors.New("owned cut disappeared")
	}
	m, err := readAutomationCutMetadata(rows[0])
	if err != nil {
		return receiverAuditStore{}, err
	}
	root := rows[0].String("root")
	if m.Source != local.store.source || m.Generation != a.request.Generation || m.Incarnation != a.facts.Incarnation || m.MembersHash != a.facts.Old.MembersHash {
		return receiverAuditStore{}, errors.New("owned cut native lifetime differs")
	}
	if err = aggregateLocalVerifyCut(ctx, tx, m); err != nil {
		return receiverAuditStore{}, err
	}
	namespace := local.store.id + ":owned-origin"
	if err = aggregateLocalFreshScratch(ctx, tx, namespace); err != nil {
		return receiverAuditStore{}, err
	}
	rows, err = tx.Query(ctx, `SELECT 1 AS present FROM local_automation_receiver_refs WHERE audit=? LIMIT 1`, namespace)
	if err != nil {
		return receiverAuditStore{}, err
	}
	if len(rows) != 0 {
		return receiverAuditStore{}, errors.New("owned origin scratch index already exists")
	}
	// This adapter consumes an actual native owned cut. No publication/signature
	// is fabricated: lineage's explicit ownedCutID mode omits only the transport
	// lineage digest check, and validates the complete original native standing.
	owned := receiverAuditStore{tx: tx, prepared: local.store.prepared, attempt: a.id, source: m.Source, id: namespace, evidenceID: m.ID, ownedCutID: m.ID, publication: receiverPublication{manifest: sourceManifest{Cut: m, Incarnation: m.Incarnation, OldValue: sourceConfigDigest(a.facts.Old), Root: root}}}
	if _, err = owned.index(ctx); err != nil {
		return receiverAuditStore{}, err
	}
	if _, err = owned.lineage(ctx, a); err != nil {
		return receiverAuditStore{}, err
	}
	if _, _, err = owned.history(ctx); err != nil {
		return receiverAuditStore{}, err
	}
	if _, _, err = owned.claimsAndCoverage(ctx, m.Head); err != nil {
		return receiverAuditStore{}, err
	}
	return owned, nil
}

// Only the bounded digest of exact accepted fields survives the intervening
// owned-cut scan. Mutable promises and the row generation are deliberately not
// acceptance provenance; the complete current row has its own dependency hash.
func aggregateLocalAcceptedIdentity(row Row) string {
	h := sha256.New()
	sourceHash(h, []byte("litevirt/local-accepted-original/v1"), automationCutInteger(row.Int64("accepted_round")), []byte(row.String("accepted_coord")), row.Bytes("accepted_nonce"), []byte(row.String("value_json")), []byte(row.String("value_digest")), []byte(row.String("accept_json")))
	return hex.EncodeToString(h.Sum(nil))
}

// These read scopes return only bounded keys and fresh fingerprints. No Row,
// value, or frame escapes into the intervening owned-cut/history audit.
func aggregateLocalRetainedAcceptance(ctx context.Context, store receiverAuditStore, component int, ordinal int64) (ClaimKey, string, error) {
	row, err := store.record(ctx, component, ordinal)
	if err != nil {
		return ClaimKey{}, "", err
	}
	key := ClaimKey{TargetKind: row.String("target_kind"), TargetName: row.String("target_name"), Incarnation: row.String("incarnation"), OwnerEpoch: row.Int64("owner_epoch"), Attempt: row.Int64("attempt")}
	if !key.IsGenerationScoped() || row.Int64("accepted_round") == 0 {
		return ClaimKey{}, "", errors.New("local copy has no transferable acceptance")
	}
	return key, aggregateLocalAcceptedIdentity(row), nil
}

func aggregateLocalOriginalAcceptance(ctx context.Context, store receiverAuditStore, component int, ordinal int64) (string, string, error) {
	row, err := store.record(ctx, component, ordinal)
	if err != nil {
		return "", "", err
	}
	raw, err := encodeAutomationCutRecord(automationCutSections[component-3].name, ordinal, row)
	if err != nil {
		return "", "", err
	}
	return aggregateLocalAcceptedIdentity(row), sourceDigest(raw), nil
}

// Preserve the full native record allowance. Local timestamps are separately
// bounded to one field; fixed descriptor/ordinal/type framing fits in 1 KiB.
// This private snapshot limit never changes native/archive codec limits.
const maxAggregateLocalRecordBytes = maxAutomationCutRecordBytes + maxSourceFieldBytes + 1024

func encodeAggregateLocalRecord(domain string, ordinal int64, row Row) ([]byte, error) {
	if ordinal <= 0 {
		return nil, errors.New("invalid local ordinal")
	}
	var b bytes.Buffer
	b.WriteString("LVCUT\x01")
	part := func(p []byte) error {
		if len(p) > maxAggregateLocalRecordBytes || b.Len() > maxAggregateLocalRecordBytes-4-len(p) {
			return errors.New("local record exceeds bound")
		}
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		b.Write(n[:])
		b.Write(p)
		return nil
	}
	if err := part([]byte(domain)); err != nil {
		return nil, err
	}
	if err := part(automationCutInteger(ordinal)); err != nil {
		return nil, err
	}
	for _, field := range row.Values {
		var p []byte
		switch v := field.(type) {
		case nil:
			p = []byte{0}
		case int64:
			p = append([]byte{1}, automationCutInteger(v)...)
		case string:
			if !utf8.ValidString(v) {
				return nil, errors.New("invalid local text")
			}
			p = append([]byte{2}, []byte(v)...)
		case []byte:
			p = append([]byte{3}, v...)
		default:
			return nil, errors.New("invalid local field type")
		}
		if err := part(p); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}
