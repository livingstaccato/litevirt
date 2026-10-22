package corrosion

import (
	"context"
	"fmt"
	"strings"
)

// These node-local projections are derived from certified history. The
// empty stage is active state; every nonempty stage is isolated reconstruction.
// Neither is exported as authority: source audits compare active state with a
// causal reconstruction, and receivers build their own isolated projections.
var automationSemanticTables = []struct{ table, columns, integers, primaryKey, nullable string }{
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
	// Append to preserve the existing first-eight identity/ownership descriptor boundary.
	{"local_automation_target_operations", "stage,cluster_uid,operation_id,kind,project_uid,principal_uid,request_id,resource_uid,target_name,sequence,decision_digest,body_json,assignment_json", "sequence", "stage,cluster_uid,operation_id", ""},
	{"local_automation_target_reservations", "stage,cluster_uid,target_key,operation_id,sequence", "sequence", "stage,cluster_uid,target_key", ""},
	{"local_automation_executors", "stage,cluster_uid,operation_id,resource_uid,executor_generation,grant_sequence,grant_digest,admission_sequence,admission_digest,grant_json", "executor_generation,grant_sequence,admission_sequence", "stage,cluster_uid,operation_id", ""},
	{"local_automation_execution_progress", "stage,cluster_uid,operation_id,resource_uid,applied_sequence,progress_json", "applied_sequence", "stage,cluster_uid,operation_id", ""},
	{"local_automation_execution_artifacts", "stage,cluster_uid,operation_id,artifact_id,resource_uid,artifact_key,artifact_kind,backend,object_id,applied_sequence,artifact_json", "applied_sequence", "stage,cluster_uid,operation_id,artifact_id", ""},
	{"local_automation_execution_terminals", "stage,cluster_uid,operation_id,resource_uid,applied_sequence,terminal_json", "applied_sequence", "stage,cluster_uid,operation_id", ""},
	{"local_automation_identity_continuity", "stage,cluster_uid,uid,generation,original_witness,parent_kind,parent_alias,parent_realm,parent_birth", "generation", "stage,uid,generation", ""},
}

func automationVerifySemanticSchemaTx(ctx context.Context, tx *LocalTx) error {
	for _, descriptor := range automationSemanticTables {
		rows, err := tx.Query(ctx, "PRAGMA table_xinfo("+descriptor.table+")")
		if err != nil {
			return err
		}
		columns := strings.Split(descriptor.columns, ",")
		if len(rows) != len(columns) {
			return fmt.Errorf("unsupported automation semantic schema: %s", descriptor.table)
		}
		for i, column := range columns {
			expectedType := "TEXT"
			if strings.Contains(","+descriptor.integers+",", ","+column+",") {
				expectedType = "INTEGER"
			}
			notNull := int64(1)
			// SQLite's ordinary TEXT PRIMARY KEY reports nullable unless the
			// DDL also declares NOT NULL (the semantic-head stage does not).
			if descriptor.nullable == column {
				notNull = 0
			}
			primaryKey := int64(0)
			for keyIndex, key := range strings.Split(descriptor.primaryKey, ",") {
				if key == column {
					primaryKey = int64(keyIndex + 1)
				}
			}
			row := rows[i]
			if row.Int64("cid") != int64(i) || row.String("name") != column || row.String("type") != expectedType || row.Int64("notnull") != notNull || row.Int64("pk") != primaryKey || row.Int64("hidden") != 0 || row.get("dflt_value") != nil {
				return fmt.Errorf("unsupported automation semantic column shape: %s.%s", descriptor.table, column)
			}
		}
	}
	if err := automationVerifyKeyIndexesTx(ctx, tx); err != nil {
		return err
	}
	if err := automationVerifyExecutionIndexesTx(ctx, tx); err != nil {
		return err
	}
	return automationVerifyContinuityIndexesTx(ctx, tx)
}

func automationVerifySemanticStageTx(ctx context.Context, tx *LocalTx, stage string) error {
	if stage == "" {
		return fmt.Errorf("source audit requires isolated stage")
	}
	for _, descriptor := range automationSemanticTables {
		columns := strings.TrimPrefix(descriptor.columns, "stage,")
		// Both differences must be empty: an extra active row is as invalid as a
		// missing one. SQL compares opaque revisions/configuration byte-for-byte.
		for _, stages := range [][2]string{{"", stage}, {stage, ""}} {
			rows, err := tx.Query(ctx, "SELECT 1 AS drift FROM (SELECT "+columns+" FROM "+descriptor.table+" WHERE stage=? EXCEPT SELECT "+columns+" FROM "+descriptor.table+" WHERE stage=?) LIMIT 1", stages[0], stages[1])
			if err != nil {
				return err
			}
			if len(rows) != 0 {
				return fmt.Errorf("active automation projection differs from certified history: %s", descriptor.table)
			}
		}
	}
	return nil
}
