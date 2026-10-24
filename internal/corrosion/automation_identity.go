package corrosion

import (
	"context"
	"fmt"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"math"
)

// Typed semantic projection effects share the existing history FULL transaction.
// Stage is empty for active projections and an isolated audit key for rebuilds.
// This function grants no admission, migration or inventory authority.
func automationApplySemanticEffectsTx(ctx context.Context, tx *LocalTx, stage string, head, next contract.Prefix, r contract.Reduction) error {
	if err := requireAutomationFull(ctx, tx); err != nil {
		return err
	}
	if len(stage) > contract.MaxStringBytes || next.Sequence != head.Sequence+1 || next.Sequence > math.MaxInt64 || next.ClusterUID == "" || next.Digest == "" {
		return fmt.Errorf("invalid semantic projection successor")
	}
	actual, err := automationSemanticHeadTx(ctx, tx, stage)
	if err != nil {
		return err
	}
	if actual != head {
		return fmt.Errorf("semantic projection predecessor unavailable")
	}
	if r.Receipt.Code != "" && (r.ExecutorEffect != nil || r.ProgressEffect != nil || r.TerminalEffect != nil || len(r.ArtifactEffects) != 0 || r.TargetEffect != nil || len(r.TargetReservations) != 0 || r.EpochEffect != nil || len(r.RecipientEffects) > 0 || r.WrappingEffect != nil || r.WrappingPrevious != nil || r.ContinuityEffect != nil || r.IdentityEffect != nil || r.OwnerEffect != nil || r.ResourcePrevious != nil || r.ResourceEffect != nil || r.NameEffect != nil || len(r.BindingEffects) != 0 || r.AdmissionEffect != nil) {
		return fmt.Errorf("rejected decision has semantic effects")
	}
	if err := automationApplyContinuityEffectTx(ctx, tx, stage, next.ClusterUID, r); err != nil {
		return err
	}
	if v := r.IdentityEffect; v != nil {
		if v.ClusterUID != next.ClusterUID || v.UID == "" || v.Kind == "" || v.Alias == "" || v.Witness == "" || v.Generation == 0 || v.Generation > math.MaxInt64 {
			return fmt.Errorf("invalid identity effect")
		}
		retired := 0
		if v.Retired {
			retired = 1
		}
		if _, err := tx.Exec(ctx, `INSERT INTO local_automation_identities(stage,uid,cluster_uid,project_uid,kind,alias,witness,generation,retired) VALUES(?,?,?,?,?,?,?,?,?)`, stage, v.UID, v.ClusterUID, v.ProjectUID, v.Kind, v.Alias, v.Witness, v.Generation, retired); err != nil {
			return err
		}
		scope := v.ProjectUID
		if v.Kind == "vm" {
			scope = ""
		}
		result, err := tx.Exec(ctx, `INSERT INTO local_automation_aliases(stage,cluster_uid,project_scope,kind,alias,uid,generation) VALUES(?,?,?,?,?,?,?) ON CONFLICT(stage,cluster_uid,project_scope,kind,alias) DO UPDATE SET uid=excluded.uid,generation=excluded.generation WHERE generation<excluded.generation`, stage, v.ClusterUID, scope, v.Kind, v.Alias, v.UID, v.Generation)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("identity alias generation did not advance")
		}
	}
	if v := r.OwnerEffect; v != nil {
		if v.ClusterUID != next.ClusterUID || v.ProjectUID == "" || v.OwnerID == "" || v.FounderPrincipalUID == "" || v.Activation > math.MaxInt64 || (v.Activation == 0) != (v.SessionID == "") || (v.SessionID == "") != (v.SessionPrincipalUID == "") {
			return fmt.Errorf("invalid owner effect")
		}
		result, err := tx.Exec(ctx, `INSERT INTO local_automation_owners(stage,cluster_uid,project_uid,owner_id,founder_principal_uid,session_id,session_principal_uid,activation) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(stage,cluster_uid,project_uid,owner_id) DO UPDATE SET session_id=excluded.session_id,session_principal_uid=excluded.session_principal_uid,activation=excluded.activation WHERE founder_principal_uid=excluded.founder_principal_uid AND activation<excluded.activation`, stage, v.ClusterUID, v.ProjectUID, v.OwnerID, v.FounderPrincipalUID, v.SessionID, v.SessionPrincipalUID, v.Activation)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("owner activation did not advance")
		}
	}
	if err := automationApplyTargetEffectsTx(ctx, tx, stage, next, r); err != nil {
		return err
	}
	if err := automationApplyBindingEffectsTx(ctx, tx, stage, next, r); err != nil {
		return err
	}
	if err := automationApplyKeyEffectsTx(ctx, tx, stage, next, r); err != nil {
		return err
	}
	if err := automationApplyExecutionEffectsTx(ctx, tx, stage, head, next, r); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO local_automation_semantic_heads(stage,cluster_uid,sequence,digest) VALUES(?,?,?,?) ON CONFLICT(stage) DO UPDATE SET cluster_uid=excluded.cluster_uid,sequence=excluded.sequence,digest=excluded.digest`, stage, next.ClusterUID, next.Sequence, next.Digest)
	return err
}

// Reset only derived semantic state. Permanent request receipts and certified
// history remain intact. Call before replaying the first historical decision.
func automationResetSemanticProjectionTx(ctx context.Context, tx *LocalTx, stage string) error {
	if err := requireAutomationFull(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_identity_continuity WHERE stage=?`, stage); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_execution_terminals WHERE stage=?`, stage); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_execution_artifacts WHERE stage=?`, stage); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_execution_progress WHERE stage=?`, stage); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_executors WHERE stage=?`, stage); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_target_reservations WHERE stage=?`, stage); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_target_operations WHERE stage=?`, stage); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_key_epochs WHERE stage=?`, stage); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_key_recipients WHERE stage=?`, stage); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_payload_wrappings WHERE stage=?`, stage); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_bindings WHERE stage=?`, stage); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_names WHERE stage=?`, stage); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_resources WHERE stage=?`, stage); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_admissions WHERE stage=?`, stage); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_aliases WHERE stage=?`, stage); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_identities WHERE stage=?`, stage); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_owners WHERE stage=?`, stage); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM local_automation_semantic_heads WHERE stage=?`, stage)
	return err
}

func automationSemanticHeadTx(ctx context.Context, tx *LocalTx, stage string) (contract.Prefix, error) {
	rows, err := tx.Query(ctx, `SELECT cluster_uid,sequence,digest FROM local_automation_semantic_heads WHERE stage=? LIMIT 1`, stage)
	if err != nil || len(rows) == 0 {
		return contract.Prefix{}, err
	}
	row := rows[0]
	if row.Int64("sequence") <= 0 || row.String("cluster_uid") == "" || row.String("digest") == "" {
		return contract.Prefix{}, &automationProofCorruptionError{cause: fmt.Errorf("invalid semantic projection head")}
	}
	return contract.Prefix{ClusterUID: row.String("cluster_uid"), Sequence: uint64(row.Int64("sequence")), Digest: row.String("digest")}, nil
}

func automationIdentityRecordTx(ctx context.Context, tx *LocalTx, stage, uid string) (*contract.IdentityRecord, error) {
	if uid == "" {
		return nil, nil
	}
	sizes, err := tx.Query(ctx, `SELECT length(CAST(uid AS BLOB))+length(CAST(cluster_uid AS BLOB))+length(CAST(project_uid AS BLOB))+length(CAST(kind AS BLOB))+length(CAST(alias AS BLOB))+length(CAST(witness AS BLOB)) AS bytes FROM local_automation_identities WHERE stage=? AND uid=? LIMIT 1`, stage, uid)
	if err != nil || len(sizes) == 0 {
		return nil, err
	}
	if sizes[0].Int64("bytes") > 6*contract.MaxStringBytes {
		return nil, fmt.Errorf("oversized identity projection")
	}
	rows, err := tx.Query(ctx, `SELECT uid,cluster_uid,project_uid,kind,alias,witness,generation,retired FROM local_automation_identities WHERE stage=? AND uid=? LIMIT 1`, stage, uid)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, fmt.Errorf("identity projection disappeared")
	}
	row := rows[0]
	if row.Int64("generation") <= 0 || row.String("uid") == "" || row.String("cluster_uid") == "" || row.String("witness") == "" || row.Int64("retired") < 0 || row.Int64("retired") > 1 {
		return nil, fmt.Errorf("invalid identity projection")
	}
	return &contract.IdentityRecord{ClusterUID: row.String("cluster_uid"), ProjectUID: row.String("project_uid"), Kind: row.String("kind"), UID: row.String("uid"), Alias: row.String("alias"), Witness: row.String("witness"), Generation: uint64(row.Int64("generation")), Retired: row.Int64("retired") == 1}, nil
}

func automationOwnerRecordTx(ctx context.Context, tx *LocalTx, stage, cluster, project, owner string) (*contract.OwnerRecord, error) {
	sizes, err := tx.Query(ctx, `SELECT length(CAST(founder_principal_uid AS BLOB))+length(CAST(session_id AS BLOB))+length(CAST(session_principal_uid AS BLOB)) AS bytes FROM local_automation_owners WHERE stage=? AND cluster_uid=? AND project_uid=? AND owner_id=? LIMIT 1`, stage, cluster, project, owner)
	if err != nil || len(sizes) == 0 {
		return nil, err
	}
	if sizes[0].Int64("bytes") > 3*contract.MaxStringBytes {
		return nil, fmt.Errorf("oversized owner projection")
	}
	rows, err := tx.Query(ctx, `SELECT founder_principal_uid,session_id,session_principal_uid,activation FROM local_automation_owners WHERE stage=? AND cluster_uid=? AND project_uid=? AND owner_id=? LIMIT 1`, stage, cluster, project, owner)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, fmt.Errorf("owner projection disappeared")
	}
	row := rows[0]
	if row.Int64("activation") < 0 || row.String("founder_principal_uid") == "" || (row.Int64("activation") == 0) != (row.String("session_id") == "") || (row.String("session_id") == "") != (row.String("session_principal_uid") == "") {
		return nil, fmt.Errorf("invalid owner projection")
	}
	return &contract.OwnerRecord{ClusterUID: cluster, ProjectUID: project, OwnerID: owner, FounderPrincipalUID: row.String("founder_principal_uid"), SessionID: row.String("session_id"), SessionPrincipalUID: row.String("session_principal_uid"), Activation: uint64(row.Int64("activation"))}, nil
}

// This bounded reader supplies the same typed predecessor facts for active
// application and an isolated reconstruction stage. It supplies no permits.
func automationSemanticProjectionTx(ctx context.Context, tx *LocalTx, stage string, p *contract.Projection, d contract.Decision) error {
	return automationSemanticProjectionSourceTx(ctx, tx, stage, p, d, nil)
}
func automationSemanticProjectionSourceTx(ctx context.Context, tx *LocalTx, stage string, p *contract.Projection, d contract.Decision, source automationKeyHistorySource) (result error) {
	defer func() {
		if result == nil {
			result = automationTargetProjectionTx(ctx, tx, stage, p, d, source)
		}
	}()
	head, err := automationSemanticHeadTx(ctx, tx, stage)
	if err != nil {
		return err
	}
	if head != p.Head {
		return fmt.Errorf("semantic predecessor unavailable")
	}
	c := d.Command
	switch c.Kind {
	case contract.IdentityContinuityCommand:
		body, err := contract.DecodeIdentityContinuityBody(c)
		if err != nil {
			return err
		}
		facts := &contract.ContinuityProjection{}
		facts.Identity, err = automationIdentityRecordTx(ctx, tx, stage, body.UID)
		if err != nil {
			return err
		}
		facts.Existing, err = automationContinuityRecordTx(ctx, tx, stage, body.ClusterUID, body.UID, body.Generation)
		if err != nil {
			return err
		}
		p.Continuity = facts

	case "rewrap_payload", "activate_key_epoch":
		if p.KeyTransition == nil {
			return fmt.Errorf("key transition causal projection was not prepared")
		}
		return nil
	case "admit_update":
		return automationUpdateProjectionTx(ctx, tx, stage, p, d, source)
	case "adopt_resource", "transfer_owner":
		return automationOwnershipProjectionTx(ctx, tx, stage, p, d)
	case "claim_executor", "record_progress", "retire_artifact", "complete_operation":
		return automationExecutionProjectionTx(ctx, tx, stage, p, d, source)
	case "admit_create":
		return automationBindingProjectionTx(ctx, tx, stage, p, d)
	case "assign_identity":
		body, err := contract.DecodeIdentityEnrollment(c)
		if err != nil {
			return err
		}
		assigned, err := contract.DecodeAssignment(d)
		if err != nil {
			return err
		}
		facts := &contract.IdentityProjection{}
		facts.Project, err = automationIdentityRecordTx(ctx, tx, stage, c.ProjectUID)
		if err != nil {
			return err
		}
		facts.Assigned, err = automationIdentityRecordTx(ctx, tx, stage, assigned.Identity.UID)
		if err != nil {
			return err
		}
		scope := c.ProjectUID
		if body.Kind == "vm" {
			scope = ""
		}
		rows, err := tx.Query(ctx, `SELECT uid,generation FROM local_automation_aliases WHERE stage=? AND cluster_uid=? AND project_scope=? AND kind=? AND alias=? LIMIT 1`, stage, c.ClusterUID, scope, body.Kind, body.Alias)
		if err != nil {
			return err
		}
		if len(rows) > 0 {
			facts.Alias, err = automationIdentityRecordTx(ctx, tx, stage, rows[0].String("uid"))
			if err != nil {
				return err
			}
			if facts.Alias == nil || facts.Alias.Generation != uint64(rows[0].Int64("generation")) {
				return fmt.Errorf("alias lifetime missing or inconsistent")
			}
		}
		if body.Kind == "vm" {
			if facts.AssignedResource, err = automationResourceRecordTx(ctx, tx, stage, assigned.Identity.UID); err != nil {
				return err
			}
			if facts.Name, err = automationNameRecordTx(ctx, tx, stage, c.ClusterUID, body.Alias); err != nil {
				return err
			}
			uid := ""
			if facts.Name != nil {
				uid = facts.Name.ResourceUID
			} else if facts.Alias != nil {
				uid = facts.Alias.UID
			}
			if facts.Resource, err = automationResourceRecordTx(ctx, tx, stage, uid); err != nil {
				return err
			}
		}
		p.Identity = facts
	case "ensure_owner", "acquire_session", "handoff_session":
		body, err := contract.DecodeOwnerBody(c)
		if err != nil {
			return err
		}
		facts := &contract.OwnershipProjection{}
		facts.Project, err = automationIdentityRecordTx(ctx, tx, stage, c.ProjectUID)
		if err != nil {
			return err
		}
		facts.Principal, err = automationIdentityRecordTx(ctx, tx, stage, c.PrincipalID)
		if err != nil {
			return err
		}
		facts.Owner, err = automationOwnerRecordTx(ctx, tx, stage, c.ClusterUID, c.ProjectUID, c.OwnerID)
		if err != nil {
			return err
		}
		if body.NextPrincipalUID != "" {
			facts.NextPrincipal, err = automationIdentityRecordTx(ctx, tx, stage, body.NextPrincipalUID)
			if err != nil {
				return err
			}
		}
		assigned, err := contract.DecodeAssignment(d)
		if err != nil {
			return err
		}
		if assigned.Owner != nil {
			sizes, err := tx.Query(ctx, `SELECT length(CAST(cluster_uid AS BLOB))+length(CAST(project_uid AS BLOB))+length(CAST(owner_id AS BLOB)) AS bytes FROM local_automation_owners WHERE stage=? AND session_id=? LIMIT 1`, stage, assigned.Owner.SessionID)
			if err != nil {
				return err
			}
			if len(sizes) > 0 {
				if sizes[0].Int64("bytes") > 3*contract.MaxStringBytes {
					return fmt.Errorf("oversized assigned session projection")
				}
				rows, err := tx.Query(ctx, `SELECT cluster_uid,project_uid,owner_id FROM local_automation_owners WHERE stage=? AND session_id=? LIMIT 1`, stage, assigned.Owner.SessionID)
				if err != nil {
					return err
				}
				if len(rows) != 1 {
					return fmt.Errorf("assigned session disappeared")
				}
				facts.AssignedSession, err = automationOwnerRecordTx(ctx, tx, stage, rows[0].String("cluster_uid"), rows[0].String("project_uid"), rows[0].String("owner_id"))
				if err != nil {
					return err
				}
			}
		}
		p.Ownership = facts
	}
	return nil
}
