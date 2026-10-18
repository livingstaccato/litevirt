package corrosion

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// Reconstruct with the existing typed reader, reducer and effect writer in an
// isolated stage. Active projections, prefix and permanent receipts never
// change during a source audit, including failed audits.
func auditAutomationCutTx(ctx context.Context, tx *LocalTx, reduce AutomationReducer) (AutomationPrefix, error) {

	rows, err := tx.Query(ctx, `SELECT id FROM local_automation_prefix WHERE sequence<0 OR (sequence=0 AND (cluster_uid<>'' OR digest<>'')) OR length(CAST(cluster_uid AS BLOB))>4096 OR length(CAST(digest AS BLOB))>64 LIMIT 1`)
	if err != nil {
		return AutomationPrefix{}, err
	}
	if len(rows) != 0 {
		return AutomationPrefix{}, fmt.Errorf("corrupt source prefix")
	}
	old, err := automationHeadTx(ctx, tx)
	if err != nil {
		return old, err
	}
	rows, err = tx.Query(ctx, `SELECT id FROM local_automation_recovery LIMIT 1`)
	if err != nil {
		return old, err
	}
	if len(rows) != 0 {
		return old, fmt.Errorf("pending automation recovery")
	}
	rows, err = tx.Query(ctx, `SELECT sequence FROM local_automation_staging LIMIT 1`)
	if err != nil {
		return old, err
	}
	if len(rows) != 0 {
		return old, fmt.Errorf("orphaned automation staging")
	}
	const stage = "source-cut-audit"
	if err = automationResetSemanticProjectionTx(ctx, tx, stage); err != nil {
		return old, err
	}
	var head AutomationPrefix
	err = walkAutomationCutRows(ctx, tx, automationCutSections[2], func(row Row) error {
		seq := row.Int64("sequence")
		if seq <= 0 || uint64(seq) != head.Sequence+1 || reduce == nil {
			return fmt.Errorf("source history incomplete or reducer unavailable")
		}
		key, _ := AutomationClaimKey(uint64(seq))
		var r AutomationRecord
		if err := decodeClaimValue(key, row.String("value_json"), &r.Value); err != nil {
			return err
		}
		d, err := automationDecision(r.Value)
		if err != nil {
			return err
		}
		if contract.ValidateSupportedDecision(d) != nil || d.Sequence != uint64(seq) || d.ParentDigest != head.Digest {
			return fmt.Errorf("unsupported or broken source history")
		}
		digest, err := r.Value.Digest()
		if err != nil || digest != row.String("digest") {
			return fmt.Errorf("source history digest mismatch")
		}
		r.Certificate, err = DecodeClaimCertificate(row.String("certificate"))
		if err != nil {
			return err
		}
		if err = validateAutomationRecordSize(r); err != nil {
			return err
		}
		if err = auditAutomationCutAnchorTx(ctx, tx, row); err != nil {
			return err
		}
		existing, err := automationRequestTx(ctx, tx, AutomationScope(d), d.Command.RequestID)
		if err != nil {
			return err
		}
		assignment, err := contract.DecodeAssignment(d)
		if err != nil {
			return err
		}
		operation, err := automationOperationTx(ctx, tx, assignment.OperationID)
		if err != nil {
			return err
		}
		projection := AutomationProjection{Head: head, Existing: existing, Operation: operation, ReplayOriginal: existing != nil && existing.Receipt.Sequence == d.Sequence}
		if err = automationSemanticProjectionTx(ctx, tx, stage, &projection, d); err != nil {
			return err
		}
		var receipt contract.Receipt
		if err = receiverAuditJSON([]byte(row.String("receipt_json")), &receipt); err != nil {
			return err
		}
		result, next, err := evaluateAutomationHistory(automationHistoryInput{Projection: projection, Value: r.Value, Digest: digest, Expected: &receipt})
		if err != nil {
			return err
		}
		if result.SaveRequest || projection.ReplayOriginal {
			// Every original must already have immutable evidence. Rebuilding
			// typed effects never manufactures a missing request. Check the
			// stored operation column too; the request reader alone omits it.
			supplied, err := tx.Query(ctx, `SELECT scope,request_id,operation_id,identity,receipt_json FROM local_automation_requests WHERE scope=? AND request_id=? LIMIT 1`, result.Scope, d.Command.RequestID)
			if err != nil {
				return err
			}
			if len(supplied) != 1 {
				return fmt.Errorf("source original request missing")
			}
			if err := receiverCompareRequest(supplied[0], AutomationRequest{Identity: result.Identity, Receipt: result.Receipt}, d); err != nil {
				return err
			}
		}
		callback, err := reduce(cloneAutomationProjection(projection), d)
		if err != nil {
			return err
		}
		if err = validateAutomationCallback(result, callback); err != nil {
			return err
		}
		if err = automationApplySemanticEffectsTx(ctx, tx, stage, head, next, result); err != nil {
			return err
		}
		head = next
		if old.Sequence == head.Sequence && old != head {
			return fmt.Errorf("source prefix conflicts with retained history")
		}
		return nil
	})
	if err != nil {
		return old, err
	}
	if old != head {
		return old, fmt.Errorf("source prefix differs from complete retained history")
	}
	// An anchor with no history must not disappear from the declared baseline.
	rows, err = tx.Query(ctx, `SELECT a.sequence FROM local_automation_anchors a LEFT JOIN local_automation_history h ON h.sequence=a.sequence WHERE h.sequence IS NULL LIMIT 1`)
	if err != nil {
		return old, err
	}
	if len(rows) != 0 {
		return old, fmt.Errorf("source anchor history missing")
	}
	err = walkAutomationCutRows(ctx, tx, automationCutSections[4], func(row Row) error { return auditAutomationCutRequestTx(ctx, tx, row, head) })
	if err != nil {
		return old, err
	}
	if err := automationVerifySemanticStageTx(ctx, tx, stage); err != nil {
		return old, err
	}
	if err := automationResetSemanticProjectionTx(ctx, tx, stage); err != nil {
		return old, err
	}
	return head, nil
}

func auditAutomationCutAnchorTx(ctx context.Context, tx *LocalTx, row Row) error {
	seq := row.Int64("sequence")
	anchorSeq := row.Int64("anchor_sequence")
	if anchorSeq < seq {
		return fmt.Errorf("invalid source anchor sequence")
	}
	// Length guards precede materializing retained certificate/value payloads.
	rows, err := tx.Query(ctx, `SELECT digest,generation,members_hash,certificate FROM local_automation_anchors WHERE sequence=? AND length(CAST(certificate AS BLOB))<=? LIMIT 1`, seq, MaxAutomationRecordBytes)
	if err != nil {
		return err
	}
	if len(rows) != 1 || rows[0].String("digest") != row.String("digest") || rows[0].Int64("generation") <= 0 || rows[0].String("members_hash") == "" {
		return fmt.Errorf("source anchor missing or corrupt")
	}
	anchor := rows[0]
	cert, err := DecodeClaimCertificate(anchor.String("certificate"))
	if err != nil {
		return err
	}
	rows, err = tx.Query(ctx, `SELECT digest,value_json FROM local_automation_history WHERE sequence=? AND length(CAST(value_json AS BLOB))<=? LIMIT 1`, anchorSeq, MaxAutomationClaimBytes)
	if err != nil {
		return err
	}
	if len(rows) != 1 {
		return fmt.Errorf("source anchor target missing")
	}
	targetDigest := rows[0].String("digest")
	var target ClaimValue
	key, err := AutomationClaimKey(uint64(anchorSeq))
	if err != nil {
		return err
	}
	if err = decodeClaimValue(key, rows[0].String("value_json"), &target); err != nil {
		return err
	}

	rows, err = tx.Query(ctx, `SELECT `+voterConfigCols+` FROM voter_configs WHERE generation=? AND deleted_at IS NULL AND length(CAST(members_json AS BLOB))<=? AND length(CAST(certificate AS BLOB))<=? LIMIT 1`, anchor.Int64("generation"), maxAutomationCutMetadataBytes, MaxAutomationRecordBytes)
	if err != nil {
		return err
	}
	if len(rows) != 1 {
		return fmt.Errorf("source anchor membership missing")
	}
	cfg, err := scanVoterConfig(rows[0])
	if err != nil {
		return err
	}
	return validateAutomationAnchor(automationAnchorInput{Sequence: seq, AnchorSequence: anchorSeq, Digest: row.String("digest"), AnchorDigest: anchor.String("digest"), Generation: anchor.Int64("generation"), MembersHash: anchor.String("members_hash"), Certificate: cert, Target: target, TargetDigest: targetDigest, Membership: cfg})
}

func auditAutomationCutRequestTx(ctx context.Context, tx *LocalTx, row Row, head AutomationPrefix) error {
	var receipt contract.Receipt
	if json.Unmarshal([]byte(row.String("receipt_json")), &receipt) != nil || receipt.Sequence == 0 || receipt.Sequence > head.Sequence {
		return fmt.Errorf("orphaned source request")
	}
	rows, err := tx.Query(ctx, `SELECT value_json,receipt_json FROM local_automation_history WHERE sequence=? AND length(CAST(value_json AS BLOB))<=? AND length(CAST(receipt_json AS BLOB))<=? LIMIT 1`, receipt.Sequence, MaxAutomationClaimBytes, maxAutomationCutMetadataBytes)
	if err != nil {
		return err
	}
	if len(rows) != 1 {
		return fmt.Errorf("source request history missing")
	}
	var value ClaimValue
	key, _ := AutomationClaimKey(receipt.Sequence)
	if err = decodeClaimValue(key, rows[0].String("value_json"), &value); err != nil {
		return err
	}
	d, err := automationDecision(value)
	if err != nil {
		return err
	}
	var original contract.Receipt
	if err = json.Unmarshal([]byte(rows[0].String("receipt_json")), &original); err != nil {
		return fmt.Errorf("source immutable request drift")
	}
	return validateAutomationRequest(row.String("scope"), row.String("request_id"), row.String("operation_id"), row.Bytes("identity"), receipt, original, d)
}

func auditAutomationCutClaimTx(ctx context.Context, tx *LocalTx, row Row, head AutomationPrefix) error {
	key := ClaimKey{TargetKind: row.String("target_kind"), TargetName: row.String("target_name"), Incarnation: row.String("incarnation"), OwnerEpoch: row.Int64("owner_epoch"), Attempt: row.Int64("attempt")}
	if err := key.Validate(); err != nil {
		return err
	}
	st, err := scanClaimRow(key, row)
	if err != nil {
		return err
	}
	if err := validateRetainedClaimState(st); err != nil {
		return err
	}
	if key.IsAutomation() && !st.Accepted.IsZero() {
		d, err := automationDecision(*st.Value)
		if err != nil {
			return err
		}
		var parent string
		var found bool
		if d.Sequence > 1 {
			parent, found, err = automationTrustedDigestTx(ctx, tx, d.Sequence-1)
			if err != nil {
				return err
			}
		}
		return validateRetainedAutomationParent(d, head, parent, found)
	}
	return nil
}
