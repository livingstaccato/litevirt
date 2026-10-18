package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

func receiverAuditJSON(raw []byte, out any) error {
	if err := json.Unmarshal(raw, out); err != nil {
		return err
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(canonical, raw) {
		return errors.New("noncanonical source semantic JSON")
	}
	return nil
}

func receiverHistoryValue(row Row) (ClaimValue, contract.Receipt, error) {
	var value ClaimValue
	var receipt contract.Receipt
	seq := row.Int64("sequence")
	key, err := AutomationClaimKey(uint64(seq))
	if err != nil {
		return value, receipt, err
	}
	if err = decodeClaimValue(key, row.String("value_json"), &value); err != nil {
		return value, receipt, err
	}
	if err = receiverAuditJSON([]byte(row.String("receipt_json")), &receipt); err != nil {
		return value, receipt, err
	}
	if !receiverDigest(row.String("digest")) {
		return value, receipt, errors.New("invalid history digest")
	}
	return value, receipt, nil
}

// Validate the independent original certificate in a scope that returns no
// full record. The checkpoint target may be a different, future history value.
func (s receiverAuditStore) originalAnchor(ctx context.Context, ordinal int64) (seq, target int64, digest string, err error) {
	row, err := s.record(ctx, 5, ordinal)
	if err != nil {
		return 0, 0, "", err
	}
	seq, target, digest = row.Int64("sequence"), row.Int64("anchor_sequence"), row.String("digest")
	if target < seq || uint64(target) > s.publication.manifest.Cut.Head.Sequence {
		return 0, 0, "", errors.New("source anchor target outside complete history")
	}
	value, _, err := receiverHistoryValue(row)
	if err != nil {
		return 0, 0, "", err
	}
	original, err := sourceCertificate(row.String("certificate"))
	if err != nil {
		return 0, 0, "", err
	}
	cfg, err := s.membership(ctx, original.ConfigGeneration)
	if err != nil {
		return 0, 0, "", err
	}
	if err = validateAutomationRecordSize(AutomationRecord{Value: value, Certificate: original}); err != nil {
		return 0, 0, "", err
	}
	err = validateAutomationAnchor(automationAnchorInput{Sequence: seq, AnchorSequence: seq, Digest: digest, AnchorDigest: digest, Generation: original.ConfigGeneration, MembersHash: cfg.MembersHash, Certificate: original, Target: value, TargetDigest: digest, Membership: cfg})
	return seq, target, digest, err
}

func (s receiverAuditStore) anchor(ctx context.Context, ordinal int64) error {
	seq, target, digest, err := s.originalAnchor(ctx, ordinal)
	if err != nil {
		return err
	}
	anchor, err := s.sequence(ctx, 6, seq)
	if err != nil {
		return err
	}
	cert, err := sourceCertificate(anchor.String("certificate"))
	if err != nil {
		return err
	}
	cfg, err := s.membership(ctx, anchor.Int64("generation"))
	if err != nil {
		return err
	}
	targetRow, err := s.sequence(ctx, 5, target)
	if err != nil {
		return err
	}
	targetValue, _, err := receiverHistoryValue(targetRow)
	if err != nil {
		return err
	}
	return validateAutomationAnchor(automationAnchorInput{Sequence: seq, AnchorSequence: target, Digest: digest, AnchorDigest: anchor.String("digest"), Generation: anchor.Int64("generation"), MembersHash: anchor.String("members_hash"), Certificate: cert, Target: targetValue, TargetDigest: targetRow.String("digest"), Membership: cfg})
}

func (s receiverAuditStore) request(ctx context.Context, scope, request string) (*AutomationRequest, error) {
	rows, err := s.query(ctx, `SELECT length(CAST(identity AS BLOB)) AS identity,length(CAST(receipt AS BLOB)) AS receipt FROM local_automation_receiver_requests WHERE audit=? AND scope=? AND request_id=? LIMIT 1`, s.id, scope, request)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	i, n := rows[0].Int64("identity"), rows[0].Int64("receipt")
	if i <= 0 || i > MaxAutomationClaimBytes || n <= 0 || n > maxAutomationCutMetadataBytes {
		return nil, errors.New("derived request exceeds bound")
	}
	rows, err = s.query(ctx, `SELECT identity,receipt FROM local_automation_receiver_requests WHERE audit=? AND scope=? AND request_id=? AND length(CAST(identity AS BLOB))=? AND length(CAST(receipt AS BLOB))=? LIMIT 1`, s.id, scope, request, i, n)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, errors.New("derived request disappeared")
	}
	out := &AutomationRequest{Identity: rows[0].Bytes("identity")}
	if err = receiverAuditJSON(rows[0].Bytes("receipt"), &out.Receipt); err != nil {
		return nil, err
	}
	return out, nil
}

func (s receiverAuditStore) operation(ctx context.Context, operation string) (*contract.Receipt, error) {
	rows, err := s.query(ctx, `SELECT length(CAST(receipt AS BLOB)) AS size FROM local_automation_receiver_requests WHERE audit=? AND operation_id=? AND operation_id<>'' LIMIT 1`, s.id, operation)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	n := rows[0].Int64("size")
	if n <= 0 || n > maxAutomationCutMetadataBytes {
		return nil, errors.New("derived operation exceeds bound")
	}
	rows, err = s.query(ctx, `SELECT receipt FROM local_automation_receiver_requests WHERE audit=? AND operation_id=? AND operation_id<>'' AND length(CAST(receipt AS BLOB))=? LIMIT 1`, s.id, operation, n)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, errors.New("derived operation disappeared")
	}
	var receipt contract.Receipt
	if err = receiverAuditJSON(rows[0].Bytes("receipt"), &receipt); err != nil {
		return nil, err
	}
	return &receipt, nil
}

func (s receiverAuditStore) suppliedRequest(ctx context.Context, scope, request string) (Row, error) {
	rows, err := s.query(ctx, `SELECT ordinal FROM local_automation_receiver_refs WHERE audit=? AND component=7 AND scope=? AND request_id=? LIMIT 1`, s.id, scope, request)
	if err != nil {
		return Row{}, err
	}
	if len(rows) != 1 {
		return Row{}, errors.New("expected original request missing from supplied inventory")
	}
	return s.record(ctx, 7, rows[0].Int64("ordinal"))
}

func receiverCompareRequest(row Row, expected AutomationRequest, d contract.Decision) error {
	var receipt contract.Receipt
	if err := receiverAuditJSON([]byte(row.String("receipt_json")), &receipt); err != nil {
		return err
	}
	if !bytes.Equal(row.Bytes("identity"), expected.Identity) {
		return errors.New("supplied original identity drift")
	}
	return validateAutomationRequest(row.String("scope"), row.String("request_id"), row.String("operation_id"), row.Bytes("identity"), receipt, expected.Receipt, d)
}

func (s receiverAuditStore) history(ctx context.Context) (AutomationPrefix, int64, error) {
	var head AutomationPrefix
	stage := "receiver-audit:" + s.id
	if s.localCursor != nil {
		if err := aggregateLocalFreshScratch(ctx, s.tx, s.id); err != nil {
			return head, 0, err
		}
	}
	if err := automationResetSemanticProjectionTx(ctx, s.tx, stage); err != nil {
		return head, 0, err
	}
	if s.localCursor != nil && s.localCursor.Sequence == 0 {
		if err := s.compareLocalSemantic(ctx, stage); err != nil {
			return head, 0, err
		}
	}
	// Anchor validation and replay share this immutable transaction but separate
	// full-value read scopes. No current record survives a target read.
	if err := s.ordinals(ctx, 5, func(ordinal int64) error { return s.anchor(ctx, ordinal) }); err != nil {
		return head, 0, err
	}
	var requests int64
	err := s.ordinals(ctx, 5, func(ordinal int64) error {
		request, err := s.keyLookup(ctx, ordinal)
		if err != nil {
			return err
		}
		prepared := AutomationProjection{Head: head}
		if err = automationResolveKeyProjectionTx(ctx, s.tx, stage, &prepared, request, receiverAutomationKeySource{s}); err != nil {
			return err
		}
		row, err := s.record(ctx, 5, ordinal)
		if err != nil {
			return err
		}
		if head.Sequence >= math.MaxInt64 || row.Int64("sequence") != int64(head.Sequence)+1 {
			return errors.New("complete source history gap")
		}
		value, receipt, err := receiverHistoryValue(row)
		if err != nil {
			return err
		}
		d, err := automationDecision(value)
		if err != nil {
			return err
		}
		existing, err := s.request(ctx, AutomationScope(d), d.Command.RequestID)
		if err != nil {
			return err
		}
		assignment, err := contract.DecodeAssignment(d)
		if err != nil {
			return err
		}
		operation, err := s.operation(ctx, assignment.OperationID)
		if err != nil {
			return err
		}
		projection := AutomationProjection{Head: head, Existing: existing, Operation: operation, KeyTransition: prepared.KeyTransition}
		if err := automationSemanticProjectionSourceTx(ctx, s.tx, stage, &projection, d, receiverAutomationKeySource{s}); err != nil {
			return err
		}
		result, next, err := evaluateAutomationHistory(automationHistoryInput{Projection: projection, Value: value, Digest: row.String("digest"), Expected: &receipt})
		if err != nil {
			return err
		}
		if err := automationApplySemanticEffectsTx(ctx, s.tx, stage, head, next, result); err != nil {
			return err
		}
		if result.SaveRequest {
			// Expected→supplied parity is checked at every causal ORIGINAL, before
			// persistence. Scratch reconstruction never repairs missing evidence.
			supplied, err := s.suppliedRequest(ctx, result.Scope, d.Command.RequestID)
			if err != nil {
				return err
			}
			if err = receiverCompareRequest(supplied, AutomationRequest{Identity: result.Identity, Receipt: result.Receipt}, d); err != nil {
				return err
			}
			raw, _ := json.Marshal(result.Receipt)
			if _, err = s.tx.Exec(ctx, `INSERT INTO local_automation_receiver_requests(audit,scope,request_id,identity,receipt,operation_id,origin) VALUES(?,?,?,?,?,?,?)`, s.id, result.Scope, d.Command.RequestID, result.Identity, raw, result.Receipt.OperationID, ordinal); err != nil {
				return err
			}
			requests++
		}
		head = next
		if s.localCursor != nil && head.Sequence == s.localCursor.Sequence {
			if head != *s.localCursor {
				return errors.New("local semantic cursor differs from certified history")
			}
			if err := s.compareLocalSemantic(ctx, stage); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return head, requests, err
	}
	if head != s.publication.manifest.Cut.Head {
		return head, requests, errors.New("published source head differs from complete reconstruction")
	}
	// Complete forward history validation establishes every link through each
	// later anchor target. Reverse anchor inventory forbids orphan evidence.
	err = s.walk(ctx, 6, func(_ int64, row Row) error {
		history, err := s.sequence(ctx, 5, row.Int64("sequence"))
		if err != nil {
			return err
		}
		if row.String("digest") != history.String("digest") {
			return errors.New("orphan or inconsistent source anchor")
		}
		return nil
	})
	if err != nil {
		return head, requests, err
	}
	// Supplied→expected parity refuses extra/orphan requests, including ones
	// that never arise in causal execution or conflict on an operation identity.
	err = s.walk(ctx, 7, func(_ int64, row Row) error {
		expected, err := s.request(ctx, row.String("scope"), row.String("request_id"))
		if err != nil {
			return err
		}
		if expected == nil {
			return errors.New("extra supplied original request")
		}
		if expected.Receipt.Sequence == 0 || expected.Receipt.Sequence > head.Sequence {
			return errors.New("orphan supplied original receipt")
		}
		original, err := s.sequence(ctx, 5, int64(expected.Receipt.Sequence))
		if err != nil {
			return err
		}
		value, _, err := receiverHistoryValue(original)
		if err != nil {
			return err
		}
		d, err := automationDecision(value)
		if err != nil {
			return err
		}
		return receiverCompareRequest(row, *expected, d)
	})
	return head, requests, err
}
