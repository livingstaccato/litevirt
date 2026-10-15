package corrosion

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// Re-run the EXISTING strict application/replay owner from genesis inside the
// cut transaction. Retained receipts remain immutable and are compared by
// automationApplyTx; no parallel reducer or caller-supplied trusted flag exists.
// Any failure rolls back prefix repair AND every inert snapshot record.
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
	if _, err = tx.Exec(ctx, `DELETE FROM local_automation_prefix WHERE id=1`); err != nil {
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
		if _, err = automationApplyTx(ctx, tx, r, d, digest, reduce, automationApplicationProvenance{kind: automationAnchoredReplay}); err != nil {
			return err
		}
		head, err = automationHeadTx(ctx, tx)
		if err != nil {
			return err
		}
		if old.Sequence == head.Sequence && old != head {
			return fmt.Errorf("source prefix conflicts with retained history")
		}
		return nil
	})
	if err != nil {
		return old, err
	}
	if old.Sequence > head.Sequence {
		return old, fmt.Errorf("source prefix history missing")
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
	key, _ := AutomationClaimKey(uint64(anchorSeq))
	if cert.Key != key || cert.ConfigGeneration != anchor.Int64("generation") || cert.Ballot.IsZero() || len(cert.Accepts) == 0 {
		return fmt.Errorf("source anchor certificate mismatch")
	}
	rows, err = tx.Query(ctx, `SELECT digest FROM local_automation_history WHERE sequence=? LIMIT 1`, anchorSeq)
	if err != nil {
		return err
	}
	if len(rows) != 1 || cert.ValueDigest != rows[0].String("digest") {
		return fmt.Errorf("source anchor target missing")
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
	if cfg.MembersHash != anchor.String("members_hash") || cfg.MembersHash != MembersHash(cfg.Members) || automationElectorateBudget(cfg.Members) != nil {
		return fmt.Errorf("source anchor membership mismatch")
	}
	counted := map[string]bool{}
	incarnations := map[string]bool{}
	for _, a := range cert.Accepts {
		member, ok := cfg.Member(a.Voter)
		if !ok || member.Incarnation != a.VoterIncarnation || counted[a.Voter] || incarnations[a.VoterIncarnation] {
			continue
		}
		if auditAutomationCutAccept(a, cert.Key, cert.Ballot, cert.ConfigGeneration, cert.ValueDigest) != nil {
			continue
		}
		counted[a.Voter] = true
		incarnations[a.VoterIncarnation] = true
	}
	if len(counted) < MajorityOf(len(cfg.Members)) {
		return fmt.Errorf("corrupt retained anchor signatures")
	}

	return nil
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
	identity, err := contract.CanonicalCommand(d.Command)
	if err != nil {
		return err
	}
	var original contract.Receipt
	if json.Unmarshal([]byte(rows[0].String("receipt_json")), &original) != nil || original != receipt || row.String("request_id") != d.Command.RequestID || row.String("scope") != AutomationScope(d) || row.String("operation_id") != receipt.OperationID || !bytes.Equal(identity, row.Bytes("identity")) {
		return fmt.Errorf("source immutable request drift")
	}
	return nil
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
	if validateAutomationBallot(st.Promised, true) != nil || validateAutomationBallot(st.Accepted, true) != nil || CompareBallots(st.Promised, st.Accepted) < 0 || st.ConfigGeneration < 0 {
		return fmt.Errorf("corrupt source claim ballots")
	}
	if st.Accepted.IsZero() {
		if st.Value != nil || st.ValueDigest != "" || st.Accept != nil {
			return fmt.Errorf("source value without acceptance")
		}
		return nil
	}
	if st.Value == nil {
		return fmt.Errorf("source accepted value missing")
	}

	if st.Accept != nil {
		// Legacy ImportClaimsAndAdopt can advance a row's promised generation
		// while preserving its authentic older acceptance. Verify the original
		// signed domain unchanged; automation's stricter generation equality is
		// already enforced by scanClaimRow/ValidateAutomationState.
		if st.Accept.ConfigGeneration < 0 || st.Accept.ConfigGeneration > st.ConfigGeneration {
			return fmt.Errorf("invalid retained accept generation")
		}
		if err := auditAutomationCutAccept(*st.Accept, st.Key, st.Accepted, st.Accept.ConfigGeneration, st.ValueDigest); err != nil {
			return err
		}
	}
	digest, err := st.Value.Digest()
	if err != nil || digest != st.ValueDigest {
		return fmt.Errorf("source accepted digest mismatch")
	}
	if key.IsVoterConfig() {
		if st.Value.Config == nil || st.Value.Config.Generation != key.OwnerEpoch+1 {
			return fmt.Errorf("invalid retained membership acceptance")
		}
	} else if refusal, _ := validateGenerationClaimValue(key, st.Value); refusal != "" {
		return fmt.Errorf("invalid source accepted value")
	}
	if key.IsAutomation() {
		d, err := automationDecision(*st.Value)
		if err != nil {
			return err
		}
		if contract.ValidateSupportedDecision(d) != nil {
			return fmt.Errorf("unsupported source accepted schema or secret coverage")
		}
		if d.Sequence > head.Sequence+1 {
			return fmt.Errorf("source accepted predecessor missing")
		}
		if d.Sequence > 1 {
			parent, found, err := automationTrustedDigestTx(ctx, tx, d.Sequence-1)
			if err != nil {
				return err
			}
			if !found || parent != d.ParentDigest || d.Command.ClusterUID != head.ClusterUID {
				return fmt.Errorf("source accepted parent mismatch")
			}
		} else if d.ParentDigest != "" {
			return fmt.Errorf("source accepted genesis parent mismatch")
		}
		// A lower-ballot losing acceptance at an already chosen slot is legitimate.
		// Its own value need not equal history at that slot; its parent must exist.
	}
	return nil
}

// This is a corruption check on an ALREADY owned durable anchor/accept, not a
// verifier for incoming authority. It neither accepts a new root nor supplies
// a time/CRL bypass to ClaimVerifier. Publication must authenticate the current
// source separately; only its original local anchored provenance permits reuse.
func auditAutomationCutAccept(a ClaimAccept, key ClaimKey, ballot Ballot, generation int64, digest string) error {
	if a.Key != key || !a.Ballot.Equal(ballot) || a.ConfigGeneration != generation || a.ValueDigest != digest || len(a.CertPEM) > 64<<10 || len(a.Signature) > 256 || a.Voter == "" || a.VoterIncarnation == "" {
		return fmt.Errorf("corrupt retained accept binding")
	}
	cert, err := parseCertPEM([]byte(a.CertPEM))
	if err != nil || cert.Subject.CommonName != a.Voter {
		return fmt.Errorf("corrupt retained signer")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !ecdsa.VerifyASN1(pub, acceptPayload(key, generation, ballot, digest, a.Voter, a.VoterIncarnation), a.Signature) {
		return fmt.Errorf("corrupt retained accept signature")
	}
	return nil
}
