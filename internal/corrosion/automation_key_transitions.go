package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"filippo.io/age"
	"github.com/litevirt/litevirt/internal/automation/contract"
)

// This source reads only immutable history and membership. The receiver uses
// authenticated source rows; a staged replay must never fall back to local data.
type automationKeyHistorySource interface {
	keyHistory(context.Context, uint64) (contract.HistoricalDecision, error)
	keyMembership(context.Context, uint64) (*VoterConfig, error)
}
type localAutomationKeySource struct{ tx *LocalTx }
type receiverAutomationKeySource struct{ store receiverAuditStore }

func (s localAutomationKeySource) keyHistory(ctx context.Context, seq uint64) (contract.HistoricalDecision, error) {
	automationObserveKeyBody(ctx, seq, nil)
	var zero contract.HistoricalDecision
	if seq == 0 || seq > math.MaxInt64 {
		return zero, fmt.Errorf("invalid original history sequence")
	}
	probe, e := s.tx.Query(ctx, `SELECT typeof(value_json) AS vt,length(CAST(value_json AS BLOB)) AS vn,typeof(digest) AS dt,length(CAST(digest AS BLOB)) AS dn,typeof(certificate) AS ct,length(CAST(certificate AS BLOB)) AS cn,typeof(receipt_json) AS rt,length(CAST(receipt_json AS BLOB)) AS rn FROM local_automation_history WHERE sequence=? LIMIT 1`, seq)
	if e != nil {
		return zero, e
	}
	if len(probe) != 1 || probe[0].String("vt") != "text" || probe[0].Int64("vn") > MaxAutomationClaimBytes || probe[0].String("dt") != "text" || probe[0].Int64("dn") != 64 || probe[0].String("ct") != "text" || probe[0].Int64("cn") > maxSourceCertificateBytes || probe[0].String("rt") != "text" || probe[0].Int64("rn") > maxRetainedReceiptBytes {
		return zero, fmt.Errorf("original history missing or malformed")
	}
	rows, e := s.tx.Query(ctx, `SELECT value_json,digest,certificate,receipt_json FROM local_automation_history WHERE sequence=? LIMIT 1`, seq)
	if e != nil {
		return zero, e
	}
	if len(rows) != 1 {
		return zero, fmt.Errorf("original history disappeared")
	}
	return keyHistoryRow(seq, rows[0])
}
func keyHistoryRow(seq uint64, row Row) (contract.HistoricalDecision, error) {
	var out contract.HistoricalDecision
	key, e := AutomationClaimKey(seq)
	if e != nil {
		return out, e
	}
	var v ClaimValue
	if e = decodeClaimValue(key, row.String("value_json"), &v); e != nil {
		return out, e
	}
	d, e := automationDecision(v)
	if e != nil {
		return out, e
	}
	digest, e := v.Digest()
	if e != nil || digest != row.String("digest") || d.Sequence != seq {
		return out, fmt.Errorf("original certified history identity differs")
	}
	cert, e := sourceCertificate(row.String("certificate"))
	if e != nil || cert.ConfigGeneration <= 0 {
		return out, fmt.Errorf("invalid referenced history certificate generation")
	}
	if d.Command.Kind == contract.CustodyImportCommand {
		a, err := contract.DecodeAssignment(d)
		if err != nil || a.CustodyImport == nil {
			return out, errAutomationAuthority
		}
		var receipt contract.Receipt
		if retainedCanonical([]byte(row.String("receipt_json")), maxRetainedReceiptBytes, &receipt) != nil || receipt.Code != "" || receipt.Sequence != seq || receipt.RequestID != d.Command.RequestID || receipt.OperationID != a.OperationID {
			return out, errAutomationAuthority
		}
		for _, member := range a.CustodyImport.Members {
			if verifyCustodyCompletion(member.Completion, member.Recipient) != nil {
				return out, errAutomationAuthority
			}
		}
	}
	return contract.SummarizeKeyHistory(d, digest, uint64(cert.ConfigGeneration))
}
func (s localAutomationKeySource) keyMembership(ctx context.Context, g uint64) (*VoterConfig, error) {
	if g == 0 || g > math.MaxInt64 {
		return nil, fmt.Errorf("invalid historical membership")
	}
	rows, e := s.tx.Query(ctx, `SELECT `+voterConfigCols+` FROM voter_configs WHERE generation=? AND deleted_at IS NULL AND length(CAST(members_json AS BLOB))<=? AND length(CAST(certificate AS BLOB))<=? LIMIT 1`, g, maxSourceConfigBytes, maxSourceCertificateBytes)
	if e != nil {
		return nil, e
	}
	if len(rows) != 1 {
		return nil, fmt.Errorf("historical membership unavailable")
	}
	return scanVoterConfig(rows[0])
}
func (s receiverAutomationKeySource) keyHistory(ctx context.Context, seq uint64) (contract.HistoricalDecision, error) {
	automationObserveKeyBody(ctx, seq, nil)
	if seq == 0 || seq > math.MaxInt64 {
		return contract.HistoricalDecision{}, fmt.Errorf("invalid receiver history sequence")
	}
	row, e := s.store.sequence(ctx, 5, int64(seq))
	if e != nil {
		return contract.HistoricalDecision{}, e
	}
	return keyHistoryRow(seq, row)
}
func (s receiverAutomationKeySource) keyMembership(ctx context.Context, g uint64) (*VoterConfig, error) {
	if g == 0 || g > math.MaxInt64 {
		return nil, fmt.Errorf("invalid receiver membership")
	}
	return s.store.membership(ctx, int64(g))
}

// Check scalar types and total allocation BEFORE reading bodies. Keys are never
// coerced into cursors. All rows of the exact stage participate, including rows
// from a corrupt other cluster or a retained future epoch (both are refused).
func automationKeyRowsTx(ctx context.Context, tx *LocalTx, table, stage string) ([]Row, error) {
	for _, d := range automationSemanticTables[8:] {
		if d.table != table {
			continue
		}
		var bad, size []string
		for _, c := range strings.Split(d.columns, ",") {
			integer := strings.Contains(","+d.integers+",", ","+c+",")
			if integer {
				bad = append(bad, "typeof("+c+")<>'integer' OR "+c+"<0")
				if c != "predecessor_activation_sequence" && !(table == "local_automation_key_recipients" && c == "host_incarnation") {
					bad = append(bad, c+"=0")
				}
			} else {
				bad = append(bad, "typeof("+c+")<>'text' OR length(CAST("+c+" AS BLOB))>4096")
				if c != "stage" {
					bad = append(bad, "length(CAST("+c+" AS BLOB))=0")
				}
				size = append(size, "length(CAST("+c+" AS BLOB))")
			}
		}
		rows, e := tx.Query(ctx, "SELECT count(*) AS n,coalesce(sum("+strings.Join(size, "+")+"),0) AS bytes,coalesce(max(CASE WHEN "+strings.Join(bad, " OR ")+" THEN 1 ELSE 0 END),0) AS bad FROM "+table+" WHERE stage=?", stage)
		if e != nil {
			return nil, e
		}
		if len(rows) != 1 || rows[0].Int64("n") > 4096 || rows[0].Int64("bytes") > 8<<20 || rows[0].Int64("bad") != 0 {
			return nil, fmt.Errorf("key projection exceeds typed bounds")
		}
		return tx.Query(ctx, "SELECT "+d.columns+" FROM "+table+" WHERE stage=? ORDER BY "+d.primaryKey+" LIMIT 4097", stage)
	}
	return nil, fmt.Errorf("unknown key projection table")
}
func keyRefJSON(ref contract.HistoryReference) string { b, _ := json.Marshal(ref); return string(b) }
func keyStoredReference(raw string) (contract.HistoryReference, error) {
	var r contract.HistoryReference
	if receiverAuditJSON([]byte(raw), &r) != nil || r.Sequence == 0 || r.Sequence > math.MaxInt64 || !receiverDigest(r.Digest) {
		return r, fmt.Errorf("malformed key statement reference")
	}
	return r, nil
}

// Optional read instrumentation observes actual backing storage; it supplies no
// facts, authority, success result or lifetime assertion to the implementation.
type automationKeyBodyObserverKey struct{}

func automationObserveKeyBody(ctx context.Context, sequence uint64, body []byte) {
	if observe, ok := ctx.Value(automationKeyBodyObserverKey{}).(func(uint64, []byte)); ok {
		observe(sequence, body)
	}
}

// A lookup request contains only bounded causal identities. Neither a Decision,
// assignment, row, envelope nor ciphertext survives the preparation scope.
type automationKeyLookup struct {
	generation          uint64
	configDigest        string
	original, bootstrap uint64
	references          []uint64
}

func automationPrepareKeyLookup(ctx context.Context, d contract.Decision, cert ClaimCertificate) (*automationKeyLookup, error) {
	if d.Command.Kind != "rewrap_payload" && d.Command.Kind != "activate_key_epoch" && d.Command.Kind != contract.CustodyImportCommand {
		return nil, nil
	}
	automationObserveKeyBody(ctx, d.Sequence, d.Command.Ciphertext)
	if e := contract.ValidateSupportedDecision(d); e != nil {
		return nil, e
	}
	a, e := contract.DecodeAssignment(d)
	if e != nil {
		return nil, e
	}
	r := &automationKeyLookup{}
	if d.Command.Kind == contract.CustodyImportCommand {
		b, e := contract.DecodeCustodyImportBody(d.Command)
		if e != nil {
			return nil, e
		}
		r.generation, r.configDigest, r.bootstrap = b.MembershipGeneration, b.ConfigDigest, b.Genesis.Sequence
	} else if d.Command.Kind == "rewrap_payload" {
		b, e := contract.DecodeRewrapPayloadBody(d.Command)
		if e != nil {
			return nil, e
		}
		r.generation, r.configDigest = b.MembershipGeneration, b.ConfigDigest
	} else {
		b, e := contract.DecodeActivateKeyEpochBody(d.Command)
		if e != nil {
			return nil, e
		}
		r.generation, r.configDigest = b.MembershipGeneration, b.ConfigDigest
	}
	if cert.ConfigGeneration <= 0 || uint64(cert.ConfigGeneration) != r.generation {
		return nil, fmt.Errorf("key transition differs from original certificate electorate")
	}
	if d.Command.Kind == contract.CustodyImportCommand {
		return r, nil
	}
	if a.KeyTransition.OriginalHistory != nil {
		r.original = a.KeyTransition.OriginalHistory.Sequence
	}
	if a.KeyTransition.Bootstrap != nil {
		r.bootstrap = a.KeyTransition.Bootstrap.Sequence
	}
	for _, recipient := range a.KeyTransition.Recipients {
		r.references = append(r.references, recipient.Enrollment.Sequence, recipient.RecipientAck.Sequence, recipient.EqualityAck.Sequence)
	}
	return r, nil
}
func automationKeyLookupRow(ctx context.Context, row Row, source automationKeyHistorySource) (*automationKeyLookup, error) {
	key, e := AutomationClaimKey(uint64(row.Int64("sequence")))
	if e != nil {
		return nil, e
	}
	var value ClaimValue
	if e = decodeClaimValue(key, row.String("value_json"), &value); e != nil {
		return nil, e
	}
	if value.Automation != nil {
		automationObserveKeyBody(ctx, uint64(row.Int64("sequence")), value.Automation.Envelope)
	}
	d, e := automationDecision(value)
	if e != nil {
		return nil, e
	}
	cert, e := sourceCertificate(row.String("certificate"))
	if e != nil {
		return nil, e
	}
	request, e := automationPrepareKeyLookup(ctx, d, cert)
	if e != nil || request == nil {
		return request, e
	}
	cfg, e := source.keyMembership(ctx, uint64(cert.ConfigGeneration))
	if e != nil {
		return nil, e
	}
	if cfg.MembersHash != request.configDigest {
		return nil, fmt.Errorf("key transition differs from original certified config")
	}
	digest := row.String("digest")
	if e = validateAutomationAnchor(automationAnchorInput{Sequence: int64(d.Sequence), AnchorSequence: int64(d.Sequence), Digest: digest, AnchorDigest: digest, Generation: cert.ConfigGeneration, MembersHash: cfg.MembersHash, Certificate: cert, Target: value, TargetDigest: digest, Membership: cfg}); e != nil {
		return nil, e
	}
	return request, nil
}
func automationResolveKeyProjectionTx(ctx context.Context, tx *LocalTx, stage string, p *contract.Projection, request *automationKeyLookup, source automationKeyHistorySource) error {
	if request == nil {
		return nil
	}
	if source == nil {
		source = localAutomationKeySource{tx}
	}
	gen := request.generation
	cfg, e := source.keyMembership(ctx, gen)
	if e != nil {
		return e
	}
	if cfg.Generation != int64(gen) || cfg.MembersHash != request.configDigest || cfg.MembersHash != MembersHash(cfg.Members) || len(cfg.Members) == 0 || len(cfg.Members) > contract.MaxKeyRecipients {
		return fmt.Errorf("invalid original historical key electorate")
	}
	f := &contract.KeyTransitionProjection{MembershipGeneration: gen, ConfigDigest: cfg.MembersHash}
	for _, m := range cfg.Members {
		f.Members = append(f.Members, contract.KeyMember{Host: m.Name, VoterIncarnation: m.Incarnation})
	}
	rows, e := automationKeyRowsTx(ctx, tx, "local_automation_key_epochs", stage)
	if e != nil {
		return e
	}
	for _, r := range rows {
		v := contract.KeyEpochRecord{ClusterUID: r.String("cluster_uid"), RecipientEpoch: r.String("recipient_epoch"), MembershipGeneration: uint64(r.Int64("membership_generation")), ConfigDigest: r.String("config_digest"), EqualityEpoch: r.String("equality_epoch"), PredecessorActivationSequence: uint64(r.Int64("predecessor_activation_sequence")), ActivationSequence: uint64(r.Int64("activation_sequence"))}
		if v.ClusterUID != p.Head.ClusterUID || v.ActivationSequence > p.Head.Sequence || !receiverDigest(v.ConfigDigest) {
			return fmt.Errorf("noncausal key epoch")
		}
		f.Epochs = append(f.Epochs, v)
	}
	rows, e = automationKeyRowsTx(ctx, tx, "local_automation_key_recipients", stage)
	if e != nil {
		return e
	}
	for _, r := range rows {
		// The typed scalar preflight runs before row allocation; retain the
		// signed-domain check here before converting the immutable host number.
		n, at := r.Int64("host_incarnation"), r.String("admitted_at")
		if n < 0 || at == "" || len(at) > contract.MaxStringBytes || !utf8.ValidString(at) || strings.ContainsRune(at, 0) {
			return fmt.Errorf("invalid historical recipient lifetime")
		}
		if _, e := time.Parse(time.RFC3339Nano, at); e != nil {
			return fmt.Errorf("invalid historical recipient admission timestamp: %w", e)
		}
		v := contract.RecipientBinding{ClusterUID: r.String("cluster_uid"), RecipientEpoch: r.String("recipient_epoch"), MembershipGeneration: uint64(r.Int64("membership_generation")), ConfigDigest: r.String("config_digest"), Host: r.String("host"), HostIncarnation: uint64(n), AdmittedAt: at, AdmissionSerial: r.String("admission_serial"), VoterIncarnation: r.String("voter_incarnation"), KeyID: r.String("key_id"), Recipient: r.String("recipient")}
		if v.Enrollment, e = keyStoredReference(r.String("enrollment_ref")); e != nil {
			return e
		}
		if v.RecipientAck, e = keyStoredReference(r.String("recipient_ack_ref")); e != nil {
			return e
		}
		if v.EqualityAck, e = keyStoredReference(r.String("equality_ack_ref")); e != nil {
			return e
		}
		native, e := age.ParseX25519Recipient(v.Recipient)
		if e != nil || native.String() != v.Recipient || v.ClusterUID != p.Head.ClusterUID || r.Int64("first_sequence") > int64(p.Head.Sequence) || !receiverDigest(v.ConfigDigest) {
			return fmt.Errorf("invalid historical recipient")
		}
		f.Recipients = append(f.Recipients, contract.KeyRecipientRecord{Binding: v, FirstSequence: uint64(r.Int64("first_sequence"))})
	}
	rows, e = automationKeyRowsTx(ctx, tx, "local_automation_payload_wrappings", stage)
	if e != nil {
		return e
	}
	for _, r := range rows {
		v := contract.PayloadWrappingRecord{ClusterUID: r.String("cluster_uid"), OperationID: r.String("operation_id"), PayloadID: r.String("payload_id"), AdmissionSequence: uint64(r.Int64("admission_sequence")), WrappingSequence: uint64(r.Int64("wrapping_sequence")), WrappingDigest: r.String("wrapping_digest"), RecipientEpoch: r.String("recipient_epoch"), MembershipGeneration: uint64(r.Int64("membership_generation")), ConfigDigest: r.String("config_digest")}
		if v.ClusterUID != p.Head.ClusterUID || v.WrappingSequence > p.Head.Sequence || v.AdmissionSequence >= v.WrappingSequence || !receiverDigest(v.WrappingDigest) || !receiverDigest(v.ConfigDigest) {
			return fmt.Errorf("noncausal payload wrapping")
		}
		f.Wrappings = append(f.Wrappings, v)
	}

	// Validate key scalars before paging. There is no cap on unrelated historical
	// admissions: the certified prefix bounds traversal, while only retained
	// payload entries count toward the canonical transition inventory capacity.
	probes, e := tx.Query(ctx, `SELECT count(*) AS n,coalesce(max(sequence),0) AS last,coalesce(max(CASE WHEN typeof(sequence)<>'integer' OR sequence<=0 OR typeof(operation_id)<>'text' OR length(CAST(operation_id AS BLOB))=0 OR length(CAST(operation_id AS BLOB))>4096 OR typeof(method)<>'text' OR method NOT IN ('admit_create','adopt_resource','transfer_owner') OR typeof(payload_id)<>'text' OR length(CAST(payload_id AS BLOB))>4096 OR (method<>'admit_create' AND payload_id<>'') THEN 1 ELSE 0 END),0) AS bad FROM local_automation_admissions INDEXED BY automation_admission_inventory WHERE stage=? AND cluster_uid=?`, stage, p.Head.ClusterUID)
	if e != nil {
		return e
	}
	if len(probes) != 1 || probes[0].Int64("bad") != 0 || uint64(probes[0].Int64("last")) > p.Head.Sequence || uint64(probes[0].Int64("n")) > p.Head.Sequence {
		return fmt.Errorf("noncausal or malformed admission inventory")
	}
	keep := map[uint64]bool{request.original: true, request.bootstrap: true}
	seen := map[uint64]bool{}
	loadHistory := func(seq uint64) error {
		if seq == 0 || seq > p.Head.Sequence {
			return fmt.Errorf("noncausal history reference")
		}
		if seen[seq] {
			return nil
		}
		h, e := source.keyHistory(ctx, seq)
		if e != nil {
			return e
		}
		if h.ClusterUID != p.Head.ClusterUID || h.Sequence != seq {
			return fmt.Errorf("referenced history cluster or sequence differs")
		}
		f.References = append(f.References, contract.HistoricalReference{Reference: contract.HistoryReference{Sequence: seq, Digest: h.Digest}, ClusterUID: h.ClusterUID, MembershipGeneration: h.MembershipGeneration})
		if keep[seq] || h.CustodyImport != nil {
			f.History = append(f.History, h)
		}
		seen[seq] = true
		return nil
	}
	var cursorSequence int64
	cursorOperation := ""
	for {
		rows, e := tx.Query(ctx, `SELECT operation_id,sequence,method,payload_id FROM local_automation_admissions INDEXED BY automation_admission_inventory WHERE stage=? AND cluster_uid=? AND (sequence,operation_id)>(?,?) AND sequence<=? ORDER BY sequence,operation_id LIMIT 64`, stage, p.Head.ClusterUID, cursorSequence, cursorOperation, p.Head.Sequence)
		if e != nil {
			return e
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			seq, operation := r.Int64("sequence"), r.String("operation_id")
			if seq < cursorSequence || (seq == cursorSequence && operation <= cursorOperation) {
				return fmt.Errorf("admission inventory cursor did not advance")
			}
			cursorSequence, cursorOperation = seq, operation
			if r.String("method") != "admit_create" || r.String("payload_id") == "" {
				continue
			}
			if len(f.Admissions) >= contract.MaxRetainedPayloads {
				return fmt.Errorf("retained payload inventory exceeds canonical transition capacity")
			}
			v, e := automationAdmissionRecordTx(ctx, tx, stage, operation)
			if e != nil {
				return e
			}
			if v == nil || v.Sequence != uint64(seq) || v.ClusterUID != p.Head.ClusterUID {
				return fmt.Errorf("retained admission identity differs")
			}
			// Pinned configuration is not an immutable secret identity and is not needed
			// by this reducer. Do not retain 1024 large configuration JSON objects.
			v.PinnedConfiguration = nil
			f.Admissions = append(f.Admissions, *v)
			if e = loadHistory(v.Sequence); e != nil {
				return e
			}
		}
	}
	for _, seq := range request.references {
		if e = loadHistory(seq); e != nil {
			return e
		}
	}
	if request.bootstrap != 0 {
		if e = loadHistory(request.bootstrap); e != nil {
			return e
		}
	}

	p.KeyTransition = f
	return nil
}
func automationApplyKeyEffectsTx(ctx context.Context, tx *LocalTx, stage string, next contract.Prefix, r contract.Reduction) error {
	if r.EpochEffect == nil && len(r.RecipientEffects) == 0 && r.WrappingEffect == nil && r.WrappingPrevious == nil {
		return nil
	}
	if e := requireAutomationFull(ctx, tx); e != nil {
		return e
	}
	if r.Receipt.Code != "" {
		return fmt.Errorf("rejected transition has effects")
	}
	for _, record := range r.RecipientEffects {
		v := record.Binding
		if record.FirstSequence != next.Sequence || v.ClusterUID != next.ClusterUID {
			return fmt.Errorf("recipient effect identity mismatch")
		}
		if _, e := tx.Exec(ctx, `INSERT INTO local_automation_key_recipients(stage,cluster_uid,recipient_epoch,membership_generation,config_digest,host,host_incarnation,admitted_at,admission_serial,voter_incarnation,key_id,recipient,enrollment_ref,recipient_ack_ref,equality_ack_ref,first_sequence) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, stage, v.ClusterUID, v.RecipientEpoch, v.MembershipGeneration, v.ConfigDigest, v.Host, v.HostIncarnation, v.AdmittedAt, v.AdmissionSerial, v.VoterIncarnation, v.KeyID, v.Recipient, keyRefJSON(v.Enrollment), keyRefJSON(v.RecipientAck), keyRefJSON(v.EqualityAck), record.FirstSequence); e != nil {
			return e
		}
	}
	if v := r.WrappingEffect; v != nil {
		if v.ClusterUID != next.ClusterUID || v.WrappingSequence != next.Sequence || v.WrappingDigest != "" || r.WrappingPrevious == nil || !receiverDigest(next.Digest) {
			return fmt.Errorf("wrapping effect identity mismatch")
		}
		rows, e := tx.Query(ctx, `SELECT wrapping_sequence,wrapping_digest FROM local_automation_payload_wrappings WHERE stage=? AND cluster_uid=? AND operation_id=? ORDER BY wrapping_sequence DESC LIMIT 1`, stage, v.ClusterUID, v.OperationID)
		if e != nil {
			return e
		}
		if len(rows) == 0 {
			if r.WrappingPrevious.Sequence != v.AdmissionSequence {
				return fmt.Errorf("original wrapping predecessor missing")
			}
		} else if uint64(rows[0].Int64("wrapping_sequence")) != r.WrappingPrevious.Sequence || rows[0].String("wrapping_digest") != r.WrappingPrevious.Digest {
			return fmt.Errorf("wrapping predecessor changed")
		}
		if _, e = tx.Exec(ctx, `INSERT INTO local_automation_payload_wrappings(stage,cluster_uid,operation_id,payload_id,admission_sequence,wrapping_sequence,wrapping_digest,recipient_epoch,membership_generation,config_digest) VALUES(?,?,?,?,?,?,?,?,?,?)`, stage, v.ClusterUID, v.OperationID, v.PayloadID, v.AdmissionSequence, v.WrappingSequence, next.Digest, v.RecipientEpoch, v.MembershipGeneration, v.ConfigDigest); e != nil {
			return e
		}
	} else if r.WrappingPrevious != nil {
		return fmt.Errorf("wrapping predecessor without effect")
	}
	if v := r.EpochEffect; v != nil {
		if v.ClusterUID != next.ClusterUID || v.ActivationSequence != next.Sequence {
			return fmt.Errorf("epoch effect identity mismatch")
		}
		rows, e := tx.Query(ctx, `SELECT activation_sequence FROM local_automation_key_epochs WHERE stage=? AND cluster_uid=? ORDER BY activation_sequence DESC LIMIT 1`, stage, v.ClusterUID)
		if e != nil {
			return e
		}
		prior := uint64(0)
		if len(rows) > 0 {
			prior = uint64(rows[0].Int64("activation_sequence"))
		}
		if prior != v.PredecessorActivationSequence {
			return fmt.Errorf("activation predecessor changed")
		}
		if _, e = tx.Exec(ctx, `INSERT INTO local_automation_key_epochs(stage,cluster_uid,recipient_epoch,membership_generation,config_digest,equality_epoch,predecessor_activation_sequence,activation_sequence) VALUES(?,?,?,?,?,?,?,?)`, stage, v.ClusterUID, v.RecipientEpoch, v.MembershipGeneration, v.ConfigDigest, v.EqualityEpoch, v.PredecessorActivationSequence, v.ActivationSequence); e != nil {
			return e
		}
	}
	return nil
}

func automationVerifyKeyIndexesTx(ctx context.Context, tx *LocalTx) error {
	type expectedIndex struct {
		name, columns string
		unique        int64
	}
	indexes := map[string][]expectedIndex{
		"local_automation_target_operations":   {{"sqlite_autoindex_local_automation_target_operations_1", "stage,cluster_uid,operation_id", 1}, {"automation_target_sequence", "stage,cluster_uid,sequence", 1}},
		"local_automation_target_reservations": {{"sqlite_autoindex_local_automation_target_reservations_1", "stage,cluster_uid,target_key", 1}, {"automation_target_operation_keys", "stage,cluster_uid,operation_id", 0}},
		"local_automation_key_epochs":          {{"sqlite_autoindex_local_automation_key_epochs_1", "stage,cluster_uid,recipient_epoch", 1}, {"automation_key_activation", "stage,cluster_uid,activation_sequence", 1}, {"automation_key_equality", "stage,cluster_uid,equality_epoch", 1}},
		"local_automation_key_recipients":      {{"sqlite_autoindex_local_automation_key_recipients_1", "stage,cluster_uid,recipient_epoch,host", 1}, {"automation_key_id", "stage,cluster_uid,key_id", 1}, {"automation_key_recipient", "stage,cluster_uid,recipient", 1}},
		"local_automation_payload_wrappings":   {{"sqlite_autoindex_local_automation_payload_wrappings_1", "stage,cluster_uid,operation_id,wrapping_sequence", 1}, {"automation_wrapping_coverage", "stage,cluster_uid,recipient_epoch,operation_id,wrapping_sequence", 0}},
		"local_automation_admissions":          {{"sqlite_autoindex_local_automation_admissions_1", "stage,operation_id", 1}, {"automation_admission_inventory", "stage,cluster_uid,sequence,operation_id", 0}},
	}
	for table, list := range indexes {
		rows, e := tx.Query(ctx, `SELECT count(*) AS n FROM pragma_index_list(?)`, table)
		if e != nil {
			return e
		}
		if len(rows) != 1 || rows[0].Int64("n") != int64(len(list)) {
			return fmt.Errorf("key projection index inventory differs")
		}
		for _, index := range list {
			rows, e = tx.Query(ctx, `SELECT "unique" AS uq,partial FROM pragma_index_list(?) WHERE name=? LIMIT 1`, table, index.name)
			if e != nil {
				return e
			}
			if len(rows) != 1 || rows[0].Int64("uq") != index.unique || rows[0].Int64("partial") != 0 {
				return fmt.Errorf("key projection index shape differs")
			}
			columns := strings.Split(index.columns, ",")
			rows, e = tx.Query(ctx, `SELECT count(*) AS n FROM pragma_index_xinfo(?) WHERE "key"=1`, index.name)
			if e != nil {
				return e
			}
			if len(rows) != 1 || rows[0].Int64("n") != int64(len(columns)) {
				return fmt.Errorf("key projection index key count differs")
			}
			for pos, col := range columns {
				rows, e = tx.Query(ctx, `SELECT 1 AS valid FROM pragma_index_xinfo(?) WHERE seqno=? AND name=? AND coll='BINARY' AND "desc"=0 AND "key"=1 LIMIT 1`, index.name, pos, col)
				if e != nil {
					return e
				}
				if len(rows) != 1 {
					return fmt.Errorf("key projection index order differs")
				}
			}
		}
	}
	return nil
}

// All current full-row reads end before the resolver can open any referenced
// original. The same transaction pins the current row for its later reopen.
func automationLocalKeyLookupTx(ctx context.Context, tx *LocalTx, sequence uint64) (*automationKeyLookup, error) {
	rows, e := tx.Query(ctx, `SELECT sequence,digest,value_json,certificate FROM local_automation_history WHERE sequence=? AND length(CAST(value_json AS BLOB))<=? AND length(CAST(certificate AS BLOB))<=? LIMIT 1`, sequence, MaxAutomationClaimBytes, maxSourceCertificateBytes)
	if e != nil {
		return nil, e
	}
	if len(rows) != 1 {
		return nil, fmt.Errorf("current historical record missing")
	}
	return automationKeyLookupRow(ctx, rows[0], localAutomationKeySource{tx})
}
func (s receiverAuditStore) keyLookup(ctx context.Context, ordinal int64) (*automationKeyLookup, error) {
	row, e := s.record(ctx, 5, ordinal)
	if e != nil {
		return nil, e
	}
	return automationKeyLookupRow(ctx, row, receiverAutomationKeySource{s})
}

func automationStoredKeyLookupTx(ctx context.Context, tx *LocalTx, sequence uint64, staged bool) (*automationKeyLookup, error) {
	table := "local_automation_history"
	if staged {
		table = "local_automation_staging"
	}
	rows, e := tx.Query(ctx, "SELECT sequence,digest,value_json,certificate FROM "+table+" WHERE sequence=? AND length(CAST(value_json AS BLOB))<=? AND length(CAST(certificate AS BLOB))<=? LIMIT 1", sequence, MaxAutomationClaimBytes, maxSourceCertificateBytes)
	if e != nil {
		return nil, e
	}
	if len(rows) != 1 {
		return nil, fmt.Errorf("owned current record unavailable")
	}
	return automationKeyLookupRow(ctx, rows[0], localAutomationKeySource{tx})
}
func automationReadOwnedRecordTx(ctx context.Context, tx *LocalTx, sequence uint64, staged bool) (AutomationRecord, string, error) {
	var out AutomationRecord
	table := "local_automation_history"
	if staged {
		table = "local_automation_staging"
	}
	rows, e := tx.Query(ctx, "SELECT digest,value_json,certificate FROM "+table+" WHERE sequence=? AND length(CAST(value_json AS BLOB))<=? AND length(CAST(certificate AS BLOB))<=? LIMIT 1", sequence, MaxAutomationClaimBytes, maxSourceCertificateBytes)
	if e != nil {
		return out, "", e
	}
	if len(rows) != 1 {
		return out, "", fmt.Errorf("owned current record unavailable")
	}
	key, e := AutomationClaimKey(sequence)
	if e != nil {
		return out, "", e
	}
	if e = decodeClaimValue(key, rows[0].String("value_json"), &out.Value); e != nil {
		return out, "", e
	}
	out.Certificate, e = sourceCertificate(rows[0].String("certificate"))
	return out, rows[0].String("digest"), e
}

// Only a durable sequence/digest crosses this boundary. In particular no
// callback ancestor owns the current decoded decision while causal originals
// are read. The transaction pins both preparation and the current reopen.
func automationApplyStoredTx(ctx context.Context, tx *LocalTx, sequence uint64, digest string, reduce AutomationReducer, source automationApplicationProvenance, staged bool) (contract.Receipt, error) {
	var zero contract.Receipt
	request, e := automationStoredKeyLookupTx(ctx, tx, sequence, staged)
	if e != nil {
		return zero, e
	}
	head, e := automationHeadTx(ctx, tx)
	if e != nil {
		return zero, e
	}
	if source.kind == automationAnchoredReplay {
		head, e = automationSemanticHeadTx(ctx, tx, "")
		if e != nil {
			return zero, e
		}
	}
	prepared := AutomationProjection{Head: head}
	if sequence > head.Sequence {
		if e = automationResolveKeyProjectionTx(ctx, tx, "", &prepared, request, nil); e != nil {
			return zero, e
		}
	}
	r, actual, e := automationReadOwnedRecordTx(ctx, tx, sequence, staged)
	if e != nil {
		return zero, e
	}
	if actual != digest {
		return zero, fmt.Errorf("owned current digest changed")
	}
	d, e := automationDecision(r.Value)
	if e != nil {
		return zero, e
	}
	return automationApplyTx(ctx, tx, r, d, digest, reduce, source, prepared.KeyTransition)
}
