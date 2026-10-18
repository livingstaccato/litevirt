package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
)

// These immutable rows own the pins. No TTL, replacement or deletion writer
// exists. Every body is fetched only after its exact SQL type/length probe.
func retainedDeliveryTx(ctx context.Context, tx *LocalTx, id string) (retainedHolder, bool, error) {
	var empty retainedHolder
	if !receiverDigest(id) {
		return empty, false, errors.New("invalid retained delivery identity")
	}
	rows, err := tx.Query(ctx, `SELECT typeof(attempt) AS at,length(CAST(attempt AS BLOB)) AS an,typeof(envelope) AS et,length(CAST(envelope AS BLOB)) AS en FROM local_automation_retained_deliveries WHERE id=? LIMIT 1`, id)
	if err != nil || len(rows) == 0 {
		return empty, false, err
	}
	row := rows[0]
	if row.String("at") != "text" || row.Int64("an") != 64 || row.String("et") != "blob" || row.Int64("en") <= 0 || row.Int64("en") > maxSourceArtifactBytes {
		return empty, false, errors.New("retained delivery stored shape differs")
	}
	rows, err = tx.Query(ctx, `SELECT attempt,envelope FROM local_automation_retained_deliveries WHERE id=? AND typeof(attempt)='text' AND length(CAST(attempt AS BLOB))=64 AND typeof(envelope)='blob' AND length(CAST(envelope AS BLOB))=? LIMIT 1`, id, row.Int64("en"))
	if err != nil {
		return empty, false, err
	}
	if len(rows) != 1 {
		return empty, false, errors.New("retained delivery changed during read")
	}
	h, err := decodeRetainedHolder(rows[0].Bytes("envelope"))
	if err != nil {
		return empty, false, err
	}
	if h.id != id || h.body.Attempt != rows[0].String("attempt") {
		return empty, false, errors.New("retained delivery binding differs")
	}
	return h, true, nil
}
func pinRetainedDeliveryTx(ctx context.Context, tx *LocalTx, h retainedHolder) error {
	old, found, err := retainedDeliveryTx(ctx, tx, h.id)
	if err != nil {
		return err
	}
	if found {
		if !bytes.Equal(old.raw, h.raw) {
			return errors.New("retained delivery immutable retry differs")
		}
		return nil
	}
	_, err = tx.Exec(ctx, `INSERT INTO local_automation_retained_deliveries(id,attempt,envelope) VALUES(?,?,?)`, h.id, h.body.Attempt, h.raw)
	return err
}
func retainedObjectTx(ctx context.Context, tx *LocalTx, delivery string, n int64) (retainedObjectDescriptor, retainedFrameAddress, bool, error) {
	var d retainedObjectDescriptor
	var a retainedFrameAddress
	if !receiverDigest(delivery) || n <= 0 {
		return d, a, false, errors.New("invalid retained object identity")
	}
	rows, err := tx.Query(ctx, `SELECT typeof(ordinal) AS ot,typeof(namespace) AS nt,length(CAST(namespace AS BLOB)) AS nn,typeof(descriptor) AS dt,length(CAST(descriptor AS BLOB)) AS dn FROM local_automation_retained_objects WHERE delivery=? AND ordinal=? LIMIT 1`, delivery, n)
	if err != nil || len(rows) == 0 {
		return d, a, false, err
	}
	row := rows[0]
	if row.String("ot") != "integer" || row.String("nt") != "text" || row.Int64("nn") <= 0 || row.Int64("nn") > 96 || row.String("dt") != "blob" || row.Int64("dn") <= 0 || row.Int64("dn") > maxAutomationCutMetadataBytes {
		return d, a, false, errors.New("retained object stored shape differs")
	}
	rows, err = tx.Query(ctx, `SELECT namespace,descriptor FROM local_automation_retained_objects WHERE delivery=? AND ordinal=? AND typeof(namespace)='text' AND length(CAST(namespace AS BLOB))=? AND typeof(descriptor)='blob' AND length(CAST(descriptor AS BLOB))=? LIMIT 1`, delivery, n, row.Int64("nn"), row.Int64("dn"))
	if err != nil {
		return d, a, false, err
	}
	if len(rows) != 1 {
		return d, a, false, errors.New("retained object changed during read")
	}
	d, err = decodeRetainedObject(rows[0].Bytes("descriptor"))
	if err != nil {
		return d, a, false, err
	}
	_, _, kind := retainedObjectSections(d.Kind)
	a, err = retainedAddress(delivery, n, d.Source, d.OriginalIdentity, kind)
	if err != nil {
		return d, a, false, err
	}
	if a.namespace != rows[0].String("namespace") {
		return d, a, false, errors.New("retained object namespace differs")
	}
	return d, a, true, nil
}
func pinRetainedObjectTx(ctx context.Context, tx *LocalTx, delivery string, entry retainedDirectoryEntry) error {
	raw, _ := json.Marshal(entry.Descriptor)
	d, err := decodeRetainedObject(raw)
	if err != nil {
		return err
	}
	old, _, found, err := retainedObjectTx(ctx, tx, delivery, entry.Ordinal)
	if err != nil {
		return err
	}
	if found {
		previous, _ := json.Marshal(old)
		if !bytes.Equal(previous, raw) {
			return errors.New("retained object immutable retry differs")
		}
		return nil
	}
	ns, err := retainedNamespace(delivery, entry.Ordinal)
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT 1 AS present FROM local_automation_retained_objects WHERE namespace=? LIMIT 1`, ns)
	if err != nil {
		return err
	}
	if len(rows) != 0 {
		return errors.New("retained namespace already pinned")
	}
	raw, _ = json.Marshal(d)
	_, err = tx.Exec(ctx, `INSERT INTO local_automation_retained_objects(delivery,ordinal,namespace,descriptor) VALUES(?,?,?,?)`, delivery, entry.Ordinal, ns, raw)
	return err
}

type retainedCompletion struct {
	Evidence  string
	Candidate retainedCandidateRef
	Coverage  string
}

func validateRetainedCompletion(c retainedCompletion) error {
	ref := c.Candidate
	if !receiverDigest(c.Evidence) || !receiverDigest(c.Coverage) || ref.Object <= 0 || (ref.Component != 3 && ref.Component != 4) || ref.Ordinal <= 0 || ref.Key.Validate() != nil || !ref.Key.IsGenerationScoped() || validateAutomationBallot(ref.Accepted, false) != nil || !receiverDigest(ref.ValueDigest) || !receiverDigest(ref.AcceptanceDigest) {
		return errors.New("invalid retained immutable completion tuple")
	}
	return nil
}
func retainedCompletionTx(ctx context.Context, tx *LocalTx, delivery string) (retainedCompletion, bool, error) {
	var c retainedCompletion
	if !receiverDigest(delivery) {
		return c, false, errors.New("invalid retained completion delivery")
	}
	rows, err := tx.Query(ctx, `SELECT typeof(evidence_digest) AS et,length(CAST(evidence_digest AS BLOB)) AS en,typeof(candidate_ref) AS ct,length(CAST(candidate_ref AS BLOB)) AS cn,typeof(coverage_digest) AS vt,length(CAST(coverage_digest AS BLOB)) AS vn FROM local_automation_retained_completions WHERE delivery=? LIMIT 1`, delivery)
	if err != nil || len(rows) == 0 {
		return c, false, err
	}
	row := rows[0]
	if row.String("et") != "text" || row.Int64("en") != 64 || row.String("ct") != "blob" || row.Int64("cn") <= 0 || row.Int64("cn") > maxAutomationCutMetadataBytes || row.String("vt") != "text" || row.Int64("vn") != 64 {
		return c, false, errors.New("retained completion stored shape differs")
	}
	rows, err = tx.Query(ctx, `SELECT evidence_digest,candidate_ref,coverage_digest FROM local_automation_retained_completions WHERE delivery=? AND typeof(evidence_digest)='text' AND length(CAST(evidence_digest AS BLOB))=64 AND typeof(candidate_ref)='blob' AND length(CAST(candidate_ref AS BLOB))=? AND typeof(coverage_digest)='text' AND length(CAST(coverage_digest AS BLOB))=64 LIMIT 1`, delivery, row.Int64("cn"))
	if err != nil {
		return c, false, err
	}
	if len(rows) != 1 {
		return c, false, errors.New("retained completion changed during read")
	}
	c.Evidence, c.Coverage = rows[0].String("evidence_digest"), rows[0].String("coverage_digest")
	if err = retainedCanonical(rows[0].Bytes("candidate_ref"), maxAutomationCutMetadataBytes, &c.Candidate); err != nil {
		return c, false, err
	}
	if err = validateRetainedCompletion(c); err != nil {
		return c, false, err
	}
	return c, true, nil
}
func pinRetainedCompletionTx(ctx context.Context, tx *LocalTx, delivery string, c retainedCompletion) error {
	if err := validateRetainedCompletion(c); err != nil {
		return err
	}
	old, found, err := retainedCompletionTx(ctx, tx, delivery)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(c.Candidate)
	if found {
		a, _ := json.Marshal(old)
		b, _ := json.Marshal(c)
		if !bytes.Equal(a, b) {
			return errors.New("retained completion immutable retry differs")
		}
		return nil
	}
	_, err = tx.Exec(ctx, `INSERT INTO local_automation_retained_completions(delivery,evidence_digest,candidate_ref,coverage_digest) VALUES(?,?,?,?)`, delivery, c.Evidence, raw, c.Coverage)
	return err
}
