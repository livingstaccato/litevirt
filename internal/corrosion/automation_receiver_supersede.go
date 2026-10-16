package corrosion

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// This preserves the original durable binding encoding. Stored predecessor
// evidence is only compared; fresh local membership and PKI authorize replacement.
type receiverAttemptBinding struct {
	Version int
	Stream  string
	Intent  AutomationSourceRequest
	Facts   receiverFacts
	Root    string
}
type receiverPredecessor struct {
	id      string
	binding []byte
	value   receiverAttemptBinding
}

const maxReceiverBindingBytes = 2*maxSourceCertificateBytes + 3*maxSourceConfigBytes

func (r *AutomationReceiver) observePredecessor(ctx context.Context) (*receiverPredecessor, error) {
	if err := r.client.sourceExportReadLock(ctx); err != nil {
		return nil, err
	}
	defer r.client.mu.RUnlock()
	tx, err := r.client.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return receiverReadPredecessor(ctx, &LocalTx{tx: tx})
}
func receiverReadPredecessor(ctx context.Context, tx *LocalTx) (*receiverPredecessor, error) {
	// CASE preserves malformed-row presence without materializing oversized TEXT
	// (including embedded NUL/multibyte) or BLOB values from protected storage.
	rows, err := tx.Query(ctx, `SELECT CASE WHEN length(CAST(attempt AS BLOB))=64 THEN attempt END AS attempt FROM local_automation_receiver_current WHERE id=1`)
	if err != nil || len(rows) != 1 || !receiverDigest(rows[0].String("attempt")) {
		return nil, errors.New("receiver durable predecessor unavailable")
	}
	p := &receiverPredecessor{id: rows[0].String("attempt")}
	rows, err = tx.Query(ctx, `SELECT CASE WHEN length(CAST(binding AS BLOB)) BETWEEN 1 AND ? THEN binding END AS binding,CASE WHEN length(CAST(job AS BLOB)) BETWEEN 1 AND 128 THEN job END AS job,CASE WHEN typeof(revision)='integer' THEN revision END AS revision FROM local_automation_receiver_jobs WHERE id=?`, maxReceiverBindingBytes, p.id)
	if err != nil || len(rows) != 1 {
		return nil, errors.New("receiver predecessor binding unavailable")
	}
	p.binding = rows[0].Bytes("binding")
	if len(p.binding) == 0 || sourceDigest([]byte("litevirt/receiver-attempt/v1"), p.binding) != p.id || json.Unmarshal(p.binding, &p.value) != nil {
		return nil, errors.New("receiver predecessor identity differs")
	}
	canonical, err := json.Marshal(p.value)
	if err != nil || !bytes.Equal(canonical, p.binding) {
		return nil, errors.New("receiver predecessor binding is not canonical")
	}
	v := p.value
	intent, err := sourceRequest(v.Intent)
	normalized, _ := json.Marshal(intent)
	original, _ := json.Marshal(v.Intent)
	if err != nil || !bytes.Equal(normalized, original) || v.Version != 1 || v.Stream != "automation" || v.Intent.Job != rows[0].String("job") || v.Intent.Revision != rows[0].Int64("revision") || !receiverDigest(v.Root) || !receiverDigest(v.Facts.Chain) || !receiverDigest(v.Facts.Certificates) {
		return nil, errors.New("invalid receiver predecessor binding")
	}
	f := v.Facts
	if f.Old == nil || f.Next == nil || f.Old.Generation != intent.Generation || f.Next.Generation != intent.Generation+1 || f.Adopted < 0 || f.Adopted > intent.Generation || len(f.Incarnation) == 0 || len(f.Incarnation) > 128 || f.Target.Name != intent.Target || len(f.Target.Address) == 0 || len(f.Target.Address) > 253 || len(f.Target.Serial) == 0 || len(f.Target.Serial) > 128 || f.Target.Port < 0 || f.Target.Port > 65535 {
		return nil, errors.New("invalid receiver predecessor context")
	}
	for _, cfg := range []*VoterConfig{f.Old, f.Next} {
		if sourceMembers(cfg.Members) != nil || len(cfg.Members) == 0 || cfg.MembersHash != MembersHash(cfg.Members) || IsForcedChange(cfg.Change) || len(cfg.Certificate) == 0 || len(cfg.Certificate) > maxSourceCertificateBytes || len(cfg.Change) > maxSourceFieldBytes || len(cfg.CreatedBy) > maxSourceFieldBytes || len(cfg.CreatedAt) > 128 {
			return nil, errors.New("invalid receiver predecessor membership shape")
		}
	}
	if ValidateVoterChange(f.Old, f.Next.VoterConfigValue) != nil {
		return nil, errors.New("invalid receiver predecessor transition")
	}
	target, ok := f.Next.Member(intent.Target)
	if !ok || target.Incarnation != f.Incarnation || sourceRoster(intent, sourceDiscovery{old: f.Old, next: f.Next}, intent.Sources[0].Name) != nil {
		return nil, errors.New("invalid receiver predecessor lifetime or roster")
	}
	return p, nil
}
func (p *receiverPredecessor) compatible(intent AutomationSourceRequest, f receiverFacts, root string) error {
	old := p.value
	// Compare chosen values, never incidental config fields or certificate bytes.
	// Exact current normal-chain verification is performed separately by Begin.
	if intent.Revision <= old.Intent.Revision || intent.Generation != old.Intent.Generation || intent.Target != old.Intent.Target || root != old.Root || f.Incarnation != old.Facts.Incarnation || f.Target != old.Facts.Target || f.Adopted != old.Facts.Adopted || sourceConfigDigest(f.Old) != sourceConfigDigest(old.Facts.Old) || sourceConfigDigest(f.Next) != sourceConfigDigest(old.Facts.Next) {
		return errors.New("receiver replacement differs from stable predecessor context")
	}
	return nil
}
