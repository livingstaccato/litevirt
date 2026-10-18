package corrosion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"hash"

	"github.com/litevirt/litevirt/internal/pki"
)

var receiverInventoryRow = errors.New("receiver inventory row read")

// Each original is fetched in a short consistent read, then SQL is terminal
// before signature authentication or reconciliation enters the PKI owner. The
// complete scan digest must be rechecked in the eventual leased FULL commit.
func (r *AutomationReceiver) establishmentRow(ctx context.Context, d aggregateLocalTable, after []any) (Row, error) {
	if err := r.client.sourceExportReadLock(ctx); err != nil {
		return Row{}, err
	}
	defer r.client.mu.RUnlock()
	tx, err := r.client.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Row{}, err
	}
	defer tx.Rollback()
	var out Row
	err = walkAggregateBoundedTableFrom(ctx, &LocalTx{tx: tx}, d, "", currentEvidenceLimit, pki.MaxHostTrustEvidenceBytes+maxReceiverBindingBytes+maxReceiverInventoryBytes+1024, after, func(_ int64, row Row) error { out = row; return receiverInventoryRow })
	if errors.Is(err, receiverInventoryRow) {
		err = nil
	}
	return out, err
}
func receiverInventoryHashRow(h hash.Hash, d aggregateLocalTable, n int64, row Row) {
	sourceHash(h, []byte(d.table), automationCutInteger(n))
	for i, v := range row.Values {
		sourceHash(h, []byte(row.Columns[i]))
		switch value := v.(type) {
		case string:
			sourceHash(h, []byte("text"), []byte(value))
		case []byte:
			sourceHash(h, []byte("blob"), value)
		case int64:
			sourceHash(h, []byte("integer"), automationCutInteger(value))
		}
	}
}
func receiverOriginalTables() []aggregateLocalTable {
	return []aggregateLocalTable{
		{"local_automation_receiver_jobs", "id,job,revision,binding,evidence", "id", "ttibb", false},
		{"local_automation_receiver_current", "id,attempt,established_inventory", "id", "itb", false},
		{"local_automation_receiver_validations", "attempt,digest,evidence", "attempt,digest", "ttb", false},
	}
}
func (r *AutomationReceiver) establishmentJob(ctx context.Context, id string) (*receiverPredecessor, []byte, error) {
	if !receiverDigest(id) {
		return nil, nil, errors.New("receiver establishment invalid job key")
	}
	rows, err := r.client.sourceExportQuery(ctx, `SELECT CASE WHEN typeof(job)='text' AND length(CAST(job AS BLOB)) BETWEEN 1 AND 128 THEN job END AS job,CASE WHEN typeof(revision)='integer' AND revision>0 THEN revision END AS revision,CASE WHEN typeof(binding)='blob' AND length(binding) BETWEEN 1 AND ? THEN binding END AS binding,CASE WHEN typeof(evidence)='blob' AND length(evidence) BETWEEN 1 AND ? THEN evidence END AS evidence FROM local_automation_receiver_jobs WHERE id=?`, maxReceiverBindingBytes, pki.MaxHostTrustEvidenceBytes, id)
	if err != nil || len(rows) != 1 {
		return nil, nil, errors.New("receiver establishment original job missing")
	}
	row := rows[0]
	binding, err := decodeReceiverBinding(id, row.String("job"), row.Int64("revision"), row.Bytes("binding"))
	if err != nil || len(row.Bytes("evidence")) == 0 {
		return nil, nil, errors.New("receiver establishment original job malformed")
	}
	return binding, row.Bytes("evidence"), nil
}

// scanEstablishmentOriginals visits ALL jobs and validations, including prior
// selections. Neither a caller-selected subset nor a retained summary can
// establish receiver ownership. This does not itself establish or reconcile
// floors: visit must authenticate a genuine local artifact (or be the explicit
// current-owner repair operation). The caller holds the receiver owner.
func (r *AutomationReceiver) scanEstablishmentOriginals(ctx context.Context, visit func(*receiverPredecessor, string, []byte, *pki.HostTrustEvidence) error) (string, error) {
	h := sha256.New()
	sourceHash(h, []byte("litevirt/receiver-establishment-originals/v1"))
	var jobs, current int64
	for _, d := range receiverOriginalTables() {
		sourceHash(h, []byte("table"), []byte(d.table), []byte(d.columns), []byte(d.keys))
		var after []any
		var count int64
		for {
			row, err := r.establishmentRow(ctx, d, after)
			if err != nil {
				return "", err
			}
			if len(row.Columns) == 0 {
				break
			}
			count++
			receiverInventoryHashRow(h, d, count, row)
			switch d.table {
			case "local_automation_receiver_current":
				if row.Int64("id") != 1 {
					return "", errors.New("receiver establishment invalid current key")
				}
				if _, _, err = r.establishmentJob(ctx, row.String("attempt")); err != nil {
					return "", err
				}
				after = []any{row.Int64("id")}
			case "local_automation_receiver_jobs":
				id := row.String("id")
				binding, err := decodeReceiverBinding(id, row.String("job"), row.Int64("revision"), row.Bytes("binding"))
				if err != nil {
					return "", err
				}
				e, err := pki.DecodeHostTrustEvidence(row.Bytes("evidence"))
				if err != nil {
					return "", err
				}
				root, digest := e.RootDigest(), e.Digest()
				if binding.value.Intent.Target != r.client.hostName || binding.value.Root != hex.EncodeToString(root[:]) {
					return "", errors.New("receiver establishment foreign original job")
				}
				// Job's initial original is mandatory, not an optional validation subset.
				rows, err := r.client.sourceExportQuery(ctx, `SELECT CASE WHEN typeof(evidence)='blob' AND length(evidence) BETWEEN 1 AND ? THEN evidence END AS evidence FROM local_automation_receiver_validations WHERE attempt=? AND digest=?`, pki.MaxHostTrustEvidenceBytes, id, hex.EncodeToString(digest[:]))
				if err != nil || len(rows) != 1 || !bytes.Equal(rows[0].Bytes("evidence"), row.Bytes("evidence")) {
					return "", errors.New("receiver establishment initial validation missing")
				}
				after = []any{id}
			case "local_automation_receiver_validations":
				id, digest, original := row.String("attempt"), row.String("digest"), row.Bytes("evidence")
				binding, _, err := r.establishmentJob(ctx, id)
				if err != nil {
					return "", err
				}
				e, err := pki.DecodeHostTrustEvidence(original)
				if err != nil {
					return "", err
				}
				root, actual := e.RootDigest(), e.Digest()
				if !receiverDigest(digest) || digest != hex.EncodeToString(actual[:]) || binding.value.Root != hex.EncodeToString(root[:]) || binding.value.Intent.Target != r.client.hostName {
					return "", errors.New("receiver establishment original validation identity differs")
				}
				if err = visit(binding, digest, original, e); err != nil {
					return "", err
				}
				after = []any{id, digest}
			}
		}
		sourceHash(h, []byte("end"), automationCutInteger(count))
		if d.table == "local_automation_receiver_jobs" {
			jobs = count
		}
		if d.table == "local_automation_receiver_current" {
			current = count
		}
	}
	if jobs > 0 && current != 1 {
		return "", errors.New("receiver establishment current selection missing")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// The final FULL check hashes raw bounded originals only. It performs no
// cryptographic parsing, signing, key lookup, capture or floor reconciliation.
func receiverOriginalDigestTx(ctx context.Context, tx *LocalTx) (string, error) {
	h := sha256.New()
	sourceHash(h, []byte("litevirt/receiver-establishment-originals/v1"))
	for _, d := range receiverOriginalTables() {
		sourceHash(h, []byte("table"), []byte(d.table), []byte(d.columns), []byte(d.keys))
		var count int64
		err := walkAggregateBoundedTable(ctx, tx, d, "", currentEvidenceLimit, pki.MaxHostTrustEvidenceBytes+maxReceiverBindingBytes+maxReceiverInventoryBytes+1024, func(n int64, row Row) error { count = n; receiverInventoryHashRow(h, d, n, row); return nil })
		if err != nil {
			return "", err
		}
		sourceHash(h, []byte("end"), automationCutInteger(count))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
