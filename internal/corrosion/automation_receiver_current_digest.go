package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/litevirt/litevirt/internal/pki"
)

// Capture the complete persisted inputs, including losing copies, all original
// spool frames, section terminals, audit indexes, and independent maxima. No
// durable ID is authority: this digest is compared only with a process-private
// snapshot produced inside the concrete successful C verifier transaction.
type receiverAggregateEvidence struct{ aggregate, digest string }

func currentEvidenceTables() []aggregateLocalTable {
	tables := []aggregateLocalTable{
		receiverEstablishedTable(),
		{"local_automation_receiver_jobs", "id,job,revision,binding,evidence", "id", "ttibb", false},
		{"local_automation_receiver_current", "id,attempt,established_inventory", "id", "itb", false},
		{"local_automation_receiver_validations", "attempt,digest,evidence", "attempt,digest", "ttb", false},
		{"local_automation_receiver_sources", "attempt,source,publication,authenticated,metadata", "attempt,source", "tttib", false},
		{"local_automation_receiver_components", "attempt,source,component,state,cursor,terminal", "attempt,source,component", "ttibti", false},
		{"local_automation_receiver_records", "attempt,source,component,ordinal,record", "attempt,source,component,ordinal", "ttiib", false},
		{"local_automation_receiver_pages", "attempt,source,component,position,request,digest,progress", "attempt,source,component,position", "ttiittb", false},
		{"local_automation_receiver_audits", "id,attempt,source,publication,root,head,lineage,coverage,records,payloads,requests", "id", "tttttbttiii", false},
		{"local_automation_receiver_refs", "audit,component,ordinal,sequence,semantic_key,scope,request_id,operation_id,claim_key,generation,accepted_round,accepted_coord,accepted_nonce", "audit,component,ordinal", "tiiibtttbiitb", false},
		{"local_automation_receiver_requests", "audit,scope,request_id,identity,receipt,operation_id,origin", "audit,scope,request_id", "tttbbti", false},
		{"local_automation_local_audits", "id,attempt,dependency,head,coverage,records,origin", "id", "tttbtib", false},
		{"local_automation_local_rows", "local_id,section,ordinal,record", "local_id,section,ordinal", "tiib", false},
		{"local_automation_aggregates", "id,attempt,local_id,head,coverage,roster", "id", "tttbtb", false},
	}
	for _, d := range aggregateEvidenceTables {
		shape := "t"
		for _, col := range d.columns {
			switch col.kind {
			case "text":
				shape += "t"
			case "blob":
				shape += "b"
			case "integer":
				shape += "i"
			}
		}
		tables = append(tables, aggregateLocalTable{d.name, "bundle," + d.names(len(d.columns)), "bundle," + d.names(d.keys), shape, false})
	}
	return tables
}
func currentEvidenceLimit(column string) int64 {
	switch column {
	case "established_inventory":
		return maxReceiverInventoryBytes
	case "artifact":
		return maxReceiverEstablishedBytes
	case "evidence":
		return pki.MaxHostTrustEvidenceBytes
	case "binding":
		return 2*maxSourceCertificateBytes + 3*maxSourceConfigBytes
	case "metadata", "roster", "origin", "origin_ref", "head":
		return maxAutomationCutMetadataBytes
	case "state", "progress":
		return receiverStateBytes
	case "cursor", "request":
		return maxSourcePublicationBytes
	case "receipt":
		return maxAutomationCutRecordBytes
	case "semantic_key", "claim_key":
		return 4 * maxSourceFieldBytes
	default:
		return aggregateLocalLimit(column)
	}
}
func (r *AutomationReceiver) currentDependencyDigestTx(ctx context.Context, tx *LocalTx, a *AutomationReceiverAttempt) (string, error) {
	if err := receiverEstablishedSchemaTx(ctx, tx); err != nil {
		return "", err
	}
	local, err := rehashAggregateLocalTx(ctx, tx, a, r.client)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	sourceHash(h, []byte("litevirt/receiver-current-dependencies/v1"), []byte(local))
	for _, d := range currentEvidenceTables() {
		sourceHash(h, []byte("table"), []byte(d.table), []byte(d.columns), []byte(d.keys))
		var count int64
		limit := currentEvidenceLimit
		if d.table == "local_automation_local_rows" {
			limit = func(column string) int64 {
				if column == "record" {
					return maxAggregateLocalRecordBytes
				}
				return currentEvidenceLimit(column)
			}
		}
		err = walkAggregateBoundedTable(ctx, tx, d, "", limit, maxReceiverEstablishedBytes+maxSourcePublicationBytes+maxAutomationCutRecordBytes, func(n int64, row Row) error {
			// Hash columns directly so an original maximum body is never nested in a
			// second serialized frame. Types, order and lengths are unambiguous.
			sourceHash(h, automationCutInteger(n))
			for i, v := range row.Values {
				sourceHash(h, []byte(row.Columns[i]))
				switch value := v.(type) {
				case []byte:
					sourceHash(h, []byte("blob"), value)
				case string:
					sourceHash(h, []byte("text"), []byte(value))
				case int64:
					sourceHash(h, []byte("integer"), automationCutInteger(value))
				}
			}
			count = n
			return nil
		})
		if err != nil {
			return "", err
		}
		sourceHash(h, []byte("end"), automationCutInteger(count))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
