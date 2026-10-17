package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
)

// The index stores bounded identities and references, never a second copy of
// signed evidence. All reads are confined to one audit/source/component/key.
type receiverAuditStore struct {
	tx                  *LocalTx
	attempt, source, id string
	publication         receiverPublication
}

func (s receiverAuditStore) record(ctx context.Context, component int, ordinal int64) (Row, error) {
	rows, err := s.tx.Query(ctx, `SELECT typeof(record) AS kind,length(CAST(record AS BLOB)) AS size FROM local_automation_receiver_records WHERE attempt=? AND source=? AND component=? AND ordinal=? LIMIT 1`, s.attempt, s.source, component, ordinal)
	if err != nil {
		return Row{}, err
	}
	if len(rows) != 1 || rows[0].String("kind") != "blob" || rows[0].Int64("size") <= 0 || rows[0].Int64("size") > maxAutomationCutRecordBytes {
		return Row{}, errors.New("audit record missing or over bound")
	}
	n := rows[0].Int64("size")
	rows, err = s.tx.Query(ctx, `SELECT record FROM local_automation_receiver_records WHERE attempt=? AND source=? AND component=? AND ordinal=? AND typeof(record)='blob' AND length(CAST(record AS BLOB))=? LIMIT 1`, s.attempt, s.source, component, ordinal, n)
	if err != nil {
		return Row{}, err
	}
	if len(rows) != 1 {
		return Row{}, errors.New("audit record changed")
	}
	raw := rows[0].Bytes("record")
	row, err := decodeSourceCutRow(component-3, ordinal, raw)
	if err != nil {
		return Row{}, err
	}
	canonical, err := encodeAutomationCutRecord(automationCutSections[component-3].name, ordinal, row)
	if err != nil || !bytes.Equal(canonical, raw) {
		return Row{}, errors.New("noncanonical audit record")
	}
	if err = receiverAuditRowTypes(component, row); err != nil {
		return Row{}, err
	}
	return row, nil
}

func (s receiverAuditStore) sequence(ctx context.Context, component int, sequence int64) (Row, error) {
	rows, err := s.tx.Query(ctx, `SELECT ordinal FROM local_automation_receiver_refs WHERE audit=? AND component=? AND sequence=? AND component IN (5,6,8,9,10,11) LIMIT 1`, s.id, component, sequence)
	if err != nil {
		return Row{}, err
	}
	if len(rows) != 1 {
		return Row{}, errors.New("required indexed source fact missing")
	}
	return s.record(ctx, component, rows[0].Int64("ordinal"))
}

func (s receiverAuditStore) walk(ctx context.Context, component int, visit func(int64, Row) error) error {
	var ordinal int64
	for {
		rows, err := s.tx.Query(ctx, `SELECT ordinal FROM local_automation_receiver_refs WHERE audit=? AND component=? AND ordinal>? ORDER BY ordinal LIMIT 1`, s.id, component, ordinal)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		next := rows[0].Int64("ordinal")
		if ordinal == math.MaxInt64 || next != ordinal+1 {
			return errors.New("audit index ordinal gap")
		}
		ordinal = next
		row, err := s.record(ctx, component, ordinal)
		if err != nil {
			return err
		}
		if err = visit(ordinal, row); err != nil {
			return err
		}
	}
}

func receiverAuditRowTypes(component int, row Row) error {
	// Lowercase fields are required; uppercase permits SQL NULL where the
	// actual existing table does. This precedes coercing Row accessors.
	shapes := map[int]string{3: "ttiiitbitbttti", 4: "tttiiitbitbttti", 5: "itttti", 6: "ititt", 7: "ttbtt", 8: "iittttt", 9: "itt", 10: "itt", 11: "ittttttT"}
	shape := shapes[component]
	if len(shape) != len(row.Values) {
		return fmt.Errorf("audit component %d field count", component)
	}
	for i, kind := range []byte(shape) {
		v := row.Values[i]
		if v == nil && kind >= 'A' && kind <= 'Z' {
			continue
		}
		switch kind {
		case 'i':
			if n, ok := v.(int64); !ok || n < 0 {
				return errors.New("invalid audit integer")
			}
		case 't', 'T':
			if _, ok := v.(string); !ok {
				return errors.New("invalid audit text")
			}
		case 'b', 'B':
			if _, ok := v.([]byte); !ok {
				return errors.New("invalid audit blob")
			}
		}
	}
	return nil
}

func (s receiverAuditStore) index(ctx context.Context) (int64, error) {
	var count int64
	for section, inv := range s.publication.manifest.Cut.Inventory {
		component := section + 3
		for position := int64(0); position < inv.Records; position++ {
			ordinal := position + 1
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			row, err := s.record(ctx, component, ordinal)
			if err != nil {
				return 0, err
			}
			var sequence, generation, round int64
			var scope, request, operation, coord string
			key, claim, nonce := []byte{}, []byte{}, []byte{}
			switch component {
			case 3, 4:
				k := ClaimKey{TargetKind: row.String("target_kind"), TargetName: row.String("target_name"), Incarnation: row.String("incarnation"), OwnerEpoch: row.Int64("owner_epoch"), Attempt: row.Int64("attempt")}
				if err = k.Validate(); err != nil {
					return 0, err
				}
				if (component == 3 && k.Incarnation != "") || (component == 4 && k.Incarnation == "") {
					return 0, errors.New("claim table lifetime differs")
				}
				claim, _ = json.Marshal(k)
				key = claim
				generation = row.Int64("config_generation")
				round = row.Int64("accepted_round")
				coord = row.String("accepted_coord")
				nonce = row.Bytes("accepted_nonce")
				if nonce == nil {
					nonce = []byte{}
				}
			case 5, 6:
				sequence = row.Int64("sequence")
				key = automationCutInteger(sequence)
			case 7:
				scope = row.String("scope")
				request = row.String("request_id")
				operation = row.String("operation_id")
				key, _ = json.Marshal([]string{scope, request})
			case 8:
				sequence = row.Int64("id")
				key = automationCutInteger(sequence)
			default:
				sequence = row.Int64("generation")
				key = automationCutInteger(sequence)
			}
			if len(key) > 4*maxSourceFieldBytes || len(coord) > maxSourceFieldBytes || len(nonce) > 256 || len(scope) > maxSourceFieldBytes || len(request) > maxSourceFieldBytes || len(operation) > maxSourceFieldBytes {
				return 0, errors.New("audit semantic identity exceeds bound")
			}
			if component != 3 && component != 4 && component != 7 && sequence <= 0 {
				return 0, errors.New("audit nonpositive sequence")
			}
			_, err = s.tx.Exec(ctx, `INSERT INTO local_automation_receiver_refs(audit,component,ordinal,sequence,semantic_key,scope,request_id,operation_id,claim_key,generation,accepted_round,accepted_coord,accepted_nonce) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, s.id, component, ordinal, sequence, key, scope, request, operation, claim, generation, round, coord, nonce)
			if err != nil {
				return 0, err
			}
			if count == math.MaxInt64 {
				return 0, errors.New("audit count overflow")
			}
			count++
		}
	}
	return count, nil
}
