package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Only compiled SELECT statements live here, never rows, parameters or bodies.
// The owner is the exact FULL transaction; the nil store field keeps B's
// established direct-query path unchanged. The fixed slots cannot grow with
// history, claims, sources, or caller SQL.
type aggregatePreparedReads struct {
	owner      *LocalTx
	statements [13]*sql.Stmt
	closed     bool
}

// The callback cannot publish success until all actual statements close. The
// same deferred cleanup also runs while unwinding a refusal or panic.
func aggregatePreparedReadsTx(tx *LocalTx, visit func(*aggregatePreparedReads) error) (err error) {
	reads := &aggregatePreparedReads{owner: tx}
	defer func() {
		if closeErr := reads.close(); err == nil {
			err = closeErr
		}
	}()
	return visit(reads)
}

func (s receiverAuditStore) query(ctx context.Context, query string, args ...interface{}) ([]Row, error) {
	if s.prepared == nil {
		return s.tx.Query(ctx, query, args...)
	}
	return s.prepared.query(ctx, s.tx, query, args...)
}

func (p *aggregatePreparedReads) query(ctx context.Context, owner *LocalTx, query string, args ...interface{}) ([]Row, error) {
	if p.closed || p.owner == nil || p.owner != owner {
		return nil, errors.New("aggregate prepared read outside owning transaction")
	}
	var slot int
	switch query {
	case `SELECT typeof(record) AS kind,length(CAST(record AS BLOB)) AS size FROM local_automation_receiver_records WHERE attempt=? AND source=? AND component=? AND ordinal=? LIMIT 1`:
		slot = 0
	case `SELECT record FROM local_automation_receiver_records WHERE attempt=? AND source=? AND component=? AND ordinal=? AND typeof(record)='blob' AND length(CAST(record AS BLOB))=? LIMIT 1`:
		slot = 1
	case `SELECT ordinal FROM local_automation_receiver_refs WHERE audit=? AND component=? AND sequence=? AND component IN (5,6,8,9,10,11) LIMIT 1`:
		slot = 2
	case `SELECT ordinal FROM local_automation_receiver_refs WHERE audit=? AND component=? AND ordinal>? ORDER BY ordinal LIMIT 1`:
		slot = 3
	case `SELECT length(CAST(identity AS BLOB)) AS identity,length(CAST(receipt AS BLOB)) AS receipt FROM local_automation_receiver_requests WHERE audit=? AND scope=? AND request_id=? LIMIT 1`:
		slot = 4
	case `SELECT identity,receipt FROM local_automation_receiver_requests WHERE audit=? AND scope=? AND request_id=? AND length(CAST(identity AS BLOB))=? AND length(CAST(receipt AS BLOB))=? LIMIT 1`:
		slot = 5
	case `SELECT length(CAST(receipt AS BLOB)) AS size FROM local_automation_receiver_requests WHERE audit=? AND operation_id=? AND operation_id<>'' LIMIT 1`:
		slot = 6
	case `SELECT receipt FROM local_automation_receiver_requests WHERE audit=? AND operation_id=? AND operation_id<>'' AND length(CAST(receipt AS BLOB))=? LIMIT 1`:
		slot = 7
	case `SELECT ordinal FROM local_automation_receiver_refs WHERE audit=? AND component=7 AND scope=? AND request_id=? LIMIT 1`:
		slot = 8
	case `SELECT typeof(record) AS kind,length(record) AS size FROM local_automation_local_rows WHERE local_id=? AND section=? AND ordinal=? LIMIT 1`:
		slot = 9
	case `SELECT record FROM local_automation_local_rows WHERE local_id=? AND section=? AND ordinal=? LIMIT 1`:
		slot = 10
	case `SELECT typeof(record) AS kind,length(record) AS size FROM local_automation_cut_records WHERE cut_id=? AND section=? AND ordinal=? LIMIT 1`:
		slot = 11
	case `SELECT record FROM local_automation_cut_records WHERE cut_id=? AND section=? AND ordinal=? LIMIT 1`:
		slot = 12
	default:
		return nil, errors.New("aggregate prepared read statement outside fixed inventory")
	}
	stmt := p.statements[slot]
	if stmt == nil {
		var err error
		// sql.Tx.PrepareContext pins this statement to the same transaction and
		// connection used by LocalTx.Query. No DB-level statement or new Tx exists.
		stmt, err = owner.tx.PrepareContext(ctx, query)
		if err != nil {
			return nil, fmt.Errorf("query: %w", err)
		}
		p.statements[slot] = stmt
	}
	rows, err := stmt.QueryContext(ctx, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []Row
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				// BLOB columns (the ballot nonces) keep their bytes; the Row
				// accessors read them back through Bytes.
				vals[i] = append([]byte(nil), b...)
			}
		}
		out = append(out, Row{Columns: cols, Values: vals})
	}
	return out, rows.Err()
}

// Invalidate first and close every slot even when an earlier close fails.
// Rows have already closed/reset before any original's decoding scope returns.
func (p *aggregatePreparedReads) close() error {
	p.closed = true
	p.owner = nil
	var first error
	for i, stmt := range p.statements {
		if stmt != nil {
			if err := stmt.Close(); err != nil && first == nil {
				first = fmt.Errorf("close aggregate prepared read: %w", err)
			}
			p.statements[i] = nil
		}
	}
	return first
}
