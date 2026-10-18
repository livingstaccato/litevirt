package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
)

// Descriptors are closed over these four actual C-owned tables. The cursor is
// the complete indexed primary-key suffix, never rowid or a residual filter.
type aggregateColumn struct {
	name, kind string
	bound      int64
	positive   bool
}
type aggregateTable struct {
	name    string
	columns []aggregateColumn
	keys    int
}

var aggregateCopiesTable = aggregateTable{"local_automation_aggregate_copies", []aggregateColumn{
	{"origin_kind", "text", 6, false}, {"origin_id", "text", 64, false}, {"component", "integer", 0, true}, {"ordinal", "integer", 0, true},
	{"claim_key", "blob", 4 * maxSourceFieldBytes, false}, {"promised_round", "integer", 0, false}, {"promised_coord", "text", maxSourceFieldBytes, false}, {"promised_nonce", "blob", 256, false},
	{"accepted_round", "integer", 0, false}, {"accepted_coord", "text", maxSourceFieldBytes, false}, {"accepted_nonce", "blob", 256, false}, {"origin_ref", "blob", maxAutomationCutMetadataBytes, false},
}, 4}
var aggregateMaximaTable = aggregateTable{"local_automation_aggregate_maxima", []aggregateColumn{
	{"claim_key", "blob", 4 * maxSourceFieldBytes, false}, {"promise_ref", "blob", 1024, false}, {"accepted_ref", "blob", 1024, false},
}, 1}
var aggregateConflictsTable = aggregateTable{"local_automation_aggregate_conflicts", []aggregateColumn{
	{"claim_key", "blob", 4 * maxSourceFieldBytes, false}, {"round", "integer", 0, true}, {"coord", "text", maxSourceFieldBytes, false}, {"nonce", "blob", 256, false}, {"first_ref", "blob", 1024, false},
}, 4}
var aggregateSourcesTable = aggregateTable{"local_automation_aggregate_sources", []aggregateColumn{
	{"source", "text", maxSourceFieldBytes, false}, {"incarnation", "text", maxSourceFieldBytes, false}, {"audit", "text", 64, false}, {"publication", "text", 64, false}, {"root", "text", 64, false}, {"cut_id", "text", maxSourceFieldBytes, false},
}, 1}
var aggregateEvidenceTables = []aggregateTable{aggregateCopiesTable, aggregateMaximaTable, aggregateConflictsTable, aggregateSourcesTable}

func (d aggregateTable) names(n int) string {
	names := make([]string, n)
	for i := range names {
		names[i] = d.columns[i].name
	}
	return strings.Join(names, ",")
}
func (d aggregateTable) probes() string {
	parts := make([]string, 0, 3*len(d.columns))
	for i, c := range d.columns {
		parts = append(parts, fmt.Sprintf("typeof(%s) AS t%d,length(CAST(%s AS BLOB)) AS n%d", c.name, i, c.name, i))
		if c.kind == "integer" {
			parts = append(parts, fmt.Sprintf("CASE WHEN typeof(%s)='integer' THEN %s ELSE NULL END AS v%d", c.name, c.name, i))
		}
	}
	return strings.Join(parts, ",")
}
func (d aggregateTable) validateProbe(row Row) error {
	for i, c := range d.columns {
		if row.String(fmt.Sprintf("t%d", i)) != c.kind {
			return errors.New("aggregate stored field type differs")
		}
		if c.kind == "integer" {
			value := row.Int64(fmt.Sprintf("v%d", i))
			if value < 0 || (c.positive && value == 0) {
				return errors.New("aggregate stored integer outside domain")
			}
		} else {
			size := row.Int64(fmt.Sprintf("n%d", i))
			if size < 0 || size > c.bound || (i < d.keys && size == 0) {
				return errors.New("aggregate stored field exceeds bound")
			}
		}
	}
	return nil
}

// The scalar query precedes the body query with the SAME indexed domain/order.
// Malformed NULL, nonpositive, fractional and excessive primary keys cannot
// hide outside a cursor made by coercing them first.
func aggregateNextRow(ctx context.Context, tx *LocalTx, d aggregateTable, bundle string, after []any) (Row, bool, error) {
	where := " WHERE bundle=?"
	args := []any{bundle}
	if after != nil {
		where += " AND (" + d.names(d.keys) + ")>(" + strings.TrimRight(strings.Repeat("?,", d.keys), ",") + ")"
		args = append(args, after...)
	}
	suffix := where + " ORDER BY " + d.names(d.keys) + " LIMIT 1"
	rows, err := tx.Query(ctx, "SELECT "+d.probes()+" FROM "+d.name+suffix, args...)
	if err != nil {
		return Row{}, false, err
	}
	if len(rows) == 0 {
		return Row{}, false, nil
	}
	if err = d.validateProbe(rows[0]); err != nil {
		return Row{}, false, err
	}
	rows, err = tx.Query(ctx, "SELECT "+d.names(len(d.columns))+" FROM "+d.name+suffix, args...)
	if err != nil {
		return Row{}, false, err
	}
	if len(rows) != 1 {
		return Row{}, false, errors.New("aggregate row disappeared")
	}
	return rows[0], true, nil
}
func aggregateWalkTable(ctx context.Context, tx *LocalTx, d aggregateTable, bundle string, visit func(Row) error) error {
	var after []any
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		row, found, err := aggregateNextRow(ctx, tx, d, bundle, after)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		if err = visit(row); err != nil {
			return err
		}
		after = append([]any(nil), row.Values[:d.keys]...)
	}
}
func aggregateExactRow(ctx context.Context, tx *LocalTx, d aggregateTable, bundle string, key []any) (Row, error) {
	args := []any{bundle}
	where := " WHERE bundle=?"
	for i := 0; i < d.keys; i++ {
		where += " AND " + d.columns[i].name + "=?"
		args = append(args, key[i])
	}
	where += " LIMIT 1"
	rows, err := tx.Query(ctx, "SELECT "+d.probes()+" FROM "+d.name+where, args...)
	if err != nil {
		return Row{}, err
	}
	if len(rows) != 1 {
		return Row{}, errors.New("immutable aggregate row missing")
	}
	if err = d.validateProbe(rows[0]); err != nil {
		return Row{}, err
	}
	rows, err = tx.Query(ctx, "SELECT "+d.names(len(d.columns))+" FROM "+d.name+where, args...)
	if err != nil {
		return Row{}, err
	}
	if len(rows) != 1 {
		return Row{}, errors.New("immutable aggregate row disappeared")
	}
	return rows[0], nil
}
func aggregateCompareTable(ctx context.Context, tx *LocalTx, d aggregateTable, built, existing string) error {
	var expected, actual int64
	err := aggregateWalkTable(ctx, tx, d, built, func(row Row) error {
		if expected == math.MaxInt64 {
			return errors.New("aggregate inventory count overflow")
		}
		expected++
		other, err := aggregateExactRow(ctx, tx, d, existing, row.Values[:d.keys])
		if err != nil {
			return err
		}
		left, _ := json.Marshal(row)
		right, _ := json.Marshal(other)
		if !bytes.Equal(left, right) {
			return errors.New("immutable aggregate row differs")
		}
		return nil
	})
	if err != nil {
		return err
	}
	err = aggregateWalkTable(ctx, tx, d, existing, func(Row) error {
		if actual >= expected {
			return errors.New("immutable aggregate extra row")
		}
		actual++
		return nil
	})
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("immutable aggregate count differs")
	}
	return nil
}

func aggregatePublishTx(ctx context.Context, tx *LocalTx, temporary, id, attempt, local string, head []byte, coverage string, rosterRaw []byte, roster []aggregateRosterEntry) error {
	for _, entry := range roster {
		if _, err := tx.Exec(ctx, `INSERT INTO local_automation_aggregate_sources(bundle,source,incarnation,audit,publication,root,cut_id) VALUES(?,?,?,?,?,?,?)`, temporary, entry.Source, entry.Incarnation, entry.Audit, entry.Publication, entry.Root, entry.Cut); err != nil {
			return err
		}
	}
	rows, err := tx.Query(ctx, `SELECT 1 AS present FROM local_automation_aggregates WHERE id=? LIMIT 1`, id)
	if err != nil {
		return err
	}
	if len(rows) > 0 {
		rows, err = tx.Query(ctx, `SELECT head,roster FROM local_automation_aggregates WHERE id=? AND typeof(attempt)='text' AND length(CAST(attempt AS BLOB))=? AND attempt=? AND typeof(local_id)='text' AND length(CAST(local_id AS BLOB))=? AND local_id=? AND typeof(head)='blob' AND length(CAST(head AS BLOB))=? AND typeof(coverage)='text' AND length(CAST(coverage AS BLOB))=64 AND coverage=? AND typeof(roster)='blob' AND length(CAST(roster AS BLOB))=? LIMIT 1`, id, len(attempt), attempt, len(local), local, len(head), coverage, len(rosterRaw))
		if err != nil {
			return err
		}
		if len(rows) != 1 || !bytes.Equal(rows[0].Bytes("head"), head) || !bytes.Equal(rows[0].Bytes("roster"), rosterRaw) {
			return errors.New("immutable aggregate manifest differs")
		}
		for _, d := range aggregateEvidenceTables {
			if err = aggregateCompareTable(ctx, tx, d, temporary, id); err != nil {
				return err
			}
		}
		return aggregateDeleteTemporaryTx(ctx, tx, temporary)
	}
	// No preexisting orphan may be absorbed by a later manifest publication.
	for _, d := range aggregateEvidenceTables {
		rows, err = tx.Query(ctx, "SELECT 1 AS present FROM "+d.name+" WHERE bundle=? LIMIT 1", id)
		if err != nil {
			return err
		}
		if len(rows) != 0 {
			return errors.New("unpublished aggregate identity already has rows")
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE local_automation_aggregate_copies SET bundle=? WHERE bundle=?`, id, temporary); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE local_automation_aggregate_maxima SET bundle=? WHERE bundle=?`, id, temporary); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE local_automation_aggregate_conflicts SET bundle=? WHERE bundle=?`, id, temporary); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE local_automation_aggregate_sources SET bundle=? WHERE bundle=?`, id, temporary); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO local_automation_aggregates(id,attempt,local_id,head,coverage,roster) VALUES(?,?,?,?,?,?)`, id, attempt, local, head, coverage, rosterRaw)
	return err
}
func aggregateDeleteTemporaryTx(ctx context.Context, tx *LocalTx, id string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_aggregate_copies WHERE bundle=?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_aggregate_maxima WHERE bundle=?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_aggregate_conflicts WHERE bundle=?`, id); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM local_automation_aggregate_sources WHERE bundle=?`, id)
	return err
}

// All seven tables are inert, but accepting a different storage shape could
// erase lifetime separation or invalidate the indexed bounded-reader contract.
func aggregateVerifySchemaTx(ctx context.Context, tx *LocalTx) error {
	type shape struct {
		name, columns, kinds string
		keys                 int
		nullableID           bool
	}
	shapes := []shape{
		{"local_automation_local_audits", "id,attempt,dependency,head,coverage,records,origin", "tttbtib", 1, true},
		{"local_automation_local_rows", "local_id,section,ordinal,record", "tiib", 3, false},
		{"local_automation_aggregates", "id,attempt,local_id,head,coverage,roster", "tttbtb", 1, true},
	}
	for _, d := range aggregateEvidenceTables {
		kinds := "t"
		for _, c := range d.columns {
			switch c.kind {
			case "text":
				kinds += "t"
			case "blob":
				kinds += "b"
			case "integer":
				kinds += "i"
			}
		}
		shapes = append(shapes, shape{d.name, "bundle," + d.names(len(d.columns)), kinds, d.keys + 1, false})
	}
	for _, s := range shapes {
		columns := strings.Split(s.columns, ",")
		if err := aggregateVerifyIndexesTx(ctx, tx, s.name, columns[:s.keys]); err != nil {
			return err
		}
		for i, column := range columns {
			// Metadata itself is finite and probed before names/defaults are loaded.
			rows, err := tx.Query(ctx, `SELECT typeof(name) AS nt,length(CAST(name AS BLOB)) AS nl,typeof(type) AS tt,length(CAST(type AS BLOB)) AS tl,typeof(dflt_value) AS dt FROM pragma_table_xinfo(?) WHERE cid=? LIMIT 1`, s.name, i)
			if err != nil {
				return err
			}
			if len(rows) != 1 || rows[0].String("nt") != "text" || rows[0].Int64("nl") > 128 || rows[0].String("tt") != "text" || rows[0].Int64("tl") > 16 || rows[0].String("dt") != "null" {
				return fmt.Errorf("unsupported aggregate storage schema: %s", s.name)
			}
			rows, err = tx.Query(ctx, `SELECT name,type,"notnull" AS nn,pk,hidden FROM pragma_table_xinfo(?) WHERE cid=? LIMIT 1`, s.name, i)
			if err != nil {
				return err
			}
			if len(rows) != 1 {
				return errors.New("unsupported aggregate storage schema disappeared")
			}
			kind := map[byte]string{'t': "TEXT", 'i': "INTEGER", 'b': "BLOB"}[s.kinds[i]]
			nn, pk := int64(1), int64(0)
			if s.nullableID && i == 0 {
				nn = 0
			}
			if i < s.keys {
				pk = int64(i + 1)
			}
			row := rows[0]
			if row.String("name") != column || row.String("type") != kind || row.Int64("nn") != nn || row.Int64("pk") != pk || row.Int64("hidden") != 0 {
				return fmt.Errorf("unsupported aggregate storage schema: %s.%s", s.name, column)
			}
		}
		rows, err := tx.Query(ctx, `SELECT 1 AS extra FROM pragma_table_xinfo(?) WHERE cid>=? LIMIT 1`, s.name, len(columns))
		if err != nil {
			return err
		}
		if len(rows) != 0 {
			return fmt.Errorf("unsupported aggregate storage schema: extra column in %s", s.name)
		}
	}
	return nil
}

func aggregateVerifyIndexesTx(ctx context.Context, tx *LocalTx, table string, primary []string) error {
	count := 1
	if table == "local_automation_aggregate_sources" {
		count = 2
	}
	for ordinal := 0; ordinal < count; ordinal++ {
		rows, err := tx.Query(ctx, `SELECT typeof(name) AS kind,length(CAST(name AS BLOB)) AS size FROM pragma_index_list(?) WHERE seq=? LIMIT 1`, table, ordinal)
		if err != nil {
			return err
		}
		if len(rows) != 1 || rows[0].String("kind") != "text" || rows[0].Int64("size") < 1 || rows[0].Int64("size") > 128 {
			return errors.New("unsupported aggregate storage schema index")
		}
		rows, err = tx.Query(ctx, `SELECT name,origin,"unique" AS uq,partial FROM pragma_index_list(?) WHERE seq=? LIMIT 1`, table, ordinal)
		if err != nil {
			return err
		}
		if len(rows) != 1 || rows[0].Int64("uq") != 1 || rows[0].Int64("partial") != 0 {
			return errors.New("unsupported aggregate storage schema index shape")
		}
		index := rows[0].String("name")
		keys := primary
		switch rows[0].String("origin") {
		case "pk":
		case "u":
			if count != 2 {
				return errors.New("unsupported aggregate storage schema extra unique index")
			}
			keys = []string{"bundle", "incarnation"}
		default:
			return errors.New("unsupported aggregate storage schema index origin")
		}
		for position, key := range keys {
			rows, err = tx.Query(ctx, `SELECT typeof(coll) AS kind,length(CAST(coll AS BLOB)) AS size FROM pragma_index_xinfo(?) WHERE seqno=? LIMIT 1`, index, position)
			if err != nil {
				return err
			}
			if len(rows) != 1 || rows[0].String("kind") != "text" || rows[0].Int64("size") > 16 {
				return errors.New("unsupported aggregate storage schema index collation")
			}
			rows, err = tx.Query(ctx, `SELECT coll,"desc" AS descending,"key" AS is_key FROM pragma_index_xinfo(?) WHERE seqno=? LIMIT 1`, index, position)
			if err != nil {
				return err
			}
			if len(rows) != 1 || rows[0].String("coll") != "BINARY" || rows[0].Int64("descending") != 0 || rows[0].Int64("is_key") != 1 {
				return errors.New("unsupported aggregate storage schema index order")
			}
			rows, err = tx.Query(ctx, `SELECT typeof(name) AS kind,length(CAST(name AS BLOB)) AS size FROM pragma_index_info(?) WHERE seqno=? LIMIT 1`, index, position)
			if err != nil {
				return err
			}
			if len(rows) != 1 || rows[0].String("kind") != "text" || rows[0].Int64("size") > 128 {
				return errors.New("unsupported aggregate storage schema index column")
			}
			rows, err = tx.Query(ctx, `SELECT name FROM pragma_index_info(?) WHERE seqno=? LIMIT 1`, index, position)
			if err != nil {
				return err
			}
			if len(rows) != 1 || rows[0].String("name") != key {
				return errors.New("unsupported aggregate storage schema index key")
			}
		}
		rows, err = tx.Query(ctx, `SELECT 1 AS extra FROM pragma_index_info(?) WHERE seqno>=? LIMIT 1`, index, len(keys))
		if err != nil {
			return err
		}
		if len(rows) != 0 {
			return errors.New("unsupported aggregate storage schema extra index key")
		}
	}
	rows, err := tx.Query(ctx, `SELECT 1 AS extra FROM pragma_index_list(?) WHERE seq>=? LIMIT 1`, table, count)
	if err != nil {
		return err
	}
	if len(rows) != 0 {
		return errors.New("unsupported aggregate storage schema extra index")
	}
	return nil
}
