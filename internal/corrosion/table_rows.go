package corrosion

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Streamed repair pulls (colonelpanik/litevirt#262,
// docs/design/ae-incremental.md).
//
// The blob dump builds every row of every requested table in memory,
// marshals and gzips the lot, and only then chunks it; the receiver
// reassembles every chunk before it merges a row. A paged pull reads each
// table a page at a time, keyset-paginated on its primary key under a brief
// read lock per page, and the receiver merges each page as it arrives.
//
// The one thing a page cannot do alone is carry merge authority: a VM or
// container child is judged against its parent row in the same payload, and
// a parent row against the manifest built from every parent row (which is
// also where a duplicated identity is detected). So tables are sent in
// merge-dependency order, and the receiver holds the parent tier — vms,
// containers, operations — until the first table after it, builds the
// manifest, merges the parents and streams the rest.

var (
	// antiEntropyPageRows bounds the rows one page carries and one read of a
	// table returns. Vars so tests can shrink them.
	antiEntropyPageRows = 1000
	// antiEntropyPageBytes bounds a page's encoded (pre-gzip) rows.
	antiEntropyPageBytes = 1 << 20
)

// ErrPageOutOfOrder is a paged pull whose tables arrive out of merge-dependency
// order: a child page before its parents would be judged without them.
var ErrPageOutOfOrder = errors.New("table rows: page out of merge-dependency order")

// streamOrder sorts tables into merge-dependency order, stable within a tier.
func streamOrder(tables []string) []string {
	out := append([]string(nil), tables...)
	sort.SliceStable(out, func(i, j int) bool { return mergeDependencyRank(out[i]) < mergeDependencyRank(out[j]) })
	return out
}

// parentTier reports whether a table's rows feed the authority manifest.
func parentTier(table string) bool { return mergeDependencyRank(table) <= 1 }

// readTablePage reads up to limit rows of table after the primary key after
// (nil: from the start), in primary-key order, under a brief read lock.
// usedOffset switches a table to OFFSET paging for the rest of its read: a
// table with no known primary key, or a page ending on a NULL key cell, which
// a row-value comparison would never get past.
func (c *Client) readTablePage(ctx context.Context, table string, pk []string, after []interface{}, offset, limit int) (cols []string, rows [][]interface{}, err error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	q := "SELECT * FROM " + table
	var args []interface{}
	switch {
	case len(pk) > 0 && after != nil:
		ph := make([]string, len(pk))
		for i := range ph {
			ph[i] = "?"
		}
		q += " WHERE (" + strings.Join(pk, ", ") + ") > (" + strings.Join(ph, ", ") + ")"
		args = append(args, after...)
		q += " ORDER BY " + strings.Join(pk, ", ") + " LIMIT ?"
		args = append(args, limit)
	case len(pk) > 0:
		q += " ORDER BY " + strings.Join(pk, ", ") + " LIMIT ? OFFSET ?"
		args = append(args, limit, offset)
	default:
		q += " ORDER BY rowid LIMIT ? OFFSET ?"
		args = append(args, limit, offset)
	}
	r, err := c.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, nil, err
	}
	defer r.Close()
	if cols, err = r.Columns(); err != nil {
		return nil, nil, err
	}
	for r.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := r.Scan(ptrs...); err != nil {
			continue
		}
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				vals[i] = string(b)
			}
		}
		rows = append(rows, vals)
	}
	return cols, rows, r.Err()
}

// pageWriter accumulates one table's rows into bounded pages.
type pageWriter struct {
	table string
	cols  []string
	buf   bytes.Buffer
	n     int
	send  func(*pb.TableRowsPage) error
	sent  int // compressed bytes sent
}

func (w *pageWriter) add(row []interface{}) error {
	enc, err := json.Marshal(row)
	if err != nil {
		return err
	}
	if w.n == 0 {
		w.buf.WriteByte('[')
	} else {
		w.buf.WriteByte(',')
	}
	w.buf.Write(enc)
	w.n++
	if w.n >= antiEntropyPageRows || w.buf.Len() >= antiEntropyPageBytes {
		return w.flush()
	}
	return nil
}

func (w *pageWriter) flush() error {
	if w.n == 0 {
		return nil
	}
	w.buf.WriteByte(']')
	var z bytes.Buffer
	gz := gzip.NewWriter(&z)
	gz.Write(w.buf.Bytes())
	gz.Close()
	page := &pb.TableRowsPage{Table: w.table, Columns: w.cols, Rows: z.Bytes(), RowCount: int32(w.n)}
	w.buf.Reset()
	w.n = 0
	w.sent += z.Len()
	return w.send(page)
}

// streamTables pages every table in tables (already resolved), narrowed by
// scope, in merge-dependency order, then sends the final marker.
func (c *Client) streamTables(ctx context.Context, tables []string, scope dumpScope, send func(*pb.TableRowsPage) error) error {
	start := time.Now()
	total := 0
	for _, table := range streamOrder(tables) {
		n, err := c.streamTable(ctx, table, scope[table], send)
		total += n
		if err != nil {
			return err
		}
	}
	c.observeDump(time.Since(start), total)
	return send(&pb.TableRowsPage{Final: true})
}

func (c *Client) streamTable(ctx context.Context, table string, set map[int]bool, send func(*pb.TableRowsPage) error) (int, error) {
	pk := tablePrimaryKeys[table]
	var keyIdx []int
	w := &pageWriter{table: table, send: send}
	var after []interface{}
	offset := 0
	useOffset := len(pk) == 0
	for {
		if err := ctx.Err(); err != nil {
			return w.sent, err
		}
		var cols []string
		var rows [][]interface{}
		var err error
		if useOffset {
			cols, rows, err = c.readTablePage(ctx, table, pk, nil, offset, antiEntropyPageRows)
		} else {
			cols, rows, err = c.readTablePage(ctx, table, pk, after, 0, antiEntropyPageRows)
		}
		if err != nil {
			if w.cols == nil {
				return 0, nil // table may not exist yet, as dumpTable treats it
			}
			return w.sent, err
		}
		if w.cols == nil {
			w.cols = cols
			if set != nil {
				keyIdx = columnIndexes(cols, bucketKeyColumns(table))
			}
		} else if !sameColumns(w.cols, cols) {
			return w.sent, fmt.Errorf("table rows: %s changed columns mid-stream", table)
		}
		for _, row := range rows {
			if set != nil && len(keyIdx) > 0 {
				if b, ok := rowBucket(row, keyIdx); ok && !set[b] {
					continue
				}
			}
			if err := w.add(row); err != nil {
				return w.sent, err
			}
		}
		if len(rows) < antiEntropyPageRows {
			break
		}
		offset += len(rows)
		if !useOffset {
			pkIdx := columnIndexes(cols, pk)
			last := rows[len(rows)-1]
			after = make([]interface{}, len(pkIdx))
			for i, k := range pkIdx {
				after[i] = last[k]
				if last[k] == nil {
					useOffset = true
				}
			}
			if len(pkIdx) != len(pk) {
				useOffset = true
			}
		}
	}
	return w.sent, w.flush()
}

// StreamTableRowsScoped pages the public tables a DumpTablesScopedBytes of the
// same request would carry. Peer-only, like the blob dump.
func (c *Client) StreamTableRowsScoped(ctx context.Context, tables []string, buckets map[string][]int, send func(*pb.TableRowsPage) error) error {
	resolved, scope, err := resolveTableDumpScope(tables, buckets)
	if err != nil {
		return err
	}
	return c.streamTables(ctx, resolved, scope, send)
}

// StreamSensitiveTableRowsScoped pages the sensitive lane, narrowed like
// DumpSensitiveTablesScopedBytes; no tables named is the whole lane. Callers
// must have checked the peer.
func (c *Client) StreamSensitiveTableRowsScoped(ctx context.Context, tables []string, buckets map[string][]int, send func(*pb.TableRowsPage) error) error {
	if len(tables) == 0 {
		return c.streamTables(ctx, sensitiveTableNames, nil, send)
	}
	resolved, scope := resolveSensitiveDumpScope(tables, buckets)
	return c.streamTables(ctx, resolved, scope, send)
}

func decodePageRows(p *pb.TableRowsPage) ([][]interface{}, error) {
	if len(p.GetRows()) == 0 {
		return nil, nil
	}
	gz, err := gzip.NewReader(bytes.NewReader(p.GetRows()))
	if err != nil {
		return nil, fmt.Errorf("table rows: %w", err)
	}
	defer gz.Close()
	data, err := io.ReadAll(gz)
	if err != nil {
		return nil, fmt.Errorf("table rows: %w", err)
	}
	var rows [][]interface{}
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, fmt.Errorf("table rows: %w", err)
	}
	return rows, nil
}

// pagedMerge is the receiving side of one paged pull.
type pagedMerge struct {
	c       *Client
	allowed map[string]bool
	// keep names the tables whose rows are retained whole for the caller
	// (the settled-tie proof).
	keep map[string]bool

	parents     syncPayload
	parentsDone bool
	manifest    *mergeAuthorityManifest
	lastRank    int
	merged      int
	skipped     int
	rows        map[string]int
	kept        syncPayload
	firstErr    error
}

func newPagedMerge(c *Client, allowed, keep map[string]bool) *pagedMerge {
	return &pagedMerge{c: c, allowed: allowed, keep: keep, lastRank: -1, rows: map[string]int{}}
}

func appendRows(p *syncPayload, table string, cols []string, rows [][]interface{}) error {
	for i := range p.Tables {
		if p.Tables[i].Name == table {
			if !sameColumns(p.Tables[i].Columns, cols) {
				return fmt.Errorf("table rows: %s changed columns mid-stream", table)
			}
			p.Tables[i].Rows = append(p.Tables[i].Rows, rows...)
			return nil
		}
	}
	p.Tables = append(p.Tables, syncTable{Name: table, Columns: cols, Rows: rows})
	return nil
}

func (m *pagedMerge) mergeOne(st syncTable) {
	mg, sk, err := m.c.mergeTable(st, m.allowed)
	m.merged += mg
	m.skipped += sk
	if err != nil && m.firstErr == nil {
		m.firstErr = err
	}
}

// finishParents builds the manifest from every parent row received and
// merges the parent tier, exactly as authorityOrderedMergeTables does for a
// blob payload.
func (m *pagedMerge) finishParents() {
	if m.parentsDone {
		return
	}
	m.parentsDone = true
	for _, st := range authorityOrderedMergeTables(&m.parents) {
		m.manifest = st.authority
		m.mergeOne(st)
	}
	if m.manifest == nil {
		m.manifest = buildMergeAuthorityManifest(&m.parents)
	}
	m.parents = syncPayload{}
}

func (m *pagedMerge) page(p *pb.TableRowsPage) error {
	table := p.GetTable()
	if table == "" {
		return nil
	}
	rank := mergeDependencyRank(table)
	if rank < m.lastRank {
		return fmt.Errorf("%w: %s after rank %d", ErrPageOutOfOrder, table, m.lastRank)
	}
	m.lastRank = rank
	rows, err := decodePageRows(p)
	if err != nil {
		return err
	}
	m.rows[table] += len(rows)
	if m.keep[table] {
		if err := appendRows(&m.kept, table, p.GetColumns(), rows); err != nil {
			return err
		}
	}
	if parentTier(table) {
		return appendRows(&m.parents, table, p.GetColumns(), rows)
	}
	m.finishParents()
	m.mergeOne(syncTable{Name: table, Columns: p.GetColumns(), Rows: rows, authority: m.manifest})
	return nil
}

func (m *pagedMerge) finish(start time.Time) error {
	m.finishParents()
	m.c.observeMerge(time.Since(start), m.merged, m.skipped)
	slog.Info("sync: merged paged remote state (LWW)", "tables", len(m.rows), "merged", m.merged, "skipped", m.skipped)
	return m.firstErr
}

// mergeTableRowsStream receives a paged pull and merges it as it arrives.
// recv returns io.EOF at the end of the stream. It returns the rows of the
// keep tables and the rows received per table. pullErr is the stream failing
// (or sending something malformed); mergeErr is a merge failing. Pages merged
// before a pull error stay merged: the merge is per-row idempotent and
// non-destructive, and the next pass pulls again.
func (c *Client) mergeTableRowsStream(recv func() (*pb.TableRowsPage, error), allowed, keep map[string]bool) (kept *syncPayload, rows map[string]int, pullErr, mergeErr error) {
	start := time.Now()
	m := newPagedMerge(c, allowed, keep)
	for {
		p, err := recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return &m.kept, m.rows, err, nil
		}
		if perr := m.page(p); perr != nil {
			return &m.kept, m.rows, perr, nil
		}
		if p.GetFinal() {
			break
		}
	}
	return &m.kept, m.rows, nil, m.finish(start)
}
