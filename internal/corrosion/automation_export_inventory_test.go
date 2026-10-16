package corrosion

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"strings"
	"sync"
	"testing"

	"modernc.org/sqlite"
)

type exportInventoryQuery struct {
	text string
	args []any
}
type exportInventoryDriver struct {
	driver.Driver
	mu      sync.Mutex
	queries []exportInventoryQuery
}
type exportInventoryConn struct {
	driver.Conn
	owner *exportInventoryDriver
}

func (d *exportInventoryDriver) Open(name string) (driver.Conn, error) {
	c, err := d.Driver.Open(name)
	if err != nil {
		return nil, err
	}
	return &exportInventoryConn{Conn: c, owner: d}, nil
}
func (c *exportInventoryConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}
func (c *exportInventoryConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(q, "SELECT section FROM local_automation_cut_records") {
		entry := exportInventoryQuery{text: q}
		for _, arg := range args {
			entry.args = append(entry.args, arg.Value)
		}
		c.owner.mu.Lock()
		c.owner.queries = append(c.owner.queries, entry)
		c.owner.mu.Unlock()
	}
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}

// A disjunctive ordinal predicate with no fixed section regresses to a scan
// of every entry for cut_id. Inspect the actual executed production statements'
// SQLite plans on the actual schema, at two retained cardinalities. Synthetic
// extra rows here are scan-work instrumentation, not authenticated source data.
func TestSourceExportInventoryIndexedSeeks(t *testing.T) {
	p, r, ctx := exportFixtureAt(t, t.TempDir())
	d := &exportInventoryDriver{Driver: &sqlite.Driver{}}
	name := fmt.Sprintf("export-inventory-%d", sourceReadDriverSequence.Add(1))
	sql.Register(name, d)
	observed, err := sql.Open(name, p.client.dsn)
	if err != nil {
		t.Fatal(err)
	}
	original := p.client.db
	p.client.db = observed
	defer func() { p.client.db = original; observed.Close() }()
	var cutID string
	if err := original.QueryRow(`SELECT id FROM local_automation_cuts WHERE generation=1`).Scan(&cutID); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{32, 16384} {
		// Existing authentic records have low ordinals. Keep their bytes intact.
		if _, err := original.Exec(`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<?) INSERT OR IGNORE INTO local_automation_cut_records(cut_id,section,ordinal,record) SELECT ?,x%9,1000+x,x'01' FROM n`, n, cutID); err != nil {
			t.Fatal(err)
		}
		d.mu.Lock()
		d.queries = nil
		d.mu.Unlock()
		if _, err := p.ExportAutomationSource(ctx, r); err != nil {
			t.Fatal("actual bounded artifact export", err)
		}
		d.mu.Lock()
		queries := append([]exportInventoryQuery(nil), d.queries...)
		d.mu.Unlock()
		if len(queries) == 0 {
			t.Fatal("observer missed production inventory checks")
		}
		var count int
		if err := original.QueryRow(`SELECT COUNT(*) FROM local_automation_cut_records WHERE cut_id=?`, cutID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		for _, q := range queries {
			rows, err := original.QueryContext(ctx, "EXPLAIN QUERY PLAN "+q.text, q.args...)
			if err != nil {
				t.Fatal(err)
			}
			var plans []string
			for rows.Next() {
				var id, parent, unused int
				var detail string
				if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
					t.Fatal(err)
				}
				plans = append(plans, detail)
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			rows.Close()
			t.Logf("retained=%d actual query=%s args=%v plan=%v", count, q.text, q.args, plans)
			if len(plans) != 1 {
				t.Errorf("inventory query lacks one bounded index seek: %v", plans)
				continue
			}
			plan := plans[0]
			sectionRange := strings.Contains(plan, "(cut_id=? AND section<?)") || strings.Contains(plan, "(cut_id=? AND section>?)")
			ordinalRange := strings.Contains(plan, "(cut_id=? AND section=? AND ordinal<?)")
			if !strings.Contains(plan, "SEARCH ") || (!sectionRange && !ordinalRange) {
				t.Errorf("inventory work grows with retained cut: query has no section/ordinal range seek: %s", plan)
			}
		}
	}
}

// Even an artifact-only request must reject malformed inventory in every one
// of the finite sections; replacing validation with no check fails this test.
func TestSourceExportInventoryMalformedRows(t *testing.T) {
	p, r, ctx := exportFixture(t)
	if _, err := p.ExportAutomationSource(ctx, r); err != nil {
		t.Fatal(err)
	}
	rows, err := p.client.Query(ctx, `SELECT id FROM local_automation_cuts WHERE generation=1`)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	id := rows[0].String("id")
	cases := [][2]int{{-1, 1}, {9, 1}}
	for section := 0; section < 9; section++ {
		cases = append(cases, [2]int{section, 0}, [2]int{section, -1})
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("section%d-ordinal%d", tc[0], tc[1]), func(t *testing.T) {
			if err := p.client.ExecOutOfProcessForTest(`INSERT INTO local_automation_cut_records(cut_id,section,ordinal,record) VALUES(?,?,?,x'01')`, id, tc[0], tc[1]); err != nil {
				t.Fatal(err)
			}
			if _, err := p.ExportAutomationSource(ctx, r); err == nil {
				t.Error("malformed published inventory exported")
			}
			if err := p.client.ExecOutOfProcessForTest(`DELETE FROM local_automation_cut_records WHERE cut_id=? AND section=? AND ordinal=?`, id, tc[0], tc[1]); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err := p.ExportAutomationSource(ctx, r); err != nil {
		t.Fatal("restored positive", err)
	}
}
