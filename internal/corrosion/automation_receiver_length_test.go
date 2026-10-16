package corrosion

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"modernc.org/sqlite"
)

// Observe actual returned SQLite values, not SQL spelling or a successful
// authorization callback. Oversized wrappers must never cross this boundary.
type receiverBodyAuditDriver struct {
	driver.Driver
	oversized *atomic.Int64
}
type receiverBodyAuditConn struct {
	driver.Conn
	oversized *atomic.Int64
}
type receiverBodyAuditRows struct {
	driver.Rows
	oversized *atomic.Int64
}

func (d *receiverBodyAuditDriver) Open(name string) (driver.Conn, error) {
	c, e := d.Driver.Open(name)
	if e != nil {
		return nil, e
	}
	return &receiverBodyAuditConn{c, d.oversized}, nil
}
func (c *receiverBodyAuditConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}
func (c *receiverBodyAuditConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	rows, e := c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
	if e != nil {
		return nil, e
	}
	if strings.Contains(q, "FROM local_automation_receiver_") {
		return &receiverBodyAuditRows{rows, c.oversized}, nil
	}
	return rows, nil
}
func (r *receiverBodyAuditRows) Next(v []driver.Value) error {
	e := r.Rows.Next(v)
	if e == nil {
		for _, x := range v {
			switch b := x.(type) {
			case string:
				if len(b) > 65536 {
					r.oversized.Add(1)
				}
			case []byte:
				if len(b) > 65536 {
					r.oversized.Add(1)
				}
			}
		}
	}
	return e
}

func TestReceiverPersistedWrapperLengthBeforeBody(t *testing.T) {
	for _, field := range []string{"id", "publication", "metadata-publication", "request", "digest", "progress", "state", "cursor", "binding"} {
		t.Run(field, func(t *testing.T) {
			producer, r, q, peer, _ := receiverFixture(t)
			ctx := context.Background()
			a, e := r.Begin(ctx, q.Intent, nil)
			if e != nil {
				t.Fatal(e)
			}
			page, e := producer.ExportAutomationSource(peer, q)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = r.Stage(ctx, a, "a", q, page); e != nil {
				t.Fatal(e)
			}
			rows, e := r.client.Query(ctx, `PRAGMA database_list`)
			if e != nil {
				t.Fatal(e)
			}
			var path string
			for _, row := range rows {
				if row.String("name") == "main" {
					path = row.String("file")
				}
			}
			if path == "" {
				t.Fatal("missing actual file DB")
			}
			var oversized atomic.Int64
			name := fmt.Sprintf("receiver-body-audit-%d", sourceReadDriverSequence.Add(1))
			sql.Register(name, &receiverBodyAuditDriver{&sqlite.Driver{}, &oversized})
			db, e := sql.Open(name, sqliteDSN(path))
			if e != nil {
				t.Fatal(e)
			}
			db.SetMaxOpenConns(1)
			r.client.mu.Lock()
			old := r.client.db
			r.client.db = db
			r.client.mu.Unlock()
			if e = old.Close(); e != nil {
				t.Fatal(e)
			}
			table, column := "pages", field
			if field == "id" || field == "binding" {
				table = "jobs"
			}
			if field == "state" || field == "cursor" {
				table = "components"
			}
			if field == "publication" || field == "metadata-publication" {
				table = "sources"
				column = "publication"
			}
			if _, e = db.Exec(`UPDATE local_automation_receiver_` + table + ` SET ` + column + `=CAST(zeroblob(2097153) AS TEXT)`); e != nil {
				t.Fatal(e)
			}
			if field == "cursor" {
				if _, e = db.Exec(`DELETE FROM local_automation_receiver_pages`); e != nil {
					t.Fatal(e)
				}
			}
			stored := func() string {
				all := []byte(receiverStored(t, r.client))
				for _, tab := range []string{"jobs", "current", "validations"} {
					rows, err := r.client.Query(ctx, `SELECT * FROM local_automation_receiver_`+tab+` ORDER BY rowid`)
					if err != nil {
						t.Fatal(err)
					}
					raw, err := json.Marshal(rows)
					if err != nil {
						t.Fatal(err)
					}
					all = append(all, raw...)
				}
				return sourceDigest(all)
			}
			active := receiverActive(t, r.client)
			before := stored()
			// State snapshots above deliberately inspect all rows for equality; reset
			// the boundary recorder before the actual production operation under test.
			oversized.Store(0)
			if field == "id" {
				_, e = r.Begin(ctx, q.Intent, nil)
			} else if field == "metadata-publication" || field == "state" {
				_, e = r.metadata(ctx, a, "a", 0, q, page)
			} else {
				_, e = r.Stage(ctx, a, "a", q, page)
			}
			if e == nil {
				t.Fatal("malformed retained wrapper accepted")
			}
			if oversized.Load() != 0 {
				t.Fatal("oversized retained wrapper materialized before refusal")
			}
			if after := receiverActive(t, r.client); after != active {
				t.Fatal("wrapper refusal changed active state")
			}
			if after := stored(); after != before {
				t.Fatal("wrapper refusal changed retained evidence/progress")
			}
		})
	}
}
