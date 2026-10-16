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
type receiverRecordAudit struct {
	component uint32
	limit     int64
}

type receiverBodyAuditDriver struct {
	driver.Driver
	oversized *atomic.Int64
	record    *receiverRecordAudit
}
type receiverBodyAuditConn struct {
	driver.Conn
	oversized *atomic.Int64
	record    *receiverRecordAudit
}
type receiverBodyAuditRows struct {
	driver.Rows
	oversized *atomic.Int64
	limit     int64
}

func (d *receiverBodyAuditDriver) Open(name string) (driver.Conn, error) {
	c, e := d.Driver.Open(name)
	if e != nil {
		return nil, e
	}
	return &receiverBodyAuditConn{c, d.oversized, d.record}, nil
}
func (c *receiverBodyAuditConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}
func (c *receiverBodyAuditConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	rows, e := c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
	if e != nil {
		return nil, e
	}
	if c.record != nil {
		if strings.HasPrefix(q, "SELECT record FROM local_automation_receiver_records") && len(args) >= 3 && args[2].Value == int64(c.record.component) {
			return &receiverBodyAuditRows{rows, c.oversized, c.record.limit}, nil
		}
	} else if strings.Contains(q, "FROM local_automation_receiver_") {
		return &receiverBodyAuditRows{rows, c.oversized, 65536}, nil
	}
	return rows, nil
}
func (r *receiverBodyAuditRows) Next(v []driver.Value) error {
	e := r.Rows.Next(v)
	if e == nil {
		for _, x := range v {
			switch b := x.(type) {
			case string:
				if int64(len(b)) > r.limit {
					r.oversized.Add(1)
				}
			case []byte:
				if int64(len(b)) > r.limit {
					r.oversized.Add(1)
				}
			}
		}
	}
	return e
}

func TestReceiverPersistedWrapperLengthBeforeBody(t *testing.T) {
	for _, field := range []string{"id", "publication", "metadata-publication", "request", "digest", "progress", "state", "cursor", "binding", "supersede-revision-text", "supersede-revision-blob"} {
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
			sql.Register(name, &receiverBodyAuditDriver{Driver: &sqlite.Driver{}, oversized: &oversized})
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
			revisionField := strings.HasPrefix(field, "supersede-revision-")
			if revisionField {
				table = "jobs"
				column = "revision"
			}
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
			if revisionField {
				var corrupt any = "x\x00" + strings.Repeat("z", 2097153)
				if field == "supersede-revision-blob" {
					corrupt = []byte(corrupt.(string))
				}
				if _, e = db.Exec(`UPDATE local_automation_receiver_jobs SET revision=?`, corrupt); e != nil {
					t.Fatal(e)
				}
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
			if revisionField {
				intent := q.Intent
				intent.Revision++
				fresh := NewAutomationReceiver(r.client, r.dir)
				_, e = fresh.Supersede(ctx, intent)
			} else if field == "id" {
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

// Both actual retained readers must reject TEXT whose character count hides
// bytes beyond the actual signed inventory/chunk limit, before driver return.
func TestReceiverRetainedRecordByteBounds(t *testing.T) {
	for _, path := range []string{"restart-metadata", "metadata-terminal", "content-terminal", "final-inventory"} {
		for _, encoding := range []string{"nul", "multibyte"} {
			t.Run(path+"/"+encoding, func(t *testing.T) {
				p, r, q, peer, _ := receiverFixture(t)
				ctx := context.Background()
				a, err := r.Begin(ctx, q.Intent, nil)
				if err != nil {
					t.Fatal(err)
				}
				receiverThrough(t, p, r, a, q, peer, 11)
				component := uint32(0)
				if path == "content-terminal" || path == "final-inventory" {
					component = 11
				}
				state, err := r.client.Query(ctx, `SELECT state FROM local_automation_receiver_components WHERE attempt=? AND source='a' AND component=?`, a.id, component)
				if err != nil || len(state) != 1 {
					t.Fatal(err)
				}
				var want sourceExportCursor
				if err = json.Unmarshal(state[0].Bytes("state"), &want); err != nil {
					t.Fatal(err)
				}
				limit := int64(maxAutomationCutRecordBytes)
				if component < 3 {
					limit = AutomationExportChunkBytes
				}
				if want.TotalBytes < limit {
					limit = want.TotalBytes
				}
				if limit < 1 {
					t.Fatal("missing genuine retained positive inventory")
				}
				var bad string
				if encoding == "nul" {
					bad = "x\x00" + strings.Repeat("z", maxAutomationCutRecordBytes+1)
				} else {
					bad = strings.Repeat("界", int(limit))
				}
				if _, err = r.client.db.Exec(`UPDATE local_automation_receiver_records SET record=? WHERE attempt=? AND source='a' AND component=? AND ordinal=1`, bad, a.id, component); err != nil {
					t.Fatal(err)
				}
				sizes, err := r.client.Query(ctx, `SELECT typeof(record) AS kind,length(record) AS chars,length(CAST(record AS BLOB)) AS bytes FROM local_automation_receiver_records WHERE attempt=? AND source='a' AND component=? AND ordinal=1`, a.id, component)
				if err != nil || len(sizes) != 1 || sizes[0].String("kind") != "text" || sizes[0].Int64("chars") < 1 || sizes[0].Int64("chars") > limit || sizes[0].Int64("bytes") <= limit {
					t.Fatal("fixture does not discriminate character and signed byte bound", err)
				}
				var page AutomationExportPage
				if path == "restart-metadata" {
					r = NewAutomationReceiver(r.client, r.dir)
					a, err = r.Begin(ctx, q.Intent, nil)
					if err != nil {
						t.Fatal(err)
					}
					q.Component = 3
					page, err = p.ExportAutomationSource(peer, q)
					if err != nil {
						t.Fatal(err)
					}
				}
				rows, err := r.client.Query(ctx, `PRAGMA database_list`)
				if err != nil {
					t.Fatal(err)
				}
				var file string
				for _, row := range rows {
					if row.String("name") == "main" {
						file = row.String("file")
					}
				}
				if file == "" {
					t.Fatal("missing actual receiver file")
				}
				var oversized atomic.Int64
				name := fmt.Sprintf("receiver-record-audit-%d", sourceReadDriverSequence.Add(1))
				sql.Register(name, &receiverBodyAuditDriver{Driver: &sqlite.Driver{}, oversized: &oversized, record: &receiverRecordAudit{component, limit}})
				db, err := sql.Open(name, sqliteDSN(file))
				if err != nil {
					t.Fatal(err)
				}
				db.SetMaxOpenConns(1)
				r.client.mu.Lock()
				old := r.client.db
				r.client.db = db
				r.client.mu.Unlock()
				if err = old.Close(); err != nil {
					t.Fatal(err)
				}
				stored := func() string {
					all := []byte(receiverStored(t, r.client))
					for _, tab := range []string{"jobs", "current", "validations"} {
						rows, e := r.client.Query(ctx, `SELECT * FROM local_automation_receiver_`+tab+` ORDER BY rowid`)
						if e != nil {
							t.Fatal(e)
						}
						raw, e := json.Marshal(rows)
						if e != nil {
							t.Fatal(e)
						}
						all = append(all, raw...)
					}
					return sourceDigest(all)
				}
				active, before := receiverActive(t, r.client), stored()
				oversized.Store(0)
				if path == "restart-metadata" {
					_, err = r.Stage(ctx, a, "a", q, page)
				} else {
					var tx *sql.Tx
					tx, err = db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
					if err != nil {
						t.Fatal(err)
					}
					if path == "final-inventory" {
						err = receiverVerifyInventory(ctx, &LocalTx{tx: tx}, a.id, "a", a.publications["a"])
					} else {
						err = receiverVerifyRows(ctx, &LocalTx{tx: tx}, a.id, "a", component, want)
					}
					tx.Rollback()
				}
				if err == nil {
					t.Error("malformed retained TEXT accepted")
				}
				if oversized.Load() != 0 {
					t.Error("oversized retained record returned before byte-bound refusal")
				}
				if receiverActive(t, r.client) != active || stored() != before {
					t.Error("retained record refusal changed active/evidence state")
				}
			})
		}
	}
}
