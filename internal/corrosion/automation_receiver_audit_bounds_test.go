package corrosion

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"modernc.org/sqlite"
)

// Wrap the real SQLite driver used by the actual receiver. Query plans are
// collected for the exact executed SQL/parameters; returned values and per-
// query row counts are observed at materialization, before corrosion.Row exists.
// This test instrumentation is not a replacement iterator or memory model.
type receiverSemanticReads struct {
	mu                                                      sync.Mutex
	enabled                                                 bool
	queries, probes, bodies, requestBodies, operationBodies int
	maxRows, maxBytes                                       int
	plans                                                   map[string]string
	bad                                                     []string
}
type receiverSemanticDriver struct {
	driver.Driver
	state *receiverSemanticReads
}
type receiverSemanticConn struct {
	driver.Conn
	state *receiverSemanticReads
}
type receiverSemanticRows struct {
	driver.Rows
	state *receiverSemanticReads
	count int
	query string
}

func (d *receiverSemanticDriver) Open(name string) (driver.Conn, error) {
	c, err := d.Driver.Open(name)
	if err != nil {
		return nil, err
	}
	return &receiverSemanticConn{c, d.state}, nil
}
func (c *receiverSemanticConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}
func (c *receiverSemanticConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	reader := c.Conn.(driver.QueryerContext)
	c.state.mu.Lock()
	enabled := c.state.enabled
	c.state.mu.Unlock()
	tracked := enabled && (strings.Contains(q, "FROM local_automation_receiver_records") || strings.Contains(q, "FROM local_automation_receiver_refs") || strings.Contains(q, "FROM local_automation_receiver_requests"))
	if tracked {
		plan, err := reader.QueryContext(ctx, "EXPLAIN QUERY PLAN "+q, args)
		if err != nil {
			return nil, err
		}
		values := make([]driver.Value, len(plan.Columns()))
		detail := ""
		for {
			err = plan.Next(values)
			if err == io.EOF {
				break
			}
			if err != nil {
				plan.Close()
				return nil, err
			}
			detail += fmt.Sprint(values[len(values)-1])
		}
		if err = plan.Close(); err != nil {
			return nil, err
		}
		c.state.mu.Lock()
		c.state.queries++
		c.state.plans[q] = detail
		if !strings.Contains(detail, "SEARCH ") || strings.Contains(detail, "SCAN ") || strings.Contains(detail, "TEMP B-TREE") {
			c.state.bad = append(c.state.bad, "not an indexed bounded search: "+q+" "+detail)
		}
		if !strings.Contains(q, "LIMIT 1") {
			c.state.bad = append(c.state.bad, "unbounded row query: "+q)
		}
		if strings.Contains(q, "length(") {
			c.state.probes++
		}
		if strings.HasPrefix(q, "SELECT record ") {
			c.state.bodies++
		}
		if strings.HasPrefix(q, "SELECT identity,receipt ") {
			c.state.requestBodies++
		}
		if strings.HasPrefix(q, "SELECT receipt ") {
			c.state.operationBodies++
		}
		c.state.mu.Unlock()
	}
	rows, err := reader.QueryContext(ctx, q, args)
	if err != nil {
		return nil, err
	}
	if tracked {
		return &receiverSemanticRows{Rows: rows, state: c.state, query: q}, nil
	}
	return rows, nil
}
func (r *receiverSemanticRows) Next(values []driver.Value) error {
	err := r.Rows.Next(values)
	if err != nil {
		return err
	}
	r.count++
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	if r.count > r.state.maxRows {
		r.state.maxRows = r.count
	}
	for _, v := range values {
		n := 0
		switch v := v.(type) {
		case []byte:
			n = len(v)
		case string:
			n = len(v)
		}
		if n > r.state.maxBytes {
			r.state.maxBytes = n
		}
	}
	return nil
}
func receiverAuditInstrument(t *testing.T, r *AutomationReceiver) *receiverSemanticReads {
	t.Helper()
	rows, err := r.client.Query(context.Background(), `PRAGMA database_list`)
	if err != nil {
		t.Fatal(err)
	}
	path := ""
	for _, row := range rows {
		if row.String("name") == "main" {
			path = row.String("file")
		}
	}
	if path == "" {
		t.Fatal("actual file-backed SQLite missing")
	}
	state := &receiverSemanticReads{plans: map[string]string{}}
	name := fmt.Sprintf("receiver-semantic-read-%d", sourceReadDriverSequence.Add(1))
	sql.Register(name, &receiverSemanticDriver{Driver: &sqlite.Driver{}, state: state})
	db, err := sql.Open(name, sqliteDSN(path))
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
	return state
}
func TestReceiverSourceAuditManyPagesBoundedReads(t *testing.T) {
	p, r, q, peer, _ := receiverAuditFixture(t, 130, nil)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	q.MaxRecords = 7
	receiverThrough(t, p, r, a, q, peer, 11)
	rows, err := r.client.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_receiver_pages WHERE attempt=? AND source='a' AND component=5`, a.id)
	if err != nil || len(rows) != 1 || rows[0].Int64("n") < 19 {
		t.Fatal("not genuinely many-page history", err)
	}
	active := receiverActive(t, r.client)
	state := receiverAuditInstrument(t, r)
	state.enabled = true
	if err = r.AuditSource(ctx, a, "a"); err != nil {
		t.Fatal(err)
	}
	state.enabled = false
	if len(state.bad) != 0 || state.maxRows != 1 || state.maxBytes > maxAutomationCutRecordBytes || state.probes < 130 || state.bodies < 130 || state.requestBodies == 0 || state.operationBodies == 0 {
		t.Fatal("actual production read bounds", state.bad, state.maxRows, state.maxBytes, state.probes, state.bodies, state.requestBodies, state.operationBodies)
	}
	if receiverActive(t, r.client) != active {
		t.Fatal("many-page audit activated receiver")
	}
	for query, plan := range state.plans {
		t.Logf("actual indexed SQL %s => %s", query, plan)
	}
	t.Logf("actual reads=%d length predicates/probes=%d body reads=%d max returned rows=%d max field bytes=%d request bodies=%d operation bodies=%d", state.queries, state.probes, state.bodies, state.maxRows, state.maxBytes, state.requestBodies, state.operationBodies)
}

func TestReceiverSourceAuditLengthBeforeMaterialization(t *testing.T) {
	for _, kind := range []string{"record-blob", "record-text-nul", "record-text-multibyte", "derived-request", "derived-operation"} {
		t.Run(kind, func(t *testing.T) {
			p, r, q, peer, _ := receiverAuditFixtureOptions(t, 3, receiverAuditOptions{uniqueRequests: kind == "derived-operation"})
			ctx := context.Background()
			a, err := r.Begin(ctx, q.Intent, nil)
			if err != nil {
				t.Fatal(err)
			}
			receiverThrough(t, p, r, a, q, peer, 11)
			if strings.HasPrefix(kind, "record-") {
				var bad any = make([]byte, maxAutomationCutRecordBytes+1)
				if kind == "record-text-nul" {
					bad = "x\x00" + strings.Repeat("z", maxAutomationCutRecordBytes+1)
				}
				if kind == "record-text-multibyte" {
					bad = strings.Repeat("界", maxAutomationCutRecordBytes/2)
				}
				if _, err = r.client.db.Exec(`UPDATE local_automation_receiver_records SET record=? WHERE attempt=? AND source='a' AND component=5 AND ordinal=2`, bad, a.id); err != nil {
					t.Fatal(err)
				}
			} else {
				column := "identity"
				if kind == "derived-operation" {
					column = "receipt"
				}
				// Corrupt a freshly derived original after the real INSERT. A later causal
				// lookup must length-probe this exact indexed row before materialization.
				if _, err = r.client.db.Exec(`CREATE TRIGGER audit_oversize AFTER INSERT ON local_automation_receiver_requests WHEN NEW.request_id='barrier' BEGIN UPDATE local_automation_receiver_requests SET ` + column + `=zeroblob(4194304) WHERE audit=NEW.audit AND scope=NEW.scope AND request_id=NEW.request_id; END`); err != nil {
					t.Fatal(err)
				}
			}
			active, derived := receiverActive(t, r.client), receiverAudited(t, r.client)
			state := receiverAuditInstrument(t, r)
			state.enabled = true
			err = r.AuditSource(ctx, a, "a")
			state.enabled = false
			if err == nil {
				t.Fatal("oversized retained or derived payload audited")
			}
			if state.maxBytes > maxAutomationCutRecordBytes || state.maxRows > 1 || len(state.bad) != 0 {
				t.Fatal("oversized body materialized before refusal", state.maxBytes, state.maxRows, state.bad)
			}
			if receiverActive(t, r.client) != active || receiverAudited(t, r.client) != derived {
				t.Fatal("oversize refusal changed active/derived state")
			}
		})
	}
}

func TestReceiverSourceAuditNearRecordBound(t *testing.T) {
	p, r, q, peer, _ := receiverAuditFixture(t, 0, func(a *claimTestVoter, _ []*claimTestVoter) {
		key := workloadKey()
		value := workloadValue(strings.Repeat("x", maxAutomationCutRecordBytes-(64<<10)), "a", "ghost")
		accepted, err := a.c.ClaimAccept(context.Background(), key, testBallot(2, "a"), value, 1, a.signer, unreachable)
		if err != nil || !accepted.Accepted {
			t.Fatal("genuine near-bound acceptance", err)
		}
	})
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, peer, 11)
	active := receiverActive(t, r.client)
	state := receiverAuditInstrument(t, r)
	state.enabled = true
	if err = r.AuditSource(ctx, a, "a"); err != nil {
		t.Fatal("genuine near-bound complete source audit", err)
	}
	state.enabled = false
	if state.maxRows != 1 || state.maxBytes < maxAutomationCutRecordBytes-(64<<10) || state.maxBytes > maxAutomationCutRecordBytes || len(state.bad) != 0 {
		t.Fatal("near-bound actual materialization", state.maxRows, state.maxBytes, state.bad)
	}
	if receiverActive(t, r.client) != active {
		t.Fatal("near-bound audit changed active state")
	}
	t.Logf("actual near-limit record field bytes=%d maximum=%d; max rows=%d", state.maxBytes, maxAutomationCutRecordBytes, state.maxRows)
}
