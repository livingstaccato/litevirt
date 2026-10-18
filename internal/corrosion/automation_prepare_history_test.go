package corrosion

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"modernc.org/sqlite"
)

type prepareHistoryReadKey struct{}
type prepareHistoryReadCount struct{ rows, bytes int64 }
type prepareHistoryReadDriver struct{ driver.Driver }
type prepareHistoryReadConn struct{ driver.Conn }
type prepareHistoryRows struct {
	driver.Rows
	counts   map[int64]prepareHistoryReadCount
	sequence int64
	column   int
}

func (d prepareHistoryReadDriver) Open(name string) (driver.Conn, error) {
	c, e := d.Driver.Open(name)
	if e != nil {
		return nil, e
	}
	return prepareHistoryReadConn{c}, nil
}
func (c prepareHistoryReadConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}
func (c prepareHistoryReadConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}
func (c prepareHistoryReadConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	rows, e := c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
	if e != nil {
		return nil, e
	}
	counts, _ := ctx.Value(prepareHistoryReadKey{}).(map[int64]prepareHistoryReadCount)
	if counts != nil && strings.Contains(q, " FROM local_automation_history") && len(args) > 0 {
		for i, name := range rows.Columns() {
			if name == "value_json" {
				if seq, ok := args[0].Value.(int64); ok {
					return &prepareHistoryRows{Rows: rows, counts: counts, sequence: seq, column: i}, nil
				}
			}
		}
	}
	return rows, nil
}
func (r *prepareHistoryRows) Next(values []driver.Value) error {
	if e := r.Rows.Next(values); e != nil {
		return e
	}
	n := r.counts[r.sequence]
	n.rows++
	switch value := values[r.column].(type) {
	case string:
		n.bytes += int64(len(value))
	case []byte:
		n.bytes += int64(len(value))
	}
	r.counts[r.sequence] = n
	return nil
}
func prepareHistoryInstrument(t *testing.T, c *Client) {
	t.Helper()
	name := fmt.Sprintf("prepare-history-%d", sourceReadDriverSequence.Add(1))
	sql.Register(name, prepareHistoryReadDriver{Driver: &sqlite.Driver{}})
	db, e := sql.Open(name, c.dsn)
	if e != nil {
		t.Fatal(e)
	}
	db.SetMaxOpenConns(1)
	if e = db.Ping(); e != nil {
		t.Fatal(e)
	}
	c.mu.Lock()
	old := c.db
	c.db = db
	c.mu.Unlock()
	if e = old.Close(); e != nil {
		t.Fatal(e)
	}
}
func prepareHistorySnapshot(t *testing.T, c *Client) string {
	t.Helper()
	rows, e := c.Query(context.Background(), `SELECT sequence,digest,value_json,certificate,receipt_json FROM local_automation_history ORDER BY sequence`)
	if e != nil {
		t.Fatal(e)
	}
	encoded, e := json.Marshal(rows)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// The real Prepare must succeed under its existing750ms budget BEFORE the
// driver-count assertion. No EXPLAIN, per-read GC or synthetic query result.
func TestAutomationPrepareHistoricalBodyReads(t *testing.T) {
	fixture := NewKeyEngineFixture(t)
	c := fixture.Clients["b"]
	prepareHistoryInstrument(t, c)
	for _, tc := range []struct {
		name     string
		sequence uint64
		want     map[int64]int64
	}{
		{"same-head", 14, map[int64]int64{14: 1}},
		{"older-distinct-original", 8, map[int64]int64{14: 1, 8: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, _ := AutomationClaimKey(tc.sequence)
			old, _, e := c.ClaimState(context.Background(), key)
			if e != nil {
				t.Fatal(e)
			}
			expectedDigest := old.ValueDigest
			expectedAccepted := old.Accepted
			expectedAccept, _ := json.Marshal(old.Accept)
			old = ClaimVoterState{}
			before := prepareHistorySnapshot(t, c)
			counts := map[int64]prepareHistoryReadCount{}
			ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), prepareHistoryReadKey{}, counts), 750*time.Millisecond)
			ballot := testBallot(10, "a")
			result, e := c.ClaimPrepare(ctx, key, ballot, 1)
			cancel()
			if e != nil || !result.Promised {
				t.Fatal("real750ms Prepare must succeed before operation-count RED", e, result.Refusal)
			}
			gotAccept, _ := json.Marshal(result.State.Accept)
			if result.State.ValueDigest != expectedDigest || !result.State.Accepted.Equal(expectedAccepted) || string(gotAccept) != string(expectedAccept) {
				t.Fatal("Prepare changed original accepted value/certificate")
			}
			if result.State.Value != nil && result.State.Value.MustDigest() != expectedDigest {
				t.Fatal("Prepare returned altered accepted original")
			}
			result = PrepareResult{}
			durable, found, e := c.ClaimState(context.Background(), key)
			if e != nil || !found || !durable.Promised.Equal(ballot) || durable.ValueDigest != expectedDigest {
				t.Fatal("promise not durable", e)
			}
			durable = ClaimVoterState{}
			if after := prepareHistorySnapshot(t, c); after != before {
				t.Fatal("Prepare changed immutable history")
			}
			t.Logf("actual historical body returns: %+v", counts)
			if len(counts) != len(tc.want) {
				t.Errorf("unexpected distinct original count: %+v", counts)
			}
			for seq, want := range tc.want {
				if counts[seq].rows != want || counts[seq].bytes == 0 {
					t.Errorf("actual original%d body returns=%d, want%d; bytes=%d", seq, counts[seq].rows, want, counts[seq].bytes)
				}
			}
		})
	}
}
