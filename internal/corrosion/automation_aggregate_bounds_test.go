package corrosion

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"modernc.org/sqlite"
)

// The original SQLite driver executes every query. This wrapper observes its
// real returned values and EXPLAIN output; it cannot supply audit facts.
type aggregateBoundsDriver struct {
	driver.Driver
	state *receiverSemanticReads
}
type aggregateBoundsConn struct {
	driver.Conn
	state *receiverSemanticReads
}

func (d *aggregateBoundsDriver) Open(name string) (driver.Conn, error) {
	c, e := d.Driver.Open(name)
	if e != nil {
		return nil, e
	}
	return &aggregateBoundsConn{c, d.state}, nil
}
func (c *aggregateBoundsConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}
func (c *aggregateBoundsConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return c.observeQuery(ctx, q, args, func() (driver.Rows, error) { return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args) })
}
func (c *aggregateBoundsConn) Prepare(query string) (driver.Stmt, error) {
	return c.PrepareContext(context.Background(), query)
}
func (c *aggregateBoundsConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	stmt, err := prepareCapacityActual(ctx, c.Conn, query)
	if err != nil {
		return nil, err
	}
	return &aggregateObservedStmt{Stmt: stmt, observer: c, query: query}, nil
}
func (c *aggregateBoundsConn) observeQuery(ctx context.Context, q string, args []driver.NamedValue, execute func() (driver.Rows, error)) (driver.Rows, error) {
	reader := c.Conn.(driver.QueryerContext)
	if strings.HasPrefix(q, "SELECT record FROM local_automation_receiver_records ") {
		if evidence, ok := ctx.Value(aggregateHeapTestKey{}).(*aggregateHeapEvidence); ok {
			evidence.beforeOriginalRead()
		}
	}

	c.state.mu.Lock()
	enabled := c.state.enabled
	c.state.mu.Unlock()
	tracked := enabled && (strings.Contains(q, "FROM local_automation_aggregate_") || strings.Contains(q, "FROM local_automation_aggregates ") || strings.HasPrefix(q, "SELECT record FROM local_automation_receiver_records ") || strings.HasPrefix(q, "SELECT record FROM local_automation_local_rows ") || strings.HasPrefix(q, "SELECT record FROM local_automation_cut_records "))
	if tracked {
		rows, err := reader.QueryContext(ctx, "EXPLAIN QUERY PLAN "+q, args)
		if err != nil {
			return nil, err
		}
		values := make([]driver.Value, len(rows.Columns()))
		detail := ""
		for {
			err = rows.Next(values)
			if err == io.EOF {
				break
			}
			if err != nil {
				rows.Close()
				return nil, err
			}
			detail += fmt.Sprint(values[len(values)-1])
		}
		if err = rows.Close(); err != nil {
			return nil, err
		}
		c.state.mu.Lock()
		c.state.queries++
		c.state.plans[q] = detail
		if !strings.Contains(detail, "SEARCH ") || strings.Contains(detail, "SCAN ") || strings.Contains(detail, "TEMP B-TREE") || !strings.Contains(q, "LIMIT 1") {
			c.state.bad = append(c.state.bad, q+" => "+detail)
		}
		if strings.Contains(q, "typeof(") {
			c.state.probes++
		} else if strings.HasPrefix(q, "SELECT origin_kind,") || strings.HasPrefix(q, "SELECT claim_key,") {
			c.state.bodies++
		}
		c.state.mu.Unlock()
	}
	rows, err := execute()
	if err != nil {
		return nil, err
	}
	if tracked {
		return &receiverSemanticRows{Rows: rows, state: c.state, query: q}, nil
	}
	return rows, nil
}
func aggregateInstrument(t *testing.T, r *AutomationReceiver) *receiverSemanticReads {
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
		t.Fatal("actual file-backed receiver missing")
	}
	state := &receiverSemanticReads{plans: map[string]string{}}
	name := fmt.Sprintf("aggregate-real-read-%d", sourceReadDriverSequence.Add(1))
	sql.Register(name, &aggregateBoundsDriver{Driver: &sqlite.Driver{}, state: state})
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
func TestAutomationAggregateActualIndexedReads(t *testing.T) {
	const claims = 37
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{33, 31}, BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
		for n := 0; n < claims; n++ {
			key := LeaseTermClaimKey(fmt.Sprintf("aggregate_bound_%d", n), 1)
			for i := 0; i < 2; i++ {
				value := ClaimValue{LeaseTerm: &LeaseTermValue{Key: key.TargetName, Term: 1, Holder: voters[i].name}}
				result, err := voters[i].c.ClaimAccept(context.Background(), key, testBallot(uint64(i+1), "same"), value, 1, voters[i].signer, unreachable)
				if err != nil || !result.Accepted {
					t.Fatalf("real bounded source acceptance: %+v %v", result, err)
				}
			}
		}
	}})
	for i := range f.producers {
		f.stage(t, i, 11, true)
	}
	state := aggregateInstrument(t, f.receiver)
	state.enabled = true
	id, err := f.receiver.auditAggregate(context.Background(), f.attempt)
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.receiver.auditAggregate(context.Background(), f.attempt)
	if err != nil || again != id {
		t.Fatal("actual retry", err)
	}
	state.enabled = false
	if len(state.bad) > 0 || state.maxRows != 1 || state.maxBytes > maxAutomationCutRecordBytes || state.probes < claims || state.bodies < claims {
		t.Fatal("actual aggregate driver bounds", state.bad, state.maxRows, state.maxBytes, state.probes, state.bodies)
	}
	ranges := 0
	for query, plan := range state.plans {
		if strings.Contains(query, ")>(") {
			ranges++
			if !strings.Contains(plan, ">") {
				t.Fatalf("tuple did not use indexed range: %s => %s", query, plan)
			}
		}
		t.Logf("actual aggregate SQL %s => %s", query, plan)
	}
	if ranges < 4 {
		t.Fatalf("full PK tuple ranges not exercised: %d", ranges)
	}
	t.Logf("actual aggregate reads=%d probes=%d bodies=%d maxRows=%d maxFieldBytes=%d indexedTuples=%d", state.queries, state.probes, state.bodies, state.maxRows, state.maxBytes, ranges)
}
func TestAutomationAggregateStoredLengthBeforeBody(t *testing.T) {
	for _, mode := range []string{"oversized-body", "text-nul-body", "fractional-key", "oversized-key", "zero-key", "negative-key"} {
		t.Run(mode, func(t *testing.T) {
			key := LeaseTermClaimKey("aggregate_probe", 1)
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
				value := ClaimValue{LeaseTerm: &LeaseTermValue{Key: key.TargetName, Term: 1, Holder: voters[0].name}}
				result, err := voters[0].c.ClaimAccept(context.Background(), key, testBallot(1, "same"), value, 1, voters[0].signer, unreachable)
				if err != nil || !result.Accepted {
					t.Fatalf("real source acceptance: %+v %v", result, err)
				}
			}})
			for i := range f.producers {
				f.stage(t, i, 11, true)
			}
			id, err := f.receiver.auditAggregate(context.Background(), f.attempt)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "oversized-body":
				_, err = f.local.c.db.Exec(`UPDATE local_automation_aggregate_copies SET origin_ref=? WHERE bundle=?`, make([]byte, maxAutomationCutMetadataBytes+1), id)
			case "text-nul-body":
				_, err = f.local.c.db.Exec(`UPDATE local_automation_aggregate_copies SET origin_ref=? WHERE bundle=?`, "x\x00"+strings.Repeat("z", maxAutomationCutMetadataBytes+1), id)
			case "fractional-key":
				_, err = f.local.c.db.Exec(`UPDATE local_automation_aggregate_copies SET ordinal=0.5 WHERE bundle=?`, id)
			case "oversized-key":
				_, err = f.local.c.db.Exec(`UPDATE local_automation_aggregate_copies SET origin_id=? WHERE bundle=?`, strings.Repeat("世", maxAutomationCutRecordBytes), id)
			case "zero-key":
				_, err = f.local.c.db.Exec(`UPDATE local_automation_aggregate_copies SET ordinal=0 WHERE bundle=?`, id)
			case "negative-key":
				_, err = f.local.c.db.Exec(`UPDATE local_automation_aggregate_copies SET ordinal=-1 WHERE bundle=?`, id)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := aggregateStored(t, f.local.c)
			state := aggregateInstrument(t, f.receiver)
			state.enabled = true
			if _, err = f.receiver.auditAggregate(context.Background(), f.attempt); err == nil {
				t.Fatal("malformed aggregate storage accepted")
			}
			state.enabled = false
			if len(state.bad) > 0 || state.maxRows > 1 || state.maxBytes > maxAutomationCutRecordBytes {
				t.Fatal("invalid data reached materialization", state.bad, state.maxRows, state.maxBytes)
			}
			if before != aggregateStored(t, f.local.c) {
				t.Fatal("invalid retained evidence repaired on refusal")
			}
			t.Logf("actual rejected %s before body; reads=%d probes=%d maxRows=%d maxFieldBytes=%d", mode, state.queries, state.probes, state.maxRows, state.maxBytes)
		})
	}
}

func TestAutomationAggregateNearBoundNativeBody(t *testing.T) {
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{2, 2}, BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
		key := workloadKey()
		for i := 0; i < 2; i++ {
			value := workloadValue(strings.Repeat("x", maxAutomationCutRecordBytes-(64<<10)), "destination", "ghost")
			result, err := voters[i].c.ClaimAccept(context.Background(), key, testBallot(uint64(i+1), "same"), value, 1, voters[i].signer, unreachable)
			if err != nil || !result.Accepted {
				t.Fatalf("actual near-bound native workload: %+v %v", result, err)
			}
		}
	}})
	for i := range f.producers {
		f.stage(t, i, 11, true)
	}
	state := aggregateInstrument(t, f.receiver)
	state.enabled = true
	evidence := &aggregateHeapEvidence{}
	ctx := context.WithValue(context.Background(), aggregateHeapTestKey{}, evidence)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	stop, stopped := make(chan struct{}), make(chan uint64, 1)
	go func() {
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		peak := before.HeapAlloc
		for {
			select {
			case <-ticker.C:
				var now runtime.MemStats
				runtime.ReadMemStats(&now)
				if now.HeapAlloc > peak {
					peak = now.HeapAlloc
				}
			case <-stop:
				stopped <- peak
				return
			}
		}
	}()
	_, err := f.receiver.auditAggregate(ctx, f.attempt)
	close(stop)
	peakHeap := <-stopped
	if err != nil {
		t.Fatal("actual near-bound C contribution", err)
	}
	state.enabled = false
	t.Logf("actual retained C original-body heap before next original: probes=%d maxLiveBytes=%d stacks=%v", evidence.probes, evidence.maxLiveBytes, evidence.stacks)
	if evidence.probes < 1 || evidence.maxLiveBytes > 1<<20 {
		t.Fatalf("C retained a prior original logical body before reading another: probes=%d live=%d", evidence.probes, evidence.maxLiveBytes)
	}
	if state.maxRows > 1 || len(state.bad) > 0 || state.maxBytes < 2<<20 || state.maxBytes > maxAutomationCutRecordBytes {
		t.Fatal("actual bounded reads", state.maxRows, state.maxBytes, state.bad)
	}
	t.Logf("actual native near-bound original=%d bytes, aggregate reads=%d maxRows=%d actual maxField=%d; sampled heap baseline=%d peak=%d (includes semantic validators, not a manual logical-body counter)", maxAutomationCutRecordBytes-(64<<10), state.queries, state.maxRows, state.maxBytes, before.HeapAlloc, peakHeap)
}

// Test-only introspection at the actual driver boundary. This uses the real
// call stack and post-GC allocation records, with no production annotations.
type aggregateHeapTestKey struct{}
type aggregateHeapEvidence struct {
	probes       int
	maxLiveBytes int64
	stacks       []string
}

func (e *aggregateHeapEvidence) beforeOriginalRead() {
	var callers [64]uintptr
	n := runtime.Callers(2, callers[:])
	frames := runtime.CallersFrames(callers[:n])
	reference := false
	for {
		frame, more := frames.Next()
		if strings.HasSuffix(frame.Function, ".aggregateReadCopy") {
			reference = true
		}
		if !more {
			break
		}
	}
	if !reference {
		return
	}
	// MemProfile may lag by up to two collection cycles.
	runtime.GC()
	runtime.GC()
	count, _ := runtime.MemProfile(nil, true)
	records := make([]runtime.MemProfileRecord, count+64)
	count, ok := runtime.MemProfile(records, true)
	if !ok {
		return
	}
	var live int64
	var stacks []string
	for _, record := range records[:count] {
		if record.InUseBytes() < 1<<20 {
			continue
		}
		f := runtime.CallersFrames(record.Stack())
		decoded, aggregate := false, false
		stack := ""
		for {
			frame, more := f.Next()
			stack += frame.Function + " "
			decoded = decoded || strings.Contains(frame.Function, "decodeAutomationFramedRow") || strings.Contains(frame.Function, "scanClaimRow")
			aggregate = aggregate || strings.Contains(frame.Function, "aggregateClaimsTx") || strings.Contains(frame.Function, "aggregateClaimAt")
			if !more {
				break
			}
		}
		if decoded && aggregate {
			live += record.InUseBytes()
			stacks = append(stacks, stack)
		}
	}
	e.probes++
	if live > e.maxLiveBytes {
		e.maxLiveBytes = live
		e.stacks = stacks
	}
}
