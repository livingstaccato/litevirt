package corrosion

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"github.com/litevirt/litevirt/internal/pki"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

type capacityPreparedStats struct {
	direct, prepares, executes, closes, open, maxOpen, badConnection int
}

func capacityPreparedEligible(query string) bool {
	switch query {
	case `SELECT typeof(record) AS kind,length(CAST(record AS BLOB)) AS size FROM local_automation_receiver_records WHERE attempt=? AND source=? AND component=? AND ordinal=? LIMIT 1`:
		return true
	case `SELECT record FROM local_automation_receiver_records WHERE attempt=? AND source=? AND component=? AND ordinal=? AND typeof(record)='blob' AND length(CAST(record AS BLOB))=? LIMIT 1`:
		return true
	case `SELECT ordinal FROM local_automation_receiver_refs WHERE audit=? AND component=? AND sequence=? AND component IN (5,6,8,9,10,11) LIMIT 1`:
		return true
	case `SELECT ordinal FROM local_automation_receiver_refs WHERE audit=? AND component=? AND ordinal>? ORDER BY ordinal LIMIT 1`:
		return true
	case `SELECT length(CAST(identity AS BLOB)) AS identity,length(CAST(receipt AS BLOB)) AS receipt FROM local_automation_receiver_requests WHERE audit=? AND scope=? AND request_id=? LIMIT 1`:
		return true
	case `SELECT identity,receipt FROM local_automation_receiver_requests WHERE audit=? AND scope=? AND request_id=? AND length(CAST(identity AS BLOB))=? AND length(CAST(receipt AS BLOB))=? LIMIT 1`:
		return true
	case `SELECT length(CAST(receipt AS BLOB)) AS size FROM local_automation_receiver_requests WHERE audit=? AND operation_id=? AND operation_id<>'' LIMIT 1`:
		return true
	case `SELECT receipt FROM local_automation_receiver_requests WHERE audit=? AND operation_id=? AND operation_id<>'' AND length(CAST(receipt AS BLOB))=? LIMIT 1`:
		return true
	case `SELECT ordinal FROM local_automation_receiver_refs WHERE audit=? AND component=7 AND scope=? AND request_id=? LIMIT 1`:
		return true
	case `SELECT typeof(record) AS kind,length(record) AS size FROM local_automation_local_rows WHERE local_id=? AND section=? AND ordinal=? LIMIT 1`:
		return true
	case `SELECT record FROM local_automation_local_rows WHERE local_id=? AND section=? AND ordinal=? LIMIT 1`:
		return true
	case `SELECT typeof(record) AS kind,length(record) AS size FROM local_automation_cut_records WHERE cut_id=? AND section=? AND ordinal=? LIMIT 1`:
		return true
	case `SELECT record FROM local_automation_cut_records WHERE cut_id=? AND section=? AND ordinal=? LIMIT 1`:
		return true
	}
	return false
}
func capacityStoreStack() bool {
	var pcs [128]uintptr
	n := runtime.Callers(2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	store, initialLocal := false, false
	for {
		f, more := frames.Next()
		store = store || strings.Contains(f.Function, ".receiverAuditStore.")
		initialLocal = initialLocal || strings.HasSuffix(f.Function, ".auditAggregateLocalTx")
		if !more {
			return store && !initialLocal
		}
	}
}

type capacityObservedTx struct {
	driver.Tx
	conn *capacityQueryConn
}

func (tx *capacityObservedTx) Commit() error {
	err := tx.Tx.Commit()
	tx.conn.reads.mu.Lock()
	tx.conn.active = false
	tx.conn.reads.mu.Unlock()
	return err
}
func (tx *capacityObservedTx) Rollback() error {
	err := tx.Tx.Rollback()
	tx.conn.reads.mu.Lock()
	tx.conn.active = false
	tx.conn.reads.mu.Unlock()
	return err
}

type capacityPreparedStmt struct {
	driver.Stmt
	conn        *capacityQueryConn
	query       string
	transaction uint64
	observed    bool
}

func prepareCapacityActual(ctx context.Context, c driver.Conn, query string) (driver.Stmt, error) {
	if p, ok := c.(driver.ConnPrepareContext); ok {
		return p.PrepareContext(ctx, query)
	}
	return c.Prepare(query)
}
func (c *capacityQueryConn) Prepare(query string) (driver.Stmt, error) {
	return c.PrepareContext(context.Background(), query)
}
func (c *capacityQueryConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	stmt, err := prepareCapacityActual(ctx, c.Conn, query)
	if err != nil {
		return nil, err
	}
	c.reads.mu.Lock()
	observed := c.reads.enabled && capacityPreparedEligible(query)
	if observed {
		p := &c.reads.prepared
		p.prepares++
		p.open++
		if p.open > p.maxOpen {
			p.maxOpen = p.open
		}
		if !c.active || c.reads.transactionConn != c || c.reads.transactionID != c.transaction {
			p.badConnection++
		}
	}
	c.reads.mu.Unlock()
	return &capacityPreparedStmt{Stmt: stmt, conn: c, query: query, transaction: c.transaction, observed: observed}, nil
}
func queryCapacityActual(ctx context.Context, stmt driver.Stmt, args []driver.NamedValue) (driver.Rows, error) {
	if s, ok := stmt.(driver.StmtQueryContext); ok {
		return s.QueryContext(ctx, args)
	}
	values := make([]driver.Value, len(args))
	for i, arg := range args {
		if arg.Name != "" {
			return nil, fmt.Errorf("named prepared argument unsupported")
		}
		values[i] = arg.Value
	}
	return stmt.Query(values)
}
func (s *capacityPreparedStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	r := s.conn.reads
	r.mu.Lock()
	enabled := r.enabled
	if enabled {
		if r.queries[s.query] == nil {
			r.queries[s.query] = &capacityQueryStats{}
		}
		r.queries[s.query].calls++
	}
	if s.observed {
		r.prepared.executes++
		if !s.conn.active || s.transaction != s.conn.transaction || r.transactionConn != s.conn || r.transactionID != s.transaction {
			r.prepared.badConnection++
		}
	}
	hook, count := r.beforePrepared, r.prepared.executes
	r.mu.Unlock()
	if s.observed && hook != nil {
		hook(count)
	}
	rows, err := queryCapacityActual(ctx, s.Stmt, args)
	if err != nil || !enabled {
		return rows, err
	}
	return &capacityQueryRows{Rows: rows, reads: r, query: s.query}, nil
}
func (s *capacityPreparedStmt) Close() error {
	err := s.Stmt.Close()
	if s.observed {
		s.conn.reads.mu.Lock()
		s.conn.reads.prepared.closes++
		s.conn.reads.prepared.open--
		if s.conn.reads.failCloseOnce {
			s.conn.reads.failCloseOnce = false
			if err == nil {
				err = errors.New("injected actual prepared close failure")
			}
		}
		s.conn.reads.mu.Unlock()
		s.observed = false
	}
	return err
}

// Removing C's transaction-scoped prepared dispatch must send thousands of
// actual SQLite reads through its direct per-call-prepare path again.
func TestAggregatePreparedReadsActualFullSeven(t *testing.T) {
	reads := automationCapacity(t, 130, 37, false)
	reads.mu.Lock()
	defer reads.mu.Unlock()
	p := reads.prepared
	t.Logf("actual driver prepared-read operations: %+v", p)
	if p.direct != 0 || p.prepares == 0 || p.prepares > 13 || p.executes < 60000 || p.closes != p.prepares || p.open != 0 || p.maxOpen > 13 || p.badConnection != 0 {
		t.Fatalf("C repeated actual direct preparation instead of same-transaction bounded reuse: %+v", p)
	}
}

// Both existing actual bounds observers run unchanged for prepared reads.
type aggregatePreparedObserver interface {
	observeQuery(context.Context, string, []driver.NamedValue, func() (driver.Rows, error)) (driver.Rows, error)
}
type aggregateObservedStmt struct {
	driver.Stmt
	observer aggregatePreparedObserver
	query    string
}

func (s *aggregateObservedStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	return s.observer.observeQuery(ctx, s.query, args, func() (driver.Rows, error) { return queryCapacityActual(ctx, s.Stmt, args) })
}

func TestAggregatePreparedReadsLifecycle(t *testing.T) {
	for _, mode := range []string{"success", "refusal", "cancel", "panic", "close-error"} {
		t.Run(mode, func(t *testing.T) {
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Continuing: true, Heads: []int{2, 2}, LocalHead: 2, BeforeFreeze: func(t *testing.T, _ []*claimTestVoter, local *claimTestVoter) {
				key := LeaseTermClaimKey("prepared_origin", 1)
				value := ClaimValue{LeaseTerm: &LeaseTermValue{Key: key.TargetName, Term: 1, Holder: local.name}}
				reply, err := local.c.ClaimAccept(context.Background(), key, testBallot(2, local.name), value, 1, local.signer, unreachable)
				if err != nil || !reply.Accepted {
					t.Fatal("real local origin", reply, err)
				}
			}})
			for i := range f.producers {
				f.stage(t, i, 11, true)
			}
			if mode == "refusal" {
				if _, err := f.local.c.db.Exec(`INSERT INTO local_automation_cut_records SELECT id,99,1,x'01' FROM local_automation_cuts`); err != nil {
					t.Fatal(err)
				}
			}
			active, spool, stored, typed := receiverActive(t, f.local.c), receiverStored(t, f.local.c), aggregateStored(t, f.local.c), automationTypedSnapshot(t, f.local.c)
			_, reads := capacityInstrument(t, f.local.c)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sentinel := "prepared-read actual driver panic"
			reads.enabled = true
			if mode == "close-error" {
				reads.failCloseOnce = true
			}
			reads.beforePrepared = func(n int) {
				if n == 2 {
					if mode == "cancel" {
						cancel()
					}
				}
			}
			var id string
			var err error
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				if mode == "panic" {
					target, e := f.attempt.view.ValidateServedHost(ctx, f.attempt.pair)
					if e != nil {
						t.Fatal(e)
					}
					defer target.Discard()
					lease, e := pki.AcquireHostCertificateLease(ctx, f.receiver.dir, target)
					if e != nil {
						t.Fatal(e)
					}
					defer lease.Release()
					err = f.receiver.transaction(ctx, f.attempt, lease, time.Time{}, func(tx *LocalTx) error {
						return aggregatePreparedReadsTx(tx, func(reads *aggregatePreparedReads) error {
							store := receiverAuditStore{tx: tx, prepared: reads, attempt: f.attempt.id, source: f.producers[0].client.hostName}
							if _, e := store.record(ctx, 3, 1); e != nil {
								return e
							}
							panic(sentinel)
						})
					})
				} else {
					id, err = f.receiver.auditAggregate(ctx, f.attempt)
				}
			}()
			reads.enabled = false
			p := reads.prepared
			t.Logf("actual driver lifecycle=%s %+v", mode, p)
			if p.prepares == 0 || p.closes != p.prepares || p.open != 0 || p.maxOpen > 13 || p.badConnection != 0 {
				t.Fatal("prepared resources escaped real transaction", p)
			}
			switch mode {
			case "success":
				if err != nil || id == "" || recovered != nil {
					t.Fatal("prepared success", id, err, recovered)
				}
			case "panic":
				if recovered != sentinel {
					t.Fatal("actual driver panic lost", recovered, err)
				}
			case "cancel":
				if !errors.Is(err, context.Canceled) {
					t.Fatal("actual cancellation lost", err)
				}
			case "close-error":
				if err == nil || !strings.Contains(err.Error(), "close aggregate prepared read") {
					t.Fatal("cleanup failure committed", id, err)
				}
			case "refusal":
				if err == nil || !strings.Contains(err.Error(), "local acceptance origin unavailable") {
					t.Fatal("late refusal lost", err)
				}
			}
			if mode != "success" && aggregateStored(t, f.local.c) != stored {
				t.Fatal("failure changed prior aggregate/local evidence")
			}
			if receiverActive(t, f.local.c) != active || receiverStored(t, f.local.c) != spool || !reflect.DeepEqual(typed, automationTypedSnapshot(t, f.local.c)) {
				t.Fatal("prepared lifecycle changed ACTIVE/spool/prior stages")
			}
			// A fresh attempt in the same process cannot reuse any closed statement.
			reads.beforePrepared = nil
			if mode != "refusal" {
				again, retryErr := f.receiver.auditAggregate(context.Background(), f.attempt)
				if retryErr != nil || again == "" || (mode == "success" && again != id) {
					t.Fatal("fresh transaction retry failed", again, retryErr)
				}
			}
		})
	}
	t.Run("scope-and-row-copy", func(t *testing.T) {
		f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Continuing: true})
		cuts, err := f.local.c.Query(context.Background(), `SELECT id FROM local_automation_cuts`)
		if err != nil || len(cuts) != 1 {
			t.Fatal(cuts, err)
		}
		err = f.local.c.ExecuteLocal(context.Background(), func(tx *LocalTx) error {
			p := &aggregatePreparedReads{owner: tx}
			defer p.close()
			q := `SELECT record FROM local_automation_cut_records WHERE cut_id=? AND section=? AND ordinal=? LIMIT 1`
			args := []interface{}{cuts[0].String("id"), 0, 1}
			first, err := p.query(context.Background(), tx, q, args...)
			if err != nil || len(first) != 1 {
				return fmt.Errorf("first actual body: %v", err)
			}
			raw := append([]byte(nil), first[0].Bytes("record")...)
			first[0].Bytes("record")[0] ^= 0xff
			second, err := p.query(context.Background(), tx, q, args...)
			if err != nil || len(second) != 1 || !bytes.Equal(raw, second[0].Bytes("record")) {
				return fmt.Errorf("prepared Row aliases prior driver/body memory: %v", err)
			}
			if _, err = p.query(context.Background(), &LocalTx{tx: tx.tx}, q, args...); err == nil {
				return errors.New("different LocalTx owner accepted")
			}
			if _, err = p.query(context.Background(), tx, "SELECT 1"); err == nil {
				return errors.New("unlisted read accepted")
			}
			if err = p.close(); err != nil {
				return err
			}
			if _, err = p.query(context.Background(), tx, q, args...); err == nil {
				return errors.New("closed reader revived")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

// Establish the actual FULL transaction from its real direct SQLite queries,
// before preparing anything; later statements must use that exact connection
// and BeginTx identity rather than merely some active transaction.
func capacityAggregateTransactionStack() bool {
	var pcs [128]uintptr
	n := runtime.Callers(2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	transaction := false
	for {
		f, more := frames.Next()
		transaction = transaction || strings.HasSuffix(f.Function, "(*AutomationReceiver).transaction")
		if !more {
			return transaction
		}
	}
}
