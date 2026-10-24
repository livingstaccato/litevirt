package corrosion

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"
	"modernc.org/sqlite"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// This exercises actual current-schema snapshot creation and its live observer with
// nonempty certified-history execution. The attempt below supplies only the
// private snapshot hash domain; this is not whole-roster aggregate acceptance.
func TestAggregateLocal86NonemptyExecutionSnapshot(t *testing.T) {
	f, _ := executionReplayCompletedFixture(t)
	ctx := context.Background()
	if got := storedVersion(t, f.c); got != CurrentSchemaVersion {
		t.Fatalf("actual current InitSchema required: got %d, want %d", got, CurrentSchemaVersion)
	}
	before := executionStorageSnapshot(t, f.c)
	attempt := &AutomationReceiverAttempt{id: "execution86-snapshot-component", binding: []byte("execution86-snapshot-component")}
	seen := map[string]int64{}
	err := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		var observation aggregateLocalObservation
		var out aggregateLocalAudit
		_, err := aggregateLocalSnapshot(ctx, tx, attempt, f.c, func(section int, n int64, row Row, raw []byte) error {
			if err := observation.observe(&out, section, n, row); err != nil {
				return err
			}
			d := aggregateLocalTables()[section]
			if strings.HasPrefix(d.table, "local_automation_exec") {
				seen[d.table]++
				decoded, err := decodeAutomationFramedRow(d.descriptor(), n, raw, maxAggregateLocalRecordBytes)
				if err != nil {
					return err
				}
				if decoded.String("operation_id") != "create-op" {
					return fmt.Errorf("execution frame lost original operation")
				}
				wrong := aggregateLocalTables()[18].descriptor()
				if _, err := decodeAutomationFramedRow(wrong, n, raw, maxAggregateLocalRecordBytes); err == nil {
					return fmt.Errorf("swapped execution section accepted")
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		if len(observation.counts) != 38 || observation.cursor != observation.prefix || observation.cursor != out.head {
			return fmt.Errorf("current execution37 observation lost certified cursors")
		}
		return nil
	})
	if err != nil {
		t.Fatal("actual nonempty execution86 snapshot observer", err)
	}
	for _, table := range executionStorageTables {
		if seen[table] == 0 {
			t.Fatal("snapshot omitted nonempty execution table", table)
		}
	}
	if !reflect.DeepEqual(before, executionStorageSnapshot(t, f.c)) {
		t.Fatal("snapshot component changed active state")
	}
}

func TestAggregateLocal86ExecutionCorruptionBounds(t *testing.T) {
	for _, mode := range []string{"wrong-live85", "oversized-json", "blob-json", "missing-unique-index"} {
		t.Run(mode, func(t *testing.T) {
			f, _ := executionReplayCompletedFixture(t)
			ctx := context.Background()
			if err := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				var err error
				switch mode {
				case "wrong-live85":
					_, err = tx.tx.ExecContext(ctx, `UPDATE schema_state SET version=85 WHERE id=1`)
				case "oversized-json":
					_, err = tx.Exec(ctx, `UPDATE local_automation_executors SET grant_json=? WHERE stage=''`, strings.Repeat("x", MaxAutomationClaimBytes+1))
				case "blob-json":
					_, err = tx.Exec(ctx, `UPDATE local_automation_execution_artifacts SET artifact_json=CAST(artifact_json AS BLOB) WHERE stage=''`)
				case "missing-unique-index":
					_, err = tx.tx.ExecContext(ctx, `DROP INDEX automation_execution_artifact_key`)
				}
				return err
			}); err != nil {
				t.Fatal("negative snapshot corruption", err)
			}
			before := executionStorageSnapshot(t, f.c)
			attempt := &AutomationReceiverAttempt{id: "execution86-negative-component", binding: []byte("execution86-negative-component")}
			err := f.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				var observation aggregateLocalObservation
				var out aggregateLocalAudit
				_, err := aggregateLocalSnapshot(ctx, tx, attempt, f.c, func(section int, n int64, row Row, _ []byte) error { return observation.observe(&out, section, n, row) })
				return err
			})
			if err == nil {
				t.Fatal("malformed execution86 snapshot accepted", mode)
			}
			if mode == "wrong-live85" && !strings.Contains(err.Error(), "local snapshot schema unavailable") {
				t.Fatal("wrong live schema refusal", err)
			}
			if !reflect.DeepEqual(before, executionStorageSnapshot(t, f.c)) {
				t.Fatal("failed snapshot changed corrupt predecessor")
			}
		})
	}
}

func TestAggregateLocalSnapshotAndFreshRehash(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprint(partial), func(t *testing.T) {
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Continuing: true, LocalHead: 3})
			ctx := context.Background()
			if partial {
				if err := f.local.c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationResetSemanticProjectionTx(ctx, tx, "") }); err != nil {
					t.Fatal(err)
				}
				if err := f.local.c.AutomationReplay(ctx, contract.Reduce, 1); err == nil {
					t.Fatal("partial fixture completed")
				}
			}
			before, typed := receiverActive(t, f.local.c), automationTypedSnapshot(t, f.local.c)
			var first aggregateLocalAudit
			err := f.local.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				var err error
				first, err = auditAggregateLocalTx(ctx, tx, f.attempt, f.local.c, "local-test-first")
				if err != nil {
					return err
				}
				if first.id == "" || first.head.Sequence != 3 {
					return fmt.Errorf("actual certified local head missing: %+v", first.head)
				}
				fresh, err := rehashAggregateLocalTx(ctx, tx, f.attempt, f.local.c)
				if err != nil {
					return err
				}
				if fresh != first.dependency {
					return fmt.Errorf("fresh digest differs")
				}
				return automationResetSemanticProjectionTx(ctx, tx, "receiver-audit:local-test-first")
			})
			if err != nil {
				t.Fatalf("actual bounded local snapshot: %v", err)
			}
			if receiverActive(t, f.local.c) != before || !reflect.DeepEqual(typed, automationTypedSnapshot(t, f.local.c)) {
				t.Fatal("local snapshot changed active or old stages")
			}
			if _, err = f.local.c.db.Exec(`UPDATE local_voter_incarnation SET created_at=created_at||'changed' WHERE id=1`); err != nil {
				t.Fatal(err)
			}
			err = f.local.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				fresh, err := rehashAggregateLocalTx(ctx, tx, f.attempt, f.local.c)
				if err == nil && fresh == first.dependency {
					return fmt.Errorf("fresh rehash ignored exact timestamp")
				}
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAggregateLocalRejectsOversizedAndFractionalKeys(t *testing.T) {
	for _, tc := range []struct {
		name, sql string
		args      []any
	}{
		{"oversized-request", `INSERT INTO local_automation_requests(scope,request_id,identity,receipt_json,operation_id) VALUES(?,'request',x'01','{}','')`, []any{strings.Repeat("x", maxSourceFieldBytes+1)}},
		{"fractional-claim", `INSERT INTO local_recovery_claims(target_kind,target_name,owner_epoch,attempt,config_generation,updated_at) VALUES('lease_term','bad',1.5,0,1,'t')`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2})
			if _, err := f.local.c.db.Exec(tc.sql, tc.args...); err != nil {
				t.Fatal(err)
			}
			before := receiverActive(t, f.local.c)
			err := f.local.c.ExecuteLocal(context.Background(), func(tx *LocalTx) error {
				_, err := auditAggregateLocalTx(context.Background(), tx, f.attempt, f.local.c, "local-test-malformed")
				return err
			})
			if err == nil || !strings.Contains(err.Error(), "local snapshot") {
				t.Fatalf("bounded malformed-key refusal missing: %v", err)
			}
			if receiverActive(t, f.local.c) != before {
				t.Fatal("malformed original was normalized")
			}
		})
	}
}

func TestAggregateLocalActualOwnedOrigin(t *testing.T) {
	for _, mode := range []string{"owned", "self-counted", "higher-promise", "missing", "fractional-extra"} {
		t.Run(mode, func(t *testing.T) {
			key := LeaseTermClaimKey("local_origin", 7)
			sources := 2
			if mode == "self-counted" {
				sources = 3
			}
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: sources, Continuing: true, BeforeFreeze: func(t *testing.T, _ []*claimTestVoter, local *claimTestVoter) {
				value := ClaimValue{LeaseTerm: &LeaseTermValue{Key: key.TargetName, Term: key.OwnerEpoch, Holder: local.name}}
				reply, err := local.c.ClaimAccept(context.Background(), key, testBallot(2, local.name), value, 1, local.signer, unreachable)
				if err != nil || !reply.Accepted {
					t.Fatalf("real own acceptance: %+v %v", reply, err)
				}
			}})
			if mode == "higher-promise" {
				if _, err := f.local.c.db.Exec(`UPDATE local_recovery_claims SET promised_round=9,updated_at=updated_at||'later' WHERE target_kind='lease_term'`); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "missing" {
				if _, err := f.local.c.db.Exec(`DELETE FROM local_automation_cuts`); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "fractional-extra" {
				if _, err := f.local.c.db.Exec(`INSERT INTO local_automation_cut_records(cut_id,section,ordinal,record) SELECT id,0.5,1,x'01' FROM local_automation_cuts LIMIT 1`); err != nil {
					t.Fatal(err)
				}
			}
			before, typed := receiverActive(t, f.local.c), automationTypedSnapshot(t, f.local.c)
			err := f.local.c.ExecuteLocal(context.Background(), func(tx *LocalTx) error {
				local, err := auditAggregateLocalTx(context.Background(), tx, f.attempt, f.local.c, "local-origin-test")
				if err != nil {
					return err
				}
				found := false
				err = local.store.walk(context.Background(), 3, func(n int64, row Row) error {
					if row.String("target_kind") != ClaimKindLeaseTerm {
						return nil
					}
					found = true
					var origin []byte
					err := aggregateLocalOriginsTx(context.Background(), tx, local, func(read func(int, int64) ([]byte, error)) error {
						var e error
						origin, e = read(3, n)
						return e
					})
					if err != nil {
						return err
					}
					if len(origin) == 0 {
						return fmt.Errorf("empty origin")
					}
					return nil
				})
				if err != nil {
					return err
				}
				if !found {
					return fmt.Errorf("original local acceptance omitted")
				}
				return automationResetSemanticProjectionTx(context.Background(), tx, "receiver-audit:local-origin-test")
			})
			if mode == "owned" || mode == "self-counted" || mode == "higher-promise" {
				if err != nil {
					t.Fatalf("genuine owned origin unavailable: %v", err)
				}
			} else if err == nil {
				t.Fatal("invalid owned origin accepted")
			}
			if mode == "missing" && !strings.Contains(err.Error(), "local acceptance origin unavailable") {
				t.Fatalf("missing origin not specific: %v", err)
			}
			if receiverActive(t, f.local.c) != before || !reflect.DeepEqual(typed, automationTypedSnapshot(t, f.local.c)) {
				t.Fatal("origin audit changed active or prior stages")
			}
		})
	}
}

func TestAggregateLocalTypedHistoryCursor(t *testing.T) {
	for _, mode := range []string{"complete", "partial", "secret", "drift"} {
		t.Run(mode, func(t *testing.T) {
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Continuing: true, BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
				verifier, err := LoadClaimVerifier(local.pki)
				if err != nil {
					t.Fatal(err)
				}
				automationTypedHistoryFixtureWithDecision(t, local, voters[0], voters[1], verifier, func(d *contract.Decision) {
					if mode == "secret" || d.Command.Kind != "admit_create" {
						return
					}
					d.Command.Ciphertext = nil
					d.Command.SecretIntentTag = nil
					d.Command.SecretKeyEpoch = ""
					a, err := contract.DecodeAssignment(*d)
					if err != nil {
						t.Fatal(err)
					}
					a.Binding.PayloadID = ""
					d.Assignment, err = json.Marshal(a)
					if err != nil {
						t.Fatal(err)
					}
				})
				key, _ := AutomationClaimKey(1)
				installAutomationEvidence(t, local.c, key, "", 1)
				if _, err = local.c.db.Exec(`UPDATE local_automation_authority SET bootstrap_request='initialize' WHERE id=1`); err != nil {
					t.Fatal(err)
				}
			}})
			ctx := context.Background()
			if mode == "partial" {
				if err := f.local.c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationResetSemanticProjectionTx(ctx, tx, "") }); err != nil {
					t.Fatal(err)
				}
				if err := f.local.c.AutomationReplay(ctx, contract.Reduce, 6); err == nil {
					t.Fatal("partial fixture complete")
				}
			}
			if mode == "drift" {
				if _, err := f.local.c.db.Exec(`UPDATE local_automation_resources SET revision='wrong' WHERE stage='' AND uid='resource-uid'`); err != nil {
					t.Fatal(err)
				}
			}
			before, typed := receiverActive(t, f.local.c), automationTypedSnapshot(t, f.local.c)
			err := f.local.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				local, err := auditAggregateLocalTx(ctx, tx, f.attempt, f.local.c, "typed-local")
				if err != nil {
					return err
				}
				if local.head.Sequence != 12 {
					return fmt.Errorf("certified typed H lost")
				}
				return automationResetSemanticProjectionTx(ctx, tx, "receiver-audit:typed-local")
			})
			if mode == "secret" {
				if err == nil || !strings.Contains(err.Error(), "required secret/equality coverage unavailable") {
					t.Fatalf("secret refusal: %v", err)
				}
			} else if mode == "drift" {
				if err == nil || !strings.Contains(err.Error(), "active automation projection differs") {
					t.Fatalf("typed drift refusal: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if receiverActive(t, f.local.c) != before || !reflect.DeepEqual(typed, automationTypedSnapshot(t, f.local.c)) {
				t.Fatal("typed audit changed active or old stages")
			}
		})
	}
}

func TestAggregateLocalCommittedRetryReopen(t *testing.T) {
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Continuing: true, LocalHead: 3})
	ctx := context.Background()
	audit := func(c *Client, a *AutomationReceiverAttempt, namespace string) string {
		t.Helper()
		var id string
		err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
			local, err := auditAggregateLocalTx(ctx, tx, a, c, namespace)
			if err != nil {
				return err
			}
			id = local.id
			if err = automationResetSemanticProjectionTx(ctx, tx, "receiver-audit:"+namespace); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `DELETE FROM local_automation_receiver_requests WHERE audit=?`, namespace); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `DELETE FROM local_automation_receiver_refs WHERE audit=?`, namespace)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	id := audit(f.local.c, f.attempt, "committed-first")
	stored, active, typed := aggregateStored(t, f.local.c), receiverActive(t, f.local.c), automationTypedSnapshot(t, f.local.c)
	if again := audit(f.local.c, f.attempt, "committed-second"); again != id || aggregateStored(t, f.local.c) != stored {
		t.Fatal("fresh scratch changed stable identity")
	}
	host, dir := f.local.c.hostName, f.receiver.dir
	if err := f.local.c.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewLocalClient(f.dir, host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	reopened.SetVoterConfigGate(func() bool { return true })
	receiver := NewAutomationReceiver(reopened, dir)
	attempt, err := receiver.Begin(ctx, f.requests[0].Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	if again := audit(reopened, attempt, "reopened"); again != id || aggregateStored(t, reopened) != stored || receiverActive(t, reopened) != active || !reflect.DeepEqual(typed, automationTypedSnapshot(t, reopened)) {
		t.Fatal("reopened immutable local snapshot changed")
	}
}

// The observer runs the exact production SQL through the actual SQLite driver,
// records its actual query plan, and counts rows/bytes before Row materializes.
// The two finite PRAGMA metadata buffers are accounted separately from bodies.
type aggregateLocalReadDriver struct {
	driver.Driver
	state, metadata *receiverSemanticReads
}
type aggregateLocalReadConn struct {
	driver.Conn
	state, metadata *receiverSemanticReads
}

func (d *aggregateLocalReadDriver) Open(name string) (driver.Conn, error) {
	c, err := d.Driver.Open(name)
	if err != nil {
		return nil, err
	}
	return &aggregateLocalReadConn{c, d.state, d.metadata}, nil
}
func (c *aggregateLocalReadConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}
func (c *aggregateLocalReadConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return c.observeQuery(ctx, q, args, func() (driver.Rows, error) { return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args) })
}
func (c *aggregateLocalReadConn) Prepare(query string) (driver.Stmt, error) {
	return c.PrepareContext(context.Background(), query)
}
func (c *aggregateLocalReadConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	stmt, err := prepareCapacityActual(ctx, c.Conn, query)
	if err != nil {
		return nil, err
	}
	return &aggregateObservedStmt{Stmt: stmt, observer: c, query: query}, nil
}
func (c *aggregateLocalReadConn) observeQuery(ctx context.Context, q string, args []driver.NamedValue, execute func() (driver.Rows, error)) (driver.Rows, error) {
	reader := c.Conn.(driver.QueryerContext)
	if sample, ok := ctx.Value(aggregateLocalHeapKey{}).(*aggregateLocalHeapSample); ok && strings.HasPrefix(q, "SELECT record ") {
		// Observe actual live allocations at the next database body read, after
		// collecting unreachable previous bodies. This is not an asserted scope.
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		sample.reads++
		if m.HeapAlloc > sample.live {
			sample.live = m.HeapAlloc
		}
		if m.TotalAlloc > sample.total {
			sample.total = m.TotalAlloc
		}
	}
	c.state.mu.Lock()
	enabled := c.state.enabled
	c.state.mu.Unlock()
	metadata := enabled && strings.HasPrefix(q, "PRAGMA table_xinfo(")
	tracked := false
	if enabled && strings.HasPrefix(q, "SELECT ") {
		for _, d := range aggregateLocalTables() {
			if strings.Contains(q, " FROM "+d.table+" ") {
				tracked = true
				break
			}
		}
		for _, table := range []string{"local_automation_receiver_refs", "local_automation_receiver_requests", "local_automation_local_rows", "local_automation_local_audits"} {
			if strings.Contains(q, " FROM "+table+" ") {
				tracked = true
			}
		}
	}
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
		if !strings.Contains(q, "LIMIT 1") || strings.Contains(detail, "TEMP B-TREE") || strings.Contains(q, "OFFSET") {
			c.state.bad = append(c.state.bad, "unbounded query/plan: "+q+" "+detail)
		}
		// The initial tuple probe walks the first index entry with no predicate;
		// every later tuple is a real indexed range, never a residual-filter scan.
		if strings.Contains(q, " WHERE ") && !strings.Contains(detail, "SEARCH ") {
			c.state.bad = append(c.state.bad, "not an indexed search: "+q+" "+detail)
		}
		if strings.Contains(q, "length(") {
			c.state.probes++
		} else {
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
	if metadata {
		return &receiverSemanticRows{Rows: rows, state: c.metadata, query: q}, nil
	}
	return rows, nil
}
func aggregateLocalInstrument(t *testing.T, c *Client) (*receiverSemanticReads, *receiverSemanticReads) {
	t.Helper()
	state := &receiverSemanticReads{plans: map[string]string{}}
	metadata := &receiverSemanticReads{}
	name := fmt.Sprintf("aggregate-local-read-%d", sourceReadDriverSequence.Add(1))
	sql.Register(name, &aggregateLocalReadDriver{Driver: &sqlite.Driver{}, state: state, metadata: metadata})
	db, err := sql.Open(name, c.dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	c.mu.Lock()
	old := c.db
	c.db = db
	c.mu.Unlock()
	if err = old.Close(); err != nil {
		t.Fatal(err)
	}
	return state, metadata
}

func TestAggregateLocalActualDriverBounds(t *testing.T) {
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Continuing: true, LocalHead: 130})
	state, metadata := aggregateLocalInstrument(t, f.local.c)
	state.enabled = true
	err := f.local.c.ExecuteLocal(context.Background(), func(tx *LocalTx) error {
		local, err := auditAggregateLocalTx(context.Background(), tx, f.attempt, f.local.c, "bounded-local")
		if err != nil {
			return err
		}
		if local.head.Sequence != 130 {
			return fmt.Errorf("large actual history missing")
		}
		return automationResetSemanticProjectionTx(context.Background(), tx, "receiver-audit:bounded-local")
	})
	state.enabled = false
	if err != nil {
		t.Fatal(err)
	}
	if len(state.bad) != 0 || state.maxRows != 1 || state.maxBytes > maxAggregateLocalRecordBytes || state.probes < 130 || state.bodies < 130 || metadata.maxRows > 16 || metadata.maxRows == 0 {
		t.Fatal("actual local production bounds", state.bad, state.maxRows, state.maxBytes, state.probes, state.bodies, metadata.maxRows)
	}
	var historyRange, claimTuple, requestTuple, typedRange, storedRange bool
	for q, plan := range state.plans {
		if strings.Contains(q, "WHERE sequence>?") && strings.Contains(q, "FROM local_automation_history") {
			historyRange = true
		}
		if strings.Contains(q, "(target_kind,target_name,owner_epoch,attempt)>") {
			claimTuple = true
		}
		if strings.Contains(q, "(scope,request_id)>") {
			requestTuple = true
		}
		if strings.Contains(q, "stage=? AND stage>?") {
			typedRange = true
		}
		if strings.Contains(q, "local_id=? AND (section,ordinal)>") {
			storedRange = true
		}
		t.Logf("actual local SQL %s => %s", q, plan)
	}
	if !historyRange || !claimTuple || !requestTuple || !typedRange || !storedRange {
		t.Fatal("missing actual literal PK range", historyRange, claimTuple, requestTuple, typedRange, storedRange)
	}
	t.Logf("actual local driver queries=%d scalar probes=%d bounded key/body reads=%d max rows=%d max field bytes=%d separate schema metadata max rows=%d max field bytes=%d", state.queries, state.probes, state.bodies, state.maxRows, state.maxBytes, metadata.maxRows, metadata.maxBytes)
}

func TestAggregateLocalActualDriverRefusesBeforeRawKey(t *testing.T) {
	for _, mode := range []string{"oversized", "fractional"} {
		t.Run(mode, func(t *testing.T) {
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2})
			section := 4
			if mode == "oversized" {
				if _, err := f.local.c.db.Exec(`INSERT INTO local_automation_requests(scope,request_id,identity,receipt_json,operation_id) VALUES(?,'r',x'01','{}','')`, strings.Repeat("x", maxSourceFieldBytes+1)); err != nil {
					t.Fatal(err)
				}
			} else {
				section = 0
				if _, err := f.local.c.db.Exec(`DELETE FROM local_recovery_claims`); err != nil {
					t.Fatal(err)
				}
				if _, err := f.local.c.db.Exec(`INSERT INTO local_recovery_claims(target_kind,target_name,owner_epoch,attempt,config_generation,updated_at) VALUES('lease_term','bad',1.5,0,1,'t')`); err != nil {
					t.Fatal(err)
				}
			}
			state, _ := aggregateLocalInstrument(t, f.local.c)
			state.enabled = true
			err := f.local.c.ExecuteLocal(context.Background(), func(tx *LocalTx) error {
				return walkAggregateLocalTable(context.Background(), tx, aggregateLocalTables()[section], "", func(int64, Row) error { return fmt.Errorf("raw body reached visitor") })
			})
			state.enabled = false
			if err == nil || !strings.Contains(err.Error(), "local snapshot invalid type or bound") || state.bodies != 0 || state.maxRows != 1 || state.maxBytes > 16 {
				t.Fatalf("unsafe key materialization: err=%v bodies=%d rows=%d bytes=%d", err, state.bodies, state.maxRows, state.maxBytes)
			}
			t.Logf("actual malformed %s: probes=%d raw key/body reads=%d maxrows=%d maxbytes=%d", mode, state.probes, state.bodies, state.maxRows, state.maxBytes)
		})
	}
}

func TestAggregateLocalAcceptedGenesisAuthority(t *testing.T) {
	for _, mode := range []string{"present", "prepare-only", "principal-drift", "request-drift"} {
		t.Run(mode, func(t *testing.T) {
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Continuing: true, BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
				key, _ := AutomationClaimKey(1)
				installAutomationEvidence(t, local.c, key, "", 1)
				if mode == "prepare-only" {
					reply, err := local.c.ClaimPrepare(context.Background(), key, testBallot(2, local.name), 1)
					if err != nil || !reply.Promised {
						t.Fatalf("actual native genesis promise: %+v %v", reply, err)
					}
					return
				}
				record := sharedAutomationRecord(t, 1, "", "req", "op", voters...)
				reply, err := local.c.ClaimAccept(context.Background(), key, testBallot(2, local.name), record.Value, 1, local.signer, nil)
				if err != nil || !reply.Accepted || reply.Accept == nil {
					t.Fatalf("actual native genesis acceptance: %+v %v", reply, err)
				}
			}})
			if mode == "principal-drift" {
				if _, err := f.local.c.db.Exec(`UPDATE local_automation_authority SET bootstrap_principal='unrelated'`); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "request-drift" {
				if _, err := f.local.c.db.Exec(`UPDATE local_automation_authority SET bootstrap_request='unrelated'`); err != nil {
					t.Fatal(err)
				}
			}
			active, typed, stored := receiverActive(t, f.local.c), automationTypedSnapshot(t, f.local.c), aggregateStored(t, f.local.c)
			err := f.local.c.ExecuteLocal(context.Background(), func(tx *LocalTx) error {
				local, err := auditAggregateLocalTx(context.Background(), tx, f.attempt, f.local.c, "accepted-genesis")
				if err != nil {
					return err
				}
				if local.head.Sequence != 0 {
					return fmt.Errorf("fixture certified H is not zero")
				}
				return automationResetSemanticProjectionTx(context.Background(), tx, "receiver-audit:accepted-genesis")
			})
			if mode == "present" || mode == "prepare-only" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), "local native accepted bootstrap identity differs") {
					t.Fatalf("accepted H0 genesis authority drift escaped: %v", err)
				}
				if aggregateStored(t, f.local.c) != stored {
					t.Fatal("refusal changed prior snapshot")
				}
			}
			if receiverActive(t, f.local.c) != active || !reflect.DeepEqual(typed, automationTypedSnapshot(t, f.local.c)) {
				t.Fatal("accepted genesis audit changed active or old stages")
			}
		})
	}
}

func TestAggregateLocalPrivateObservationExcludesCredentialDigest(t *testing.T) {
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2})
	// Actual schema74 private observation, not a certified principal or provider.
	secret := "private-credential-digest-must-not-enter-snapshot"
	if _, err := f.local.c.db.Exec(`INSERT INTO local_automation_credential_issuance(kind,credential_id,username,witness,principal_uid,cluster_uid,credential_digest,valid) VALUES('token','private-id','fixture','witness','private-principal','private-cluster',?,1)`, secret); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var first aggregateLocalAudit
	err := f.local.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		var err error
		first, err = auditAggregateLocalTx(ctx, tx, f.attempt, f.local.c, "private-observation")
		if err != nil {
			return err
		}
		return automationResetSemanticProjectionTx(ctx, tx, "receiver-audit:private-observation")
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := f.local.c.Query(ctx, `SELECT record FROM local_automation_local_rows WHERE local_id=?`, first.id)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if strings.Contains(string(row.Bytes("record")), secret) {
			t.Fatal("credential digest copied")
		}
	}
	if _, err = f.local.c.db.Exec(`UPDATE local_automation_credential_issuance SET credential_digest='different-private-digest'`); err != nil {
		t.Fatal(err)
	}
	err = f.local.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		digest, err := rehashAggregateLocalTx(ctx, tx, f.attempt, f.local.c)
		if err == nil && digest != first.dependency {
			return fmt.Errorf("credential digest entered dependency hash")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.local.c.db.Exec(`UPDATE local_automation_credential_issuance SET valid=0`); err != nil {
		t.Fatal(err)
	}
	err = f.local.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		digest, err := rehashAggregateLocalTx(ctx, tx, f.attempt, f.local.c)
		if err == nil && digest == first.dependency {
			return fmt.Errorf("private observation invalidation omitted")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAggregateLocalPreservesOldScratchAndMalformedSnapshot(t *testing.T) {
	for _, mode := range []string{"old-stage", "extra-snapshot-row"} {
		t.Run(mode, func(t *testing.T) {
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2})
			ctx := context.Background()
			namespace := "collision-test"
			if mode == "old-stage" {
				if _, err := f.local.c.db.Exec(`INSERT INTO local_automation_semantic_heads(stage,cluster_uid,sequence,digest) VALUES(?,'prior-cluster',19,'prior-digest')`, "receiver-audit:"+namespace); err != nil {
					t.Fatal(err)
				}
			} else {
				var id string
				err := f.local.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
					local, err := auditAggregateLocalTx(ctx, tx, f.attempt, f.local.c, "prior-snapshot")
					if err != nil {
						return err
					}
					id = local.id
					return automationResetSemanticProjectionTx(ctx, tx, "receiver-audit:prior-snapshot")
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.local.c.db.Exec(`INSERT INTO local_automation_local_rows(local_id,section,ordinal,record) VALUES(?,100,1,x'01')`, id); err != nil {
					t.Fatal(err)
				}
			}
			before, typed, stored := receiverActive(t, f.local.c), automationTypedSnapshot(t, f.local.c), aggregateStored(t, f.local.c)
			err := f.local.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				_, err := auditAggregateLocalTx(ctx, tx, f.attempt, f.local.c, namespace)
				return err
			})
			want := "local scratch stage already exists"
			if mode == "extra-snapshot-row" {
				want = "local snapshot identity collision inventory"
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("exact refusal missing: %v", err)
			}
			if receiverActive(t, f.local.c) != before || !reflect.DeepEqual(typed, automationTypedSnapshot(t, f.local.c)) || aggregateStored(t, f.local.c) != stored {
				t.Fatal("refusal changed pre-existing evidence")
			}
		})
	}
}

func TestAggregateLocalActualNearRecordBound(t *testing.T) {
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Continuing: true, BeforeFreeze: func(t *testing.T, _ []*claimTestVoter, local *claimTestVoter) {
		key := workloadKey()
		payload := maxAutomationCutRecordBytes - (64 << 10)
		for round := uint64(2); round <= 3; round++ {
			value := workloadValue(strings.Repeat("x", payload), local.name, "ghost")
			accepted, err := local.c.ClaimAccept(context.Background(), key, testBallot(round, local.name), value, 1, local.signer, unreachable)
			if err != nil || !accepted.Accepted {
				t.Fatalf("genuine near-bound native claim: %+v %v", accepted, err)
			}
			rows, err := local.c.Query(context.Background(), "SELECT "+automationCutSections[0].columns+" FROM local_recovery_claims WHERE target_kind=? AND target_name=? AND owner_epoch=? AND attempt=?", key.TargetKind, key.TargetName, key.OwnerEpoch, key.Attempt)
			if err != nil || len(rows) != 1 {
				t.Fatal("native size fixture", err)
			}
			raw, err := encodeAutomationCutRecord(automationCutSections[0].name, 1, rows[0])
			if err != nil {
				t.Fatal("genuine native frame", err)
			}
			if round == 3 && (len(raw) < maxAutomationCutRecordBytes-128 || len(raw) > maxAutomationCutRecordBytes) {
				t.Fatalf("native near-ceiling frame=%d", len(raw))
			}
			payload += maxAutomationCutRecordBytes - 32 - len(raw)
		}
	}})
	state, metadata := aggregateLocalInstrument(t, f.local.c)
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	sample := &aggregateLocalHeapSample{}
	ctx := context.WithValue(context.Background(), aggregateLocalHeapKey{}, sample)
	state.enabled = true
	err := f.local.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		local, err := auditAggregateLocalTx(ctx, tx, f.attempt, f.local.c, "near-bound-local")
		if err != nil {
			return err
		}
		// Locate the ordinal in its own body scope before auditing the origin.
		var acceptedOrdinal int64
		err = local.store.walk(ctx, 3, func(n int64, row Row) error {
			if row.String("target_kind") == ClaimKindVM {
				acceptedOrdinal = n
			}
			return nil
		})
		if err != nil {
			return err
		}
		if acceptedOrdinal == 0 {
			return fmt.Errorf("near-bound accepted claim missing")
		}
		if err = aggregateLocalOriginsTx(ctx, tx, local, func(read func(int, int64) ([]byte, error)) error {
			_, e := read(3, acceptedOrdinal)
			return e
		}); err != nil {
			return err
		}
		return automationResetSemanticProjectionTx(ctx, tx, "receiver-audit:near-bound-local")
	})
	state.enabled = false
	if err != nil {
		t.Fatalf("valid near-bound native local acceptance/origin refused: %v", err)
	}
	if len(state.bad) != 0 || state.maxRows != 1 || state.maxBytes < maxAutomationCutRecordBytes-(64<<10) || state.maxBytes > maxAggregateLocalRecordBytes || metadata.maxRows > 16 {
		t.Fatal("near-bound materialization", state.bad, state.maxRows, state.maxBytes, metadata.maxRows)
	}
	if sample.reads == 0 {
		t.Fatal("no actual heap samples at body reads")
	}
	t.Logf("actual driver-triggered heap sample reads=%d baseline=%d max-live-before-next-body=%d total-allocated-during-audit=%d (includes SQLite/metadata/codec copies, not a one-buffer assertion)", sample.reads, baseline.HeapAlloc, sample.live, sample.total-baseline.TotalAlloc)
	t.Logf("actual near-bound local claim/origin maxfieldbytes=%d maxrows=%d metadata-maxrows=%d", state.maxBytes, state.maxRows, metadata.maxRows)
}

type aggregateLocalHeapKey struct{}
type aggregateLocalHeapSample struct {
	reads       int
	live, total uint64
}
