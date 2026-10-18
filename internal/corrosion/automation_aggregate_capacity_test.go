package corrosion

import (
	"context"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime/pprof"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
	"modernc.org/sqlite"
)

// These are actual C costs, not a D current-proof test: auditAggregate uses a
// zero observation time. In particular, elapsed > 10s must remain visible.
func TestAutomationCapacityLegalSevenToSix(t *testing.T) {
	automationCapacity(t, 130, 37, false)
}

func TestAutomationCapacitySevenToSixNearNativeLimit(t *testing.T) {
	automationCapacity(t, 2, 1, true)
}

func automationCapacity(t *testing.T, history, claims int, near bool) *capacityQueryReads {
	t.Helper()
	ctx := pprof.WithLabels(context.Background(), pprof.Labels("automation_capacity_workload", fmt.Sprintf("history%d-claims%d-near%t", history, claims, near)))
	setup := time.Now()
	heads := []int{history, history, history, history, history, history, history}
	f := newAggregateFixture(t, aggregateFixtureOptions{
		Old: 7, Sources: 7, Continuing: true, Remove: "old-0", Heads: heads, LocalHead: history,
		BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
			for n := 0; n < claims; n++ {
				key := LeaseTermClaimKey(fmt.Sprintf("capacity_%03d", n), 1)
				value := ClaimValue{LeaseTerm: &LeaseTermValue{Key: key.TargetName, Term: 1, Holder: "retained-holder"}}
				if near {
					key = workloadKey()
					value = workloadValue(strings.Repeat("x", maxAutomationCutRecordBytes-(64<<10)), "destination", "ghost")
				}
				for i, voter := range voters {
					reply, err := voter.c.ClaimAccept(ctx, key, testBallot(uint64(i+2), "capacity"), value, 1, voter.signer, unreachable)
					if err != nil || !reply.Accepted {
						t.Fatalf("genuine retained acceptance %s/%d: %+v %v", voter.name, n, reply, err)
					}
				}
			}
		},
	})
	setupDuration := time.Since(setup)
	old, err := GetVoterConfig(ctx, f.local.c, 1)
	if err != nil {
		t.Fatal(err)
	}
	next, err := GetVoterConfig(ctx, f.local.c, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(old.Members) != 7 || len(next.Members) != 6 || next.Change != VoterChangeRm("old-0") || ValidateVoterChange(old, next.VoterConfigValue) != nil {
		t.Fatal("capacity requires genuine signed legal seven-to-six removal")
	}
	certificate, err := DecodeClaimCertificate(next.Certificate)
	if err != nil || len(certificate.Accepts) != 7 {
		t.Fatal("independent ordinary successor votes missing", err)
	}
	// Retain removed old standing as a source, and native continuing receiver
	// standing until actual transfer. No G2 automation authority is installed.
	for _, i := range []int{0, 6} {
		adopted, err := AdoptedVoterConfig(ctx, f.voters[i].c)
		if err != nil || adopted.Generation != 1 {
			t.Fatal("old standing lost", i, err)
		}
	}
	seenDB, seenKey, seenPublication, seenCut := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	var cutRecords, cutBytes, cutMetadata, configBytes, certificateBytes int64
	for i, producer := range f.producers {
		if _, err := os.Stat(filepath.Join(producer.client.dataDir, "state.db")); err != nil {
			t.Fatal("not FULL file-backed", err)
		}
		pair, err := pki.ServedHostKeyPair(producer.dir)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		key, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := producer.client.Query(ctx, `SELECT id,metadata,root FROM local_automation_cuts WHERE generation=1`)
		if err != nil || len(rows) != 1 {
			t.Fatal("independent frozen cut missing", err)
		}
		cut := rows[0].String("id")
		if seenDB[producer.client.dsn] || seenKey[string(key)] || seenPublication[f.requests[i].Publication] || seenCut[cut] {
			t.Fatal("cloned source identity")
		}
		seenDB[producer.client.dsn], seenKey[string(key)], seenPublication[f.requests[i].Publication], seenCut[cut] = true, true, true, true
		cutInfo, err := readAutomationCutMetadata(rows[0])
		if err != nil {
			t.Fatal(err)
		}
		if cutInfo.Head.Sequence != uint64(history) || cutInfo.Inventory[0].Records != int64(claims+2) || cutInfo.Inventory[1].Records != 0 || cutInfo.Inventory[2].Records != int64(history) || cutInfo.Inventory[3].Records != int64(history) || cutInfo.Inventory[4].Records != int64(history) {
			t.Fatalf("actual per-source cut inventory differs %s: %+v", producer.client.hostName, cutInfo)
		}
		for component, inventory := range cutInfo.Inventory {
			t.Logf("capacity originalCut source=%s component=%d section=%s originalRecords=%d originalBytes=%d", producer.client.hostName, component+3, inventory.Section, inventory.Records, inventory.Bytes)
		}
		if size := int64(len(rows[0].Bytes("metadata"))); size > cutMetadata {
			cutMetadata = size
		}
		rows, err = producer.client.Query(ctx, `SELECT COUNT(*) AS n,COALESCE(SUM(length(record)),0) AS bytes FROM local_automation_cut_records WHERE cut_id=?`, cut)
		if err != nil || len(rows) != 1 {
			t.Fatal(err)
		}
		cutRecords += rows[0].Int64("n")
		cutBytes += rows[0].Int64("bytes")
		rows, err = producer.client.Query(ctx, `SELECT MAX(length(CAST(members_json AS BLOB))) AS members,MAX(length(CAST(certificate AS BLOB))) AS certificate FROM voter_configs`)
		if err != nil || len(rows) != 1 {
			t.Fatal(err)
		}
		if n := rows[0].Int64("members"); n > configBytes {
			configBytes = n
		}
		if n := rows[0].Int64("certificate"); n > certificateBytes {
			certificateBytes = n
		}
	}
	var pages, transferredBytes, historyPages int64
	historyPageCounts := make([]int64, len(f.producers))
	staging := time.Now()
	for i, producer := range f.producers {
		request := f.requests[i]
		request.MaxRecords = 7 // 130 records require at least 19 genuine pages.
		source := producer.client.hostName
		var sourceHistoryPages int64
		for component := uint32(0); component < 12; component++ {
			request.Component, request.Cursor = component, ""
			for {
				page, err := producer.ExportAutomationSource(f.exportCtx, request)
				if err != nil {
					t.Fatalf("actual export %s/%d: %v", source, component, err)
				}
				if _, err = f.receiver.Stage(ctx, f.attempt, source, request, page); err != nil {
					t.Fatalf("actual stage %s/%d: %v", source, component, err)
				}
				pages++
				if component == 5 {
					historyPages++
					sourceHistoryPages++
				}
				transferredBytes += int64(len(page.Metadata) + len(page.Chunk))
				for _, record := range page.Records {
					transferredBytes += int64(len(record))
				}
				if page.Terminal {
					break
				}
				request.Cursor = page.Cursor
			}
		}
		if history == 130 && sourceHistoryPages < 19 {
			t.Fatal("source not genuinely many-page", source, sourceHistoryPages)
		}
		if err := f.receiver.AuditSource(ctx, f.attempt, source); err != nil {
			t.Fatalf("actual COMPLETE audit %s: %v", source, err)
		}
		historyPageCounts[i] = sourceHistoryPages
	}
	stagingDuration := time.Since(staging)
	for i, producer := range f.producers {
		automationCapacityOriginals(t, f, producer.client.hostName, history, claims, near, historyPageCounts[i])
	}
	currentLocal, err := f.local.c.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_history`)
	if err != nil || len(currentLocal) != 1 || currentLocal[0].Int64("n") != int64(history) {
		t.Fatal("additional local history inventory differs", currentLocal, err)
	}
	if history == 130 && historyPages < 7*19 {
		t.Fatal("many-page inventory not exercised", historyPages)
	}
	t.Logf("capacity setup+Freeze/Prepare/Publish=%s export+Stage+7AuditSource=%s old=7 next=6 fixed=7 historyPerSource=%d retainedClaimsPerSource=%d cutRecords=%d cutBytes=%d pages=%d historyPages=%d transferredPayloadBytes=%d", setupDuration, stagingDuration, history, claims, cutRecords, cutBytes, pages, historyPages, transferredBytes)
	t.Logf("capacity metadata maxCut=%d maxElectorate=%d maxCertificate=%d configuredCutMetadata=%d configuredElectorate=%d configuredCertificate=%d", cutMetadata, configBytes, certificateBytes, maxAutomationCutMetadataBytes, maxSourceConfigBytes, maxSourceCertificateBytes)
	active, typed, spool := receiverActive(t, f.local.c), automationTypedSnapshot(t, f.local.c), receiverStored(t, f.local.c)
	localReads, metadata := aggregateLocalInstrument(t, f.local.c)
	localReads.enabled = true
	rehashStart := time.Now()
	var digest string
	err = f.local.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		var err error
		digest, err = rehashAggregateLocalTx(ctx, tx, f.attempt, f.local.c)
		return err
	})
	rehashDuration := time.Since(rehashStart)
	localReads.enabled = false
	if err != nil || digest == "" {
		t.Fatal("actual FULL isolated local rehash", err)
	}
	if len(localReads.bad) != 0 || localReads.maxRows != 1 || localReads.maxBytes > maxAggregateLocalRecordBytes || localReads.probes < history || metadata.maxRows > 16 || metadata.maxRows == 0 {
		t.Fatal("FULL local read bounds", localReads.bad, localReads.maxRows, localReads.maxBytes, localReads.probes, metadata.maxRows)
	}
	t.Logf("capacity isolatedFULLRehash=%s queries=%d probes=%d bodyKeyReads=%d maxRows=%d maxFieldBytes=%d separateSchemaMetadataMaxRows=%d separateSchemaMetadataMaxFieldBytes=%d", rehashDuration, localReads.queries, localReads.probes, localReads.bodies, localReads.maxRows, localReads.maxBytes, metadata.maxRows, metadata.maxBytes)
	// Remove every observing driver for the first actual aggregate. CPU profile
	// labels distinguish this phase from fixture/network work and the later
	// instrumented retry; profiler sampling itself is reported separately.
	capacityReplaceDB(t, f.local.c, "sqlite")
	aggregateStart := time.Now()
	id, err := capacityAggregatePhase(ctx, f, "aggregate-unobserved-first")
	unobservedDuration := time.Since(aggregateStart)
	t.Logf("capacity actualAggregateObserversRemoved=%s observationLifetime=%s isolatedRehashOverLifetime=%t unobservedAggregateOverLifetime=%t CZeroObservedDoesNotProveD=true", unobservedDuration, sourceTargetObservationLifetime, rehashDuration >= sourceTargetObservationLifetime, unobservedDuration >= sourceTargetObservationLifetime)
	if err != nil || id == "" {
		t.Fatalf("actual full7 COMPLETE aggregate without observers: %v", err)
	}
	if active != receiverActive(t, f.local.c) || !reflect.DeepEqual(typed, automationTypedSnapshot(t, f.local.c)) || spool != receiverStored(t, f.local.c) {
		t.Fatal("unobserved first aggregate changed active/typed/source-spool state")
	}
	aggregateReads, allReads := capacityInstrument(t, f.local.c)
	aggregateReads.enabled, allReads.enabled = true, true
	aggregateStart = time.Now()
	again, err := capacityAggregatePhase(ctx, f, "aggregate-observed-retry")
	aggregateDuration := time.Since(aggregateStart)
	aggregateReads.enabled, allReads.enabled = false, false
	t.Logf("capacity instrumentedAggregateRetry=%s observationLifetime=%s retryOverLifetime=%t lifecycle=retry EXPLAINOverheadIncluded=true", aggregateDuration, sourceTargetObservationLifetime, aggregateDuration >= sourceTargetObservationLifetime)
	if err != nil || again != id {
		t.Fatalf("actual observed retry changed aggregate identity: %q -> %q %v", id, again, err)
	}
	if len(aggregateReads.bad) != 0 || aggregateReads.maxRows != 1 || aggregateReads.maxBytes > maxAutomationCutRecordBytes || aggregateReads.probes < claims || aggregateReads.bodies < claims {
		t.Fatal("actual aggregate read bounds", aggregateReads.bad, aggregateReads.maxRows, aggregateReads.maxBytes, aggregateReads.probes, aggregateReads.bodies)
	}
	allReads.report(t)
	rows, err := f.local.c.Query(ctx, `SELECT source,incarnation FROM local_automation_aggregate_sources WHERE bundle=? ORDER BY source`, id)
	if err != nil || len(rows) != 7 {
		t.Fatal("fixed maximal old roster reduced", len(rows), err)
	}
	for i, row := range rows {
		if row.String("source") != f.voters[i].name || row.String("incarnation") != f.voters[i].inc {
			t.Fatal("aggregate did not pin exact authenticated source", i)
		}
	}
	rows, err = f.local.c.Query(ctx, `SELECT head FROM local_automation_aggregates WHERE id=?`, id)
	var head AutomationPrefix
	if err != nil || len(rows) != 1 || json.Unmarshal(rows[0].Bytes("head"), &head) != nil || head.Sequence != uint64(history) {
		t.Fatal("real certified history maximum lost", head, err)
	}
	rows, err = f.local.c.Query(ctx, `SELECT COUNT(*) AS n,COALESCE(SUM(length(origin_ref)),0) AS bytes FROM local_automation_aggregate_copies WHERE bundle=? AND origin_kind='local'`, id)
	if err != nil || len(rows) != 1 || rows[0].Int64("n") != int64(claims) || rows[0].Int64("bytes") == 0 {
		t.Fatal("own original acceptance origins lost", err)
	}
	localOriginBytes := rows[0].Int64("bytes")
	rows, err = f.local.c.Query(ctx, `SELECT s.source,COUNT(c.ordinal) AS n FROM local_automation_aggregate_sources s LEFT JOIN local_automation_aggregate_copies c ON c.bundle=s.bundle AND c.origin_kind='source' AND c.origin_id=s.audit WHERE s.bundle=? GROUP BY s.source ORDER BY s.source`, id)
	if err != nil || len(rows) != 7 {
		t.Fatal("source copy inventory missing", err)
	}
	var sourceCopies int64
	for i, row := range rows {
		if row.String("source") != f.voters[i].name || row.Int64("n") != int64(claims) {
			t.Fatal("source original copy count differs", row)
		}
		sourceCopies += row.Int64("n")
		t.Logf("capacity originalAggregateCopies source=%s exactCopies=%d", row.String("source"), row.Int64("n"))
	}
	rows, err = f.local.c.Query(ctx, `SELECT (SELECT COUNT(*) FROM local_automation_aggregate_copies WHERE bundle=?) AS copies,(SELECT COUNT(*) FROM local_automation_aggregate_maxima WHERE bundle=?) AS maxima,(SELECT COUNT(*) FROM local_automation_aggregate_conflicts WHERE bundle=?) AS ballots`, id, id, id)
	if err != nil || len(rows) != 1 || rows[0].Int64("copies") != int64(8*claims) || rows[0].Int64("maxima") != int64(claims) || rows[0].Int64("ballots") != int64(7*claims) {
		t.Fatal("all original inputs not reconciled", rows, err)
	}
	t.Logf("capacity exactAllOriginalInputs sourceCopies=%d additionalLocalCopies=%d allCopies=%d claimKeys=%d distinctAcceptedBallots=%d sourceHistoryOriginals=%d additionalLocalHistory=%d logicalCertifiedHistory=%d repeatedSQLReadsAreNotOriginalCounts=true", sourceCopies, claims, rows[0].Int64("copies"), rows[0].Int64("maxima"), rows[0].Int64("ballots"), 7*history, history, history)
	t.Logf("capacity aggregate queries=%d probes=%d bodies=%d maxRows=%d maxFieldBytes=%d localOriginalCopies=%d localOriginBytes=%d nearNative=%t configuredRecordBound=%d", aggregateReads.queries, aggregateReads.probes, aggregateReads.bodies, aggregateReads.maxRows, aggregateReads.maxBytes, int64(claims), localOriginBytes, near, maxAutomationCutRecordBytes)
	if near && (localReads.maxBytes < maxAutomationCutRecordBytes-(64<<10) || aggregateReads.maxBytes < maxAutomationCutRecordBytes-(64<<10)) {
		t.Fatal("near native-limit actual bodies were not materialized", localReads.maxBytes, aggregateReads.maxBytes)
	}
	if active != receiverActive(t, f.local.c) || !reflect.DeepEqual(typed, automationTypedSnapshot(t, f.local.c)) || spool != receiverStored(t, f.local.c) {
		t.Fatal("capacity phases changed active/typed/source-spool state")
	}
	return allReads
}

// Inspect the actual staged originals after all phase timing stops. Read counts
// and byte counts below describe records, never SQL rereads of those records.
func automationCapacityOriginals(t *testing.T, f *aggregateFixture, source string, history, claims int, near bool, pages int64) {
	t.Helper()
	ctx := context.Background()
	rows, err := f.local.c.Query(ctx, `SELECT ordinal,record FROM local_automation_receiver_records WHERE attempt=? AND source=? AND component=3 ORDER BY ordinal`, f.attempt.id, source)
	if err != nil || len(rows) != claims+2 {
		t.Fatal("source original claim component count differs", source, len(rows), err)
	}
	kind := ClaimKindLeaseTerm
	if near {
		kind = ClaimKindVM
	}
	retained, membership := 0, 0
	membershipEpochs := map[int64]bool{}
	for _, original := range rows {
		claim, err := decodeSourceCutRow(0, original.Int64("ordinal"), original.Bytes("record"))
		if err != nil {
			t.Fatal(err)
		}
		if claim.String("target_kind") == ClaimKindVoterConfig {
			membership++
			epoch := claim.Int64("owner_epoch")
			if epoch < 0 || epoch > 1 || membershipEpochs[epoch] || claim.Int64("accepted_round") == 0 {
				t.Fatal("ordinary genesis/successor original differs", source, epoch)
			}
			membershipEpochs[epoch] = true
		}
		if claim.String("target_kind") == kind {
			retained++
			if claim.Int64("accepted_round") == 0 || len(claim.String("accept_json")) == 0 {
				t.Fatal("original lost genuine acceptance", source)
			}
		}
	}
	if retained != claims || membership != 2 || !membershipEpochs[0] || !membershipEpochs[1] {
		t.Fatal("source observed retained claims differ", source, retained, claims)
	}
	rows, err = f.local.c.Query(ctx, `SELECT component,COUNT(*) AS n,COALESCE(SUM(length(record)),0) AS bytes FROM local_automation_receiver_records WHERE attempt=? AND source=? GROUP BY component ORDER BY component`, f.attempt.id, source)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int64]int64{}
	for _, row := range rows {
		seen[row.Int64("component")] = row.Int64("n")
		t.Logf("capacity stagedOriginal source=%s component=%d records=%d bytes=%d", source, row.Int64("component"), row.Int64("n"), row.Int64("bytes"))
	}
	if seen[3] != int64(claims+2) || seen[4] != 0 || seen[5] != int64(history) || seen[6] != int64(history) || seen[7] != int64(history) {
		t.Fatal("actual staged component inventory differs", source, seen)
	}
	t.Logf("capacity observedSourceOriginals source=%s history=%d retainedClaims=%d allClaimRecordsIncludingTwoMembership=%d historyPages=%d", source, seen[5], retained, seen[3], pages)
}

func capacityAggregatePhase(ctx context.Context, f *aggregateFixture, phase string) (id string, err error) {
	pprof.Do(ctx, pprof.Labels("automation_capacity_phase", phase), func(ctx context.Context) {
		id, err = f.receiver.auditAggregate(ctx, f.attempt)
	})
	return id, err
}

func capacityReplaceDB(t *testing.T, c *Client, driverName string) {
	t.Helper()
	db, err := sql.Open(driverName, c.dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	c.mu.Lock()
	old := c.db
	c.db = db
	c.mu.Unlock()
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
}

// This outer driver counts actual returned value payloads over the entire
// aggregate path, including finite metadata queries. It delegates every query
// and row to SQLite. The inner observers separately enforce their SQL bounds.
// Byte totals include string/blob payloads, numeric widths, and bool widths;
// they exclude slice/string headers, driver/allocator overhead, and peak heap.
type capacityQueryStats struct{ calls, rows, bytes, maxRows, maxField, maxRow, maxQuery int64 }
type capacityQueryReads struct {
	mu              sync.Mutex
	enabled         bool
	queries         map[string]*capacityQueryStats
	prepared        capacityPreparedStats
	beforePrepared  func(int)
	failCloseOnce   bool
	transactionConn *capacityQueryConn
	transactionID   uint64
}
type capacityQueryDriver struct {
	driver.Driver
	reads *capacityQueryReads
}
type capacityQueryConn struct {
	driver.Conn
	reads       *capacityQueryReads
	transaction uint64
	active      bool
}
type capacityQueryRows struct {
	driver.Rows
	reads        *capacityQueryReads
	query        string
	count, bytes int64
}

func (d *capacityQueryDriver) Open(name string) (driver.Conn, error) {
	c, err := d.Driver.Open(name)
	if err != nil {
		return nil, err
	}
	return &capacityQueryConn{Conn: c, reads: d.reads}, nil
}
func (c *capacityQueryConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	c.reads.mu.Lock()
	c.transaction++
	c.active = true
	c.reads.mu.Unlock()
	return &capacityObservedTx{Tx: tx, conn: c}, nil
}
func (c *capacityQueryConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if capacityAggregateTransactionStack() {
		c.reads.mu.Lock()
		if c.reads.enabled {
			if c.reads.transactionConn == nil {
				c.reads.transactionConn, c.reads.transactionID = c, c.transaction
			}
			if c.reads.transactionConn != c || c.reads.transactionID != c.transaction || !c.active {
				c.reads.prepared.badConnection++
			}
		}
		c.reads.mu.Unlock()
	}
	if capacityPreparedEligible(query) && capacityStoreStack() {
		c.reads.mu.Lock()
		if c.reads.enabled {
			c.reads.prepared.direct++
		}
		c.reads.mu.Unlock()
	}
	c.reads.mu.Lock()
	enabled := c.reads.enabled
	if enabled {
		if c.reads.queries[query] == nil {
			c.reads.queries[query] = &capacityQueryStats{}
		}
		c.reads.queries[query].calls++
	}
	c.reads.mu.Unlock()
	rows, err := c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
	if err != nil || !enabled {
		return rows, err
	}
	return &capacityQueryRows{Rows: rows, reads: c.reads, query: query}, nil
}
func (r *capacityQueryRows) Next(values []driver.Value) error {
	if err := r.Rows.Next(values); err != nil {
		return err
	}
	var rowBytes, fieldBytes int64
	for _, value := range values {
		var n int64
		switch value := value.(type) {
		case []byte:
			n = int64(len(value))
		case string:
			n = int64(len(value))
		case int64, float64:
			n = 8
		case bool:
			n = 1
		case nil:
		default:
			return fmt.Errorf("unexpected actual SQLite value type %T", value)
		}
		rowBytes += n
		if n > fieldBytes {
			fieldBytes = n
		}
	}
	r.count++
	r.bytes += rowBytes
	r.reads.mu.Lock()
	defer r.reads.mu.Unlock()
	stats := r.reads.queries[r.query]
	stats.rows++
	stats.bytes += rowBytes
	if r.count > stats.maxRows {
		stats.maxRows = r.count
	}
	if fieldBytes > stats.maxField {
		stats.maxField = fieldBytes
	}
	if rowBytes > stats.maxRow {
		stats.maxRow = rowBytes
	}
	if r.bytes > stats.maxQuery {
		stats.maxQuery = r.bytes
	}
	return nil
}
func capacityInstrument(t *testing.T, c *Client) (*receiverSemanticReads, *capacityQueryReads) {
	t.Helper()
	aggregate := &receiverSemanticReads{plans: map[string]string{}}
	all := &capacityQueryReads{queries: map[string]*capacityQueryStats{}}
	name := fmt.Sprintf("capacity-real-read-%d", sourceReadDriverSequence.Add(1))
	sql.Register(name, &capacityQueryDriver{Driver: &aggregateBoundsDriver{Driver: &sqlite.Driver{}, state: aggregate}, reads: all})
	capacityReplaceDB(t, c, name)
	return aggregate, all
}
func (r *capacityQueryReads) report(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	var queries []string
	for query := range r.queries {
		queries = append(queries, query)
	}
	sort.Strings(queries)
	var calls, rows, bytes, maxRows, maxField, maxRow, maxQuery int64
	for _, query := range queries {
		s := r.queries[query]
		if strings.HasPrefix(query, "SELECT record ") && (s.maxRows > 1 || s.maxQuery > maxAggregateLocalRecordBytes) {
			t.Fatal("actual original body per-query bound", query, *s)
		}
		if strings.HasPrefix(query, "PRAGMA table_xinfo(") && s.maxRows > 16 {
			t.Fatal("schema metadata buffer bound", query, *s)
		}
		calls += s.calls
		rows += s.rows
		bytes += s.bytes
		if s.maxRows > maxRows {
			maxRows = s.maxRows
		}
		if s.maxField > maxField {
			maxField = s.maxField
		}
		if s.maxRow > maxRow {
			maxRow = s.maxRow
		}
		if s.maxQuery > maxQuery {
			maxQuery = s.maxQuery
		}
		t.Logf("capacity SQLFrequency lifecycle=observed-retry calls=%d returnedRows=%d returnedPayloadBytes=%d maxRowsPerQuery=%d maxFieldBytes=%d maxRowPayloadBytes=%d maxQueryPayloadBytes=%d SQL=%s", s.calls, s.rows, s.bytes, s.maxRows, s.maxField, s.maxRow, s.maxQuery, query)
	}
	if calls == 0 || rows == 0 || maxField == 0 || maxRow < maxField || maxQuery < maxRow {
		t.Fatal("whole query observer did not observe actual rows")
	}
	t.Logf("capacity wholeAggregateQueries lifecycle=observed-retry queries=%d rows=%d repeatedReturnedPayloadBytes=%d maxRowsPerQuery=%d maxFieldBytes=%d maxRowPayloadBytes=%d maxQueryPayloadBytes=%d includesFiniteMetadata=true excludesAllocatorOverheadAndPeakHeap=true", calls, rows, bytes, maxRows, maxField, maxRow, maxQuery)
}
