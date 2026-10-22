package corrosion

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"filippo.io/age"
)

// Frozen original schema78/80 shape, never derived from the new schemaDDL or
// constructed by calling current InitSchema. All16 columns and indexes persist.
const custodyLifetimeOriginalRecipientDDL = `CREATE TABLE local_automation_key_recipients (
 stage TEXT NOT NULL, cluster_uid TEXT NOT NULL, recipient_epoch TEXT NOT NULL,
 membership_generation INTEGER NOT NULL CHECK(membership_generation>0), config_digest TEXT NOT NULL,
 host TEXT NOT NULL, host_incarnation INTEGER NOT NULL CHECK(host_incarnation>0), admitted_at TEXT NOT NULL,
 admission_serial TEXT NOT NULL, voter_incarnation TEXT NOT NULL, key_id TEXT NOT NULL, recipient TEXT NOT NULL,
 enrollment_ref TEXT NOT NULL, recipient_ack_ref TEXT NOT NULL, equality_ack_ref TEXT NOT NULL,
 first_sequence INTEGER NOT NULL CHECK(first_sequence>0), PRIMARY KEY(stage,cluster_uid,recipient_epoch,host))`

const custodyLifetimeRecipientColumns = `stage,cluster_uid,recipient_epoch,membership_generation,config_digest,host,host_incarnation,admitted_at,admission_serial,voter_incarnation,key_id,recipient,enrollment_ref,recipient_ack_ref,equality_ack_ref,first_sequence`

func TestAutomationCustodyLifetimeMigration(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := custodyLifetimeFileClient(t, dir)
	t.Cleanup(func() { _ = c.Close() })
	custodyLifetimeBuildComposed82(t, c)
	for _, stage := range []string{"", "audit-a", "audit-b"} {
		if err := custodyLifetimeInsertRecipient(t, c, stage, "positive-control", 17); err != nil {
			t.Fatalf("SETUP composed82 positive insertion %q: %v", stage, err)
		}
	}
	if err := custodyLifetimeInsertRecipient(t, c, "", "old-host-zero", 0); err == nil || !strings.Contains(err.Error(), "host_incarnation>0") {
		t.Fatalf("SETUP composed82 did not enforce genuine old CHECK: %v", err)
	}
	before, err := c.Query(ctx, "SELECT "+custodyLifetimeRecipientColumns+" FROM local_automation_key_recipients ORDER BY stage,host")
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := c.Query(ctx, `SELECT id,applied_at,checksum FROM applied_migrations ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	if storedVersion(t, c) != 82 {
		t.Fatal("SETUP composed82 stamp missing")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	c = custodyLifetimeFileClient(t, dir)
	if storedVersion(t, c) != 82 {
		t.Fatal("SETUP composed82 did not persist")
	}
	// First InitSchema call for this fresh composed82 prerequisite fixture.
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("COMPOSED82_UPGRADE_REFUSED: %v", err)
	}
	after, err := c.Query(ctx, "SELECT "+custodyLifetimeRecipientColumns+" FROM local_automation_key_recipients ORDER BY stage,host")
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("COMPOSED82_RECIPIENT_BYTES_OR_STAGES_CHANGED: %v", err)
	}
	upgraded, err := c.Query(ctx, `SELECT id,applied_at,checksum FROM applied_migrations ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	oldIDs := map[string]bool{}
	for _, row := range ledger {
		oldIDs[row.String("id")] = true
	}
	var preserved []Row
	for _, row := range upgraded {
		if oldIDs[row.String("id")] {
			preserved = append(preserved, row)
		}
	}
	if !reflect.DeepEqual(ledger, preserved) {
		t.Fatal("COMPOSED82_LEDGER_BYTES_CHANGED")
	}
	if err := custodyLifetimeInsertRecipient(t, c, "audit-a", "new-host-zero", 0); err != nil {
		t.Fatalf("COMPOSED82_UPGRADE_N0_REFUSED: %v", err)
	}
	if storedVersion(t, c) != 86 || appliedCount(t, c) != len(ledger)+8 || countAppliedID(t, c, automationCustodyMigrationID) != 1 {
		t.Fatal("composed82 upgrade did not append schema83 recipient unit, two schema84 target units, schema85 token stamp and four schema86 execution units")
	}
	if err := c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationVerifySemanticSchemaTx(ctx, tx) }); err != nil {
		t.Fatal("rebuilt semantic/index guards refused", err)
	}
	complete := custodyLifetimeSnapshot(t, c)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	c = custodyLifetimeFileClient(t, dir)
	for range 2 {
		if err := InitSchema(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(complete, custodyLifetimeSnapshot(t, c)) {
		t.Fatal("migrated86 reopen/init changed all-stage rows or ledger")
	}
}

// Fresh composed SQL82, using the frozen old recipient constraint before the
// owned SQL83 rebuild. No historical database or archived ledger is relabeled.
// This synthetic predecessor is not the archived descriptor82 namespace; it
// must be upgraded before any new cut is frozen.
func custodyLifetimeBuildComposed82(t *testing.T, c *Client) {
	custodyLifetimeBuildComposed82DDL(t, c, custodyLifetimeOriginalRecipientDDL)
}

func custodyLifetimeBuildComposed82DDL(t *testing.T, c *Client, originalDDL string) {
	t.Helper()
	ctx := context.Background()
	// Install frozen original recipient DDL FIRST. CREATE IF NOT EXISTS in
	// schemaDDL cannot substitute the corrected constraint into this fixture.
	if err := c.execLocal(ctx, originalDDL); err != nil {
		t.Fatal(err)
	}
	for _, ddl := range schemaDDL {
		if err := c.execLocal(ctx, ddl); err != nil {
			t.Fatalf("SETUP composed82 DDL: %v", err)
		}
	}
	if err := c.execLocal(ctx, appliedMigrationsDDL); err != nil {
		t.Fatal(err)
	}
	for _, m := range schemaMigrationLedger {
		if m.Version <= 82 {
			// Fresh composed prerequisite only: published SG70/project71 and relocated SQL72..82.
			// This is not the immutable original80 ledger from tree6edc84a7.
			if err := c.execLocal(ctx, `INSERT INTO applied_migrations(id,applied_at,checksum) VALUES(?,?,?)`, m.ID, "composed82-fixture", sha256hex(m.SQL)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := c.execLocal(ctx, `INSERT OR REPLACE INTO schema_state(id,version,updated_at) VALUES(1,82,'composed82-fixture')`); err != nil {
		t.Fatal(err)
	}
}

// custodyLifetimeBuildOriginal80 reopens a fixed source-data fixture from the
// signed d2264444/tree6edc84a7 original80 boundary. It never derives its DDL,
// positional IDs or checksums from the newly composed live schema.
func custodyLifetimeBuildOriginal80(t *testing.T, c *Client) {
	t.Helper()
	raw, err := os.ReadFile("testdata/automation_original80_d2264444.json")
	if err != nil {
		t.Fatal(err)
	}
	if sha256hex(string(raw)) != "1cd79a66d04f470a9a77e35d9336e7e75923fa82665d6821cab0e2ec0fba2efb" {
		t.Fatal("frozen original80 fixture bytes changed")
	}
	var fixture struct {
		SourceCommit         string   `json:"source_commit"`
		SourceTree           string   `json:"source_tree"`
		SourceSchemaBlob     string   `json:"source_schema_blob"`
		Version              int      `json:"version"`
		DDL                  []string `json:"ddl"`
		AppliedMigrationsDDL string   `json:"applied_migrations_ddl"`
		Ledger               []struct {
			ID       string `json:"id"`
			Version  int    `json:"version"`
			SQL      string `json:"sql"`
			Checksum string `json:"checksum"`
		} `json:"ledger"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.SourceCommit != "d2264444ab949de12a5a87da2ed29c9f72a565f3" || fixture.SourceTree != "6edc84a7dc91ca1b5d9244f0735e0743bc7fc3d7" || fixture.SourceSchemaBlob != "266be870323216083d53c751a6cd198cc1487e53" || fixture.Version != 80 || len(fixture.DDL) != 186 || len(fixture.Ledger) != 196 {
		t.Fatal("original80 fixture provenance differs")
	}
	ctx := context.Background()
	for _, ddl := range fixture.DDL {
		if err := c.execLocal(ctx, ddl); err != nil {
			t.Fatal("frozen original80 DDL", err)
		}
	}
	if err := c.execLocal(ctx, fixture.AppliedMigrationsDDL); err != nil {
		t.Fatal(err)
	}
	for _, m := range fixture.Ledger {
		if m.Version > 80 || sha256hex(m.SQL) != m.Checksum {
			t.Fatal("original80 ledger fixture changed", m.ID)
		}
		if err := c.execLocal(ctx, `INSERT INTO applied_migrations(id,applied_at,checksum) VALUES(?,?,?)`, m.ID, "2026-10-18T00:00:00Z", m.Checksum); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.execLocal(ctx, `INSERT OR REPLACE INTO schema_state(id,version,updated_at) VALUES(1,80,'2026-10-18T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
}

func custodyLifetimeFileClient(t *testing.T, dir string, host ...string) *Client {
	t.Helper()
	c, err := NewLocalClient(dir, host...)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	wal, err := c.Query(ctx, `PRAGMA journal_mode`)
	if err != nil || len(wal) != 1 || wal[0].String("journal_mode") != "wal" {
		t.Fatalf("SETUP file-backed WAL required: %v", err)
	}
	full, err := c.Query(ctx, `PRAGMA synchronous`)
	if err != nil || len(full) != 1 || full[0].Int64("synchronous") != 2 {
		t.Fatalf("SETUP FULL required: %v", err)
	}
	return c
}

func custodyLifetimeInsertRecipient(t *testing.T, c *Client, stage, host string, n int64) error {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	// Storage-row fixture only: these references supply no fresh authority.
	ref := `{"sequence":1,"digest":"` + strings.Repeat("b", 64) + `"}`
	return c.execLocal(context.Background(), "INSERT INTO local_automation_key_recipients("+custodyLifetimeRecipientColumns+") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
		stage, "established-cluster", "recipient-1", int64(1), strings.Repeat("a", 64), host, n,
		"2026-10-18T00:00:00Z", "a1", "voter-database-a", "key-"+host, identity.Recipient().String(), ref, ref, ref, int64(2))
}

func TestAutomationCustodyLifetimeSchema83(t *testing.T) {
	ctx := context.Background()
	t.Run("fresh_reopen_idempotent", func(t *testing.T) {
		dir := t.TempDir()
		c := custodyLifetimeFileClient(t, dir)
		t.Cleanup(func() { _ = c.Close() })
		if err := InitSchema(ctx, c); err != nil {
			t.Fatal(err)
		}
		if err := custodyLifetimeInsertRecipient(t, c, "", "host-zero", 0); err != nil {
			t.Fatal("fresh schema rejects zero", err)
		}
		if err := custodyLifetimeInsertRecipient(t, c, "stage-positive", "host-max", 9223372036854775807); err != nil {
			t.Fatal("fresh schema rejects MaxInt64", err)
		}
		if err := custodyLifetimeInsertRecipient(t, c, "", "host-negative", -1); err == nil {
			t.Fatal("fresh schema admits negative host")
		}
		for _, column := range []string{"membership_generation", "first_sequence"} {
			if err := c.execLocal(ctx, "UPDATE local_automation_key_recipients SET "+column+"=0 WHERE host='host-zero'"); err == nil {
				t.Fatal("other positive counter relaxed", column)
			}
		}
		if corrected, err := automationCustodyRecipientShape(ctx, c); err != nil || !corrected {
			t.Fatal("fresh strict shape invalid", corrected, err)
		}
		if err := c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationVerifySemanticSchemaTx(ctx, tx) }); err != nil {
			t.Fatal("fresh semantic/index guard", err)
		}
		before := custodyLifetimeSnapshot(t, c)
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		c = custodyLifetimeFileClient(t, dir)
		for range 2 {
			if err := InitSchema(ctx, c); err != nil {
				t.Fatal(err)
			}
		}
		if storedVersion(t, c) != 86 || countAppliedID(t, c, automationCustodyMigrationID) != 1 || !reflect.DeepEqual(before, custodyLifetimeSnapshot(t, c)) {
			t.Fatal("fresh86 reopen/init changed schema, rows or ledger")
		}
	})
	for _, tc := range []struct {
		name, ddl, mutation string
	}{
		{"extra_column", custodyLifetimeOriginalRecipientDDL, `ALTER TABLE local_automation_key_recipients ADD COLUMN unexpected TEXT`},
		{"wrong_pk", strings.Replace(custodyLifetimeOriginalRecipientDDL, "PRIMARY KEY(stage,cluster_uid,recipient_epoch,host)", "PRIMARY KEY(stage,cluster_uid,host,recipient_epoch)", 1), ""},
		{"wrong_check", strings.Replace(custodyLifetimeOriginalRecipientDDL, "CHECK(host_incarnation>0)", "CHECK(host_incarnation>=-1)", 1), ""},
		{"missing_index", custodyLifetimeOriginalRecipientDDL, `DROP INDEX automation_key_id`},
		{"extra_index", custodyLifetimeOriginalRecipientDDL, `CREATE INDEX unexpected_recipient_index ON local_automation_key_recipients(host)`},
		{"wrong_index", custodyLifetimeOriginalRecipientDDL, `DROP INDEX automation_key_id; CREATE UNIQUE INDEX automation_key_id ON local_automation_key_recipients(stage,cluster_uid,host)`},
		{"trigger", custodyLifetimeOriginalRecipientDDL, `CREATE TRIGGER unexpected_recipient_trigger AFTER INSERT ON local_automation_key_recipients BEGIN SELECT 1; END`},
		{"occupied_replacement", custodyLifetimeOriginalRecipientDDL, `CREATE TABLE local_automation_key_recipients__schema81(evidence TEXT)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := custodyLifetimeFileClient(t, t.TempDir())
			t.Cleanup(func() { _ = c.Close() })
			custodyLifetimeBuildComposed82DDL(t, c, tc.ddl)
			if err := custodyLifetimeInsertRecipient(t, c, "audit-preserve", "positive", 17); err != nil {
				t.Fatal(err)
			}
			if tc.mutation != "" {
				if err := c.execLocal(ctx, tc.mutation); err != nil {
					t.Fatal(err)
				}
			}
			before := custodyLifetimeSnapshot(t, c)
			if err := InitSchema(ctx, c); err == nil || !strings.Contains(err.Error(), "custody") {
				t.Fatal("unsupported shape did not fail custody preflight", err)
			}
			custodyLifetimeAssertRollback(t, c, before)
		})
	}
	t.Run("copy_failure", func(t *testing.T) {
		c := custodyLifetimeFileClient(t, t.TempDir())
		t.Cleanup(func() { _ = c.Close() })
		custodyLifetimeBuildComposed82(t, c)
		custodyLifetimePrimeUnrelatedTargetLedger(t, c)
		if err := custodyLifetimeInsertRecipient(t, c, "active-positive", "positive", 17); err != nil {
			t.Fatal(err)
		}
		conn, err := c.db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// Corrupt negative fixture only. The connection-scoped bypass is OFF
		// before the real migration; this row is never a valid-history positive.
		for _, sql := range []string{
			`PRAGMA ignore_check_constraints=ON`,
			`INSERT INTO local_automation_key_recipients SELECT stage||'-bad',cluster_uid,recipient_epoch,membership_generation,config_digest,host,-1,admitted_at,admission_serial,voter_incarnation,key_id,recipient,enrollment_ref,recipient_ack_ref,equality_ack_ref,first_sequence FROM local_automation_key_recipients`,
			`PRAGMA ignore_check_constraints=OFF`,
		} {
			if _, err := conn.ExecContext(ctx, sql); err != nil {
				_ = conn.Close()
				t.Fatal(err)
			}
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		before := custodyLifetimeSnapshot(t, c)
		if err := InitSchema(ctx, c); err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
			t.Fatal("copy failure did not reach replacement CHECK", err)
		}
		custodyLifetimeAssertRollback(t, c, before)
	})
	t.Run("ledger_failure_after_rebuild", func(t *testing.T) {
		c := custodyLifetimeFileClient(t, t.TempDir())
		t.Cleanup(func() { _ = c.Close() })
		custodyLifetimeBuildComposed82(t, c)
		custodyLifetimePrimeUnrelatedTargetLedger(t, c)
		if err := custodyLifetimeInsertRecipient(t, c, "audit-preserve", "positive", 17); err != nil {
			t.Fatal(err)
		}
		if err := c.execLocal(ctx, `CREATE TRIGGER custody_reject_ledger BEFORE INSERT ON applied_migrations WHEN NEW.id='r_automation_key_recipients_host_zero' BEGIN SELECT RAISE(ABORT,'custody-ledger-injected'); END`); err != nil {
			t.Fatal(err)
		}
		before := custodyLifetimeSnapshot(t, c)
		if err := InitSchema(ctx, c); err == nil || !strings.Contains(err.Error(), "custody-ledger-injected") {
			t.Fatal("ledger failure did not follow rebuilt table/indexes", err)
		}
		custodyLifetimeAssertRollback(t, c, before)
	})
}

// These synthetic recipient-rebuild fixtures already install ALL current DDL,
// including the two84 target tables, SQL85 token stamp and four86 execution
// tables. Pre-record
// precisely these already-present unrelated units so rollback isolates the
// custody transaction, not InitSchema's earlier independent mark-only work.
// The database remains an explicitly synthetic SQL82 fixture, never an archive.
func custodyLifetimePrimeUnrelatedTargetLedger(t *testing.T, c *Client) {
	t.Helper()
	seen, stampUnits, executionUnits := 0, 0, 0
	executionTargets := map[string]string{
		"t_local_automation_executors":           "local_automation_executors",
		"t_local_automation_execution_progress":  "local_automation_execution_progress",
		"t_local_automation_execution_artifacts": "local_automation_execution_artifacts",
		"t_local_automation_execution_terminals": "local_automation_execution_terminals",
	}
	for _, m := range schemaMigrationLedger {
		executionTarget, execution := executionTargets[m.ID]
		if m.ID != "t_local_automation_target_operations" && m.ID != "t_local_automation_target_reservations" && m.ID != "a094_tokens_user_created_at" && !execution {
			continue
		}
		if m.ID == "a094_tokens_user_created_at" {
			stampUnits++
			if m.Version != 85 || m.Kind != kindAddColumn || m.Target != "tokens.user_created_at" || m.SQL != "ALTER TABLE tokens ADD COLUMN user_created_at TEXT NOT NULL DEFAULT ''" {
				t.Fatal("unexpected token stamp prerequisite unit", m)
			}
		} else if execution {
			executionUnits++
			if m.Version != 86 || m.Kind != kindCreateTable || m.Target != executionTarget || m.SQL != "" {
				t.Fatal("unexpected execution prerequisite unit", m)
			}
		} else {
			target := map[string]string{"t_local_automation_target_operations": "local_automation_target_operations", "t_local_automation_target_reservations": "local_automation_target_reservations"}[m.ID]
			if m.Version != 84 || m.Kind != kindCreateTable || m.Target != target || m.SQL != "" {
				t.Fatal("unexpected target prerequisite unit", m)
			}
		}
		present, err := m.present(context.Background(), c)
		if err != nil || !present {
			t.Fatal("unrelated prerequisite DDL missing", m.ID, err)
		}
		if err := c.execLocal(context.Background(), `INSERT INTO applied_migrations(id,applied_at,checksum) VALUES(?,?,?)`, m.ID, "synthetic-custody-isolation", sha256hex(m.SQL)); err != nil {
			t.Fatal(err)
		}
		seen++
	}
	if seen != 7 || stampUnits != 1 || executionUnits != 4 {
		t.Fatal("expected exactly two target units, one token stamp and four execution prerequisites", seen, stampUnits, executionUnits)
	}
}

func custodyLifetimeSnapshot(t *testing.T, c *Client) map[string][]Row {
	t.Helper()
	queries := map[string]string{"schema": `SELECT type,name,tbl_name,sql FROM sqlite_master WHERE tbl_name='local_automation_key_recipients' OR name='local_automation_key_recipients__schema81' ORDER BY type,name`, "rows": `SELECT * FROM local_automation_key_recipients ORDER BY stage,host`, "ledger": `SELECT id,applied_at,checksum FROM applied_migrations ORDER BY id`}
	out := map[string][]Row{}
	for name, query := range queries {
		rows, err := c.Query(context.Background(), query)
		if err != nil {
			t.Fatal(err)
		}
		out[name] = rows
	}
	return out
}

func custodyLifetimeAssertRollback(t *testing.T, c *Client, before map[string][]Row) {
	t.Helper()
	if storedVersion(t, c) != 82 || countAppliedID(t, c, automationCustodyMigrationID) != 0 || !reflect.DeepEqual(before, custodyLifetimeSnapshot(t, c)) {
		t.Fatal("failed recipient migration changed old schema/data/ledger")
	}
}
