package corrosion

import (
	"context"
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
	custodyLifetimeBuildOriginal80(t, c)
	for _, stage := range []string{"", "audit-a", "audit-b"} {
		if err := custodyLifetimeInsertRecipient(t, c, stage, "positive-control", 17); err != nil {
			t.Fatalf("SETUP original80 positive insertion %q: %v", stage, err)
		}
	}
	if err := custodyLifetimeInsertRecipient(t, c, "", "old-host-zero", 0); err == nil || !strings.Contains(err.Error(), "host_incarnation>0") {
		t.Fatalf("SETUP original80 did not enforce genuine old CHECK: %v", err)
	}
	before, err := c.Query(ctx, "SELECT "+custodyLifetimeRecipientColumns+" FROM local_automation_key_recipients ORDER BY stage,host")
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := c.Query(ctx, `SELECT id,applied_at,checksum FROM applied_migrations ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	if storedVersion(t, c) != 80 {
		t.Fatal("SETUP original80 stamp missing")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	c = custodyLifetimeFileClient(t, dir)
	if storedVersion(t, c) != 80 {
		t.Fatal("SETUP original80 did not persist")
	}
	// First and only InitSchema call for this established old baseline.
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("ORIGINAL80_UPGRADE_REFUSED: %v", err)
	}
	after, err := c.Query(ctx, "SELECT "+custodyLifetimeRecipientColumns+" FROM local_automation_key_recipients ORDER BY stage,host")
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("ORIGINAL80_RECIPIENT_BYTES_OR_STAGES_CHANGED: %v", err)
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
		t.Fatal("ORIGINAL80_LEDGER_BYTES_CHANGED")
	}
	if err := custodyLifetimeInsertRecipient(t, c, "audit-a", "new-host-zero", 0); err != nil {
		t.Fatalf("ORIGINAL80_UPGRADE_N0_REFUSED: %v", err)
	}
	if storedVersion(t, c) != 81 || appliedCount(t, c) != len(ledger)+1 || countAppliedID(t, c, automationCustodyMigrationID) != 1 {
		t.Fatal("original80 upgrade did not append exactly one schema81 unit")
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
		t.Fatal("migrated81 reopen/init changed all-stage rows or ledger")
	}
}

func custodyLifetimeBuildOriginal80(t *testing.T, c *Client) {
	custodyLifetimeBuildOriginal80DDL(t, c, custodyLifetimeOriginalRecipientDDL)
}

func custodyLifetimeBuildOriginal80DDL(t *testing.T, c *Client, originalDDL string) {
	t.Helper()
	ctx := context.Background()
	// Install frozen original recipient DDL FIRST. CREATE IF NOT EXISTS in
	// schemaDDL cannot substitute the corrected constraint into this fixture.
	if err := c.execLocal(ctx, originalDDL); err != nil {
		t.Fatal(err)
	}
	for _, ddl := range schemaDDL {
		if err := c.execLocal(ctx, ddl); err != nil {
			t.Fatalf("SETUP original80 DDL: %v", err)
		}
	}
	if err := c.execLocal(ctx, appliedMigrationsDDL); err != nil {
		t.Fatal(err)
	}
	for _, m := range schemaMigrationLedger {
		if m.Version <= 80 {
			// All old units/SQL/checksums remain immutable from tree6edc.
			if err := c.execLocal(ctx, `INSERT INTO applied_migrations(id,applied_at,checksum) VALUES(?,?,?)`, m.ID, "2026-10-18T00:00:00Z", sha256hex(m.SQL)); err != nil {
				t.Fatal(err)
			}
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

func TestAutomationCustodyLifetimeSchema81(t *testing.T) {
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
		if storedVersion(t, c) != 81 || countAppliedID(t, c, automationCustodyMigrationID) != 1 || !reflect.DeepEqual(before, custodyLifetimeSnapshot(t, c)) {
			t.Fatal("fresh81 reopen/init changed schema, rows or ledger")
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
			custodyLifetimeBuildOriginal80DDL(t, c, tc.ddl)
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
		custodyLifetimeBuildOriginal80(t, c)
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
		custodyLifetimeBuildOriginal80(t, c)
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
	if storedVersion(t, c) != 80 || countAppliedID(t, c, automationCustodyMigrationID) != 0 || !reflect.DeepEqual(before, custodyLifetimeSnapshot(t, c)) {
		t.Fatal("failed recipient migration changed old schema/data/ledger")
	}
}
