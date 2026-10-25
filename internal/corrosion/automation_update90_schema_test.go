package corrosion

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const update90LedgerID = "i_automation_admission_resource_desired"

func update90Ledger(t *testing.T, c *Client) []Row {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT id,checksum,applied_at FROM applied_migrations ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// Removing the real index ledger unit must fail derivedSchemaVersion and the
// actual ledger/checksum assertions even when a version constant says90.
func TestAutomationUpdate90RequiredIndexLedger(t *testing.T) {
	c := NewTestClientT(t)
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	if CurrentSchemaVersion != 91 || storedVersion(t, c) != 91 || derivedSchemaVersion(ctx, c) != 91 {
		t.Fatalf("real required-index migration did not establish90: code=%d stored=%d derived=%d", CurrentSchemaVersion, storedVersion(t, c), derivedSchemaVersion(ctx, c))
	}
	units := 0
	for _, m := range schemaMigrationLedger {
		if m.Version != 90 {
			continue
		}
		units++
		if m.ID != update90LedgerID || m.Target != "automation_admission_resource_desired" || m.SQL != automationUpdateIndexSQL {
			t.Fatalf("wrong required-index ledger identity: %+v", m)
		}
	}
	rows, err := c.Query(ctx, `SELECT checksum FROM applied_migrations WHERE id=?`, update90LedgerID)
	if units != 1 || err != nil || len(rows) != 1 || rows[0].String("checksum") != sha256hex(automationUpdateIndexSQL) {
		t.Fatal("required-index unit not durably recorded by exact SQL", units, rows, err)
	}
	if err := c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationVerifyUpdateIndexesTx(ctx, tx) }); err != nil {
		t.Fatal("actual required index/partial predicate/scoped seek", err)
	}
	before := update90Ledger(t, c)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal("idempotent90 init", err)
	}
	if !reflect.DeepEqual(before, update90Ledger(t, c)) {
		t.Fatal("idempotent90 init rewrote migration receipts")
	}
}

func TestAutomationUpdate90RechecksAlreadyLedgeredIndex(t *testing.T) {
	for _, wrong := range []string{"missing", "predicate", "predicate-case", "predicate-space", "order", "unique"} {
		t.Run(wrong, func(t *testing.T) {
			c := NewTestClientT(t)
			ctx := context.Background()
			if err := InitSchema(ctx, c); err != nil {
				t.Fatal(err)
			}
			before := update90Ledger(t, c)
			if _, err := c.db.ExecContext(ctx, `DROP INDEX automation_admission_resource_desired`); err != nil {
				t.Fatal("negative corruption setup", err)
			}
			statement := automationUpdateIndexSQL
			switch wrong {
			case "predicate":
				statement = strings.Replace(statement, "('admit_create','admit_update')", "('admit_create')", 1)
			case "predicate-case":
				statement = strings.ReplaceAll(strings.ReplaceAll(statement, "admit_create", "ADMIT_CREATE"), "admit_update", "ADMIT_UPDATE")
			case "predicate-space":
				statement = strings.Replace(statement, "'admit_create'", "'admit_ create'", 1)
			case "order":
				statement = strings.Replace(statement, "sequence DESC", "sequence ASC", 1)
			case "unique":
				statement = strings.Replace(statement, "CREATE INDEX", "CREATE UNIQUE INDEX", 1)
			}
			if wrong != "missing" {
				if _, err := c.db.ExecContext(ctx, statement); err != nil {
					t.Fatal("negative malformed index setup", err)
				}
			}
			err := InitSchema(ctx, c)
			if wrong == "missing" {
				if err != nil {
					t.Fatal("missing required index was not safely recreated", err)
				}
				if err := c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationVerifyUpdateIndexesTx(ctx, tx) }); err != nil {
					t.Fatal(err)
				}
			} else {
				if err == nil {
					t.Fatal("already-ledgered malformed required index silently accepted")
				}
				rows, queryErr := c.Query(ctx, `SELECT sql FROM sqlite_master WHERE type='index' AND name='automation_admission_resource_desired'`)
				if queryErr != nil || len(rows) != 1 || rows[0].String("sql") != statement {
					t.Fatal("refusal dropped/replaced malformed index", rows, queryErr)
				}
			}
			if !reflect.DeepEqual(before, update90Ledger(t, c)) {
				t.Fatal("reopen rewrote previously applied ledger")
			}
		})
	}
}

func TestAutomationUpdate90WrongIndexCannotStampFirstUpgrade(t *testing.T) {
	for _, mode := range []string{"order", "predicate-case", "predicate-space"} {
		t.Run(mode, func(t *testing.T) {
			c := NewTestClientT(t)
			ctx := context.Background()
			// Install only the original admissions table and a wrong same-name index.
			// No schema version or migration receipt is fabricated for this refusal.
			found := false
			for _, ddl := range schemaDDL {
				if strings.Contains(ddl, "CREATE TABLE IF NOT EXISTS local_automation_admissions (") {
					if _, err := c.db.ExecContext(ctx, ddl); err != nil {
						t.Fatal(err)
					}
					found = true
				}
			}
			if !found {
				t.Fatal("admissions DDL fixture not found")
			}
			wrong := strings.Replace(automationUpdateIndexSQL, "sequence DESC", "sequence ASC", 1)
			if mode == "predicate-case" {
				wrong = strings.ReplaceAll(strings.ReplaceAll(automationUpdateIndexSQL, "admit_create", "ADMIT_CREATE"), "admit_update", "ADMIT_UPDATE")
			}
			if mode == "predicate-space" {
				wrong = strings.Replace(automationUpdateIndexSQL, "'admit_create'", "'admit_ create'", 1)
			}
			if _, err := c.db.ExecContext(ctx, wrong); err != nil {
				t.Fatal(err)
			}
			if err := InitSchema(ctx, c); err == nil {
				t.Fatal("malformed required index silently stamped first upgrade")
			}
			for _, query := range []string{`SELECT count(*) AS n FROM applied_migrations WHERE id='i_automation_admission_resource_desired'`, `SELECT count(*) AS n FROM schema_state WHERE version>=90`} {
				rows, err := c.Query(ctx, query)
				if err != nil || len(rows) != 1 || rows[0].Int64("n") != 0 {
					t.Fatal("failed required-index step established90", query, rows, err)
				}
			}
			rows, err := c.Query(ctx, `SELECT sql FROM sqlite_master WHERE type='index' AND name='automation_admission_resource_desired'`)
			if err != nil || len(rows) != 1 || rows[0].String("sql") != wrong {
				t.Fatal(fmt.Sprintf("wrong index changed on refusal: %v %v", rows, err))
			}
		})
	}
}

func TestAutomationUpdate90IndexAndReceiptRollbackTogether(t *testing.T) {
	c := NewTestClientT(t)
	ctx := context.Background()
	if _, err := c.db.ExecContext(ctx, appliedMigrationsDDL); err != nil {
		t.Fatal(err)
	}
	// A real SQLite failure after CREATE INDEX, at the new receipt write, must
	// roll the index back with that receipt. This trigger is test corruption.
	if _, err := c.db.ExecContext(ctx, `CREATE TRIGGER update90_abort_receipt BEFORE INSERT ON applied_migrations WHEN NEW.id='i_automation_admission_resource_desired' BEGIN SELECT RAISE(ABORT,'required-index receipt fault'); END`); err != nil {
		t.Fatal(err)
	}
	if err := InitSchema(ctx, c); err == nil || !strings.Contains(err.Error(), "required-index receipt fault") {
		t.Fatal("required-index receipt fault did not abort actual migration", err)
	}
	for _, query := range []string{`SELECT count(*) AS n FROM sqlite_master WHERE type='index' AND name='automation_admission_resource_desired'`, `SELECT count(*) AS n FROM applied_migrations WHERE id='i_automation_admission_resource_desired'`, `SELECT count(*) AS n FROM schema_state WHERE version>=90`} {
		rows, err := c.Query(ctx, query)
		if err != nil || len(rows) != 1 || rows[0].Int64("n") != 0 {
			t.Fatal("failed atomic index migration left index/receipt/version90", query, rows, err)
		}
	}
}
