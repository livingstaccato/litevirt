package main

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The credentials split absorbs a secret that a node which has not latched
// credentials_split_v1 wrote to the old column alone (corrosion
// absorbUnlatchedSecretWrite). It recognises those writes by PARSING the
// statement (secretWriteOf). A writer in a form the parser does not read would
// skip the absorb silently, and a latched reader would serve the value from
// before it. So every registered statement shape that writes a secret column
// must be one the parser reads, with the right bindings.
//
// The oracle is SQLite itself, not a second parser: each shape is executed
// against a scratch copy of the real schema with a distinct marker bound to
// every placeholder, and the markers that land in the secret column, the key
// column and updated_at are what corrosion.SecretWrite must report.

// secretColumns are the three secret columns and each parent's primary key.
var secretColumns = []struct{ table, pk, column string }{
	{"hosts", "name", "ipmi_pass"},
	{"users", "username", "password_hash"},
	{"tokens", "id", "token_hash"},
}

// extraSecretShapes is empty. A mutation check adds a shape here to prove the
// guard reports one the parser cannot read.
var extraSecretShapes []string

// ledgerShapeSQL maps every fingerprint in the generated and historical
// ledger files to a SQL text that produces it: the current tree's builders for
// the generated ledger, corrosion.HistoricalShapes for the historical one. A
// fingerprint with no SQL fails the test, so the walk covers the ledgers
// completely rather than whatever is easy to reach.
func ledgerShapeSQL(t *testing.T) map[string]string {
	t.Helper()
	_, findings, err := scanTree(repoRoot)
	if err != nil {
		t.Fatalf("scan tree: %v", err)
	}
	bySQL := map[string]string{}
	for _, f := range findings {
		if f.fp != "" && f.sql != "" {
			bySQL[f.fp] = f.sql
		}
	}
	for _, hs := range corrosion.HistoricalShapes() {
		le, err := corrosion.LedgerEntryFor(hs.SQL)
		if err != nil {
			t.Fatalf("derive historical %q: %v", hs.SQL, err)
		}
		bySQL[le.Fingerprint] = hs.SQL
	}
	out := map[string]string{}
	for _, file := range []struct{ path, v string }{
		{"stmtledger_generated.go", "stmtLedger"},
		{"stmtledger_historical.go", "historicalLedger"},
	} {
		for fp := range ledgerFileKeys(t, filepath.Join(repoRoot, "internal", "corrosion", file.path), file.v) {
			sqlText, ok := bySQL[fp]
			if !ok {
				t.Errorf("%s: %s has no SQL in the tree or HistoricalShapes; the secret-write guard "+
					"cannot check it", file.path, fp)
				continue
			}
			out[fp] = sqlText
		}
	}
	for i, s := range extraSecretShapes {
		out[fmt.Sprintf("extra-%d", i)] = s
	}
	return out
}

// namesSecretColumn reports which secret column an INSERT or UPDATE writes,
// by the column list or SET clause, independently of corrosion's parser.
func namesSecretColumn(sqlText string) (table, pk, column string, ok bool) {
	norm := strings.Join(strings.Fields(sqlText), " ")
	for _, sc := range secretColumns {
		insert := regexp.MustCompile(`(?i)^INSERT (OR \w+ )?INTO ` + sc.table + ` ?\(([^)]*)\)`)
		if m := insert.FindStringSubmatch(norm); m != nil {
			for _, c := range strings.Split(m[2], ",") {
				if strings.TrimSpace(c) == sc.column {
					return sc.table, sc.pk, sc.column, true
				}
			}
		}
		update := regexp.MustCompile(`(?i)^UPDATE ` + sc.table + ` SET (.*?) WHERE `)
		if m := update.FindStringSubmatch(norm); m != nil &&
			regexp.MustCompile(`(^|[ ,])`+sc.column+` =`).MatchString(m[1]) {
			return sc.table, sc.pk, sc.column, true
		}
	}
	return "", "", "", false
}

// seedRow is a parent row every NOT NULL column of which is set, keyed on key.
func seedRow(table, key string) (string, []interface{}) {
	switch table {
	case "hosts":
		return `INSERT INTO hosts (name, address, ssh_user, cert_serial, ipmi_pass, created_at, updated_at)
			VALUES (?, 'a', 'u', 'c', 'seed', 'seed', 'seed')`, []interface{}{key}
	case "users":
		return `INSERT INTO users (username, role, password_hash, created_at, updated_at)
			VALUES (?, 'r', 'seed', 'seed', 'seed')`, []interface{}{key}
	default:
		return `INSERT INTO tokens (id, username, name, token_hash, created_at, updated_at)
			VALUES (?, 'u', 'n', 'seed', 'seed', 'seed')`, []interface{}{key}
	}
}

// landedMarkers executes sqlText with marker params inside a transaction it
// rolls back, and reports which markers SQLite put in the key column, the
// secret column and updated_at of the row it wrote.
func landedMarkers(db *sql.DB, sqlText, table, pk, column string, markers []interface{}) (key, value, ts string, err error) {
	tx, err := db.Begin()
	if err != nil {
		return "", "", "", err
	}
	defer func() { _ = tx.Rollback() }()
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(sqlText)), "UPDATE") {
		// One seeded row per marker, so the WHERE matches whichever marker the
		// key is bound to.
		for _, m := range markers {
			q, args := seedRow(table, m.(string))
			if _, err := tx.Exec(q, args...); err != nil {
				return "", "", "", fmt.Errorf("seed %s: %w", table, err)
			}
		}
	}
	if _, err := tx.Exec(sqlText, markers...); err != nil {
		return "", "", "", fmt.Errorf("exec with markers: %w", err)
	}
	row := tx.QueryRow(`SELECT ` + pk + `, ` + column + `, updated_at FROM ` + table + ` WHERE ` + column + ` != 'seed'`)
	if err := row.Scan(&key, &value, &ts); err != nil {
		return "", "", "", fmt.Errorf("read back the written row: %w", err)
	}
	return key, value, ts, nil
}

func TestEverySecretWriteShapeIsOneTheAbsorbReads(t *testing.T) {
	shapes := ledgerShapeSQL(t)
	c := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(context.Background(), c); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	db := c.DB()
	fps := make([]string, 0, len(shapes))
	for fp := range shapes {
		fps = append(fps, fp)
	}
	sort.Strings(fps)

	checked := 0
	for _, fp := range fps {
		sqlText := shapes[fp]
		table, pk, column, ok := namesSecretColumn(sqlText)
		if !ok {
			continue
		}
		checked++
		n := strings.Count(sqlText, "?")
		markers := make([]interface{}, n)
		for i := range markers {
			markers[i] = fmt.Sprintf("m%02d", i)
		}
		wantKey, wantVal, wantTS, err := landedMarkers(db, sqlText, table, pk, column, markers)
		if err != nil {
			t.Errorf("%s writes %s.%s but could not be executed as an oracle (%v):\n%s", fp, table, column, err, sqlText)
			continue
		}
		gotTable, gotKey, gotVal, gotTS, ok := corrosion.SecretWrite(corrosion.Statement{SQL: sqlText, Params: markers})
		if !ok {
			t.Errorf("%s writes %s.%s but corrosion.SecretWrite does not recognise it — a node that has "+
				"not latched credentials_split_v1 writing in this shape would never be absorbed:\n%s",
				fp, table, column, sqlText)
			continue
		}
		if gotTable != table || gotKey != wantKey || gotVal != wantVal || gotTS != wantTS {
			t.Errorf("%s: SecretWrite = (table %s, key %s, value %s, updated_at %s), SQLite wrote "+
				"(table %s, key %s, value %s, updated_at %s):\n%s",
				fp, gotTable, gotKey, gotVal, gotTS, table, wantKey, wantVal, wantTS, sqlText)
		}
	}
	// hosts/users/tokens each have several secret-writing shapes; fewer than
	// this means the walk found nothing, not that nothing needs checking.
	if checked < 10 {
		t.Fatalf("checked only %d secret-writing shapes; the ledger walk is broken", checked)
	}
	t.Logf("checked %d secret-writing shapes", checked)
}
