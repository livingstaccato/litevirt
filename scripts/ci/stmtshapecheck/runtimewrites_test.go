package main

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The host runtime split absorbs a report that a node not yet writing
// host_runtime made to hosts' runtime columns alone (corrosion
// absorbUnlatchedRuntimeWrite). It recognises those writes by PARSING the
// statement, so a writer in a form the parser does not read would skip the
// absorb silently, and a latched reader would go on serving the version or
// totals from before it. So every registered statement shape that writes
// hosts.version, schema_version, cpu_total, mem_total, disk_total or
// capacity_policy_hash must be one the parser reads, with the right host,
// updated_at and values. The oracle is SQLite, as in membershipwrites_test.go.

// extraRuntimeShapes is empty. A mutation check adds a shape here to prove the
// guard reports one the parser cannot read.
var extraRuntimeShapes []string

var hostsRuntimeColumns = []string{"version", "schema_version", "cpu_total", "mem_total", "disk_total", "capacity_policy_hash"}

// runtimeColumnsWritten reports which runtime columns an INSERT or UPDATE on
// hosts names, by its column list or SET clause, independently of corrosion's
// parser.
func runtimeColumnsWritten(sqlText string) map[string]bool {
	norm := strings.Join(strings.Fields(sqlText), " ")
	var cols []string
	if m := regexp.MustCompile(`(?i)^INSERT (OR \w+ )?INTO hosts ?\(([^)]*)\)`).FindStringSubmatch(norm); m != nil {
		for _, c := range strings.Split(m[2], ",") {
			cols = append(cols, strings.TrimSpace(c))
		}
	} else if m := regexp.MustCompile(`(?i)^UPDATE hosts SET (.*?) WHERE `).FindStringSubmatch(norm); m != nil {
		for _, a := range regexp.MustCompile(`(?:^|, )([a-z_]+) =`).FindAllStringSubmatch(m[1], -1) {
			cols = append(cols, a[1])
		}
	}
	out := map[string]bool{}
	for _, c := range cols {
		for _, rc := range hostsRuntimeColumns {
			if c == rc {
				out[c] = true
			}
		}
	}
	return out
}

type landedRuntime struct {
	name, ts string
	vals     map[string]string // column -> value as text, "<nil>" for NULL
}

// landedRuntimeRow runs sqlText with markers in a transaction it rolls back,
// seeding one hosts row per marker for an UPDATE (live, then tombstoned), and
// reports the row the statement wrote.
func landedRuntimeRow(db *sql.DB, sqlText string, markers []interface{}) (landedRuntime, error) {
	isUpdate := strings.HasPrefix(strings.ToUpper(strings.TrimSpace(sqlText)), "UPDATE")
	seedings := []bool{false}
	if isUpdate {
		seedings = append(seedings, true)
	}
	var lastErr error
	for _, deleted := range seedings {
		row, n, err := func() (landedRuntime, int64, error) {
			tx, err := db.Begin()
			if err != nil {
				return landedRuntime{}, 0, err
			}
			defer func() { _ = tx.Rollback() }()
			if isUpdate {
				for _, m := range markers {
					var del interface{}
					if deleted {
						del = "gone"
					}
					if _, err := tx.Exec(`INSERT INTO hosts (name, address, ssh_user, cert_serial, state,
						version, created_at, updated_at, deleted_at)
						VALUES (?, 'a', 'u', 'seed', 'seed', 'seed', 'seed', 'seed', ?)`, fmt.Sprint(m), del); err != nil {
						return landedRuntime{}, 0, fmt.Errorf("seed hosts: %w", err)
					}
				}
			}
			res, err := tx.Exec(sqlText, markers...)
			if err != nil {
				return landedRuntime{}, 0, fmt.Errorf("exec with markers: %w", err)
			}
			n, _ := res.RowsAffected()
			if n != 1 {
				return landedRuntime{}, n, nil
			}
			r := landedRuntime{vals: map[string]string{}}
			var v, s, cpu, mem, disk, ph sql.NullString
			if err := tx.QueryRow(`SELECT name, updated_at, CAST(version AS TEXT), CAST(schema_version AS TEXT),
				CAST(cpu_total AS TEXT), CAST(mem_total AS TEXT), CAST(disk_total AS TEXT), CAST(capacity_policy_hash AS TEXT)
				FROM hosts WHERE updated_at != 'seed'`).Scan(&r.name, &r.ts, &v, &s, &cpu, &mem, &disk, &ph); err != nil {
				return landedRuntime{}, 1, err
			}
			for col, x := range map[string]sql.NullString{"version": v, "schema_version": s, "cpu_total": cpu,
				"mem_total": mem, "disk_total": disk, "capacity_policy_hash": ph} {
				if x.Valid {
					r.vals[col] = x.String
				} else {
					r.vals[col] = "<nil>"
				}
			}
			return r, 1, nil
		}()
		if err != nil {
			lastErr = err
			continue
		}
		if n == 1 {
			return row, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no seeding made the statement change exactly one row")
	}
	return landedRuntime{}, lastErr
}

func runtimeValueText(v interface{}) string {
	if v == nil {
		return "<nil>"
	}
	return fmt.Sprint(v)
}

func TestEveryRuntimeWriteShapeIsOneTheAbsorbReads(t *testing.T) {
	shapes := ledgerShapeSQL(t)
	for i, s := range extraRuntimeShapes {
		shapes[fmt.Sprintf("extra-runtime-%d", i)] = s
	}
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
		want := runtimeColumnsWritten(sqlText)
		if len(want) == 0 {
			continue
		}
		checked++
		markers := make([]interface{}, strings.Count(sqlText, "?"))
		for i := range markers {
			markers[i] = int64(1000 + i)
		}
		landed, err := landedRuntimeRow(db, sqlText, markers)
		if err != nil {
			t.Errorf("%s writes a hosts runtime column but could not be executed as an oracle (%v):\n%s", fp, err, sqlText)
			continue
		}
		host, ts, cols, ok := corrosion.RuntimeWrite(corrosion.Statement{SQL: sqlText, Params: markers})
		if !ok {
			t.Errorf("%s writes a hosts runtime column but corrosion.RuntimeWrite does not recognise it — "+
				"a node not yet writing host_runtime that wrote in this shape would never be absorbed:\n%s", fp, sqlText)
			continue
		}
		if host != landed.name || ts != landed.ts {
			t.Errorf("%s: RuntimeWrite host %s updated_at %s, SQLite wrote host %s updated_at %s:\n%s",
				fp, host, ts, landed.name, landed.ts, sqlText)
		}
		for col := range want {
			got, has := cols[col]
			if !has {
				t.Errorf("%s: RuntimeWrite leaves %s out, SQLite wrote %s:\n%s", fp, col, landed.vals[col], sqlText)
				continue
			}
			if runtimeValueText(got) != landed.vals[col] {
				t.Errorf("%s: RuntimeWrite %s = %s, SQLite wrote %s:\n%s", fp, col, runtimeValueText(got), landed.vals[col], sqlText)
			}
		}
		for col := range cols {
			if !want[col] {
				t.Errorf("%s: RuntimeWrite reports %s, which the statement does not write:\n%s", fp, col, sqlText)
			}
		}
	}
	// InsertHost, the boot reports, the version and resource reports, current
	// and historical; fewer means the walk is broken.
	if checked < 5 {
		t.Fatalf("checked only %d runtime-writing shapes; the ledger walk is broken", checked)
	}
	t.Logf("checked %d runtime-writing shapes", checked)
}
