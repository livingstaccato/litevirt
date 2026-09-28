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

// The host membership split absorbs a write that a node not yet writing
// host_membership made to hosts' state or isolation columns alone (corrosion
// absorbUnlatchedMembershipWrite). It recognises those writes by PARSING the
// statement. A writer in a form the parser does not read would skip the absorb
// silently, and a latched reader would go on serving the state from before it
// — a fence that never shows. So every registered statement shape that writes
// hosts.state, hosts.isolation_epoch or hosts.isolation_reason must be one the
// parser reads, with the right host, updated_at and values.
//
// The oracle is SQLite itself, as in secretwrites_test.go: each shape is run
// against a scratch copy of the real schema with a distinct integer marker
// bound to every placeholder, and what lands in the hosts row is what
// corrosion.MembershipWrite must report.

// extraMembershipShapes is empty. A mutation check adds a shape here to prove
// the guard reports one the parser cannot read.
var extraMembershipShapes []string

// membershipColumnsWritten reports which membership column groups an INSERT
// or UPDATE on hosts writes, by its column list or SET clause, independently
// of corrosion's parser.
func membershipColumnsWritten(sqlText string) (state, iso bool) {
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
	for _, c := range cols {
		switch c {
		case "state":
			state = true
		case "isolation_epoch", "isolation_reason":
			iso = true
		}
	}
	return state, iso
}

type hostsRow struct {
	name, state, reason, ts string
	epoch                   int64
}

// landedHostsRow runs sqlText with markers in a transaction it rolls back. For
// an UPDATE it first seeds one hosts row per marker (named by it), in each of
// the states a guard might require — live, tombstoned, and at each marker's
// isolation epoch — and uses the first seeding under which exactly one row
// changed. It reports the row the statement wrote.
func landedHostsRow(db *sql.DB, sqlText string, markers []interface{}) (hostsRow, error) {
	isUpdate := strings.HasPrefix(strings.ToUpper(strings.TrimSpace(sqlText)), "UPDATE")
	type seeding struct {
		deleted bool
		epoch   interface{}
	}
	seedings := []seeding{{}}
	if isUpdate {
		seedings = append(seedings, seeding{deleted: true})
		for _, m := range markers {
			seedings = append(seedings, seeding{epoch: m})
		}
	}
	var lastErr error
	for _, sd := range seedings {
		row, n, err := func() (hostsRow, int64, error) {
			tx, err := db.Begin()
			if err != nil {
				return hostsRow{}, 0, err
			}
			defer func() { _ = tx.Rollback() }()
			if isUpdate {
				for _, m := range markers {
					var del interface{}
					if sd.deleted {
						del = "gone"
					}
					epoch := sd.epoch
					if epoch == nil {
						epoch = 0
					}
					if _, err := tx.Exec(`INSERT INTO hosts (name, address, ssh_user, cert_serial, state,
						isolation_epoch, isolation_reason, created_at, updated_at, deleted_at)
						VALUES (?, 'a', 'u', 'seed', 'seed', ?, 'seed', 'seed', 'seed', ?)`,
						fmt.Sprint(m), epoch, del); err != nil {
						return hostsRow{}, 0, fmt.Errorf("seed hosts: %w", err)
					}
				}
			}
			res, err := tx.Exec(sqlText, markers...)
			if err != nil {
				return hostsRow{}, 0, fmt.Errorf("exec with markers: %w", err)
			}
			n, _ := res.RowsAffected()
			if n != 1 {
				return hostsRow{}, n, nil
			}
			var r hostsRow
			err = tx.QueryRow(`SELECT name, state, isolation_epoch, COALESCE(isolation_reason, ''), updated_at
				FROM hosts WHERE updated_at != 'seed'`).Scan(&r.name, &r.state, &r.epoch, &r.reason, &r.ts)
			return r, n, err
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
	return hostsRow{}, lastErr
}

func TestEveryMembershipWriteShapeIsOneTheAbsorbReads(t *testing.T) {
	shapes := ledgerShapeSQL(t)
	for i, s := range extraMembershipShapes {
		shapes[fmt.Sprintf("extra-membership-%d", i)] = s
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
		wantState, wantIso := membershipColumnsWritten(sqlText)
		if !wantState && !wantIso {
			continue
		}
		checked++
		markers := make([]interface{}, strings.Count(sqlText, "?"))
		for i := range markers {
			markers[i] = int64(1000 + i)
		}
		want, err := landedHostsRow(db, sqlText, markers)
		if err != nil {
			t.Errorf("%s writes a hosts membership column but could not be executed as an oracle (%v):\n%s", fp, err, sqlText)
			continue
		}
		host, ts, hasState, state, hasIso, epoch, reason, ok := corrosion.MembershipWrite(corrosion.Statement{SQL: sqlText, Params: markers})
		if !ok {
			t.Errorf("%s writes hosts' state or isolation but corrosion.MembershipWrite does not recognise it — "+
				"a node not yet writing host_membership that wrote in this shape would never be absorbed:\n%s", fp, sqlText)
			continue
		}
		if host != want.name || ts != want.ts {
			t.Errorf("%s: MembershipWrite host %s updated_at %s, SQLite wrote host %s updated_at %s:\n%s",
				fp, host, ts, want.name, want.ts, sqlText)
		}
		if hasState != wantState || (wantState && state != want.state) {
			t.Errorf("%s: MembershipWrite state (%v, %q), SQLite wrote state=%v %q:\n%s",
				fp, hasState, state, wantState, want.state, sqlText)
		}
		if hasIso != wantIso || (wantIso && (epoch != want.epoch || reason != want.reason)) {
			t.Errorf("%s: MembershipWrite isolation (%v, %d, %q), SQLite wrote isolation=%v %d %q:\n%s",
				fp, hasIso, epoch, reason, wantIso, want.epoch, want.reason, sqlText)
		}
	}
	// InsertHost, the startup writes, UpdateHostState, isolate/clear and
	// re-admission, current and historical; fewer means the walk is broken.
	if checked < 8 {
		t.Fatalf("checked only %d membership-writing shapes; the ledger walk is broken", checked)
	}
	t.Logf("checked %d membership-writing shapes", checked)
}
