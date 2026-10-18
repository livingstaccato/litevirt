package corrosion

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"modernc.org/sqlite"
)

// Observe values returned by real SQLite, rather than matching SQL spelling.
// Removing the storage length predicate must expose an oversized returned body.
type retainedBodyDriver struct {
	driver.Driver
	oversized *atomic.Int64
	wrongType *atomic.Int64
}
type retainedBodyConn struct {
	driver.Conn
	oversized *atomic.Int64
	wrongType *atomic.Int64
}

func (d *retainedBodyDriver) Open(name string) (driver.Conn, error) {
	c, err := d.Driver.Open(name)
	if err != nil {
		return nil, err
	}
	return &retainedBodyConn{c, d.oversized, d.wrongType}, nil
}
func (c *retainedBodyConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}
func (c *retainedBodyConn) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	rows, err := c.Conn.(driver.QueryerContext).QueryContext(ctx, q, a)
	if err != nil {
		return nil, err
	}
	return &retainedTypeAuditRows{&receiverBodyAuditRows{rows, c.oversized, MaxAutomationClaimBytes}, c.wrongType}, nil
}

type retainedTypeAuditRows struct {
	driver.Rows
	wrongType *atomic.Int64
}

func (r *retainedTypeAuditRows) Next(dest []driver.Value) error {
	err := r.Rows.Next(dest)
	if err == nil {
		for i, column := range r.Columns() {
			if column == "value_json" || column == "digest" || column == "anchor_digest" {
				if _, blob := dest[i].([]byte); blob {
					r.wrongType.Add(1)
				}
			}
		}
	}
	return err
}

func TestAutomationRetainedTypeBeforeAcceptBody(t *testing.T) {
	testAutomationRetainedBeforeAcceptBody(t, true)
}
func TestAutomationRetainedLengthBeforeAcceptBody(t *testing.T) {
	testAutomationRetainedBeforeAcceptBody(t, false)
}
func testAutomationRetainedBeforeAcceptBody(t *testing.T, wrongStorageType bool) {
	for _, field := range []string{"value_json", "history_digest", "anchor_digest"} {
		t.Run(field, func(t *testing.T) {
			_, a, b, _ := threeVoters(t)
			ctx := context.Background()
			first := sharedAutomationRecord(t, 1, "", "req", "op", a, b)
			if _, err := applySharedAutomation(t, a.c, first, contract.Reduce, automationFreshAnchor); err != nil {
				t.Fatal(err)
			}
			second := sharedAutomationRecord(t, 2, first.Value.MustDigest(), "barrier", "barrier-op", a, b)
			if _, err := applySharedAutomation(t, a.c, second, contract.Reduce, automationFreshAnchor); err != nil {
				t.Fatal(err)
			}
			key, _ := AutomationClaimKey(1)
			installAutomationEvidence(t, a.c, key, "", 1)
			var oversized, wrongType atomic.Int64
			name := fmt.Sprintf("retained-body-%d", sourceReadDriverSequence.Add(1))
			sql.Register(name, &retainedBodyDriver{&sqlite.Driver{}, &oversized, &wrongType})
			observed, err := sql.Open(name, a.c.dsn)
			if err != nil {
				t.Fatal(err)
			}
			observed.SetMaxOpenConns(1)
			if _, err := observed.Exec(`PRAGMA synchronous=FULL`); err != nil {
				t.Fatal(err)
			}
			original := a.c.db
			a.c.db = observed
			defer func() { a.c.db = original; observed.Close() }()
			accepted, err := a.c.ClaimAccept(ctx, key, testBallot(2, "a"), first.Value, 1, a.signer, nil)
			if err != nil || !accepted.Accepted {
				t.Fatal("bounded retained positive", accepted, err)
			}
			table, column := "local_automation_history", "value_json"
			if field == "history_digest" {
				column = "digest"
			}
			if field == "anchor_digest" {
				table = "local_automation_anchors"
				column = "digest"
			}
			if wrongStorageType {
				if _, err := original.Exec("UPDATE " + table + " SET " + column + "=CAST(" + column + " AS BLOB) WHERE sequence=2"); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := original.Exec("UPDATE "+table+" SET "+column+"=CAST(zeroblob(?) AS TEXT) WHERE sequence=2", MaxAutomationClaimBytes+1); err != nil {
					t.Fatal(err)
				}
			}
			permanent := func() []Row {
				rows, err := a.c.Query(ctx, `SELECT sequence,length(CAST(value_json AS BLOB)),length(CAST(digest AS BLOB)),receipt_json,certificate FROM local_automation_history UNION ALL SELECT sequence,0,length(CAST(digest AS BLOB)),members_hash,certificate FROM local_automation_anchors ORDER BY 1,2,3`)
				if err != nil {
					t.Fatal(err)
				}
				return rows
			}
			before := permanent()
			typed := automationTypedSnapshot(t, a.c)
			stateBefore, found, err := a.c.ClaimState(ctx, key)
			if err != nil || !found {
				t.Fatal(err)
			}
			oversized.Store(0)
			wrongType.Store(0)
			freshKey, value := automationFixture(t, 3, second.Value.MustDigest())
			refused, err := a.c.ClaimAccept(ctx, freshKey, testBallot(3, "a"), value, 1, a.signer, nil)
			if refused.Accepted || refused.Accept != nil || err == nil && refused.Refusal == "" {
				t.Fatal("oversized retained evidence admitted", refused, err)
			}
			if wrongType.Load() != 0 {
				t.Error("wrong-type retained evidence crossed SQLite boundary before refusal")
			}
			if oversized.Load() != 0 {
				t.Error("oversized retained evidence crossed SQLite boundary before refusal")
			}
			if _, found, err := a.c.ClaimState(ctx, freshKey); err != nil || found {
				t.Fatal("oversized refusal wrote fresh claim", found, err)
			}
			stateAfter, found, err := a.c.ClaimState(ctx, key)
			if err != nil || !found || !reflect.DeepEqual(stateBefore, stateAfter) || !reflect.DeepEqual(before, permanent()) || !reflect.DeepEqual(typed, automationTypedSnapshot(t, a.c)) {
				t.Fatal("oversized refusal mutated retained state", err)
			}
		})
	}
}
