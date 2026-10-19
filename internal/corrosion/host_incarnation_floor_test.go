package corrosion

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestOlderIncarnation(t *testing.T) {
	const stamp = "2026-10-11T09:00:00.250000000Z"
	for _, tc := range []struct {
		local, incoming string
		want            bool
	}{
		{stamp, "2026-09-01T10:00:00Z", true},                   // the stale database's row
		{stamp, "2026-10-11T08:59:59.999999999Z", false},        // within the HLC's skew: an insert behind the stamp
		{stamp, "2026-10-11T08:55:00.250000001Z", false},        // the far edge of that skew
		{stamp, "2026-10-11T08:55:00.249999999Z", true},         // just beyond it
		{stamp, "2026-10-11T09:00:00Z", false},                  // an older build's insert in the same second
		{stamp, stamp, false},                                   // the same incarnation
		{stamp, "2026-10-11T09:00:01Z", false},                  // a later one (an empty-database re-add)
		{stamp, "2026-10-11T09:00:00.500000000Z", false},        // a later re-admission
		{stamp, "", false},                                      // no evidence
		{stamp, "not a time", false},                            // no evidence
		{"2026-10-11T09:00:00Z", "2026-09-01T10:00:00Z", false}, // never re-admitted: no floor
		{"", "2026-09-01T10:00:00Z", false},
	} {
		if got := olderIncarnation(tc.local, tc.incoming); got != tc.want {
			t.Errorf("olderIncarnation(%q, %q) = %v, want %v", tc.local, tc.incoming, got, tc.want)
		}
	}
}

// The merge floor itself, against a stored row: a re-admitted row refuses the
// previous incarnation's newer live row, and nothing else.
func TestHostsOlderIncarnationRefused(t *testing.T) {
	c := newTestDB(t)
	ctx := context.Background()
	oldIncarnation(t, c)
	applyRemote(t, c, "2999000000000-0000-peer", Statement{SQL: readmitHostSQL, Params: []interface{}{
		"10.0.0.15", "root", 22, 7443, HostStateJoining, readmitSerial, "2999-01-01T00:00:00.000001Z", "host-x", readmitSerial,
	}})
	cols := []string{"name", "region", "created_at", "deleted_at", "updated_at"}
	table := syncTable{Name: "hosts", Columns: cols}
	for _, tc := range []struct {
		name string
		row  []interface{}
		want bool
	}{
		{"the stale database's newer row", []interface{}{"host-x", "rack-a", "2026-01-01T00:00:00Z", nil, "2999-02-01T00:00:00.000001Z"}, true},
		{"the same incarnation", []interface{}{"host-x", "rack-b", "2999-01-01T00:00:00.000001000Z", nil, "2999-02-01T00:00:00.000001Z"}, false},
		{"a later incarnation", []interface{}{"host-x", "default", "2999-01-02T00:00:00Z", nil, "2999-02-01T00:00:00.000001Z"}, false},
		{"a tombstone", []interface{}{"host-x", "rack-a", "2026-01-01T00:00:00Z", "2999-02-01T00:00:00Z", "2999-02-01T00:00:00.000001Z"}, false},
		{"another host", []interface{}{"host-y", "rack-a", "2026-01-01T00:00:00Z", nil, "2999-02-01T00:00:00.000001Z"}, false},
	} {
		tx, err := c.DB().BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, reason, err := hostsOlderIncarnationRefused(tx, table, tc.row, []string{"name"}, []int{0})
		_ = tx.Rollback()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.want || (got && reason != "older_incarnation") {
			t.Errorf("%s: refused = %v (%q), want %v", tc.name, got, reason, tc.want)
		}
	}
}

// hostsRowImage is c's stored hosts row for host: its columns and values.
func hostsRowImage(t *testing.T, c *Client, host string) ([]string, []interface{}) {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT * FROM hosts WHERE name = ?`, host)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read %s: %d %v", host, len(rows), err)
	}
	return rows[0].Columns, append([]interface{}(nil), rows[0].Values...)
}

func mergeHostsRow(t *testing.T, c *Client, cols []string, row []interface{}) {
	t.Helper()
	table := syncTable{Name: "hosts", Columns: cols}
	if _, _, err := c.mergeChunk(table, [][]interface{}{row}, buildMergeUpsertSQL("hosts", cols, []string{"name"}),
		[]string{"name"}, []int{indexOf(cols, "name")}, indexOf(cols, "updated_at")); err != nil {
		t.Fatalf("mergeChunk: %v", err)
	}
}

// The re-admission's stamp is the admitter's HLC physical time, which may lead
// a host's wall clock by up to hlc.MaxSkewMS. A machine re-added on an EMPTY
// database inserts its row after its admission, but by its own clock, so its
// created_at can fall that far behind the stamp. A node that refused the
// insert over the old tombstone has only anti-entropy left to carry it; it
// must take the insert's row, its own grpc_port included — grpc_port has no
// other writer than the insert and a re-admission. A genuinely stale row,
// whose created_at is its original insert's, is still refused.
func TestHostsFloor_AnEmptyDBReaddWithinTheSkewKeepsItsInsert(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name, created string
		wantTaken     bool
	}{
		{"an empty-database insert 4 minutes behind the stamp", "2999-01-01T00:01:00.000000000Z", true},
		{"the stale database's row", "2026-01-01T00:00:00Z", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestDB(t)
			oldIncarnation(t, c)
			if _, err := c.DB().Exec(`UPDATE hosts SET created_at = '2026-01-01T00:00:00Z' WHERE name = 'host-x'`); err != nil {
				t.Fatal(err)
			}
			applyRemote(t, c, "2999000000000-0000-peer", Statement{SQL: readmitHostSQL, Params: []interface{}{
				"10.0.0.15", "root", 22, 7443, HostStateJoining, readmitSerial, "2999-01-01T00:05:00.000001Z", "host-x", readmitSerial,
			}})
			cols, row := hostsRowImage(t, c, "host-x")
			row[indexOf(cols, "created_at")] = tc.created
			row[indexOf(cols, "grpc_port")] = int64(17443)
			row[indexOf(cols, "updated_at")] = "2999-01-01T00:06:00.000001Z"
			mergeHostsRow(t, c, cols, row)

			rows, err := c.Query(ctx, `SELECT grpc_port, created_at FROM hosts WHERE name = 'host-x'`)
			if err != nil || len(rows) != 1 {
				t.Fatalf("read host-x: %d %v", len(rows), err)
			}
			taken := fmt.Sprint(rows[0].Int64("grpc_port")) == "17443"
			if taken != tc.wantTaken {
				t.Errorf("incoming row (created_at %s) taken = %v, want %v; host-x now grpc_port %d created_at %s",
					tc.created, taken, tc.wantTaken, rows[0].Int64("grpc_port"), rows[0].String("created_at"))
			}
		})
	}
}

// The floor's warning names a row once per refusalLogInterval, however many
// anti-entropy cycles refuse it; another row is named at once.
func TestRefusalLogLimiter(t *testing.T) {
	var l refusalLogLimiter
	t0 := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	if !l.allow("hosts/h1", t0) {
		t.Fatal("the first refusal of a row must be logged")
	}
	if l.allow("hosts/h1", t0.Add(time.Minute)) {
		t.Error("a refusal of the same row a minute later was logged again")
	}
	if !l.allow("hosts/h2", t0.Add(time.Minute)) {
		t.Error("another row's first refusal was not logged")
	}
	if !l.allow("hosts/h1", t0.Add(refusalLogInterval)) {
		t.Errorf("the same row was not logged again after %s", refusalLogInterval)
	}
}

// A5 (lab eqts-test26): the warning named one cause, a host re-added while
// its data directory still held its old database. On the lab the stale row
// came from a peer of the previous release that had applied the legacy
// re-admission without its created_at, and the re-added host's database was
// not involved. The advice names both.
func TestHostsIncarnationAdvice_NamesALaggingPeer(t *testing.T) {
	for _, want := range []string{"previous release", "does not hold the re-admitted row", "data directory"} {
		if !strings.Contains(hostsIncarnationAdvice, want) {
			t.Errorf("the advice does not mention %q: %s", want, hostsIncarnationAdvice)
		}
	}
}
