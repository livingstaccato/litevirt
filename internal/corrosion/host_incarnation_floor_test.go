package corrosion

import (
	"context"
	"testing"
)

func TestOlderIncarnation(t *testing.T) {
	const stamp = "2026-10-11T09:00:00.250000000Z"
	for _, tc := range []struct {
		local, incoming string
		want            bool
	}{
		{stamp, "2026-09-01T10:00:00Z", true},                   // the stale database's row
		{stamp, "2026-10-11T08:59:59.999999999Z", true},         // the second before
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
