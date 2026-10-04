package corrosion

import (
	"context"
	"testing"
)

// A re-added host's registration and boot write that reach a node ahead of
// its admission must not land on the old machine's tombstone
// (host_tombstone_guard.go). The fleet test
// TestFleet_BootWriteAheadOfAdmissionDoesNotRemoveTheHost drives the whole
// sequence; these pin each statement on one receiver.

func removedHost(t *testing.T) (*Client, string) {
	t.Helper()
	c := newTestDB(t)
	ctx := context.Background()
	if err := InsertHost(ctx, c, HostRecord{Name: "host-x", Address: "10.0.0.15", State: "active", CertSerial: "01old"}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteHost(ctx, c, "host-x"); err != nil {
		t.Fatal(err)
	}
	_, _, _, ts := hostRow(t, c)
	return c, ts
}

func hostRow(t *testing.T, c *Client) (deleted bool, serial, state, updated string) {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT deleted_at, cert_serial, state, updated_at FROM hosts WHERE name = 'host-x'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read host-x: %d %v", len(rows), err)
	}
	r := rows[0]
	return r.String("deleted_at") != "", r.String("cert_serial"), r.String("state"), r.String("updated_at")
}

func TestReplicatedHostWrite_LeavesATombstoneAlone(t *testing.T) {
	const ts = "2999-01-01T00:00:00.000002Z"
	for name, st := range map[string]Statement{
		// The new daemon's InsertHost, on its empty database.
		"registration": {SQL: insertHostSQL, Params: []interface{}{
			"host-x", "10.0.0.15", "root", 22, 7443, "active", readmitSerial,
			64, 262144, 0, "best-effort", "v-new", "worker", 0.0, 0.0, -1, -1, "", "2999-01-01T00:00:00Z", ts}},
		// Its boot write.
		"boot write": {SQL: `UPDATE hosts SET state = ?, version = COALESCE(NULLIF(?, ''), version), schema_version = ?, updated_at = ? WHERE name = ?`,
			Params: []interface{}{"active", "v-new", CurrentSchemaVersion, ts, "host-x"}},
	} {
		c, before := removedHost(t)
		applyRemote(t, c, "2999000000000-0001-peer", st)
		deleted, serial, _, updated := hostRow(t, c)
		if !deleted || updated != before || serial != "01old" {
			t.Errorf("%s: tombstone now (deleted %v, serial %s, updated_at %s), want it untouched at %s: "+
				"a newer tombstone outlives the admission that follows", name, deleted, serial, updated, before)
		}
	}
}

// The two statements that DO write a tombstone still apply: the re-admission,
// and a removal that reaches a row already removed.
func TestReplicatedHostWrite_ReadmissionStillApplies(t *testing.T) {
	c, _ := removedHost(t)
	const ts = "2999-01-01T00:00:00.000001Z"
	applyRemote(t, c, "2999000000000-0000-peer", Statement{SQL: readmitHostSQL, Params: []interface{}{
		"10.0.0.15", "root", 22, 7443, HostStateJoining, readmitSerial, ts, "host-x", readmitSerial,
	}})
	if deleted, serial, state, _ := hostRow(t, c); deleted || serial != readmitSerial || state != HostStateJoining {
		t.Errorf("re-admission: deleted %v serial %s state %s, want it live and joining", deleted, serial, state)
	}

	// Removed again; a late duplicate removal still restamps it.
	applyRemote(t, c, "2999000000000-0002-peer", Statement{SQL: deleteHostSQL,
		Params: []interface{}{"2999-01-02T00:00:00Z", "2999-01-02T00:00:00.000001Z", "host-x"}})
	applyRemote(t, c, "2999000000000-0003-peer", Statement{SQL: deleteHostSQL,
		Params: []interface{}{"2999-01-03T00:00:00Z", "2999-01-03T00:00:00.000001Z", "host-x"}})
	if deleted, _, _, updated := hostRow(t, c); !deleted || updated != "2999-01-03T00:00:00.000001Z" {
		t.Errorf("removal over a tombstone: deleted %v updated_at %s, want the later removal applied", deleted, updated)
	}
}

// A write to a live host row is untouched by the guard.
func TestReplicatedHostWrite_LiveRowApplies(t *testing.T) {
	c := newTestDB(t)
	if err := InsertHost(context.Background(), c, HostRecord{Name: "host-x", Address: "10.0.0.15", State: "joining", CertSerial: "01"}); err != nil {
		t.Fatal(err)
	}
	applyRemote(t, c, "2999000000000-0001-peer", Statement{
		SQL:    `UPDATE hosts SET state = ?, version = COALESCE(NULLIF(?, ''), version), schema_version = ?, updated_at = ? WHERE name = ?`,
		Params: []interface{}{"active", "v-new", CurrentSchemaVersion, "2999-01-01T00:00:00.000002Z", "host-x"}})
	if _, _, state, _ := hostRow(t, c); state != "active" {
		t.Errorf("boot write on a live row: state %s, want active", state)
	}
}
