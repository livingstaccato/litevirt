package corrosion

import (
	"context"
	"testing"
)

// migrateAcknowledgedTiesPK rebuilds acknowledged_ties as CREATE _new, copy,
// DROP, RENAME. Run as four separate statements, a crash between them left one
// of two states on disk, and the next start had to cope with each:
//
//   - after the CREATE (or the copy): the narrow table is intact beside a
//     leftover acknowledged_ties_new, and the rerun's CREATE failed "already
//     exists", so the daemon could not start;
//   - after the DROP: acknowledged_ties is gone, InitSchema's CREATE IF NOT
//     EXISTS makes an empty one on the wide key, the migration sees the wide
//     key and returns, and every acknowledgement in acknowledged_ties_new is
//     lost.

const narrowAcknowledgedTiesDDL = `CREATE TABLE acknowledged_ties (
	table_name      TEXT NOT NULL,
	pk              TEXT NOT NULL,
	content_pair    TEXT NOT NULL,
	acknowledged_at TEXT NOT NULL,
	acknowledged_by TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (table_name, pk)
)`

const leftoverAcknowledgedTiesNewDDL = `CREATE TABLE acknowledged_ties_new (
	table_name      TEXT NOT NULL,
	pk              TEXT NOT NULL,
	content_pair    TEXT NOT NULL,
	acknowledged_at TEXT NOT NULL,
	acknowledged_by TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (table_name, pk, content_pair)
)`

func seedLocal(t *testing.T, c *Client, stmts ...string) {
	t.Helper()
	for _, s := range stmts {
		if err := c.execLocal(context.Background(), s); err != nil {
			t.Fatalf("seed (%.50s): %v", s, err)
		}
	}
}

func assertAcknowledgedTiesRecovered(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()
	rows, err := c.Query(ctx, `SELECT pk, content_pair, acknowledged_by FROM acknowledged_ties ORDER BY pk`)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if len(rows) != 2 || rows[0].String("content_pair") != "pair-a" || rows[1].String("acknowledged_by") != "bob" {
		t.Fatalf("the operator's acknowledgements did not survive the interrupted rebuild: %+v", rows)
	}
	keyed := false
	info, err := c.Query(ctx, `PRAGMA table_info(acknowledged_ties)`)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range info {
		if r.String("name") == "content_pair" && r.Int("pk") > 0 {
			keyed = true
		}
	}
	if !keyed {
		t.Error("content_pair is not part of the primary key after recovery")
	}
	left, err := c.Query(ctx, `SELECT name FROM sqlite_master WHERE name = 'acknowledged_ties_new'`)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Error("acknowledged_ties_new is still present after recovery")
	}
}

// Crashed after the copy, before the DROP: both tables hold the rows.
func TestMigrateAcknowledgedTiesPK_RecoversFromALeftoverNewTable(t *testing.T) {
	c := NewTestClientT(t)
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	seedLocal(t, c,
		`DROP TABLE acknowledged_ties`,
		narrowAcknowledgedTiesDDL,
		`INSERT INTO acknowledged_ties VALUES
		   ('vms','vm1','pair-a','2026-09-20T19:44:06Z','alice'),
		   ('vms','vm2','pair-b','2026-09-21T02:22:15Z','bob')`,
		leftoverAcknowledgedTiesNewDDL,
		`INSERT INTO acknowledged_ties_new SELECT * FROM acknowledged_ties`,
	)
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("the restart after an interrupted rebuild cannot start the daemon: %v", err)
	}
	assertAcknowledgedTiesRecovered(t, c)
}

// Crashed after the DROP, before the RENAME: only acknowledged_ties_new holds
// the rows.
func TestMigrateAcknowledgedTiesPK_RecoversRowsStrandedInTheNewTable(t *testing.T) {
	c := NewTestClientT(t)
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	seedLocal(t, c,
		`DROP TABLE acknowledged_ties`,
		leftoverAcknowledgedTiesNewDDL,
		`INSERT INTO acknowledged_ties_new VALUES
		   ('vms','vm1','pair-a','2026-09-20T19:44:06Z','alice'),
		   ('vms','vm2','pair-b','2026-09-21T02:22:15Z','bob')`,
	)
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	assertAcknowledgedTiesRecovered(t, c)
}
