package daemon

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// zeroAdminDaemon is a daemon whose replica holds two deleted admins and no
// live one, caught up so the floor may act.
func zeroAdminDaemon(t *testing.T) *Daemon {
	t.Helper()
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.MarkReplicaCaughtUpForTests("peer")
	for _, u := range []string{"alice", "bob"} {
		if err := corrosion.InsertUser(ctx, db, u, "admin", "x"); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range []string{"alice", "bob"} {
		if err := corrosion.DeleteUser(ctx, db, u); err != nil {
			t.Fatal(err)
		}
	}
	return &Daemon{cfg: &Config{HostName: "node-0"}, db: db}
}

// The reinstatement row is signed like every other audit row when the client
// carries a signing keyring (the auditWriters registry in internal/corrosion).
func TestAuditWriter_AdminFloorRowsAreSigned(t *testing.T) {
	ctx := context.Background()
	d := zeroAdminDaemon(t)
	corrosion.SignAuditRowsForTest(t, d.db, "node-0")
	d.checkAdminFloor(ctx, 0) // arms
	d.checkAdminFloor(ctx, 0) // acts
	corrosion.AssertAuditRowsSignedForTest(t, d.db, 1)
}

// A reinstatement brings back an account an operator deleted. The daemon's
// tick must leave an audit row naming it, or the only record is a log line on
// whichever node acted.
func TestAdminFloor_AReinstatementIsAudited(t *testing.T) {
	ctx := context.Background()
	d := zeroAdminDaemon(t)
	db := d.db

	d.checkAdminFloor(ctx, 0) // arms
	d.checkAdminFloor(ctx, 0) // acts

	rows, err := db.Query(ctx,
		`SELECT target FROM audit_log WHERE action = 'user.admin_reinstated'`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].String("target") != "alice" {
		t.Fatalf("audit rows for the reinstatement: %d (first target %q), want one naming alice",
			len(rows), func() string {
				if len(rows) > 0 {
					return rows[0].String("target")
				}
				return ""
			}())
	}
}
