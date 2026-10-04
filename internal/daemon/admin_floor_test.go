package daemon

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A reinstatement brings back an account an operator deleted. The daemon's
// tick must leave an audit row naming it, or the only record is a log line on
// whichever node acted.
func TestAdminFloor_AReinstatementIsAudited(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.MarkReplicaCaughtUpForTests("peer")
	d := &Daemon{cfg: &Config{HostName: "node-0"}, db: db}
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
