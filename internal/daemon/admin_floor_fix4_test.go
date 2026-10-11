package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func adminCondition(t *testing.T, d *Daemon) (bool, string) {
	t.Helper()
	row, found, err := corrosion.GetHealthCondition(context.Background(), d.db, adminFloorEvaluator,
		CondNoUnrestrictedAdmin, "host", d.cfg.HostName)
	if err != nil {
		t.Fatal(err)
	}
	return found && row.Lifecycle == corrosion.ConditionConfirmed, row.Evidence
}

// I1a: when the only admins are a case-duplicate pair, the floor reinstates
// nothing, and the condition names the pair and the command root resolves it
// with.
func TestAdminFloor_DuplicatePairIsNamedNotResurrected(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.MarkReplicaCaughtUpForTests("peer")
	for _, u := range []string{"admin", "Admin", "oldops"} {
		if err := corrosion.InsertUser(ctx, db, u, "admin", "x"); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.DeleteUser(ctx, db, "oldops"); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{cfg: &Config{HostName: "node-0"}, db: db}
	d.checkAdminFloor(ctx, 0)
	d.checkAdminFloor(ctx, 0)
	if u, _ := corrosion.GetUser(ctx, db, "oldops"); u != nil {
		t.Fatal("the floor reinstated oldops beside a duplicate admin pair")
	}
	open, ev := adminCondition(t, d)
	if !open || !strings.Contains(ev, "lv user delete --exact admin") {
		t.Fatalf("no_unrestricted_admin open=%v evidence=%s; want it open, naming `lv user delete --exact admin`", open, ev)
	}
}

// I1a: an account the floor reinstated has no usable credential until root
// gives it one; the condition says how.
func TestAdminFloor_ReinstatedAccountNamesResetAdmin(t *testing.T) {
	ctx := context.Background()
	d := zeroAdminDaemon(t)
	d.checkAdminFloor(ctx, 0) // arms
	d.checkAdminFloor(ctx, 0) // acts
	open, ev := adminCondition(t, d)
	if !open || !strings.Contains(ev, "lv user reset-admin --user alice") {
		t.Fatalf("no_unrestricted_admin open=%v evidence=%s; want it open, naming `lv user reset-admin --user alice`", open, ev)
	}
}
