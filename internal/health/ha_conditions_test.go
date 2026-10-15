package health

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// An HA condition opens with its evidence, follows a change of evidence, and
// resolves; one a previous process left open is resolved by the first Sync
// with nothing to report.
func TestHACondition_OpensFollowsAndResolves(t *testing.T) {
	ctx := t.Context()
	db := testLogicDB(t)
	read := func() corrosion.HealthCondition {
		row, _, err := corrosion.GetHealthCondition(ctx, db, corrosion.HADisarmEvaluator, corrosion.CondHADisarmed, "host", "h1")
		if err != nil {
			t.Fatal(err)
		}
		return row
	}
	c := &HACondition{DB: db, Host: "h1", Code: corrosion.CondHADisarmed, Severity: corrosion.SeverityWarning}
	if !c.Sync(ctx, true, "disarmed by alice") {
		t.Fatal("open did not land")
	}
	if r := read(); r.Lifecycle != corrosion.ConditionConfirmed || r.Evidence != "disarmed by alice" || r.Severity != corrosion.SeverityWarning {
		t.Fatalf("opened: %+v", r)
	}
	c.Sync(ctx, true, "disarmed by bob")
	if r := read(); r.Evidence != "disarmed by bob" {
		t.Fatalf("evidence not followed: %+v", r)
	}
	c.Sync(ctx, false, "")
	if r := read(); r.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("not resolved: %+v", r)
	}

	(&HACondition{DB: db, Host: "h1", Code: corrosion.CondHADisarmed, Severity: corrosion.SeverityWarning}).Sync(ctx, true, "x")
	fresh := &HACondition{DB: db, Host: "h1", Code: corrosion.CondHADisarmed, Severity: corrosion.SeverityWarning}
	fresh.Sync(ctx, false, "")
	if r := read(); r.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("a previous process's open condition was not resolved: %+v", r)
	}
}
