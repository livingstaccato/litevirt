package daemon

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestReportAuditSeeded_ShowsAnUnseededNodeUntilItIsSeeded is M-O: an operator
// finds which nodes `lv host add` may run against in `lv health`. An unseeded
// node raises audit_not_seeded about itself; it is resolved once seeded.
//
// Mutation: never raise the condition — nothing to see.
func TestReportAuditSeeded_ShowsAnUnseededNodeUntilItIsSeeded(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{cfg: &Config{HostName: "node-0", DataDir: t.TempDir()}, db: db}
	if d.reportAuditSeeded(ctx) {
		t.Fatal("fixture: seeded")
	}
	row, found, err := corrosion.GetHealthCondition(ctx, db, auditHoldEvaluator, CondAuditNotSeeded, "host", "node-0")
	if err != nil || !found || row.Lifecycle != corrosion.ConditionConfirmed {
		t.Fatalf("audit_not_seeded not raised for an unseeded node: %+v found=%v %v", row, found, err)
	}
	if err := db.MarkAuditSeeded(ctx, "test"); err != nil {
		t.Fatal(err)
	}
	if !d.reportAuditSeeded(ctx) {
		t.Fatal("still reported unseeded")
	}
	row, _, _ = corrosion.GetHealthCondition(ctx, db, auditHoldEvaluator, CondAuditNotSeeded, "host", "node-0")
	if row.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("audit_not_seeded not resolved once seeded: %+v", row)
	}
}
