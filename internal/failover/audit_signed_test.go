package failover

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestAuditWriter_CoordinatorRowsAreSigned: every audit row the failover
// coordinator writes goes through Coordinator.audit on its client, so on a
// signing client every one comes out signed and verify counts it so. Listed in
// corrosion's TestAuditWriters_EveryCallSiteIsCovered.
func TestAuditWriter_CoordinatorRowsAreSigned(t *testing.T) {
	ctx := context.Background()
	const host = "node-0"
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	corrosion.SignAuditRowsForTest(t, db, host)
	c := NewCoordinator(host, db)

	c.audit(ctx, "failover", "web", "rescheduled from node-1 to node-0", "ok")
	c.noteLeaseTermRefusal(ctx, "vm", "db", "node-1")

	corrosion.AssertAuditRowsSignedForTest(t, db, 2)
}
