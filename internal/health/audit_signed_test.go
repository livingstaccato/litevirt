package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/randid"
)

// TestAuditWriter_OwnerAssertRowsAreSigned: the health package's two audit
// writers — the VM owner-assert and the container owner-rekey — write through
// the client they were built with, so on a signing client their rows come out
// signed and verify counts them so. Listed in corrosion's
// TestAuditWriters_EveryCallSiteIsCovered.
func TestAuditWriter_OwnerAssertRowsAreSigned(t *testing.T) {
	ctx := context.Background()
	const host = "node-0"
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	corrosion.SignAuditRowsForTest(t, db, host)

	NewReconciler(host, t.TempDir(), db, nil).auditOwnerAssert(ctx, "web", "node-1")
	NewContainerChecker(host, db, nil).auditRekey(ctx, "ct1", "node-1")

	corrosion.AssertAuditRowsSignedForTest(t, db, 2)
}

// The partition.settle audit row (settle.go) is signed like every other.
func TestAuditWriter_SettleRowsAreSigned(t *testing.T) {
	ctx := context.Background()
	const host = "node-0"
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	corrosion.SignAuditRowsForTest(t, db, host)
	_ = auditSettle(ctx, db, host, "vm-a", "stopped the local copy", randid.New())
	corrosion.AssertAuditRowsSignedForTest(t, db, 1)
}

// auditSystem: the health loops' replication direction switches.
func TestAuditWriter_SystemRowsAreSigned(t *testing.T) {
	ctx := context.Background()
	const host = "node-0"
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	corrosion.SignAuditRowsForTest(t, db, host)
	auditSystem(ctx, db, host, "replication.reverse", "vm-a", "vm vm-a moved node-1 -> node-0: replication now runs node-0 -> node-1 (dr)", "ok")
	corrosion.AssertAuditRowsSignedForTest(t, db, 1)
}
