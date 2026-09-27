package network

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A release this node REFUSED — the lease is not held by the named owner here —
// must not be replayed by peers. Relayed, it tombstones the lease on any peer
// whose copy still names that owner: the stale-detach hazard the owner-scoped
// WHERE exists to stop, reintroduced through replication.
func TestReleaseLease_ARefusedReleaseIsNotRelayed(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	count := func() int64 {
		rows, err := db.Query(ctx, `SELECT COUNT(*) AS n FROM mutation_log`)
		if err != nil {
			t.Fatal(err)
		}
		return rows[0].Int64("n")
	}
	before := count()
	if err := ReleaseLease(ctx, db, "net1", "10.0.0.9", "mac", "vm", "", "no-vm"); err == nil {
		t.Fatal("premise: releasing a lease nobody holds succeeded")
	}
	if after := count(); after != before {
		t.Errorf("a refused release queued %d statement(s) for replication", after-before)
	}
	if got := db.ParkedUpdates(); got != 0 {
		t.Errorf("a refused release parked %d update(s)", got)
	}
}
