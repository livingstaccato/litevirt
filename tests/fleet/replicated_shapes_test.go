package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleetHarness_AnUnregisteredReplicatedWriteStallsAndIsReported pins both
// halves of replicated_shapes.go on independent replicas: a raw write whose
// shape is not in the ledger really does stop the writer's stream (the hazard),
// and the stop-time check names it (the guard). setHostCapacity's old raw
// `UPDATE hosts` is the statement, because it is the one that did this to the
// iSCSI fleet tests.
func TestFleetHarness_AnUnregisteredReplicatedWriteStallsAndIsReported(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	c.AllowUnregisteredReplicatedWrites("this test writes the unregistered statement on purpose")
	ctx := context.Background()
	a, b := c.Nodes[0], c.Nodes[1]

	const raw = `UPDATE hosts SET cpu_total = ?, mem_total = ?, mem_reserve_mib = ?, updated_at = ? WHERE name = ?`
	if err := a.DB.Execute(ctx, raw, 64, 65536, -1, a.DB.NowTS(), a.Name); err != nil {
		t.Fatalf("raw write: %v", err)
	}
	// A registered write made after it never reaches the peer: it is queued
	// behind the statement the peer refuses.
	if err := corrosion.SetHostLabel(ctx, a.DB, a.Name, "behind", "the-stall"); err != nil {
		t.Fatalf("SetHostLabel: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h, _ := corrosion.GetHost(ctx, b.DB, a.Name); h != nil && h.Labels["behind"] == "the-stall" {
			t.Fatal("a write queued behind an unregistered statement replicated; the stall this guard exists for is gone, so re-check what it protects")
		}
		time.Sleep(100 * time.Millisecond)
	}

	bad := unregisteredReplicatedStatements(c.Nodes)
	if len(bad) != 1 || !strings.Contains(bad[0], "UPDATE hosts SET cpu_total = ?, mem_total = ?, mem_reserve_mib = ?") ||
		!strings.Contains(bad[0], "logged on "+a.Name) {
		t.Fatalf("the check reported %q; want exactly the raw UPDATE, logged on %s", bad, a.Name)
	}
}

// TestFleetHarness_SetHostCapacityReplicates: the helper's writes are
// registered statements, so on independent replicas the node's later writes
// still reach its peer, and the check has nothing to report.
func TestFleetHarness_SetHostCapacityReplicates(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	ctx := context.Background()
	a, b := c.Nodes[0], c.Nodes[1]

	setHostCapacity(t, c, a.Name, 8, 2048)
	if err := corrosion.SetHostLabel(ctx, a.DB, a.Name, "after", "capacity"); err != nil {
		t.Fatalf("SetHostLabel: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		h, _ := corrosion.GetHost(ctx, b.DB, a.Name)
		if h != nil && h.Labels["after"] == "capacity" && h.CPUTotal == 8 && h.MemTotal == 2048 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s's writes after setHostCapacity never reached %s: %+v", a.Name, b.Name, h)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if bad := unregisteredReplicatedStatements(c.Nodes); len(bad) != 0 {
		t.Fatalf("setHostCapacity logged statements no receiver applies:\n%s", strings.Join(bad, "\n"))
	}
}
