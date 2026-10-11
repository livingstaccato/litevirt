package fleet

import (
	"context"
	"fmt"
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

	if err := a.DB.Execute(ctx, rawHostWrite, 64, 65536, -1, a.DB.NowTS(), a.Name); err != nil {
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

	bad, unreadable := unregisteredReplicatedStatements(c.Nodes)
	if len(unreadable) != 0 {
		t.Fatalf("the check could not read the logs: %q", unreadable)
	}
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
	if bad, _ := unregisteredReplicatedStatements(c.Nodes); len(bad) != 0 {
		t.Fatalf("setHostCapacity logged statements no receiver applies:\n%s", strings.Join(bad, "\n"))
	}
}

// rawHostWrite logs setHostCapacity's old raw UPDATE on n: a statement no
// receiver applies.
const rawHostWrite = `UPDATE hosts SET cpu_total = ?, mem_total = ?, mem_reserve_mib = ?, updated_at = ? WHERE name = ?`

// captureShapeFailures routes c's stop-time shape failure to the returned
// slice instead of failing the test running it.
func captureShapeFailures(c *Cluster) *[]string {
	var got []string
	c.shapeErrorf = func(format string, args ...any) { got = append(got, fmt.Sprintf(format, args...)) }
	return &got
}

// TestFleetHarness_StopFailsAClusterThatLoggedAnUnregisteredStatement pins the
// wiring, not just the scan: Cluster.Stop itself fails the test, naming the
// statement and the node. Each arm is a cluster stopped in-test with the
// failure captured; the scan alone being right proves nothing if Stop never
// runs it, or runs it after the databases close.
func TestFleetHarness_StopFailsAClusterThatLoggedAnUnregisteredStatement(t *testing.T) {
	ctx := context.Background()
	raw := func(t *testing.T, n *Node) {
		t.Helper()
		if err := n.DB.Execute(ctx, rawHostWrite, 64, 65536, -1, n.DB.NowTS(), n.Name); err != nil {
			t.Fatalf("raw write on %s: %v", n.Name, err)
		}
	}

	t.Run("reported", func(t *testing.T) {
		for _, opts := range []Options{{Nodes: 2}, {Nodes: 2, IndependentReplicas: true}} {
			c := New(t, opts)
			got := captureShapeFailures(c)
			raw(t, c.Nodes[0])
			c.Stop()
			if len(*got) != 1 || !strings.Contains((*got)[0], "UPDATE hosts SET cpu_total = ?, mem_total = ?, mem_reserve_mib = ?") ||
				!strings.Contains((*got)[0], "logged on "+c.Nodes[0].Name) {
				t.Fatalf("IndependentReplicas=%v: Stop reported %q; want one failure naming the raw UPDATE logged on %s",
					opts.IndependentReplicas, *got, c.Nodes[0].Name)
			}
		}
	})
	t.Run("shared database is not checked", func(t *testing.T) {
		c := New(t, Options{Nodes: 2, SharedCRDT: true})
		got := captureShapeFailures(c)
		raw(t, c.Nodes[0])
		c.Stop()
		if len(*got) != 0 {
			t.Fatalf("a SharedCRDT cluster, which replicates nothing, was reported: %q", *got)
		}
	})
	t.Run("opted out", func(t *testing.T) {
		c := New(t, Options{Nodes: 2})
		got := captureShapeFailures(c)
		c.AllowUnregisteredReplicatedWrites("this arm checks the opt-out")
		raw(t, c.Nodes[0])
		c.Stop()
		if len(*got) != 0 {
			t.Fatalf("an opted-out cluster was reported: %q", *got)
		}
	})
	t.Run("a log it cannot read fails", func(t *testing.T) {
		c := New(t, Options{Nodes: 2})
		got := captureShapeFailures(c)
		c.Nodes[1].DB.Close()
		c.Stop()
		if len(*got) != 1 || !strings.Contains((*got)[0], c.Nodes[1].Name+": read mutation_log") {
			t.Fatalf("Stop reported %q; want the unreadable log on %s", *got, c.Nodes[1].Name)
		}
	})
	t.Run("clean", func(t *testing.T) {
		c := New(t, Options{Nodes: 2, IndependentReplicas: true})
		got := captureShapeFailures(c)
		setHostCapacity(t, c, c.Nodes[0].Name, 8, 2048)
		c.Stop()
		if len(*got) != 0 {
			t.Fatalf("registered writes only, and Stop reported: %q", *got)
		}
	})
}

// TestFleetHarness_SetHostCapacityClearsTheReserve: sizing a host puts its
// memory reserve back to the cluster default on every node, as the helper's
// old raw write did, so a reserve one step of a scenario set does not leak
// into a later sizing.
func TestFleetHarness_SetHostCapacityClearsTheReserve(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	h := c.Nodes[1].Name
	setHostMemReserve(t, c, h, 0)
	setHostCapacity(t, c, h, 8, 2048)
	for _, n := range c.Nodes {
		rec, err := corrosion.GetHost(ctx, n.DB, h)
		if err != nil || rec == nil {
			t.Fatalf("GetHost %s on %s: %v", h, n.Name, err)
		}
		if rec.MemReserveMiB != nil {
			t.Fatalf("%s still holds a %d MiB reserve for %s after setHostCapacity; want the cluster default",
				n.Name, *rec.MemReserveMiB, h)
		}
	}
}
