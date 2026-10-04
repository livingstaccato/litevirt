package fleet

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// healthRow is observer's verdict on target as n's replica holds it.
type healthRow struct {
	present bool
	status  string
	deleted string
	updated string
}

func healthRowOn(t *testing.T, n *Node, observer, target string) healthRow {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT status, COALESCE(deleted_at, '') AS deleted_at, updated_at FROM host_health WHERE observer = ? AND target = ?`,
		observer, target)
	if err != nil {
		t.Fatalf("%s: read host_health: %v", n.Name, err)
	}
	if len(rows) == 0 {
		return healthRow{}
	}
	return healthRow{true, rows[0].String("status"), rows[0].String("deleted_at"), rows[0].String("updated_at")}
}

// TestFleet_HostHealthVerdictAfterARemovalIsLiveOnEveryReplica: `lv host rm`
// tombstones every host_health row about the host. When `lv host add` gives
// the name back and the observers probe it again, each verdict is an
// INSERT OR REPLACE: on its observer it replaces the whole row, tombstone and
// all, but every receiver applied it as an upsert of the columns it names,
// which do not include deleted_at. The observer's verdicts on the new machine
// stayed deleted on every other node for good — no anti-entropy repairs it,
// since on a tie the tombstone wins and it would delete the observer's own
// row too — so the connectivity view and the dual-run detector's last-alive
// evidence, which read live rows only, never saw them.
//
// Mutation: applying the verdict without deleted_at = NULL (the plain
// upsert) leaves r holding the row deleted, and the wait below times out.
func TestFleet_HostHealthVerdictAfterARemovalIsLiveOnEveryReplica(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 3409})
	o, r, d := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)
	go health.NewChecker(o.Name, o.PKIDir, o.DB).Start(ctx)

	eventually(t, convergeTimeout, "r to hold o's live verdict on d", func() bool {
		row := healthRowOn(t, r, o.Name, d.Name)
		return row.present && row.deleted == ""
	})

	// `lv host rm d`: its health rows are tombstoned with it.
	if err := corrosion.DeleteHost(ctx, o.DB, d.Name); err != nil {
		t.Fatalf("remove %s: %v", d.Name, err)
	}
	eventually(t, convergeTimeout, "the removal's tombstone on r", func() bool {
		return healthRowOn(t, r, o.Name, d.Name).deleted != ""
	})

	// `lv host add d` with a new certificate, and its boot write: o probes it
	// again and publishes a verdict over the tombstone.
	if _, err := c.SelfClient(o).AdmitHost(ctx, &pb.AdmitHostRequest{
		Name: d.Name, Address: d.Address, CertSerial: "0a0b0c0d0e0f",
	}); err != nil {
		t.Fatalf("admit %s again: %v", d.Name, err)
	}
	if err := corrosion.UpdateHostStartup(ctx, o.DB, d.Name, "active", "", 0, 0, 0, false); err != nil {
		t.Fatalf("boot write: %v", err)
	}
	eventually(t, convergeTimeout, "o's own verdict on the re-added d", func() bool {
		row := healthRowOn(t, o, o.Name, d.Name)
		return row.present && row.deleted == ""
	})

	// Every replica holds that verdict live, as o does.
	for deadline := time.Now().Add(2 * convergeTimeout); ; time.Sleep(50 * time.Millisecond) {
		mine, theirs := healthRowOn(t, o, o.Name, d.Name), healthRowOn(t, r, o.Name, d.Name)
		if theirs.present && theirs.deleted == "" && theirs.status == mine.status {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("o's verdict on the re-added d: o holds %+v, r holds %+v", mine, theirs)
		}
	}
	edges, err := c.SelfClient(r).GetClusterHealth(ctx, &pb.GetClusterHealthRequest{})
	if err != nil {
		t.Fatalf("cluster health on r: %v", err)
	}
	seen := false
	for _, e := range edges.GetConnectivity() {
		seen = seen || (e.GetObserver() == o.Name && e.GetTarget() == d.Name)
	}
	if !seen {
		t.Errorf("r's connectivity view has no edge %s→%s for the re-added host", o.Name, d.Name)
	}
}
