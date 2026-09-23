package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedFenceQuorum puts a fresh quorum of observations about "bad" in the store
// and returns the coordinator that will act on them.
func seedFenceQuorum(t *testing.T, status string) (*Coordinator, *corrosion.Client, context.Context) {
	t.Helper()
	db := newTestDB(t)
	ctx := context.Background()

	for _, h := range []struct{ name, addr string }{{"bad", "10.0.0.10"}, {"good", "10.0.0.11"}} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h.name, Address: h.addr, SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "manual",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h.name, err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "bad", Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	fresh := time.Now().UTC().Format(time.RFC3339)
	for _, obs := range []string{"coordinator", "good"} {
		if err := db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health
			 (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, 'bad', ?, ?, NULL, ?)`,
			obs, status, offlineThreshold, fresh); err != nil {
			t.Fatalf("insert health: %v", err)
		}
	}
	return newTestCoordinator("coordinator", db), db, ctx
}

// A host every observer can REACH and talk to is not a host to power-cycle.
//
// Fencing quorum counts consecutive_failures, and an unready observation is a
// failed observation — so without excluding it here, teaching the health
// checker to notice a wedged database would have turned that new signal
// straight into a power-off. The two verdicts license different actions: an
// unreachable host cannot be reasoned with and gets fenced; a host that answers
// and says it cannot serve loses its votes, its placements and its pushes, and
// keeps its power.
func TestCoordinator_UnreadyQuorumDoesNotFence(t *testing.T) {
	c, db, ctx := seedFenceQuorum(t, "unready")

	c.run(ctx)

	h, _ := corrosion.GetHost(ctx, db, "bad")
	if h == nil || h.State != "active" {
		t.Errorf("a reachable-but-unready host was fenced; state=%v", h)
	}
	vm, _ := corrosion.GetVM(ctx, db, "vm1")
	if vm == nil || vm.HostName != "bad" {
		t.Errorf("VM rescheduled off a host that was never fenced; vm=%+v", vm)
	}
}

// The control: the same quorum of SUSPECT observations still fences. Without
// it, excluding every row from fencing quorum would pass the test above.
func TestCoordinator_SuspectQuorumStillFences(t *testing.T) {
	c, db, ctx := seedFenceQuorum(t, "suspect")

	c.run(ctx)

	h, _ := corrosion.GetHost(ctx, db, "bad")
	if h == nil || h.State == "active" {
		t.Errorf("an unreachable host with a fresh fencing quorum was not fenced; state=%v", h)
	}
}
