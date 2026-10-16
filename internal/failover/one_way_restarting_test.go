package failover

import (
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A host restarting ('upgrading', inside its allowance) is not a one-way
// partition. Its daemon writes healthy rows for its peers before its own gRPC
// server serves, so the voters fail it while it marks them healthy — exactly
// the one-way shape — for the 15-25 s a graceful restart takes (lab 1,
// 2026-10-16: the raises checked that day were on hosts coming back; some of
// them may have been hosts returning from a fence, which this does not cover).
// The fence path already skips such a host; the one-way check ran before that
// skip. A host booting back from a fence is recorded 'fenced' or 'offline',
// not 'upgrading', and can still raise it for that window.
//
// Mutation: run detectOneWay before the restarting check, as before — the
// condition is raised and this goes red.
func TestPartitionPause_ARestartingHostIsNotOneWay(t *testing.T) {
	c, db, ctx, _ := pauseCoordinator(t, true)
	ensureVoter(t, db, "down")
	if err := corrosion.UpdateHostState(ctx, db, "down", "upgrading"); err != nil {
		t.Fatal(err)
	}
	seedOneWay(t, db, c.now(), -20*time.Second)
	c.run(ctx)
	if row, raised := oneWayRow(t, db); raised {
		t.Fatalf("partition_one_way raised for a host restarting inside its allowance: %+v", row)
	}
	// Past the allowance it is judged as any host.
	c.UpgradingTimeout = time.Nanosecond
	c.run(ctx)
	if row, raised := oneWayRow(t, db); !raised {
		t.Fatalf("partition_one_way not raised for a host 'upgrading' past its allowance: %+v", row)
	}
}
