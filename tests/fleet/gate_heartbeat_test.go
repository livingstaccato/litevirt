// The fleet's gates run the stall heartbeat, as the daemon's checker does.
//
// A health.Checker measures its own scheduling: a gap between two beats
// longer than a probe tick reads as "this node was not running", and for the
// grace window after it the checker counts no peer as live that it last saw
// healthy before the gap (gate.go quorumOver). In the daemon the heartbeat
// beats every 250ms whatever else the node is doing, so only a node that
// really stopped sees a gap. A gate the harness wires WITHOUT the heartbeat
// beats only when something reads it, so any scenario step that takes longer
// than a probe tick between two gate reads — a replication run, under -race —
// reads as a stall, and the next gate read refuses with no_quorum. That is
// how every TestFleet_AutoPromote_* scenario failed under -race once a
// replication run grew past the tick.

package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/health"
)

// A gate nobody reads for longer than a probe tick is idle, not stalled: the
// execution gate still holds quorum afterwards.
//
// Mutation "no heartbeat in the harness" (gateFor does not start it) — red:
// the gate refuses with no_quorum and logs a stall.
func TestFleet_Gate_AnIdleGateIsNotAStalledOne(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	gates := enforceGate(t, c)
	ctx := context.Background()

	// Longer than the stall threshold (one probe tick), with no gate read.
	time.Sleep(health.StallGrace/health.FailuresToFence + 500*time.Millisecond)

	for _, n := range c.Nodes {
		if g := gates[n.Name].ExecutionGate(ctx); !g.OK {
			t.Errorf("%s: ExecutionGate after an idle spell = %s, want OK: an idle gate read as a stall", n.Name, g.Reason)
		}
		if gates[n.Name].InStallGrace() {
			t.Errorf("%s: in stall grace after an idle spell; nothing stopped", n.Name)
		}
	}
}
