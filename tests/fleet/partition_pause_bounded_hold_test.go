// The bridged hold is bounded (lab 1 at f9bafd75, drills W1 P2 and W5c). A
// self-paused host that a non-voter bridge reached was held at its
// partition-pause deadline while the bridge lasted; once the bridge was cut
// too, the bridge's failing run began after the fence, and that restarted
// run (with, on the explicit set, a pause report dated on a clock 60 s
// behind) held the recovery for as long as the outage lasted, with no way
// out but power-off and `lv host fence-confirm`.
//
// When enough voters have failed the host without a break since before the
// fence that it cannot have regained a majority since, the bridge's answers
// are all it can have seen: the deadline goes ahead
// (docs/design/partition-pause.md §4.2 step 3).
package fleet

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
)

// TestFleet_PartitionPause_DerivedSetBridgeCutRecovers: W1 P2. On the
// derived voter set n0..n4 the bridge n5 holds n0's recovery at the deadline
// (TestFleet_PartitionPause_DerivedSetBridgeStallsVisibly). Then n0 is cut
// from n1 and n5 as well. Their failing runs begin after the fence, but n2,
// n3 and n4 have failed n0 since before it: three of five voters, so n0
// cannot have held a majority since. The deadline goes ahead and pp-vm runs
// once, on the majority.
//
// Mutation: drop the derived exemption (selfPauseStillStands passes
// noRegain=false to quietFallback) — the hold stays under the restarted runs
// and the recovery wait times out.
func TestFleet_PartitionPause_DerivedSetBridgeCutRecovers(t *testing.T) {
	ctx := context.Background()
	c, s, rs := derivedBridgeHeld(t)
	owner, n1, n2, n5 := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[5]
	logs := captureLogs(t)

	c.SplitGossip([]*Node{owner}, []*Node{n1, n5})

	minority := c.Nodes[:2]
	dest := waitRecovered(t, c, minority)
	assertRecoveredOnce(t, c, s, rs, dest, minority)
	eventually(t, time.Minute, "ha.recovery.bridged to resolve on node-2", func() bool {
		row, ok, err := corrosion.GetHealthCondition(ctx, n2.DB, failover.RefenceEvaluator,
			failover.CondRecoveryBridged, "host", owner.Name)
		return err == nil && ok && row.Lifecycle == corrosion.ConditionResolved
	})
	out := logs.String()
	for _, want := range []string{
		"partition-pause deadline passed; recovering the host's workloads",
		"the partition-pause deadline went ahead",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("node-2 never logged %q", want)
		}
	}
}

// TestFleet_PartitionPause_ExplicitSetSkewedPauserBridgeCutRecovers: W5c. On
// the explicit voter set n0..n4, n0 alone is cut from the other voters while
// the non-voter n5 still reaches it, and n0's clock is 60 s behind. Its
// partition_paused condition is stamped on that clock, so it reads as
// raised before this outage and the bridged deadline holds. Then n0 is cut
// from n5 too: n5's failing run begins after the fence, but n1..n4 have
// failed n0 since before it, so it cannot have regained a majority, and the
// deadline goes ahead on that alone.
//
// The control arm has no step: the host's word dates to this outage and the
// deadline goes ahead while the bridge still stands, which shows that the
// skew is what holds the bridged deadline.
//
// Mutation: drop the explicit exemption (the noRegainSinceIn check in
// selfPauseStillStands) — the skewed arm holds under the restarted run and
// "predates this outage", and its recovery wait times out.
func TestFleet_PartitionPause_ExplicitSetSkewedPauserBridgeCutRecovers(t *testing.T) {
	for _, skewed := range []bool{true, false} {
		t.Run(map[bool]string{true: "skewed", false: "control"}[skewed], func(t *testing.T) {
			ctx := context.Background()
			c, s, rs := bridgeFleetWith(t, ppOpts{coordinators: map[string]bool{"node-2": true}, pauserOnNodeClock: true}, Options{ClockSeam: true})
			owner, n2, n5 := c.Nodes[0], c.Nodes[2], c.Nodes[5]
			if skewed {
				owner.StepClock(-60 * time.Second)
			}
			minority := []*Node{owner}
			c.SplitGossip(minority, c.Nodes[1:5])

			if !skewed {
				dest := waitRecovered(t, c, minority)
				assertRecoveredOnce(t, c, s, rs, dest, minority)
				return
			}
			eventually(t, ppRecoverBound, "node-2's deadline to hold on a pause report that predates the outage", func() bool {
				row, ok, err := corrosion.GetHealthCondition(ctx, n2.DB, failover.RefenceEvaluator,
					failover.CondRecoveryBridged, "host", owner.Name)
				if err != nil || !ok || row.Lifecycle != corrosion.ConditionConfirmed {
					return false
				}
				var ev struct {
					Detail string `json:"detail"`
				}
				return json.Unmarshal([]byte(row.Evidence), &ev) == nil && strings.Contains(ev.Detail, "predates this outage")
			})
			cond, ok, err := corrosion.GetHealthCondition(ctx, n2.DB, corrosion.PartitionPauseEvaluator,
				corrosion.CondPartitionPaused, "host", owner.Name)
			if err != nil || !ok {
				t.Fatalf("setup: node-2 holds no partition_paused for %s (%v)", owner.Name, err)
			}
			raised, ok := corrosion.ParseUpdatedAt(cond.FirstSeen)
			if !ok || n2.Now().Sub(raised) < 55*time.Second {
				t.Fatalf("setup: %s's partition_paused was raised at %s, not 55 s or more behind node-2's clock: the step did not reach the pauser",
					owner.Name, cond.FirstSeen)
			}
			for _, n := range c.Nodes[1:] {
				if _, ok := firstEvent(n, "start", "pp-vm"); ok {
					t.Fatalf("setup: %s started pp-vm while the bridged deadline held", n.Name)
				}
			}

			c.SplitGossip(minority, []*Node{n5})

			dest := waitRecovered(t, c, minority)
			assertRecoveredOnce(t, c, s, rs, dest, minority)
		})
	}
}
