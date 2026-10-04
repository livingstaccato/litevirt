// Fleet scenarios: when did the outage start? A confirmation made during an
// outage belongs to it however long the outage then runs.
//
// Observed on the kvm003 lab (main-e004c250). The coordinator estimated an
// observer's run start as updated_at − (n−1) × health.ProbeInterval, one failed
// probe per 2 s. A probe of a powered-off host runs out its dial timeout, so a
// run actually advanced one count every ~2.85 s (node-2's view of node-5 in
// drill 5: n=3 at 05:53:47.4, n=19 at 05:54:32.9), and the estimated start
// drifted later the longer the host stayed down. In drill 6 operator
// confirmations made at 06:02:44 were judged to predate an outage "starting"
// at 06:03:09 ("both predate this outage, NOT resuming"), and nothing
// recovered on the forced generation for six minutes. In drill 3 a fence
// resume was declined the same way: "no observer has watched the host stay
// down".
//
// A failing verdict now carries its run's start in last_seen, and the
// coordinator reads that instead of estimating it.
package fleet

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// labCadence is how often a run of failed probes of a powered-off host
// advanced on the lab: the dial timeout, not health.ProbeInterval.
const labCadence = 2850 * time.Millisecond

// publishHealthRun writes n's failing verdict about target for a run of failed
// probes that began at began, one every labCadence, last published at `at`.
// carryStart is this build's checker, which publishes began in last_seen; an
// older build's verdict carries none.
func publishHealthRun(t *testing.T, n *Node, target string, began, at time.Time, carryStart bool) {
	t.Helper()
	failures := int(at.Sub(began)/labCadence) + 1
	var lastSeen interface{}
	if carryStart {
		lastSeen = began.UTC().Format(time.RFC3339Nano)
	}
	if err := n.DB.Execute(context.Background(),
		`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
		n.Name, target, "suspect", failures, lastSeen, at.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("publish %s's health of %s: %v", n.Name, target, err)
	}
}

// TestFleet_ConfirmationDuringALongOutageCounts is drill 6's order of events
// at the lab's probe cadence: d goes dark, the operator confirms it off thirty
// seconds later, and the coordinator looks six minutes after that, with no
// fence of d on record. The confirmation belongs to this outage, so the lease
// holder fences d afresh and recovers its VM.
//
//   - this-outage: both observers on this build. Fenced once, VM moved.
//   - stale-confirmation: d answered after the confirmation and has been dark
//     again for three minutes. Nothing is fenced, nothing moves.
//   - older-build-observers: the same outage as this-outage, reported by
//     observers whose verdicts carry no start. The coordinator falls back to
//     the count's lower bound, which never counts an earlier outage's
//     confirmation as this one's and so, at this cadence, does not count this
//     one either: nothing moves until an observer on this build reports.
//
// Mutation: ignore last_seen in observerStreakSpans (estimate from the count
// alone, as before) — this-outage goes red: nothing is fenced, as on the lab.
func TestFleet_ConfirmationDuringALongOutageCounts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		seed       int64
		stale      bool
		carryStart bool
		wantMove   bool
	}{
		{name: "this-outage", seed: 3201, carryStart: true, wantMove: true},
		{name: "stale-confirmation", seed: 3202, stale: true, carryStart: true},
		{name: "older-build-observers", seed: 3203},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: tc.seed})
			a, b, d := c.Nodes[0], c.Nodes[1], c.Nodes[2]
			vm := "vm-" + tc.name
			insertVM(t, a, vm, d.Name)
			c.WaitConverged(t, convergeTimeout)
			c.Kill(d)

			clock := NewVirtualClock(time.Now().UTC())
			cs := c.NewCoordinators(clock)
			// d went dark thirty seconds before the operator confirmed it off.
			// FenceHost stamps the row with the real clock, which the virtual
			// one started from.
			outage := clock.Now().Add(-30 * time.Second)
			if _, err := c.SelfClient(a).FenceHost(ctx,
				&pb.FenceHostRequest{Name: d.Name, Confirmed: true, ConfirmManualOnly: true}); err != nil {
				t.Fatalf("fence-confirm %s: %v", d.Name, err)
			}
			clock.Advance(6 * time.Minute)
			if tc.stale {
				// d answered after the confirmation; this run began three
				// minutes ago.
				outage = clock.Now().Add(-3 * time.Minute)
			}
			for _, o := range []*Node{a, b} {
				publishHealthRun(t, o, d.Name, outage, clock.Now(), tc.carryStart)
			}
			c.WaitConverged(t, convergeTimeout, a, b)

			for i := 0; i < 3; i++ {
				cs.Tick(ctx, a)
				clock.Advance(contentionPoll)
			}

			fencedD := 0
			for _, f := range cs.Fences() {
				if f.Target == d.Name {
					fencedD++
				}
			}
			moved := vmOn(t, a, vm).HostName != d.Name
			if !tc.wantMove {
				if fencedD != 0 || moved {
					t.Fatalf("fenced %s %d times, VM moved=%v; want neither", d.Name, fencedD, moved)
				}
				return
			}
			if fencedD != 1 {
				t.Fatalf("the coordinator fenced %s %d times on a confirmation made thirty seconds into this outage, "+
					"want exactly 1 fresh fence", d.Name, fencedD)
			}
			if !moved {
				t.Fatalf("%s is still recorded on %s after the confirmation and a fresh fence", vm, d.Name)
			}
		})
	}
}
