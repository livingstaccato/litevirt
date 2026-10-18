package fleet

// What the health-probe mesh costs a cluster per cycle, measured (#262).
//
// Every node runs a real health.Checker whose probes are real Ready RPCs over
// mTLS to the other daemons, and the serving-side probe meter (probe_meter.go)
// counts the probes answered and their response bytes. Each size runs several
// consecutive cycles on every node at once — the shape of every checker's 2 s
// tick — and each cycle must cost exactly the documented number of probes
// (docs/operating-model.md, "Health-probe cost"):
//
//   - with today's voter set, where every host not offline, maintenance or
//     fenced votes, every voter probes every peer: N·(N−1);
//   - with a voter set smaller than the cluster, a non-voter probes every
//     voter plus three other non-voters.
//
// The 50-node size boots 50 daemons; -short stops at 20.

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// probeCheckInterval is the checker's probe interval (docs/migration-failover.md,
// "Hosts probe each other ... every 2 seconds"), for the per-second figure.
const probeCheckInterval = 2 * time.Second

// probeMeshCycles is how many consecutive cycles each shape runs. Every one
// must cost the same: a cycle that costs more than the last is a leak.
const probeMeshCycles = 3

func TestFleet_ProbeMesh_CostPerCycle(t *testing.T) {
	for _, tc := range []struct {
		nodes, voters int
		// The documented probes per cycle: every host voting, and with
		// `voters` voters.
		allVoting, withVoters int
	}{
		{5, 3, 20, 20},
		{20, 5, 380, 215},
		{50, 5, 2450, 605},
	} {
		t.Run(fmt.Sprintf("nodes=%d", tc.nodes), func(t *testing.T) {
			if testing.Short() && tc.nodes > 20 {
				t.Skip("-short: the 50-node size boots 50 daemons")
			}
			// The documented figures are what the probe plan's own formula
			// gives; a table entry that disagrees with it is a typo here, not
			// a measurement.
			n, v := tc.nodes, tc.voters
			if tc.allVoting != n*(n-1) || tc.withVoters != v*(n-1)+(n-v)*(v+min(3, n-v-1)) {
				t.Fatalf("table entry %+v disagrees with the probe plan's formula", tc)
			}
			measureProbeMesh(t, tc.nodes, tc.voters, tc.allVoting, tc.withVoters)
		})
	}
}

func measureProbeMesh(t *testing.T, nodes, voters, allVoting, withVoters int) {
	ctx := context.Background()
	booted := time.Now()
	c := New(t, Options{Nodes: nodes})
	t.Logf("%d nodes booted in %v", nodes, time.Since(booted).Round(time.Millisecond))

	checkers := make([]*health.Checker, len(c.Nodes))
	for i, n := range c.Nodes {
		chk := health.NewChecker(n.Name, n.PKIDir, n.DB)
		chk.SetPeerReadiness(n.Server.PeerReady)
		checkers[i] = chk
	}

	// cycle runs one probe cycle on every node at once and returns what the
	// cluster served.
	cycle := func() (probes, bytes int64, took time.Duration) {
		c.ResetProbeStats()
		start := time.Now()
		var wg sync.WaitGroup
		for _, chk := range checkers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if !chk.CheckAllPeersForTests(ctx) {
					t.Error("a probe cycle could not list the hosts")
				}
			}()
		}
		wg.Wait()
		took = time.Since(start)
		probes, bytes = c.ProbeStats()
		return probes, bytes, took
	}
	run := func(label string, want int) {
		t.Helper()
		for i := range probeMeshCycles {
			probes, bytes, took := cycle()
			t.Logf("%s, cycle %d: %d probes (%.0f/s at a %v interval), %d response bytes, %v wall",
				label, i+1, probes, float64(probes)/probeCheckInterval.Seconds(), probeCheckInterval,
				bytes, took.Round(time.Millisecond))
			if probes != int64(want) {
				t.Errorf("%s, cycle %d: %d probes, want %d", label, i+1, probes, want)
			}
		}
	}

	// Today's voter set: every active host votes.
	vs, err := corrosion.VoterSet(ctx, c.Nodes[0].DB)
	if err != nil {
		t.Fatalf("VoterSet: %v", err)
	}
	if len(vs) != nodes {
		t.Fatalf("precondition: %d voters of %d hosts; today's voter set has every active host voting", len(vs), nodes)
	}
	run(fmt.Sprintf("%d nodes, every host voting", nodes), allVoting)

	// A voter set smaller than the cluster.
	names := make([]string, 0, len(c.Nodes))
	for _, n := range c.Nodes {
		names = append(names, n.Name)
	}
	sort.Strings(names)
	set := map[string]bool{}
	for _, name := range names[:voters] {
		set[name] = true
	}
	for _, chk := range checkers {
		chk.SetVoterSetForTests(func(context.Context) (map[string]bool, error) { return set, nil })
	}
	run(fmt.Sprintf("%d nodes, %d voters", nodes, voters), withVoters)
}
