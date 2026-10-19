package fleet

// What the health-probe mesh costs a cluster per cycle, measured (#262).
//
// Every node runs a real health.Checker whose probes are real Ready RPCs over
// mTLS to the other daemons, and the serving-side probe meter (probe_meter.go)
// counts the probes answered and their response bytes. Each size runs several
// consecutive cycles on every node, a few nodes at a time, and each cycle must
// send exactly the documented number of probes (docs/operating-model.md,
// "Health-probe cost"):
//
//   - with today's voter set, where every host not offline, maintenance or
//     fenced votes, every voter probes every peer: N·(N−1);
//   - with a voter set smaller than the cluster, a non-voter probes every
//     voter plus three other non-voters.
//
// The count asserted is the probes each checker SENDS, counted where it calls
// its prober, so a probe that a loaded machine lets time out still counts as
// planned. Every one sent that did not fail at the caller must have been
// answered by a server, and no server may answer more than were sent, which
// is what makes the serving-side meter a check on the wire, not on the plan.
//
// The sizes run are those up to LITEVIRT_FLEET_PROBE_NODES (default 20, so the
// test stays cheap in the ordinary suite); the 50-node figures need it at 50.

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
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

func probeMeshMaxNodes(t *testing.T) int {
	t.Helper()
	v := os.Getenv("LITEVIRT_FLEET_PROBE_NODES")
	if v == "" {
		return 20
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 5 {
		t.Fatalf("LITEVIRT_FLEET_PROBE_NODES=%q: want an integer >= 5", v)
	}
	return n
}

func TestFleet_ProbeMesh_CostPerCycle(t *testing.T) {
	maxNodes := probeMeshMaxNodes(t)
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
			if tc.nodes > maxNodes {
				t.Skipf("%d nodes: set LITEVIRT_FLEET_PROBE_NODES=%d to run it", tc.nodes, tc.nodes)
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

	// sent and failed count, at the caller, the probes the checkers send and
	// the ones that failed there. The checkers run a few at a time, so they are
	// only ever written from one cycle.
	var sent, failed atomic.Int64
	checkers := make([]*health.Checker, len(c.Nodes))
	for i, n := range c.Nodes {
		chk := health.NewChecker(n.Name, n.PKIDir, n.DB)
		chk.SetPeerReadiness(func(ctx context.Context, host, addr string) (bool, string, error) {
			sent.Add(1)
			ok, reason, err := n.Server.PeerReady(ctx, host, addr)
			if err != nil {
				failed.Add(1)
			}
			return ok, reason, err
		})
		checkers[i] = chk
	}

	// cycle runs one probe cycle on every node, a few at a time, and returns
	// what the checkers sent and the cluster served.
	cycle := func() (probes, served, lost, bytes int64, took time.Duration) {
		c.ResetProbeStats()
		sent.Store(0)
		failed.Store(0)
		start := time.Now()
		sem := make(chan struct{}, 8)
		var wg sync.WaitGroup
		for _, chk := range checkers {
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				if !chk.CheckAllPeersForTests(ctx) {
					t.Error("a probe cycle could not list the hosts")
				}
			}()
		}
		wg.Wait()
		took = time.Since(start)
		served, bytes = c.ProbeStats()
		return sent.Load(), served, failed.Load(), bytes, took
	}
	run := func(label string, want int) {
		t.Helper()
		for i := range probeMeshCycles {
			probes, served, lost, bytes, took := cycle()
			t.Logf("%s, cycle %d: %d probes (%.0f/s at a %v interval), %d served, %d failed at the caller, %d response bytes, %v wall",
				label, i+1, probes, float64(probes)/probeCheckInterval.Seconds(), probeCheckInterval,
				served, lost, bytes, took.Round(time.Millisecond))
			if probes != int64(want) {
				t.Errorf("%s, cycle %d: %d probes sent, want %d", label, i+1, probes, want)
			}
			// A probe that failed at the caller may still have reached a
			// server; one that did not fail must have.
			if served > probes || served < probes-lost {
				t.Errorf("%s, cycle %d: %d probes sent, %d failed at the caller, but %d served: a probe is not costing one Ready RPC",
					label, i+1, probes, lost, served)
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
