package fleet

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
)

// relayElection is the relay set node n elects from its OWN replica — the
// exact inputs the replicator and anti-entropy use (Members, hosts, demotion
// rows), so two nodes that disagree here push through different relays.
func relayElection(n *Node, cfg corrosion.RelayConfig) *corrosion.RelaySet {
	return corrosion.ComputeRelays(n.DB.Members(), n.Name, cfg,
		corrosion.RelayEligibleHosts(context.Background(), n.DB))
}

// TestFleet_RelayHealthDemotesADegradedLinkEverywhere (colonelpanik/litevirt#175):
// node-0 sorts first, so name order makes it a relay. First ONE link to it
// degrades, for longer than healthFreshness: one observer of four is below
// the bar, and nothing is demoted. Then its links from node-1 and node-2
// degrade — their readiness probes of it fail, replication still
// gets through — which is two of its four voter observers, a third, and short
// of the three a fence needs. The failover lease holder demotes it, and every
// node then elects the SAME relay set without it, with node-0 a leaf that
// still has its relay pair. Healed, it is restored on every node after the
// restore window.
//
// Real health checkers, real readiness RPCs through the per-link fault
// injector, the production Replicator push loop; only the windows are shortened.
//
// Mutations: (1) count only FRESH verdicts in the demotion denominator (the
// round-0 evaluator) — the healthy verdicts age out, the one degraded link
// reads 1/1 and node-0 is demoted, red; and the healed verdicts age out
// inside the 45 s restore window, so it would never be restored either.
// (2) Compute eligibility from each node's LOCAL probe view instead of
// the replicated demotion rows — node-1 and node-2 drop node-0 while node-0,
// node-3 and node-4 keep it, the sets disagree, red.
func TestFleet_RelayHealthDemotesADegradedLinkEverywhere(t *testing.T) {
	restore := []func(){}
	defer func() {
		for _, f := range restore {
			f()
		}
	}()
	for _, v := range []struct {
		p *time.Duration
		d time.Duration
	}{
		{&failover.RelayDemoteWindow, 6 * time.Second},
		// Longer than healthFreshness (30 s), as in production: a healed
		// observer publishes one healthy verdict and then nothing, and that
		// verdict must still count when the window ends.
		{&failover.RelayRestoreWindow, 45 * time.Second},
	} {
		old := *v.p
		*v.p = v.d
		restore = append(restore, func() { *v.p = old })
	}

	cfg := corrosion.RelayConfig{BaseRelays: 2}
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, Relays: cfg.BaseRelays, FaultSeed: 1750})
	c.WaitConverged(t, convergeTimeout)
	n0, n1, n2, lead := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[4]

	// relay_health_v1 and failover_scope_v1 latched: every node runs this
	// build.
	for _, n := range c.Nodes {
		n.DB.SetClusterPolicyGate(func() bool { return true })
		n.DB.SetRelayHealthGate(func() bool { return true })
	}
	if rs := relayElection(n0, cfg); !rs.IsRelay(n0.Name) {
		t.Fatalf("precondition: relays = %v, want %s (it sorts first)", rs.Relays(), n0.Name)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	for _, n := range c.Nodes {
		chk := health.NewChecker(n.Name, n.PKIDir, n.DB)
		chk.SetPeerReadiness(n.Server.PeerReady)
		wg.Add(1)
		go func() { defer wg.Done(); chk.Start(ctx) }()
	}

	// One lease holder, driven here so the shortened windows are only ever
	// read from this goroutine.
	var fences []string
	coord := failover.NewCoordinator(lead.Name, lead.DB)
	coord.SetFencer(func(_ context.Context, h fence.HostConfig) fence.Result {
		fences = append(fences, h.Name)
		return fence.Result{Method: "fleet-test", Success: true}
	})
	coord.RelayConfig = cfg
	tick := func() { coord.RunOnce(ctx) }

	// One degraded link of four is below the bar (a third: 2). Held well
	// past healthFreshness, so the other observers' healthy verdicts — written
	// once, at their first probe — are stale, as they are in production.
	c.SetLinkFault(n1, n0, LinkFault{BlockReady: true})
	oneLink := time.Now().Add(55 * time.Second)
	for time.Now().Before(oneLink) {
		tick()
		if d, _ := corrosion.ListRelayDemotions(ctx, lead.DB); len(d) != 0 {
			t.Fatalf("demoted %v with one of four observers failing", d)
		}
		time.Sleep(time.Second)
	}

	c.SetLinkFault(n2, n0, LinkFault{BlockReady: true})

	agree := func(wantRelay bool) (bool, string) {
		var first []string
		for _, n := range c.Nodes {
			rs := relayElection(n, cfg)
			if rs.IsRelay(n0.Name) != wantRelay {
				return false, fmt.Sprintf("%s elects %v", n.Name, rs.Relays())
			}
			if !wantRelay && rs.AssignedRelays(n0.Name)[0] == "" {
				return false, fmt.Sprintf("%s gives %s no relay pair", n.Name, n0.Name)
			}
			if first == nil {
				first = rs.Relays()
			} else if !slices.Equal(first, rs.Relays()) {
				return false, fmt.Sprintf("%s elects %v, %s elects %v", c.Nodes[0].Name, first, n.Name, rs.Relays())
			}
		}
		return true, ""
	}
	waitAgree := func(wantRelay bool, within time.Duration, what string) {
		t.Helper()
		deadline := time.Now().Add(within)
		last := ""
		for time.Now().Before(deadline) {
			tick()
			ok, why := agree(wantRelay)
			if ok {
				return
			}
			last = why
			time.Sleep(time.Second)
		}
		t.Fatalf("%s: never happened within %s; last: %s", what, within, last)
	}

	waitAgree(false, 90*time.Second, "every node electing the same relay set without "+n0.Name)
	if len(fences) != 0 {
		t.Fatalf("fenced %v: a third of the observers failing is a demotion, not a fence", fences)
	}

	c.ClearLinkFaults()
	waitAgree(true, 3*time.Minute, n0.Name+" restored to relay duty on every node after the heal")
	if len(fences) != 0 {
		t.Fatalf("fenced %v", fences)
	}
}
