package fleet

// What one anti-entropy pass costs a cluster, measured (#262).
//
// Every node runs one anti-entropy pass against independent replicas the
// production push loop has already converged, and the serving-side meter
// (ae_meter.go) counts the anti-entropy RPCs answered and the response bytes
// sent. Each shape is measured twice:
//
//   - steady state: every replica agrees, so a pass is digests only;
//   - one drifted row: a single stacks row exists on one node and nowhere
//     else — written beneath the replicator, the divergence anti-entropy is
//     the safety net for — so the pass also pulls dumps.
//
// "legacy" is the pass as it was before #262: every member contacted, and a
// mismatch answered with the full dump. It is reproduced exactly by running
// the full-sweep pass (RunOnce) with every node answering StreamTableDump, the
// paged StreamTableRows and GetTableBucketDigests as
// Unimplemented, which is what the pull's fallback does against an older peer.
// "sampled" is the scheduled pass as the loop now runs it.
//
// The node count is LITEVIRT_FLEET_AE_NODES (default 12, so the test stays
// cheap in the ordinary suite); the figures in docs/operating-model.md were
// taken at 50.

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func aeScaleNodes(t *testing.T) int {
	t.Helper()
	v := os.Getenv("LITEVIRT_FLEET_AE_NODES")
	if v == "" {
		return 12
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 2 {
		t.Fatalf("LITEVIRT_FLEET_AE_NODES=%q: want an integer >= 2", v)
	}
	return n
}

// runAEPass runs one anti-entropy pass on every node, a few at a time — the
// shape of every node's jittered timer firing within one interval. Each node
// gets a fresh AntiEntropy, so the trigger's cooldown does not refuse the pass;
// for the sampled pass that also means a fresh permutation per pass, which is
// the pessimistic case for how fast drift spreads.
func runAEPass(t *testing.T, c *Cluster, sampled bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, n := range c.Nodes {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			ae := corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0)
			if sampled {
				ae.RunSampledOnce(ctx)
			} else {
				ae.RunOnce(ctx)
			}
		}()
	}
	wg.Wait()
}

func logAEStats(t *testing.T, label string, nodes int, stats map[string]AEMethodStats) {
	t.Helper()
	total := AEStatsTotal(stats)
	t.Logf("%-28s @ %d nodes: %6d RPCs %10d bytes (%.1f RPCs/node, %.0f bytes/node)",
		label, nodes, total.Calls, total.Bytes,
		float64(total.Calls)/float64(nodes), float64(total.Bytes)/float64(nodes))
	for _, m := range AEStatsMethods(stats) {
		s := stats[m]
		t.Logf("    %-26s calls=%-6d bytes=%d", m, s.Calls, s.Bytes)
	}
}

func dumpCalls(s map[string]AEMethodStats) (full, table int) {
	return s["StreamStateDump"].Calls + s["GetStateDump"].Calls, s["StreamTableDump"].Calls + s["StreamTableRows"].Calls
}

// seedDrift writes a stacks row on n that no other node has and no push will
// carry.
func seedDrift(t *testing.T, n *Node, name string) {
	t.Helper()
	seedUnreplicatedStack(t, n, name)
}

// convergeByAE runs full-sweep passes until every replica agrees, so the next
// measurement starts from a converged cluster.
func convergeByAE(t *testing.T, c *Cluster) {
	t.Helper()
	for i := 0; i < 10; i++ {
		apart, err := divergence(c.Nodes)
		if err != nil {
			t.Fatalf("divergence: %v", err)
		}
		if len(apart) == 0 {
			return
		}
		runAEPass(t, c, false)
	}
	apart, _ := divergence(c.Nodes)
	t.Fatalf("replicas still apart after 10 full anti-entropy passes: %v", apart)
}

func TestFleet_AntiEntropyScale_PassCost(t *testing.T) {
	nodes := aeScaleNodes(t)
	start := time.Now()
	c := New(t, Options{Nodes: nodes, IndependentReplicas: true})
	a := c.Nodes[0]

	// Enough state that a full dump is not trivially small next to one table.
	for i := 0; i < 200; i++ {
		insertVM(t, a, fmt.Sprintf("vm-%03d", i), a.Name)
	}
	c.WaitConverged(t, 90*time.Second)
	t.Logf("cluster of %d up and converged in %s", nodes, time.Since(start).Round(time.Millisecond))

	// ── sampled, the scheduled pass as it now runs ──
	c.ResetAEStats()
	runAEPass(t, c, true)
	sampledSteady := c.AEStats()
	logAEStats(t, "sampled, steady state", nodes, sampledSteady)

	seedDrift(t, c.Nodes[len(c.Nodes)/2], "drift-sampled")
	c.ResetAEStats()
	runAEPass(t, c, true)
	sampledDrift := c.AEStats()
	logAEStats(t, "sampled, one drifted row", nodes, sampledDrift)

	// How many sampled passes the drifted row takes to reach every replica.
	passes := 1
	for ; passes < 30; passes++ {
		if apart, err := divergence(c.Nodes); err != nil {
			t.Fatalf("divergence: %v", err)
		} else if len(apart) == 0 {
			break
		}
		runAEPass(t, c, true)
	}
	t.Logf("sampled passes until every replica held the drifted row: %d", passes)
	convergeByAE(t, c)

	// ── legacy: every member, full dump ──
	for _, n := range c.Nodes {
		defer n.DoNotImplement("StreamTableDump")()
		defer n.DoNotImplement("StreamTableRows")()
		defer n.DoNotImplement("StreamSensitiveTableRows")()
		defer n.DoNotImplement("GetTableBucketDigests")()
	}
	c.ResetAEStats()
	runAEPass(t, c, false)
	legacySteady := c.AEStats()
	logAEStats(t, "legacy, steady state", nodes, legacySteady)

	seedDrift(t, c.Nodes[len(c.Nodes)/2], "drift-legacy")
	c.ResetAEStats()
	runAEPass(t, c, false)
	legacyDrift := c.AEStats()
	logAEStats(t, "legacy, one drifted row", nodes, legacyDrift)
	t.Logf("total elapsed %s", time.Since(start).Round(time.Millisecond))

	// What the numbers must say, at any size.
	for label, s := range map[string]map[string]AEMethodStats{"sampled": sampledSteady, "legacy": legacySteady} {
		if full, table := dumpCalls(s); full+table != 0 {
			t.Errorf("%s: a pass over converged replicas pulled a dump: %+v", label, s)
		}
	}
	if full, table := dumpCalls(sampledDrift); full != 0 || table == 0 {
		t.Errorf("sampled drift pass: full dumps=%d table dumps=%d, want table dumps only", full, table)
	}
	if full, _ := dumpCalls(legacyDrift); full == 0 {
		t.Errorf("precondition: the legacy drift pass pulled no full dump, so it is not the legacy pass: %+v", legacyDrift)
	}
	if legacySteady["GetStateDigest"].Calls != nodes*(nodes-1) {
		t.Errorf("precondition: legacy pass made %d digest calls, want every ordered pair = %d",
			legacySteady["GetStateDigest"].Calls, nodes*(nodes-1))
	}
	// Relays + k per node: at most 3+⌈N/50⌉−1 fellow relays (a relay) or 2
	// (a leaf), plus k=2.
	maxPerNode := 3 + (nodes+49)/50 - 1 + 2
	if got := sampledSteady["GetStateDigest"].Calls; got > nodes*maxPerNode {
		t.Errorf("sampled pass made %d digest calls, want at most %d per node (%d)", got, maxPerNode, nodes*maxPerNode)
	}
	if nodes > maxPerNode+1 && AEStatsTotal(sampledSteady).Calls >= AEStatsTotal(legacySteady).Calls {
		t.Errorf("sampled steady-state pass (%d RPCs) is no cheaper than the legacy pass (%d)",
			AEStatsTotal(sampledSteady).Calls, AEStatsTotal(legacySteady).Calls)
	}
}
