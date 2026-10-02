// Fleet scenario: the two halves of a healed gossip partition merge again
// (colonelpanik/litevirt#260).
//
// kvm003 drill, 2026-10-02: nftables split {node-1,node-2} from
// {node-3,node-4,node-5} for five minutes. More than eight minutes after the
// heal both sides were still logging "cleaned watermark for departed peer" for
// the other, and the minority never received what the majority wrote during the
// partition — a fence row, a VM moved to node-5, a claim proof — until a daemon
// restart called Join.
//
// The re-join loop dialled only when a node saw NOBODY, and neither side of a
// 2|3 split is empty. memberlist does not re-merge two live clusters by itself:
// each side declares the other dead, reaps it after GossipToTheDeadTime, and
// nobody dials it again. Replication and anti-entropy both take their peers
// from Members(), so nothing else repairs it either.
//
// The failure is multi-node by construction, and only a real memberlist can
// show it: the default harness seeds Members(), so its view never decays.
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// remergeBound is how long after the heal the halves have to be one cluster
// again, with the partition's write replicated. At the harness's 200 ms base
// interval the re-merge backoff caps at four passes, about 1.25 s; the rest is
// headroom for the replicator's own reconnect under a loaded runner. The old
// trigger never merges at all, so the bound only has to be finite.
const remergeBound = 30 * time.Second

func TestGossip_HealedPartitionRemergesAndReplicates(t *testing.T) {
	key, err := pki.NewGossipKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		key       []byte
		restarted bool
	}{
		{name: "plaintext"},
		// A re-merge is memberlist's ordinary Join, so under an enforced
		// keyring it must cross the cut encrypted and be admitted like any
		// other join — and drop nothing on encryption grounds doing it.
		{name: "enforced", key: key},
		// Every daemon restarts during the partition, losing the gossip
		// addresses it remembered: the re-merge has only the hosts table's
		// recorded addresses to dial, on the cluster's one gossip_port.
		{name: "restarted", restarted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testHealedPartitionRemerges(t, tc.key, tc.restarted)
		})
	}
}

func testHealedPartitionRemerges(t *testing.T, key []byte, restarted bool) {
	// Every node a relay, so each side of the split keeps replicating within
	// itself (with three base relays a leaf can lose every relay it has).
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, Relays: 5, RealGossip: true, GossipKey: key})
	minority, majority := c.Nodes[:2], c.Nodes[2:]

	c.SplitGossip(minority, majority)

	// Each side declares the other dead... which can take well over 30 s. A
	// node whose probes keep failing degrades its own Lifeguard health score,
	// and memberlist stretches its probe interval and suspicion timeout by up
	// to 8x: on the two-node side, node-0 has been seen still holding a
	// majority node alive 30 s in while that node had long dropped node-0.
	// This bound is how long detection may take, not a claim about it.
	c.WaitGossip(t, 2*time.Minute, "each side of the split to lose the other", func() bool {
		for _, a := range minority {
			for _, b := range majority {
				if GossipSees(a, b) || GossipSees(b, a) {
					return false
				}
			}
		}
		return true
	})
	// ...and keeps its own side.
	for _, side := range [][]*Node{minority, majority} {
		for _, a := range side {
			for _, b := range side {
				if a != b && !GossipSees(a, b) {
					t.Fatalf("%s lost %s on its own side of the split:\n  %s", a.Name, b.Name, c.gossipViews())
				}
			}
		}
	}
	// ...and then REAPS it: past GossipToTheDeadTime memberlist stops
	// gossiping to a dead member, which is what leaves nobody to dial it once
	// the network heals. Healing before that would let memberlist re-merge by
	// itself and prove nothing, so it is observed, not assumed.
	c.WaitGossipReaped(t, 30*time.Second)
	if restarted {
		c.ForgetGossipAddresses()
	}

	// The majority writes while the minority cannot hear it — the drill's
	// fence row, moved VM and claim proof stand in as one replicated row.
	ctx := context.Background()
	const marker = "written-during-partition"
	writer := majority[0]
	if err := corrosion.UpdateHostVersion(ctx, writer.DB, writer.Name, marker); err != nil {
		t.Fatal(err)
	}
	versionOn := func(n *Node) string {
		h, err := corrosion.GetHost(ctx, n.DB, writer.Name)
		if err != nil || h == nil {
			return ""
		}
		return h.Version
	}
	// It replicates within the majority, and does NOT cross the split: the
	// partition is real for replication too.
	c.WaitGossip(t, 15*time.Second, "the write to replicate within the majority", func() bool {
		for _, n := range majority {
			if versionOn(n) != marker {
				return false
			}
		}
		return true
	})
	for _, n := range minority {
		if versionOn(n) == marker {
			t.Fatalf("%s received the majority's write across the partition; the split is not a split", n.Name)
		}
	}

	healed := time.Now()
	c.HealGossip()

	c.WaitGossip(t, remergeBound, "the halves of the healed partition to merge into one gossip cluster",
		c.GossipConverged)
	merged := time.Since(healed)

	for _, n := range minority {
		n := n
		c.WaitGossip(t, remergeBound-time.Since(healed), n.Name+" to receive the write made during the partition",
			func() bool { return versionOn(n) == marker })
	}
	t.Logf("gossip re-merged %v after the heal; the partition's write reached the minority %v after it",
		merged.Round(time.Millisecond), time.Since(healed).Round(time.Millisecond))

	if len(key) > 0 {
		for _, n := range c.Nodes {
			if r := n.DB.GossipAuthRejections(); r != 0 {
				t.Errorf("%s dropped %d gossip messages on encryption grounds; a re-merge must run under the "+
					"cluster key like any join", n.Name, r)
			}
		}
	}
}
