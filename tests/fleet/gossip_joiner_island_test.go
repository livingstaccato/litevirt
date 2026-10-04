// Fleet scenario: hosts re-added together on fresh databases must not form an
// island of their own.
//
// kvm003 drill 6, 2026-10-04 (main-07196394): node-3/4/5 were killed, removed
// with `lv host rm --dead`, rebuilt on fresh databases and re-added seconds
// apart. From then on the three replicated only among themselves. Their
// replicas never received node-1/node-2's hosts rows, so they refused both
// in gossip ("not found in cluster state or gossip"), adopted no voter
// generation, and a rolling restart of either side changed nothing.
//
// Gossip admission let a seeded node with no other host's row admit anyone,
// and closed that window at the first foreign hosts row of ANY kind. The
// rebuilt nodes each booted and pushed their own row to the others before
// anti-entropy's first pass, so each newcomer's window was closed by another
// newcomer. The rows of the established hosts were written long ago and pruned
// from every push backlog, so anti-entropy is the only way they arrive, and
// anti-entropy dials only admitted members. Nothing could break the loop.
//
// The scenario is multi-node by construction: it needs real gossip admission,
// real pushes between the joiners, and anti-entropy across all of it.
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestGossip_FreshJoinersDoNotIslandEachOther(t *testing.T) {
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, Relays: 4, RealGossip: true, Joiners: 2})
	established, joiners := c.Nodes[:2], c.Nodes[2:]
	ctx := context.Background()

	holdsRow := func(on *Node, name string) bool {
		h, err := corrosion.GetHost(ctx, on.DB, name)
		return err == nil && h != nil
	}

	// The drill's moment: each joiner receives the other's own row by push
	// before any anti-entropy has run. That row is what closed the window.
	c.WaitGossip(t, 20*time.Second, "each joiner to be pushed the other joiner's row", func() bool {
		for _, j := range joiners {
			for _, o := range joiners {
				if j != o && !holdsRow(j, o.Name) {
					return false
				}
			}
		}
		return true
	})
	for _, j := range joiners {
		for _, e := range established {
			if holdsRow(j, e.Name) {
				t.Fatalf("%s already holds %s's row before anti-entropy ran; the established history was not "+
					"pruned, so this scenario proves nothing", j.Name, e.Name)
			}
		}
	}

	// Anti-entropy on every node — the operator's `lv cluster converge`, so
	// sampling cannot decide whether a pass reaches the established hosts.
	const bound = 30 * time.Second
	deadline := time.Now().Add(bound)
	for {
		for _, n := range c.Nodes {
			corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
		}
		healed := true
		for _, j := range joiners {
			for _, e := range established {
				if !holdsRow(j, e.Name) || !GossipSees(j, e) || !GossipSees(e, j) {
					healed = false
				}
			}
		}
		if healed {
			return
		}
		if time.Now().After(deadline) {
			for _, j := range joiners {
				for _, e := range established {
					t.Errorf("%s: holds %s's row=%v, admits it in gossip=%v", j.Name, e.Name,
						holdsRow(j, e.Name), GossipSees(j, e))
				}
			}
			t.Fatalf("the joiners formed an island of their own %v after they were pushed each other's rows:\n  %s",
				bound, c.gossipViews())
		}
		time.Sleep(200 * time.Millisecond)
	}
}
