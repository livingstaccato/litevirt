// Fleet scenarios for a removal that a lagging node's later write to the
// removed host races (corrosion/host_removal_stands.go): the host stays
// removed over the WAL and in anti-entropy, and a re-add still converges.
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const removedHost = "wl"

// removalRace is three split nodes holding wl live, node-0 removing it while
// node-2 lags, and node-2 then recording wl's state, stamped after the
// removal it has not seen. Over the WAL, node-1 hears node-2's write before
// node-0's removal: node-0 is cut from node-1 until it has. With aeFirst,
// anti-entropy runs between every pair while node-2's WAL is still cut. A
// non-nil prepare runs on wl's converged row before the race.
func removalRace(t *testing.T, aeFirst bool, prepare func(c *Cluster)) *Cluster {
	t.Helper()
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 5535})
	for _, n := range c.Nodes {
		splitMembership(t, n)
	}
	remover, mid, lagging := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if err := corrosion.InsertHost(ctx, remover.DB, corrosion.HostRecord{
		Name: removedHost, Address: "10.0.0.9", SSHUser: "root", CertSerial: "s1", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	if prepare != nil {
		prepare(c)
	}

	c.Isolate(lagging)
	c.SetLinkFaultBoth(remover, mid, LinkFault{Block: true})
	if err := corrosion.DeleteHost(ctx, remover.DB, removedHost); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := corrosion.UpdateHostState(ctx, lagging.DB, removedHost, "offline"); err != nil {
		t.Fatal(err)
	}
	if h, _ := corrosion.GetHost(ctx, lagging.DB, removedHost); h == nil {
		t.Fatalf("fixture: %s does not hold %s live", lagging.Name, removedHost)
	}
	if aeFirst {
		hostAntiEntropyRound(t, c)
		assertRemoved(t, c, "after anti-entropy, the WAL still cut")
	} else {
		c.SetLinkFaultBoth(lagging, mid, LinkFault{})
		eventually(t, convergeTimeout, mid.Name+" to apply "+lagging.Name+"'s state write", func() bool {
			h, _ := corrosion.GetHost(ctx, mid.DB, removedHost)
			return h != nil && h.State == "offline"
		})
	}
	c.ClearLinkFaults()
	eventually(t, convergeTimeout, "the WAL to drain", func() bool {
		n, err := undelivered(c.Nodes)
		return err == nil && n == 0
	})
	return c
}

// assertRemoved fails for each node that lists wl or counts its vote.
func assertRemoved(t *testing.T, c *Cluster, when string) {
	t.Helper()
	ctx := context.Background()
	for _, n := range c.Nodes {
		if h, err := corrosion.GetHost(ctx, n.DB, removedHost); err != nil || h != nil {
			t.Errorf("%s, %s: GetHost(%s) = %+v (err %v), want it removed", when, n.Name, removedHost, h, err)
		}
		hosts, err := corrosion.ListHosts(ctx, n.DB)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range hosts {
			if h.Name == removedHost {
				t.Errorf("%s, %s: ListHosts lists %s (%s)", when, n.Name, removedHost, h.State)
			}
		}
		if votes(t, n, removedHost) {
			t.Errorf("%s, %s: %s votes", when, n.Name, removedHost)
		}
	}
}

// hostAntiEntropyRound merges every node's full state into every other node,
// the peer-only sensitive lane included.
func hostAntiEntropyRound(t *testing.T, c *Cluster) {
	t.Helper()
	for _, a := range c.Nodes {
		for _, b := range c.Nodes {
			if a == b {
				continue
			}
			if err := b.DB.MergeStateBytesLWW(pullDump(t, c, a)); err != nil {
				t.Fatalf("merge %s into %s: %v", a.Name, b.Name, err)
			}
			if err := b.DB.MergeSensitiveStateBytesLWW(a.DB.DumpSensitiveStateBytes()); err != nil {
				t.Fatalf("merge %s's sensitive state into %s: %v", a.Name, b.Name, err)
			}
		}
	}
}

// TestFleet_ALaggingHostStateWriteDoesNotBringBackARemovedHost: node-0
// removes wl while node-2 lags, and node-2 then records wl's state. wl stays
// removed on every node for GetHost, ListHosts and the voter set: over the
// WAL alone, and when anti-entropy runs before the WAL heals.
//
// Mutations: the WAL removal left to the clock (hostRemovalEndsLocalAdmission
// returns false) turns "the WAL first" red on node-1 and node-2; anti-entropy
// deciding two rows at incarnation 0 by the clock (sameLegacyAdmission
// returns false) turns "anti-entropy first" red on every node.
func TestFleet_ALaggingHostStateWriteDoesNotBringBackARemovedHost(t *testing.T) {
	t.Run("the WAL first", func(t *testing.T) {
		c := removalRace(t, false, nil)
		assertRemoved(t, c, "over the WAL")
		hostAntiEntropyRound(t, c)
		assertRemoved(t, c, "after anti-entropy")
		c.WaitConverged(t, convergeTimeout)
	})
	t.Run("anti-entropy first", func(t *testing.T) {
		c := removalRace(t, true, nil)
		assertRemoved(t, c, "after the WAL heals")
		hostAntiEntropyRound(t, c)
		assertRemoved(t, c, "after a second anti-entropy round")
		c.WaitConverged(t, convergeTimeout)
	})
}

// TestFleet_ARemovedHostReaddedAfterALaggingWriteConverges: after the race
// above, wl is added again, once by the counted re-admission (a new
// incarnation) and once by the legacy one (incarnation 0, a new created_at
// stamp). Every node holds the new admission live, with its certificate.
//
// Mutation: sameLegacyAdmission ignoring created_at (any two rows at 0) turns
// "legacy" red: the tombstone of the first admission ends the second on
// every node after anti-entropy.
func TestFleet_ARemovedHostReaddedAfterALaggingWriteConverges(t *testing.T) {
	for _, counted := range []bool{true, false} {
		name := "legacy"
		if counted {
			name = "counted"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			c := removalRace(t, false, nil)
			remover, lagging := c.Nodes[0], c.Nodes[2]
			assertRemoved(t, c, "before the re-add")
			// node-2 is cut again and still holds whatever the WAL left it.
			c.Isolate(lagging)
			h := corrosion.HostRecord{Name: removedHost, Address: "10.0.0.9", SSHUser: "root",
				CertSerial: "s2", State: corrosion.HostStateJoining}
			if counted {
				if _, _, err := corrosion.AdmitHostV2(ctx, remover.DB, h,
					capabilities.GrantForTest(t, capabilities.FeatureHostIncarnation)); err != nil {
					t.Fatal(err)
				}
			} else if err := corrosion.AdmitHost(ctx, remover.DB, h); err != nil {
				t.Fatal(err)
			}
			hostAntiEntropyRound(t, c)
			c.ClearLinkFaults()
			eventually(t, convergeTimeout, "the WAL to drain", func() bool {
				n, err := undelivered(c.Nodes)
				return err == nil && n == 0
			})
			hostAntiEntropyRound(t, c)
			for _, n := range c.Nodes {
				got, err := corrosion.GetHost(ctx, n.DB, removedHost)
				if err != nil || got == nil || got.CertSerial != "s2" {
					t.Errorf("%s: GetHost(%s) = %+v (err %v), want the re-added host with s2", n.Name, removedHost, got, err)
				}
			}
			c.WaitConverged(t, convergeTimeout)
		})
	}
}

// TestFleet_ARemovedHostOfAnOlderBuild: rows an older build wrote, mid-roll.
// Such a build inserts created_at in whole seconds and re-admits without
// stamping a new one.
//
//   - "its row stays removed": wl's row carries an older build's created_at,
//     and the race above still ends with wl removed everywhere once
//     anti-entropy has run (the serial tells the admission);
//   - "an unstamped re-add is not undone": node-2 missed a re-add an older
//     build made, and still holds the removal; nodes 0 and 1 hold the re-added
//     row under the same created_at with the new certificate. Anti-entropy
//     takes the re-add everywhere.
//
// Mutation: sameLegacyAdmission comparing created_at alone (no serial) turns
// "an unstamped re-add is not undone" red on every node.
func TestFleet_ARemovedHostOfAnOlderBuild(t *testing.T) {
	const legacyCreated = "2026-01-01T00:00:00Z"
	asOlderBuild := func(c *Cluster) {
		for _, n := range c.Nodes {
			if _, err := n.DB.DB().Exec(`UPDATE hosts SET created_at = ? WHERE name = ?`, legacyCreated, removedHost); err != nil {
				t.Fatal(err)
			}
		}
		c.WaitConverged(t, convergeTimeout)
	}
	t.Run("its row stays removed", func(t *testing.T) {
		c := removalRace(t, false, asOlderBuild)
		hostAntiEntropyRound(t, c)
		assertRemoved(t, c, "after anti-entropy")
		c.WaitConverged(t, convergeTimeout)
	})
	t.Run("an unstamped re-add is not undone", func(t *testing.T) {
		ctx := context.Background()
		c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 5536})
		for _, n := range c.Nodes {
			splitMembership(t, n)
		}
		if err := corrosion.InsertHost(ctx, c.Nodes[0].DB, corrosion.HostRecord{
			Name: removedHost, Address: "10.0.0.9", SSHUser: "root", CertSerial: "s1", State: "active",
		}); err != nil {
			t.Fatal(err)
		}
		c.WaitConverged(t, convergeTimeout)
		asOlderBuild(c)
		c.Isolate(c.Nodes[0])
		c.Isolate(c.Nodes[1])
		c.Isolate(c.Nodes[2])
		const removedAt, readdedAt = "2026-02-01T00:00:00.000000000Z", "2026-02-02T00:00:00.000000000Z"
		if _, err := c.Nodes[2].DB.DB().Exec(`UPDATE hosts SET deleted_at = ?, updated_at = ? WHERE name = ?`,
			removedAt, removedAt, removedHost); err != nil {
			t.Fatal(err)
		}
		for _, n := range c.Nodes[:2] {
			if _, err := n.DB.DB().Exec(`UPDATE hosts SET cert_serial = 's2', deleted_at = NULL, updated_at = ? WHERE name = ?`,
				readdedAt, removedHost); err != nil {
				t.Fatal(err)
			}
		}
		hostAntiEntropyRound(t, c)
		for _, n := range c.Nodes {
			got, err := corrosion.GetHost(ctx, n.DB, removedHost)
			if err != nil || got == nil || got.CertSerial != "s2" {
				t.Errorf("%s: GetHost(%s) = %+v (err %v), want the re-added host with s2", n.Name, removedHost, got, err)
			}
		}
	})
}
