// The container half of colonelpanik/litevirt#250 (docs/design/recovery-claims.md
// §7.1 "Containers"): the two-coordinator scenario of
// failover_two_coordinators_test.go through startRelocation. A container's
// rootfs died with its host, so relocation re-keys its row to a survivor for
// that survivor to recreate it from its image — and two coordinators that each
// believe they hold the lease can each re-key it to themselves.
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// liveContainerHosts lists the hosts n's replica has a live row for name on.
func liveContainerHosts(t *testing.T, n *Node, name string) []string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT host_name FROM containers WHERE name = ? AND deleted_at IS NULL ORDER BY host_name`, name)
	if err != nil {
		t.Fatalf("%s: read containers: %v", n.Name, err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.String("host_name"))
	}
	return out
}

// TestFleet_TwoCoordinators_OneFailedHost_OneContainerOwner.
//
// Mutation (claims arm): skip claimContainerRelocation in imageRecreateOrSkip —
// each coordinator re-keys the container to itself, and after the heal two
// live rows claim it.
func TestFleet_TwoCoordinators_OneFailedHost_OneContainerOwner(t *testing.T) {
	for _, tc := range []struct {
		name   string
		claims bool
	}{
		{"proof-gated", false},
		{"proof-gated-with-claims", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			clock := NewVirtualClock(time.Now().UTC())
			place := func(c *Cluster, a, _, victim *Node) {
				if err := corrosion.UpsertContainer(ctx, a.DB, corrosion.ContainerRecord{
					HostName: victim.Name, Name: "ct-victim", Image: "docker.io/library/alpine:3.19",
					State: "running", OnHostFailure: "image-recreate", MemMiB: 512,
				}); err != nil {
					t.Fatalf("seed container: %v", err)
				}
			}
			var c *Cluster
			var a, b, victim *Node
			if tc.claims {
				c, a, b, victim = claimFleetWith(t, clock, 2541, place)
			} else {
				c = New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2541})
				a, b, victim = c.Nodes[0], c.Nodes[1], c.Nodes[2]
				place(c, a, b, victim)
				c.WaitConverged(t, convergeTimeout)
				c.Isolate(victim)
				c.SetLinkFaultBoth(a, b, slowLink)
				PublishHealth(t, a, victim.Name, 5, clock.Now())
				PublishHealth(t, b, victim.Name, 5, clock.Now())
				c.WaitConverged(t, convergeTimeout, a, b)
			}
			// Each survivor's own load, so the two placements differ (see the VM
			// scenario for why that matters).
			for _, n := range []*Node{a, b} {
				if err := corrosion.InsertVM(ctx, n.DB, corrosion.VMRecord{
					Name: "load-" + n.Name, HostName: n.Name, Spec: `{}`, State: "running", CPUActual: 16, MemActual: 200000,
				}, nil, nil); err != nil {
					t.Fatal(err)
				}
			}
			c.WaitConverged(t, convergeTimeout, a, b)
			c.SetLinkFaultBoth(a, b, LinkFault{Block: true})
			for _, n := range []*Node{a, b} {
				if err := corrosion.UpdateVMState(ctx, n.DB, "load-"+n.Name, "stopped", ""); err != nil {
					t.Fatal(err)
				}
			}
			cs := c.NewCoordinators(clock)
			for _, coord := range cs.ByNode {
				coord.Gate = quorateGate{}
			}
			cs.Tick(ctx, a, b)

			rekeyed := map[string]bool{}
			for _, n := range []*Node{a, b} {
				for _, h := range liveContainerHosts(t, n, "ct-victim") {
					if h == n.Name {
						rekeyed[n.Name] = true
					}
				}
			}
			c.ClearLinkFaults()
			c.Kill(victim)
			for _, n := range []*Node{a, b} {
				corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
			}
			c.WaitConvergedExcept(t, convergeTimeout, []string{"leader_lease_terms"}, a, b)
			after := liveContainerHosts(t, a, "ct-victim")
			if !tc.claims {
				if len(rekeyed) != 2 || len(after) != 2 {
					t.Fatalf("without claims each coordinator should re-key the container to itself and both rows "+
						"survive the heal (the bug); got re-keyed %v, live rows after the heal %v", rekeyed, after)
				}
				return
			}
			if len(rekeyed) != 1 {
				t.Fatalf("with claims %d survivors re-keyed the container to themselves (%v), want exactly one", len(rekeyed), rekeyed)
			}
			if len(after) != 1 {
				t.Fatalf("after the heal %d live rows claim ct-victim (%v), want one", len(after), after)
			}
			var loser *Node
			for _, n := range []*Node{a, b} {
				if !rekeyed[n.Name] {
					loser = n
				}
			}
			if ids := proofsNaming(t, loser, "ct-victim", loser.Name); len(ids) != 0 {
				t.Errorf("the loser %s holds relocation proof(s) naming itself: %v", loser.Name, ids)
			}
		})
	}
}
