// A decided claim value whose destination cannot take the workload is not
// written; its destination abandons it and the claim moves on.
//
// Observed on the kvm003-f3 lab (main-b3368d7c). In drill 4, a coordinator's
// claim for o4 at owner epoch 4 was accepted by node-2 alone, for destination
// node-5, and refused by the rest (recovery_claim_owner_reachable): no
// certificate. In drill 6 the forced reconfiguration to {node-1, node-2}
// imported node-2's accepted value, as §4.6 says it must. node-5 was then
// removed for good and a rebuilt machine added under its name. The moment it
// was admitted, still `joining`, the coordinator's claim for o4 found that
// accepted value in phase 1, adopted it as Paxos requires, certified it, and
// minted the proof for the new node-5 — while its own log said `to=node-2`.
// Nothing checked the adopted destination: the eligibility, placement and gate
// checks all ran on the coordinator's own pick.
//
// The value cannot be swapped: once a majority may have accepted it, every
// later proposer at that key must propose it (§3.16). What the protocol does
// allow is moving the KEY on, to the next attempt, with evidence that the
// decided value will never execute (§3.12): here the destination's signed
// abandonment of the proof, which it records before it signs and checks in
// the same transaction as any later claim of that proof.
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_RecoveryClaim_AnAdoptedValueTheDestinationCannotTakeMovesOn:
//
//  1. a, b, victim and d form voter generation 1; victim owns o4;
//  2. victim dies; a claim for o4's recovery reaches b alone, for
//     destination d, and forms no certificate;
//  3. d can no longer take o4: it is `joining` (the lab's case: the machine
//     re-added under a removed host's name), or it is active but has not the
//     memory o4 needs;
//  4. a's coordinator recovers victim. Its claim adopts b's accepted value,
//     which is decided for d.
//
// The proof for d must not be written. d abandons it, the claim moves to
// attempt 1, and o4 is decided for a host that can take it.
//
// Mutation: drop the adopted-destination check in claimRecovery — a writes
// the proof naming d in both arms. Pass no placement check from the
// reschedule site — the capacity arm writes it.
func TestFleet_RecoveryClaim_AnAdoptedValueTheDestinationCannotTakeMovesOn(t *testing.T) {
	for _, tc := range []struct {
		name  string
		unfit func(t *testing.T, a, d *Node)
	}{
		{"joining", func(t *testing.T, a, d *Node) {
			if err := corrosion.UpdateHostState(context.Background(), a.DB, d.Name, "joining"); err != nil {
				t.Fatalf("mark %s joining: %v", d.Name, err)
			}
		}},
		{"no capacity", func(t *testing.T, a, d *Node) {
			// On the coordinator's replica only, unlogged: what it places by.
			if _, err := a.DB.DB().Exec(`UPDATE hosts SET mem_total = 1024 WHERE name = ?`, d.Name); err != nil {
				t.Fatalf("shrink %s: %v", d.Name, err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			clock := NewVirtualClock(time.Now().UTC())
			c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 2611})
			a, b, victim, d := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]

			// 1.
			if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
				Name: "o4", HostName: victim.Name, Spec: `{"on_host_failure":"restart-any"}`, State: "running",
				CPUActual: 1, MemActual: 4096,
			}, nil, nil); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			c.WaitConverged(t, convergeTimeout)
			genesisByTick(t, c, a)
			enableRecoveryClaims(t, c)

			// 2.
			c.Kill(victim)
			for _, n := range []*Node{a, b, d} {
				PublishHealth(t, n, victim.Name, 5, clock.Now())
			}
			c.WaitConverged(t, convergeTimeout, a, b, d)
			key := vmKey(a, "o4", 0)
			if resp := rogueAcceptAt(t, c, d, b, key, victim.Name, d.Name, 1); !resp.GetAccepted() {
				t.Fatalf("setup: %s refused the drill-4 value: %+v", b.Name, resp)
			}
			stale := voterState(t, b, key)
			if stale.Value == nil || stale.Value.Proof == nil || stale.Value.Proof.DestHost != d.Name {
				t.Fatalf("setup: %s holds no accepted value for %s: %+v", b.Name, d.Name, stale)
			}
			adopted := stale.Value.Proof.ID

			// 3.
			tc.unfit(t, a, d)
			if tc.name == "joining" {
				c.WaitConverged(t, convergeTimeout, a, b, d)
			}

			// 4.
			cs := c.NewCoordinators(clock)
			cs.ByNode[a.Name].Gate = quorateGate{}
			cs.Tick(ctx, a)

			if ids := proofsNaming(t, a, "o4", d.Name); len(ids) != 0 {
				t.Fatalf("%s wrote proof(s) %v sending o4 to %s, which cannot take it: an adopted value's "+
					"destination must pass the checks the coordinator's own pick does", a.Name, ids, d.Name)
			}
			pr, cert := pendingCert(t, a, "o4")
			if pr.DestHost == d.Name || pr.DestHost == victim.Name {
				t.Fatalf("o4 is pending on %s; want a host that can take it", pr.DestHost)
			}
			if cert.Key.Attempt != 1 {
				t.Fatalf("o4 was decided at attempt %d, want attempt 1: attempt 0 is decided for %s and cannot change",
					cert.Key.Attempt, d.Name)
			}
			if abandoned, err := d.DB.ProofAbandoned(ctx, adopted); err != nil || !abandoned {
				t.Fatalf("%s did not record its abandonment of the adopted proof %s: %v %v", d.Name, adopted, abandoned, err)
			}
		})
	}
}
