// With an adopted voter generation, two surviving workers recover a lost
// host's workloads: the voter majority governs, not the two-worker witness
// heuristic.
//
// Observed on the kvm003-f3 lab (main-b3368d7c, drill 6): three of five voters
// were lost for good, fence-confirmed, and `lv cluster voter force-reconfigure`
// decided generation 10 = {node-1, node-2}. The coordinator fenced the lost
// hosts afresh and then refused every reschedule with missing_witness
// (DecisionGate: exactly two voting-eligible workers, no witness) until a third
// host was admitted. The same rule refuses a three-voter cluster that has lost
// one host, which this scenario runs: once the dead host is fenced, two workers
// are left.
//
// The rule's job — no decision on either side of a 1-1 split — is kept by the
// voter majority itself: each side of a split sees one voter of the
// generation, below its majority, and its gate refuses no_quorum.
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// latchedGate is a node's real health checker — its own probes, quorum and
// DecisionGate — on a cluster where split_brain_gate_v1 has latched, so the
// coordinator takes the proof-gated path that consults DecisionGate.
type latchedGate struct{ *health.Checker }

func (g latchedGate) Enforced(_ context.Context, tok string) bool {
	return tok == capabilities.SplitBrainGateV1
}
func (latchedGate) PeerSupportsFresh(context.Context, string, string) bool { return true }

// TestFleet_Failover_TwoSurvivingVotersRecover:
//
//  1. a, b and v form voter generation 1; v owns vm-2v;
//  2. v dies, and a and b each record their failed probes of it;
//  3. a's coordinator fences v and recovers vm-2v. After the fence a and b
//     are the only voting-eligible workers, and there is no witness.
//
// The VM must be rescheduled. In the split arm a and b cannot reach each
// other: neither side has a majority of the generation, and neither moves
// anything (both may fence v, which they agreed was down before the split).
//
// Mutation: drop the adopted-generation exemption in decisionGate — the
// recovery arm is refused missing_witness and vm-2v stays on v.
func TestFleet_Failover_TwoSurvivingVotersRecover(t *testing.T) {
	for _, split := range []bool{false, true} {
		t.Run(map[bool]string{false: "recovery", true: "split"}[split], func(t *testing.T) {
			ctx := context.Background()
			c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 3401})
			a, b, v := c.Nodes[0], c.Nodes[1], c.Nodes[2]
			insertVM(t, a, "vm-2v", v.Name)
			c.WaitConverged(t, convergeTimeout)
			genesisByTick(t, c, a)

			// 2.
			c.Kill(v)
			clock := NewVirtualClock(time.Now().UTC())
			for _, n := range []*Node{a, b} {
				PublishHealth(t, n, v.Name, 5, clock.Now())
			}
			c.WaitConverged(t, convergeTimeout, a, b)
			if split {
				c.SetLinkFaultBoth(a, b, LinkFault{Block: true})
			}

			// Each node's real checker, with the probe results a cycle gives
			// it: v down, and the other survivor up — or down, across the
			// split. The fleet's link faults block RPCs, not the checker's
			// TLS dial, so the split is given to the checkers directly.
			gates := map[string]*health.Checker{}
			for _, pair := range [][2]*Node{{a, b}, {b, a}} {
				self, other := pair[0], pair[1]
				gates[self.Name] = gateFor(t, c, self)
				gates[self.Name].SeedPeersForTests(map[string]bool{v.Name: false, other.Name: !split})
				want := health.QuorumYes
				if split {
					want = health.QuorumNo
				}
				if st, live, need := gates[self.Name].QuorumProof(ctx); st != want {
					t.Fatalf("precondition: %s quorum %v (%d/%d), want %v", self.Name, st, live, need, want)
				}
			}

			// 3. In the split both sides tick; otherwise the one coordinator.
			cs := c.NewCoordinators(clock)
			for _, n := range []*Node{a, b} {
				cs.ByNode[n.Name].Gate = latchedGate{gates[n.Name]}
			}
			ticking := []*Node{a}
			if split {
				ticking = []*Node{a, b}
			}
			cs.Tick(ctx, ticking...)
			clock.Advance(contentionPoll)
			cs.Tick(ctx, ticking...)

			if split {
				// Both may fence v: they agreed it was down before the split,
				// and a fence is idempotent (recovery-claims.md §2, non-goals).
				// Neither may move what v held.
				for _, n := range []*Node{a, b} {
					if vm := vmOn(t, n, "vm-2v"); vm.HostName != v.Name || vm.PendingActionID != "" {
						t.Fatalf("%s moved vm-2v (%+v) from one side of a 1-1 split", n.Name, vm)
					}
				}
				return
			}
			c.WaitConverged(t, convergeTimeout, a, b)
			vm := vmOn(t, a, "vm-2v")
			if vm.HostName == v.Name || vm.PendingActionID == "" {
				t.Fatalf("vm-2v was not recovered off the fenced %s by the two surviving voters: %+v", v.Name, vm)
			}
			if h, err := corrosion.GetHost(ctx, a.DB, v.Name); err != nil || h == nil || h.State != "fenced" {
				t.Fatalf("%s is not recorded fenced: %+v %v", v.Name, h, err)
			}
		})
	}
}
