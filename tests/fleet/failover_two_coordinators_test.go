// Fleet scenario for colonelpanik/litevirt#250: two coordinators, one failed
// host, and replication between the coordinators blocked for the decision
// window — while each still sees quorum, because its health view was
// replicated before the window opened.
//
// The leader lease is an upsert into the local replica followed by a re-read
// of that same row, so each coordinator acquires it, fences the victim and
// authorizes recovery before the other's claim can arrive. The property this
// pins is the one recovery has to guarantee regardless: AT MOST ONE writable
// owner of the workload results.
//
// It is the scenario failover_independent_test.go runs with replication
// completing inside one poll; here the two polls land inside one replication
// round. Without recovery claims both arms produce TWO owners — the bug the
// issue reports, kept as a witness so the enforced arm cannot pass vacuously.
// With recovery_claim_v1 enforced the two coordinators' claims are one Paxos
// decision, so exactly one destination holds a certificate and only it starts
// (docs/design/recovery-claims.md §3.16).
package fleet

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// quorateGate stands in for a health.Checker that has quorum and a latched
// split_brain_gate_v1 — which both coordinators genuinely do here: health
// probes between them succeed, only replication is held back. It admits every
// decision, so the proof-gated path runs through the proof mint and the
// executor's single-use claim rather than being refused before them.
type quorateGate struct{}

func (quorateGate) DecisionGate(context.Context) health.GateResult {
	return health.GateResult{OK: true}
}
func (quorateGate) QuorumProof(context.Context) (health.QuorumState, int, int) {
	return health.QuorumYes, 2, 2
}
func (quorateGate) Enforced(context.Context, string) bool                  { return true }
func (quorateGate) PeerSupportsFresh(context.Context, string, string) bool { return true }

var _ failover.FailoverGate = quorateGate{}

// TestFleet_TwoCoordinators_OneFailedHost_AtMostOneWritableOwner.
//
// Mutation (claims arm): drop the recovery-claim gate in startPendingVM —
// both destinations start the VM and the arm goes red. The two claims-off
// arms are the same assertion inverted: they show the double owner the issue
// reports, and fail if a change makes it disappear without claims (in which
// case the enforced arm would be proving nothing).
func TestFleet_TwoCoordinators_OneFailedHost_AtMostOneWritableOwner(t *testing.T) {
	for _, tc := range []struct {
		name   string
		gated  bool // split_brain_gate_v1 enforced: proof-linked reschedule, claimed by the executor
		claims bool // recovery_claim_v1 enforced: claim before mint, verify before execute
		// rogue: b's COORDINATOR does not claim — it mints an uncertified proof,
		// as a coordinator with the flag off does — while every destination
		// still verifies. The destination is where G2 says the guarantee is
		// enforced, and this is the arm in which only it can hold.
		rogue bool
	}{
		{"legacy", false, false, false},
		{"proof-gated", true, false, false},
		{"proof-gated-with-claims", true, true, false},
		{"proof-gated-with-claims-and-an-uncertified-coordinator", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			clock := NewVirtualClock(time.Now().UTC())
			var c *Cluster
			var a, b, victim *Node
			if tc.claims {
				c, a, b, victim = claimFleet(t, clock, 266, "vm-victim")
			} else {
				c, a, b, victim = failedHostFleet(t, clock, "vm-victim")
			}

			// Each survivor runs a workload of its own, known to both.
			for _, n := range []*Node{a, b} {
				if err := corrosion.InsertVM(ctx, n.DB, corrosion.VMRecord{
					Name: "load-" + n.Name, HostName: n.Name, Spec: `{}`, State: "running",
					CPUActual: 16, MemActual: 65536,
				}, nil, nil); err != nil {
					t.Fatalf("InsertVM load on %s: %v", n.Name, err)
				}
			}
			c.WaitConverged(t, convergeTimeout, a, b)

			// The decision window opens: nothing crosses between the coordinators.
			// Claim RPCs are ordinary gRPC and still reach their peer (§3.16).
			c.SetLinkFaultBoth(a, b, LinkFault{Block: true})

			// Each survivor stops its own workload, and the other does not hear of
			// it. This is the independent history #250 is about — each replica holds
			// a write the other has not received — and it is what makes the two
			// placements differ. Without it both coordinators see identical state and
			// choose the same survivor, which hides the double authorization behind a
			// coincidence of choice rather than preventing it.
			for _, n := range []*Node{a, b} {
				if err := corrosion.UpdateVMState(ctx, n.DB, "load-"+n.Name, "stopped", ""); err != nil {
					t.Fatalf("stop load on %s: %v", n.Name, err)
				}
			}

			cs := c.NewCoordinators(clock)
			if tc.gated {
				for _, coord := range cs.ByNode {
					coord.Gate = quorateGate{}
				}
			}
			if tc.rogue {
				cs.ByNode[b.Name].RecoveryClaimEnforced = func(context.Context) bool { return false }
			}
			// Both polls fire inside the window.
			cs.Tick(ctx, a, b)

			// Each survivor's executor acts on its own replica.
			for _, n := range []*Node{a, b} {
				var rec *health.Reconciler
				if tc.claims {
					rec = claimReconciler(t, n)
				} else {
					rec = health.NewReconciler(n.Name, t.TempDir(), n.DB, n.Virt)
					if tc.gated {
						rec.SetGate(epochGate{})
					}
				}
				rec.ReconcileOnce(ctx)
			}

			var owners, views []string
			for _, n := range []*Node{a, b} {
				vm := vmOn(t, n, "vm-victim")
				state, _ := n.Virt.DomainState("vm-victim")
				views = append(views, fmt.Sprintf("%s: replica says host=%s state=%s epoch=%d proof=%q; libvirt=%q",
					n.Name, vm.HostName, vm.State, vm.OwnerEpoch, vm.PendingActionID, state))
				if state == string(libvirtfake.StateRunning) {
					owners = append(owners, n.Name)
				}
			}
			detail := fmt.Sprintf("fences=%+v\n  %s", cs.Fences(), strings.Join(views, "\n  "))
			if !tc.claims {
				// The issue, reproduced: each coordinator authorized its own
				// destination and each destination started the VM.
				if len(owners) != 2 {
					t.Fatalf("without recovery claims this scenario produced %d writable owners, not the two "+
						"colonelpanik/litevirt#250 reports — the witness no longer reproduces the bug\n  %s",
						len(owners), detail)
				}
				return
			}
			if len(owners) != 1 {
				t.Fatalf("%d writable owners of vm-victim (%s) with recovery claims enforced, want exactly one\n  %s",
					len(owners), strings.Join(owners, ", "), detail)
			}
			winner, loser := a, b
			if owners[0] == b.Name {
				winner, loser = b, a
			}
			if tc.rogue {
				// b minted its own proof in its own replica and pointed the VM at
				// itself; its destination refused it for want of a certificate.
				if winner != a {
					t.Fatalf("the uncertified coordinator's destination %s started the VM\n  %s", b.Name, detail)
				}
				return
			}
			// The loser wrote no pending row naming itself and no proof naming
			// itself: whatever it wrote is the winner's decided proof (§3.13).
			if vm := vmOn(t, loser, "vm-victim"); vm.HostName == loser.Name {
				t.Errorf("the loser %s's replica points vm-victim at itself: %+v", loser.Name, vm)
			}
			if ids := proofsNaming(t, loser, "vm-victim", loser.Name); len(ids) != 0 {
				t.Errorf("the loser %s holds proof(s) naming itself as the destination: %v", loser.Name, ids)
			}

			// Heal: replication resumes between the survivors (the victim stays
			// dead). Both replicas agree on one owner, and no second domain ever
			// ran — the 40 s split in the issue's report becomes none.
			c.ClearLinkFaults()
			c.Kill(victim)
			// leader_lease_terms keeps both survivors' claims of the contested
			// term by design (leader_lease_contest_test.go); everything else,
			// the proof rows included, converges.
			// The two copies of the decided proof differ in what a value does not
			// carry (the loser's created_at, the winner's evidence fields and
			// certificate ballot); anti-entropy is what settles them, as it runs
			// periodically in a daemon.
			for _, n := range []*Node{a, b} {
				corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
			}
			c.WaitConvergedExcept(t, convergeTimeout, []string{"leader_lease_terms"}, a, b)
			for _, n := range []*Node{a, b} {
				if vm := vmOn(t, n, "vm-victim"); vm.HostName != winner.Name {
					t.Errorf("after the heal %s's replica says vm-victim is on %s, want the one owner %s",
						n.Name, vm.HostName, winner.Name)
				}
			}
			for _, ev := range loser.Virt.EventLog() {
				if ev.Domain == "vm-victim" && ev.Op == "start" {
					t.Errorf("the loser %s started vm-victim at %s", loser.Name, ev.When)
				}
			}
		})
	}
}
