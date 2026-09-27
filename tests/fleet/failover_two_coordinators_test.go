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
// round.
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

func TestFleet_TwoCoordinators_OneFailedHost_AtMostOneWritableOwner(t *testing.T) {
	t.Skip("colonelpanik/litevirt#250: two coordinators can each authorize recovery inside one replication round; see issue")

	for _, tc := range []struct {
		name  string
		gated bool // split_brain_gate_v1 enforced: proof-linked reschedule, claimed by the executor
	}{
		{"legacy", false},
		{"proof-gated", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			clock := NewVirtualClock(time.Now().UTC())
			c, a, b, _ := failedHostFleet(t, clock, "vm-victim")

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
			// Both polls fire inside the window.
			cs.Tick(ctx, a, b)

			// Each survivor's executor acts on its own replica.
			for _, n := range []*Node{a, b} {
				rec := health.NewReconciler(n.Name, t.TempDir(), n.DB, n.Virt)
				if tc.gated {
					rec.SetGate(epochGate{})
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
			if len(owners) > 1 {
				t.Errorf("%d writable owners of vm-victim (%s) after one failed host and two coordinators; "+
					"fences=%+v\n  %s",
					len(owners), strings.Join(owners, ", "), cs.Fences(), strings.Join(views, "\n  "))
			}
		})
	}
}
