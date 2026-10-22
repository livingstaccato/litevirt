package fleet

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// hungRetryVMs is the owner's VM backend as its pauser sees it: the first
// resume of one domain fails at once, and the next one re-cuts the network as
// it begins and then hangs for hang before it fails, as a resume stuck on a
// wedged qemu's libvirt job lock does. Every other resume is ordinary.
type hungRetryVMs struct {
	health.PauseVMBackend
	name   string
	hang   time.Duration
	onHang func()
	mu     sync.Mutex
	calls  int
}

func (h *hungRetryVMs) ResumePartitionPaused(name, uuid string) error {
	if name != h.name {
		return h.PauseVMBackend.ResumePartitionPaused(name, uuid)
	}
	h.mu.Lock()
	h.calls++
	n := h.calls
	h.mu.Unlock()
	if n == 1 {
		return errors.New("internal error: unable to execute QEMU command 'cont'")
	}
	if n == 2 {
		h.onHang()
	}
	time.Sleep(h.hang)
	return errors.New("Timed out during operation: cannot acquire state change lock")
}

// TestFleet_PartitionPause_PartitionReturnsDuringAHungResume: a fleet-wide
// blip pauses the owner's VMs; after the heal one pass resumes three of them
// and fails the fourth's resume; a later pass retries it, and that resume
// hangs, and the partition comes back (owner and one peer cut off from the
// three-host majority) as it begins. The majority fences the owner and,
// relying on its pause, recovers all four after its wait. No VM may run on
// both sides at any instant.
//
// The three resumed in the earlier pass are the point: the pass that hangs
// did not resume them, so its own re-pause does not cover them, and only the
// owner's ordinary pause path, which needs quorum readings, can stop them.
// Before each step of a pass was bounded by R, the hung resume held the
// pauser, which took no reading until the call returned, and the three ran
// beside their replacements (re-review 3, finding 1).
//
// Mutation: no step bound on the resume (wait for the call) — the three run
// on both sides.
func TestFleet_PartitionPause_PartitionReturnsDuringAHungResume(t *testing.T) {
	const vms, hang = 4, 40 * time.Second
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, Relays: 5, RealGossip: true})
	owner := c.Nodes[0]
	var names []string
	for i := 0; i < vms; i++ {
		name := fmt.Sprintf("hr-%d", i)
		names = append(names, name)
		insertVMPolicy(t, owner, name, owner.Name, "restart-any")
	}
	c.WaitConverged(t, convergeTimeout)
	for _, name := range names {
		owner.Virt.SetState(name, libvirtfake.StateRunning)
	}
	genesisByTick(t, c, c.Nodes[2])
	enableRecoveryClaims(t, c)

	minority, majority := c.Nodes[:2], c.Nodes[2:]
	hung := names[vms-1]
	resplit := make(chan time.Time, 1)
	s := newPPStack(t, c, ppOpts{latched: true, coordinators: map[string]bool{c.Nodes[2].Name: true},
		vmBackend: func(n *Node) health.PauseVMBackend {
			if n != owner {
				return n.Virt
			}
			return &hungRetryVMs{PauseVMBackend: n.Virt, name: hung, hang: hang, onHang: func() {
				c.SplitGossip(minority, majority)
				resplit <- time.Now()
			}}
		}})
	samplers := map[string]*runSampler{}
	for _, name := range names {
		samplers[name] = sampleRunning(t, c, name)
	}

	// A fleet-wide blip: no majority anywhere, every VM pauses, nothing moves.
	c.SplitAll()
	eventually(t, 60*time.Second, "the owner to pause every VM", func() bool {
		for _, name := range names {
			if st, _ := owner.Virt.RawState(name); st != libvirtfake.StatePaused {
				return false
			}
		}
		return true
	})
	// The heal; a later pass's retry of the fourth re-cuts the network.
	c.HealGossip()
	var at time.Time
	select {
	case at = <-resplit:
	case <-time.After(2 * time.Minute):
		t.Fatal("the owner never retried the failed resume after the heal")
	}
	t.Logf("the partition returned at %s, as the owner's retry of %s began", at.Format("15:04:05.000"), hung)
	for _, name := range names[:vms-1] {
		if st, _ := owner.Virt.RawState(name); st != libvirtfake.StateRunning {
			t.Fatalf("setup: %s is %s on the owner when the partition returned, want running (resumed by an earlier pass)", name, st)
		}
	}

	eventually(t, ppRecoverBound, "the majority to recover every VM", func() bool {
		for _, name := range names {
			on := false
			for _, n := range majority {
				if st, ok := n.Virt.RawState(name); ok && st == libvirtfake.StateRunning {
					on = true
				}
			}
			if !on {
				return false
			}
		}
		return true
	})
	if len(s.fencesOf(owner.Name)) == 0 {
		t.Fatalf("no coordinator fenced %s", owner.Name)
	}
	// Past the hung call's return, so a late landing would be seen.
	if wait := time.Until(at.Add(hang + 2*time.Second)); wait > 0 {
		time.Sleep(wait)
	}
	for _, name := range names {
		rs := samplers[name]
		rs.mu.Lock()
		maxRun, overlap := rs.max, rs.overlap
		rs.mu.Unlock()
		if maxRun > 1 {
			t.Errorf("%s ran on both sides of the returned partition: %v", name, overlap)
		}
	}
}
