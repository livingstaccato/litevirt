package fleet

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// slowResumeVMs is a node's VM backend as its pauser sees it, with every
// partition-pause resume taking delay (a slow libvirtd), and the first one
// calling onFirst as it begins.
type slowResumeVMs struct {
	health.PauseVMBackend
	delay   time.Duration
	once    sync.Once
	onFirst func()
}

func (s *slowResumeVMs) ResumePartitionPaused(name, uuid string) error {
	s.once.Do(s.onFirst)
	time.Sleep(s.delay)
	return s.PauseVMBackend.ResumePartitionPaused(name, uuid)
}

// TestFleet_PartitionPause_PartitionReturnsMidResumePass: a fleet-wide blip
// pauses the owner's VMs; the network heals and the owner starts resuming
// them, one slow resume at a time; the partition comes back, owner and one
// peer cut off from the three-host majority, while that resume pass is still
// running. The majority fences the owner and, relying on its pause, recovers
// the VMs after its wait. No VM may run on both sides at any instant.
//
// Before the pass was bounded to E and re-read the quorum between records, a
// healed pass resumed every record however long it took and took no quorum
// sample meanwhile, so the owner noticed the new partition only after the
// whole pass, and paused T_pause after that: later than the majority's
// replacements, which ran beside the copies it had just resumed (re-review
// 2, N5).
//
// Mutation: an unbounded pass (partitionResumePassBudget of an hour, no
// quorum re-check) — a VM runs on both sides.
func TestFleet_PartitionPause_PartitionReturnsMidResumePass(t *testing.T) {
	const vms, resumeDelay = 4, 8 * time.Second
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, Relays: 5, RealGossip: true})
	owner := c.Nodes[0]
	var names []string
	for i := 0; i < vms; i++ {
		name := fmt.Sprintf("mp-%d", i)
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
	resplit := make(chan time.Time, 1)
	s := newPPStack(t, c, ppOpts{latched: true, coordinators: map[string]bool{c.Nodes[2].Name: true},
		vmBackend: func(n *Node) health.PauseVMBackend {
			if n != owner {
				return n.Virt
			}
			return &slowResumeVMs{PauseVMBackend: n.Virt, delay: resumeDelay, onFirst: func() {
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
	// The heal; the owner's first resume re-cuts the network mid-pass.
	c.HealGossip()
	var at time.Time
	select {
	case at = <-resplit:
	case <-time.After(2 * time.Minute):
		t.Fatal("the owner never began resuming after the heal")
	}
	t.Logf("the partition returned at %s, during the owner's first resume", at.Format("15:04:05.000"))

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
	time.Sleep(2 * time.Second)
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
