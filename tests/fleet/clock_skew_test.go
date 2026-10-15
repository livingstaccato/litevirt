// Fleet scenarios for a node whose clock runs fast (lab 1 drill W5,
// 2026-10-15, voter_forward_45s). Both document a gap and are skipped. Options.ClockSeam moves one node's wall
// clock for its row stamps and its HLC, and its coordinator reads the same
// clock (Node.Now), so a scenario steps a node as the drill steps a lab node.
package fleet

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/testkit/slogtest"
)

// TestFleet_AFastClockDoesNotTakeALiveLease: a voter whose clock runs 50 s
// fast must not take the failover lease from a live holder that keeps
// renewing it. The lease is a wall-clock compare (leader_election.expires_at
// against the claimant's now, corrosion/leader_lease_hold.go), so a claimant
// whose now is past the holder's expiry reads a live lease as lapsed.
//
// It fails today: node-1 takes the lease within seconds of the step (lab 1
// took term 50 the same way at +45 s). With the step at 0 it passes, so the
// failure is the clock. Skipped until the design decides whether lease_term
// should prevent it.
func TestFleet_AFastClockDoesNotTakeALiveLease(t *testing.T) {
	t.Skip("documents a gap: a voter whose clock runs more than leaseDuration ahead takes a live failover lease " +
		"(wall-clock expiry, no skew guard on takeover); fails today with enforcement.lease_term off. " +
		"Pending lease_term ON lab evidence (controller)")
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, Relays: 3, RealGossip: true, ClockSeam: true})
	holder, fast := c.Nodes[0], c.Nodes[1]
	s := newPPStack(t, c, ppOpts{latched: true,
		coordinators:     map[string]bool{holder.Name: true, fast.Name: true},
		lateCoordinators: map[string]bool{fast.Name: true}})
	eventually(t, time.Minute, holder.Name+" to hold the failover lease on every replica", func() bool {
		for _, n := range c.Nodes {
			if h, _, err := leaseRowFor(t, n); err != nil || h != holder.Name {
				return false
			}
		}
		return true
	})
	fast.StepClock(50 * time.Second)
	s.startCoordinator(s.node(fast), 0)
	for end := time.Now().Add(time.Minute); time.Now().Before(end); time.Sleep(250 * time.Millisecond) {
		for _, n := range c.Nodes {
			if h, _, _ := leaseRowFor(t, n); h == fast.Name {
				t.Fatalf("%s, its clock 50 s fast, took the failover lease from %s, which was renewing it (read on %s)",
					fast.Name, holder.Name, n.Name)
			}
		}
	}
}

// TestFleet_ForwardSkewedVoterDoesNotBlindTheHolder: one non-holder voter's
// clock runs 40 s fast. The holder, whose clock is true, must still fence a
// partitioned victim in the normal window, ignoring as future-dated only the
// skewed voter's observations. Replication carries the skewed HLC physical to
// every node, and NowWallTS floors each stamp above it, so every observer's
// row runs as far ahead and the holder ignores them all.
//
// The skewed node runs no coordinator: whether it takes the lease is
// TestFleet_AFastClockDoesNotTakeALiveLease.
//
// It fails today: the holder ignores every observer's row about the victim
// as future-dated and fences nothing within 90 s. With the NowWallTS floor
// removed it fences in about 11 s, ignoring only the skewed observer, so the
// failure is the floor. Skipped until the design decides the fix.
func TestFleet_ForwardSkewedVoterDoesNotBlindTheHolder(t *testing.T) {
	t.Skip("documents a gap: without hlc_lww_v1 latched, one voter's fast clock reaches every node's updated_at " +
		"through the HLC floor in corrosion NowWallTS, so a non-skewed holder ignores every observation as " +
		"future-dated and fences nothing while the skew lasts. Pending lease_term ON lab evidence (controller)")
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, Relays: 5, RealGossip: true, ClockSeam: true})
	victim, skewed, holder := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	insertVMPolicy(t, victim, "skew-vm", victim.Name, "restart-any")
	c.WaitConverged(t, convergeTimeout)
	victim.Virt.SetState("skew-vm", libvirtfake.StateRunning)

	var mu sync.Mutex
	var buf bytes.Buffer
	slogtest.Swap(t, slog.New(slog.NewTextHandler(&lockedBuf{mu: &mu, b: &buf}, nil)))

	s := newPPStack(t, c, ppOpts{latched: true, coordinators: map[string]bool{holder.Name: true}})
	skewed.StepClock(40 * time.Second)
	time.Sleep(5 * time.Second) // the skewed stamps replicate
	split := time.Now()
	c.SplitGossip(c.Nodes[:1], c.Nodes[1:])
	fenced := false
	for end := time.Now().Add(90 * time.Second); time.Now().Before(end) && !fenced; time.Sleep(500 * time.Millisecond) {
		fenced = len(s.fencesOf(victim.Name)) > 0
	}
	mu.Lock()
	defer mu.Unlock()
	ignored := map[string]int{}
	var sample string
	for _, l := range strings.Split(buf.String(), "\n") {
		if !strings.Contains(l, "ignoring a future-dated health observation") {
			continue
		}
		for _, f := range strings.Fields(l) {
			if o, ok := strings.CutPrefix(f, "observer="); ok {
				ignored[o]++
				if o != skewed.Name && sample == "" {
					sample = l
				}
			}
		}
	}
	if !fenced {
		t.Fatalf("%s did not fence the partitioned %s within 90 s; future-dated observations ignored, by observer: %v\n  e.g. %s",
			holder.Name, victim.Name, ignored, sample)
	}
	t.Logf("fenced %v after the split", s.fencesOf(victim.Name)[0].at.Sub(split).Round(time.Second))
	if sample != "" {
		t.Fatalf("the holder ignored rows from observers whose clocks are true (%v): %s", ignored, sample)
	}
}

type lockedBuf struct {
	mu *sync.Mutex
	b  *bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
