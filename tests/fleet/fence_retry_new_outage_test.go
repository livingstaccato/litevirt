// Fleet scenario: lab 1 Redfish drill, finding R1. A host that fails again
// minutes after an earlier outage's fence, and whose new fence fails, is
// fenced again on the failed-fence retry backoff — not held back until the
// earlier outage's fence row is five minutes old.
package fleet

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// TestFleet_FenceRetry_NewOutageIsNotHeldByThePreviousOutagesFence: the
// leader a fences d over SSH and recovers vm (outage 1). d boots again and
// its daemon records it 'active'. A minute later d fails again (outage 2);
// a's fence of it fails, which records d 'offline'. The retry must run on the
// documented backoff, 30 s after the failure, and the one after that 60 s
// later — no sooner, so a failing BMC is not stormed.
//
// On lab 1 the retry came exactly 5:00 after outage 1's fence row
// (2026-10-12, R1): with d no longer 'active', nothing dated its current
// life, and outage 1's success counted as a "recent fence record" that
// skipped every retry.
//
// Mutation: drop the floor that keeps the retry's recent-fence check to rows
// newer than the failed attempt it repeats (the first retry goes red: no fence
// until outage 1's row is five minutes old); count every row as before the
// failure, or skip the retry's backoff (the cadence goes red).
func TestFleet_FenceRetry_NewOutageIsNotHeldByThePreviousOutagesFence(t *testing.T) {
	ctx := context.Background()
	vm, vm2 := "vm-r1", "vm-r1-again"
	c, a, b, cc, _, d := crashFleet(t, 2791, vm)
	voters := []*Node{a, b, cc}
	// host_membership_split_v1 is mandatory and latched on any current
	// cluster, lab 1 included: host_membership is where the coordinator
	// learns when a host last turned active.
	for _, n := range c.Nodes {
		splitMembership(t, n)
	}
	if _, err := c.SelfClient(a).ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: d.Name, FenceStrategy: "ssh"}); err != nil {
		t.Fatalf("configure %s fence strategy ssh: %v", d.Name, err)
	}
	// A confirmed SSH power-off of d recovers its workloads only by its
	// operator's choice.
	trustSSHPoweroffOn(t, c, a, d, voters...)
	c.WaitConverged(t, convergeTimeout, voters...)

	clock := NewVirtualClock(time.Now().UTC())
	cs := c.NewCoordinators(clock)
	var fail atomic.Bool
	var fences atomic.Int32
	var fencedAt []time.Time // virtual instants of a's fences of d
	cs.ByNode[a.Name].Gate = quorateGate{}
	cs.ByNode[a.Name].SetFencer(func(_ context.Context, h fence.HostConfig) fence.Result {
		if h.Name != d.Name {
			t.Errorf("a fenced %s, want only %s", h.Name, d.Name)
		}
		fences.Add(1)
		fencedAt = append(fencedAt, clock.Now())
		if fail.Load() {
			return fence.Result{Method: "ssh", Success: false, Detail: "ssh: connection refused"}
		}
		return sshOff
	})

	// Outage 1: a fences d and recovers vm. The observers count d down
	// after the split pass dated its membership.
	clock.Advance(time.Minute)
	for _, n := range voters {
		PublishHealthRun(t, n, d.Name, streakSince(30*time.Second), clock.Now().Add(-30*time.Second), clock.Now())
	}
	c.WaitConverged(t, convergeTimeout, voters...)
	if decided := tickUntilDecided(ctx, t, cs, a, d, vm, 6); decided == nil {
		t.Fatalf("fixture: outage 1 did not recover %s: %+v, fences %v", vm, vmOn(t, a, vm), fencesOf(t, a, d.Name))
	}
	if n := fences.Load(); n != 1 {
		t.Fatalf("fixture: outage 1 ran %d fence(s) of %s, want 1", n, d.Name)
	}

	// d boots again: its daemon's boot write records it 'active' (hostboot:
	// no graceful stop recorded). In a later wall second than outage 1's
	// fence row, as by minutes on the lab: a row in the activation's own
	// second still counts for the host's new life.
	c.ClearLinkFaults()
	c.WaitConverged(t, convergeTimeout)
	waitNextWallSecond()
	if err := corrosion.UpdateHostStartup(ctx, d.DB, d.Name, "active", "", 0, 0, 0, false); err != nil {
		t.Fatalf("%s's boot write: %v", d.Name, err)
	}
	c.WaitConverged(t, convergeTimeout)
	if got := hostStateOn(t, a, d.Name); got != "active" {
		t.Fatalf("fixture: %s is %q on %s after its boot write, want active", d.Name, got, a.Name)
	}
	// A workload on d for outage 2, which no failed fence may move.
	insertVM(t, a, vm2, d.Name)
	clock.Advance(30 * time.Second)
	for _, n := range voters {
		PublishHealth(t, n, d.Name, 0, clock.Now())
	}
	c.WaitConverged(t, convergeTimeout, voters...)
	cs.Tick(ctx, a)

	// Outage 2, a minute after outage 1's fence: d fails again, and its
	// fence now fails (the BMC, or here SSH, is unreachable).
	clock.Advance(30 * time.Second)
	c.Kill(d)
	fail.Store(true)
	runStart := clock.Now()
	publish := func() {
		for _, n := range voters {
			PublishHealthRun(t, n, d.Name, streakSince(clock.Now().Sub(runStart)), runStart, clock.Now())
		}
		c.WaitConverged(t, convergeTimeout, voters...)
	}
	clock.Advance(15 * time.Second)
	publish()
	cs.Tick(ctx, a)
	if n := fences.Load(); n != 2 {
		t.Fatalf("outage 2: a ran %d fence(s) of %s in all, want 2 (outage 1's, and outage 2's first): %v",
			n, d.Name, fencesOf(t, a, d.Name))
	}
	failedAt := fencedAt[1]
	c.WaitConverged(t, convergeTimeout, voters...)
	if got := hostStateOn(t, a, d.Name); got != "offline" {
		t.Fatalf("fixture: %s is %q after outage 2's failed fence, want offline", d.Name, got)
	}

	// Two minutes of a's cycles: retries at +30 s and +90 s (30 s, then 60 s).
	for clock.Now().Sub(failedAt) < 2*time.Minute {
		clock.Advance(contentionPoll)
		publish()
		cs.Tick(ctx, a)
	}
	if v := vmOn(t, a, vm2); v.HostName != d.Name || v.PendingActionID != "" {
		t.Errorf("%s moved off %s with every fence of outage 2 failed: %+v", vm2, d.Name, v)
	}
	got := fencedAt[1:]
	if len(got) < 2 {
		t.Fatalf("outage 2: %d fence attempt(s) of %s in the 2 minutes after its first failed, want the first and its retry 30 s later; held back by outage 1's fence row (%s ago)?",
			len(got), d.Name, clock.Now().Sub(fencedAt[0]).Round(time.Second))
	}
	if gap := got[1].Sub(got[0]); gap < 30*time.Second || gap > 30*time.Second+contentionPoll {
		t.Errorf("the first retry came %s after the failed fence, want 30 s (one poll of slack)", gap)
	}
	if len(got) != 3 {
		t.Errorf("outage 2: %d fence attempt(s) of %s in 2 minutes, want 3 (the first, +30 s, +90 s): %v", len(got), d.Name, got)
	} else if gap := got[2].Sub(got[1]); gap < time.Minute || gap > time.Minute+contentionPoll {
		t.Errorf("the second retry came %s after the first, want 60 s (one poll of slack)", gap)
	}
	if got := hostStateOn(t, a, d.Name); got != "offline" {
		t.Errorf("%s is %q with every fence of outage 2 failed, want offline: no recovery without a proof", d.Name, got)
	}
}
