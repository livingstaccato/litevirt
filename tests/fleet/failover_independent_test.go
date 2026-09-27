// Fleet scenarios: the failover invariants the SharedCRDT scenarios assert
// (failover_test.go, failover_dispute_test.go), re-run with independent
// replicas — each node deciding from its OWN database, with the production push
// loop carrying the lease, the fence and the reschedule between them over links
// that delay and duplicate.
//
// These hold on main, and the condition under which they hold is the point:
// replication between the coordinators completes inside one poll interval, so
// the second coordinator decides with the first one's lease already in its
// replica. failover_two_coordinators_test.go is the same fleet with that
// condition removed.
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// contentionPoll is the failover coordinator's poll interval, the step the
// virtual clock takes between one node's tick and the next.
const contentionPoll = 5 * time.Second

// slowLink is a healthy-but-slow replication link: every push waits, some
// arrive twice. Slow relative to a local write, fast relative to a poll.
var slowLink = LinkFault{Delay: 20 * time.Millisecond, Jitter: 20 * time.Millisecond, Duplicate: 0.3}

// failedHostFleet brings up three independent replicas — two survivors and a
// victim — puts the given VMs on the victim, lets that replicate everywhere,
// then fails the victim (isolated from replication) and has each survivor
// publish its own failed probe of it. Returns once the survivors agree.
func failedHostFleet(t *testing.T, clock *VirtualClock, vms ...string) (c *Cluster, a, b, victim *Node) {
	t.Helper()
	c = New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 266})
	a, b, victim = c.Nodes[0], c.Nodes[1], c.Nodes[2]
	for _, vm := range vms {
		insertVM(t, a, vm, victim.Name)
	}
	c.WaitConverged(t, convergeTimeout)

	c.Isolate(victim)
	c.SetLinkFaultBoth(a, b, slowLink)
	// Each observer writes only its OWN verdict, as the health checker does;
	// quorum on either survivor therefore needs the other's row to arrive.
	PublishHealth(t, a, victim.Name, 5, clock.Now())
	PublishHealth(t, b, victim.Name, 5, clock.Now())
	c.WaitConverged(t, convergeTimeout, a, b)
	return c, a, b, victim
}

// TestFleet_IndependentReplicas_Failover_LeaderContentionUnderDelay is
// TestFleet_Failover_LeaderContention on independent replicas: both survivors
// run a coordinator, exactly one fences, and every survivor ends up agreeing
// the VM moved off the victim to the same host.
func TestFleet_IndependentReplicas_Failover_LeaderContentionUnderDelay(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, victim := failedHostFleet(t, clock, "vm-victim")
	cs := c.NewCoordinators(clock)

	// a's poll fires first. Its lease, fence and reschedule then travel to b
	// over the slow link before b's poll fires one interval later.
	cs.Tick(ctx, a)
	c.WaitConverged(t, convergeTimeout, a, b)
	clock.Advance(contentionPoll)
	cs.Tick(ctx, b)
	// And a further interval with both polling together: the lease is now in
	// both replicas, so neither re-fences.
	c.WaitConverged(t, convergeTimeout, a, b)
	clock.Advance(contentionPoll)
	cs.Tick(ctx, a, b)
	c.WaitConverged(t, convergeTimeout, a, b)

	if f := cs.Fences(); len(f) != 1 {
		t.Fatalf("expected exactly one fence across two coordinators, got %+v", f)
	}
	var owner string
	for _, n := range []*Node{a, b} {
		vm := vmOn(t, n, "vm-victim")
		if vm == nil || vm.HostName == victim.Name {
			t.Fatalf("%s: vm-victim still on the fenced host: %+v", n.Name, vm)
		}
		if owner == "" {
			owner = vm.HostName
		} else if vm.HostName != owner {
			t.Fatalf("survivors disagree on the owner: %s says %s, another says %s", n.Name, vm.HostName, owner)
		}
		if h, _ := corrosion.GetHost(ctx, n.DB, victim.Name); h == nil || h.State == "active" {
			t.Errorf("%s: victim still active after the fence: %+v", n.Name, h)
		}
	}
	if st := c.LinkStats(a, b); st.Applied == 0 {
		t.Fatalf("nothing crossed a→b; the scenario did not exercise replication: %+v", st)
	}
}

// TestFleet_IndependentReplicas_Failover_RefusesDisputedWorkload is
// TestFleet_Failover_RefusesDisputedWorkload with the ownership condition
// raised on a DIFFERENT node from the coordinator: b saw the dual run, and a
// decides. The refusal holds because the condition reached a's replica first.
func TestFleet_IndependentReplicas_Failover_RefusesDisputedWorkload(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, victim := failedHostFleet(t, clock, "vm-clean", "vm-disputed")

	nowRFC := clock.Now().Format(time.RFC3339)
	if err := corrosion.UpsertHealthCondition(ctx, b.DB, corrosion.HealthCondition{
		Evaluator: "dual_run", Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "vm-disputed",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityCritical,
		Hosts: []string{victim.Name, b.Name}, FirstSeen: nowRFC, LastSeen: nowRFC,
	}); err != nil {
		t.Fatalf("raise condition on %s: %v", b.Name, err)
	}
	c.WaitConverged(t, convergeTimeout, a, b)
	if disputed, _, err := corrosion.WorkloadHasActiveOwnershipCondition(ctx, a.DB, "vm", "vm-disputed"); err != nil || !disputed {
		t.Fatalf("the condition raised on %s never reached %s (disputed=%v err=%v)", b.Name, a.Name, disputed, err)
	}

	cs := c.NewCoordinators(clock)
	cs.Tick(ctx, a)
	c.WaitConverged(t, convergeTimeout, a, b)

	for _, n := range []*Node{a, b} {
		if clean := vmOn(t, n, "vm-clean"); clean == nil || clean.HostName == victim.Name {
			t.Errorf("%s: vm-clean must be rescheduled off the fenced host: %+v", n.Name, clean)
		}
		if disputed := vmOn(t, n, "vm-disputed"); disputed == nil || disputed.HostName != victim.Name {
			t.Errorf("%s: vm-disputed was recovered (%+v) — automated recovery must refuse a "+
				"workload with an active ownership condition", n.Name, disputed)
		}
	}
}
