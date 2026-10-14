// Partition pause with a non-voter that reaches both halves of a split of the
// voters (lab 1 TestDrill1, 2026-10-14). node-6 there was the witness: outside
// the adopted voter generation, and in neither half of the cut, so it kept
// probing and replicating to both sides. Safety held — the minority paused
// and nothing ran twice — but the majority never recovered:
//
//   - its deadline re-check counted node-6's healthy probes of the paused
//     minority host as "the host answered since the fence";
//   - when the failover lease was held in the minority at the cut, its holder
//     kept renewing it, node-6 kept receiving the renewals, and every majority
//     takeover was refused on node-6's word that the lease was live.
package fleet

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// bridgeFleet is six nodes, voter generation 2 = n0..n4 (n5 removed, as
// node-6 was on lab 1), recovery claims enforced, pp-vm running on n0, and
// every node's partition-pause wiring. The scenario splits [n0 n1] from
// [n2 n3 n4]; n5 stays connected to both.
func bridgeFleet(t *testing.T, o ppOpts) (c *Cluster, s *ppStack, rs *runSampler) {
	t.Helper()
	ctx := context.Background()
	c = New(t, Options{Nodes: 6, IndependentReplicas: true, Relays: 6, RealGossip: true})
	owner := c.Nodes[0]
	insertVMPolicy(t, owner, "pp-vm", owner.Name, "restart-any")
	c.WaitConverged(t, convergeTimeout)
	owner.Virt.SetState("pp-vm", libvirtfake.StateRunning)
	genesisByTick(t, c, c.Nodes[2])
	if _, err := c.SelfClient(c.Nodes[2]).ChangeVoterConfig(ctx,
		&pb.ChangeVoterConfigRequest{Op: "rm", Host: c.Nodes[5].Name}); err != nil {
		t.Fatalf("voter rm %s: %v", c.Nodes[5].Name, err)
	}
	adoptAll(t, c, 2)
	for _, n := range c.Nodes {
		v, err := corrosion.VoterSet(ctx, n.DB)
		if err != nil || len(v) != 5 || v[c.Nodes[5].Name] {
			t.Fatalf("setup: %s's voter set is %v (%v), want n0..n4", n.Name, v, err)
		}
	}
	enableRecoveryClaims(t, c)
	o.latched = true
	s = newPPStack(t, c, o)
	rs = sampleRunning(t, c, "pp-vm")
	eventually(t, time.Minute, "the owner's pauser to be healed before the split", func() bool {
		return s.node(owner).pauser.HealedForTests()
	})
	return c, s, rs
}

// assertRecoveredOnce checks the safety half of a bridged scenario once the
// replacement runs on dest: the owner paused before the replacement started,
// the replacement started only after the wait, pp-vm never ran on two hosts
// at once, and no minority node fenced anything.
func assertRecoveredOnce(t *testing.T, c *Cluster, s *ppStack, rs *runSampler, dest *Node, minority []*Node) {
	t.Helper()
	owner := c.Nodes[0]
	susp, ok := firstEvent(owner, "suspend", "pp-vm")
	if !ok {
		t.Fatalf("%s never suspended pp-vm", owner.Name)
	}
	start, ok := firstEvent(dest, "start", "pp-vm")
	if !ok {
		t.Fatalf("%s runs pp-vm with no start event", dest.Name)
	}
	if !susp.When.Before(start.When) {
		t.Fatalf("the replacement started on %s at %s, before %s paused the original at %s",
			dest.Name, start.When.Format("15:04:05.000"), owner.Name, susp.When.Format("15:04:05.000"))
	}
	fences := s.fencesOf(owner.Name)
	if len(fences) == 0 {
		t.Fatalf("no coordinator fenced %s", owner.Name)
	}
	if w := ppWait(len(c.Nodes) - 1); start.When.Sub(fences[0].at) < w {
		t.Fatalf("%s started pp-vm %v after the fence decision; the wait is %v", dest.Name,
			start.When.Sub(fences[0].at), w)
	}
	rs.mu.Lock()
	maxRun, overlap := rs.max, rs.overlap
	rs.mu.Unlock()
	if maxRun > 1 {
		t.Fatalf("pp-vm ran on more than one host at once: %v", overlap)
	}
	if got := runningOn(c, "pp-vm"); len(got) != 1 || got[0] != dest.Name {
		t.Fatalf("pp-vm runs on %v, want only %s", got, dest.Name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.fence {
		for _, m := range minority {
			if f.by == m.Name {
				t.Fatalf("minority node %s fenced %s; a coordinator without the voter majority decides nothing", m.Name, f.target)
			}
		}
	}
}

// waitRecovered waits for some node outside the minority to run pp-vm.
func waitRecovered(t *testing.T, c *Cluster, minority []*Node) *Node {
	t.Helper()
	in := map[string]bool{}
	for _, m := range minority {
		in[m.Name] = true
	}
	var dest *Node
	eventually(t, ppRecoverBound, "the majority to start pp-vm's replacement", func() bool {
		for _, n := range c.Nodes {
			if in[n.Name] {
				continue
			}
			if st, ok := n.Virt.RawState("pp-vm"); ok && st == libvirtfake.StateRunning {
				dest = n
				return true
			}
		}
		return false
	})
	return dest
}

// TestFleet_PartitionPause_NonVoterReachingBothSidesDoesNotVetoRecovery: the
// majority holds the lease. n5 keeps probing the paused n0 healthy, and the
// minority's own voter n1 does too; neither shows that n0 holds a voter
// majority, so neither may veto the recovery after the wait.
//
// Mutation: count every observer again in the self-pause deadline check
// (retryPauseWait → fenceStillStands) — "recovering nothing ... observer
// node-5 saw the host answer after the fence", and the recovery wait times out.
func TestFleet_PartitionPause_NonVoterReachingBothSidesDoesNotVetoRecovery(t *testing.T) {
	c, s, rs := bridgeFleet(t, ppOpts{coordinators: map[string]bool{"node-2": true}})
	minority, majority := c.Nodes[:2], c.Nodes[2:5]
	c.SplitGossip(minority, majority)

	dest := waitRecovered(t, c, minority)
	assertRecoveredOnce(t, c, s, rs, dest, minority)
}

// TestFleet_PartitionPause_ASuccessorResumesPastANonVoter: the majority's
// coordinator fences n0 and stops before its wait ends, as a daemon restart
// or a lease hand-off does. Its successor finds the self-pause fence record
// with n5 (and n1, through n5) seeing n0 answer; it must resume from the
// record, wait afresh, and recover.
//
// Mutation: drop the self-pause branch in resumeActionFor — the successor
// declines the record ("observer node-1 saw the host answer after the fence")
// and the recovery wait times out.
func TestFleet_PartitionPause_ASuccessorResumesPastANonVoter(t *testing.T) {
	c, s, rs := bridgeFleet(t, ppOpts{
		coordinators:     map[string]bool{"node-2": true, "node-3": true},
		lateCoordinators: map[string]bool{"node-2": true, "node-3": true},
	})
	owner, n2, n3 := c.Nodes[0], c.Nodes[2], c.Nodes[3]
	stop2 := s.startCoordinator(s.node(n2), 0)
	eventually(t, time.Minute, "node-2 to hold the failover lease on every node", func() bool {
		for _, n := range c.Nodes {
			if h, _, err := corrosion.ReadLeaseRow(context.Background(), n.DB, "failover"); err != nil || h != n2.Name {
				return false
			}
		}
		return true
	})
	minority, majority := c.Nodes[:2], c.Nodes[2:5]
	c.SplitGossip(minority, majority)
	eventually(t, ppRecoverBound, "node-2 to fence node-0", func() bool { return len(s.fencesOf(owner.Name)) > 0 })
	stop2()
	for _, n := range c.Nodes[1:] {
		if _, ok := firstEvent(n, "start", "pp-vm"); ok {
			t.Fatalf("setup: %s started pp-vm before node-2 stopped; its wait had not passed", n.Name)
		}
	}
	s.startCoordinator(s.node(n3), 0)

	dest := waitRecovered(t, c, minority)
	assertRecoveredOnce(t, c, s, rs, dest, minority)
	for _, f := range s.fencesOf(owner.Name) {
		if f.by != n2.Name {
			t.Fatalf("%s fenced %s again; the successor must resume from the recorded self-pause fence", f.by, owner.Name)
		}
	}
}

// TestFleet_LeaseHeldInTheMinority_MajorityTakesOverPastANonVoter: the
// failover lease is held by n1 at the cut. n1 has lost the voter majority, so
// it must stop renewing; once its lease lapses on n5, a majority coordinator
// takes it over and recovers n0's VM after the wait. The control cuts n5 off
// from the minority as well, so nothing bridges the halves: it passes with or
// without the fix, which shows the bridge is what the fix is about.
//
// Mutation: drop the quorum gate in front of the lease (acquireLeaseResult) —
// n1 keeps renewing, n5 keeps reporting the lease live for node-1, and no
// majority node ever holds it (the bridged arm goes red; the control stays
// green).
func TestFleet_LeaseHeldInTheMinority_MajorityTakesOverPastANonVoter(t *testing.T) {
	for _, bridged := range []bool{true, false} {
		t.Run(map[bool]string{true: "bridged", false: "control"}[bridged], func(t *testing.T) {
			ctx := context.Background()
			c, s, rs := bridgeFleet(t, ppOpts{
				coordinators:     map[string]bool{"node-1": true, "node-2": true},
				lateCoordinators: map[string]bool{"node-2": true},
			})
			n1, n2, n5 := c.Nodes[1], c.Nodes[2], c.Nodes[5]
			eventually(t, time.Minute, "node-1 to hold the failover lease on every node", func() bool {
				for _, n := range c.Nodes {
					if h, _, err := corrosion.ReadLeaseRow(ctx, n.DB, "failover"); err != nil || h != n1.Name {
						return false
					}
				}
				return true
			})
			s.startCoordinator(s.node(n2), 0)
			minority, majority := c.Nodes[:2], c.Nodes[2:5]
			if !bridged {
				majority = c.Nodes[2:]
			}
			c.SplitGossip(minority, majority)

			// The majority's own replica, and the bridge's: n5's copy of the
			// minority's lease was what refused every takeover.
			eventually(t, 45*time.Second+time.Minute, "a majority coordinator to take the failover lease over", func() bool {
				for _, n := range []*Node{n2, n5} {
					if h, _, err := corrosion.ReadLeaseRow(ctx, n.DB, "failover"); err != nil || h != n2.Name {
						return false
					}
				}
				return true
			})
			dest := waitRecovered(t, c, minority)
			assertRecoveredOnce(t, c, s, rs, dest, minority)
		})
	}
}

// TestFleet_PartitionPause_DerivedSetBridgeStallsVisibly: the same split with
// NO voter generation adopted, so the voter set is derived. n5 is in
// maintenance: up, outside the voter set, and in neither half, so it still
// reaches both. On a derived set the deadline keeps the conservative rule —
// any observer that sees the host answer holds its recovery — so the
// majority waits, fences, and then recovers nothing for as long as the split
// lasts. That stall is safe, and must be visible: ha.recovery.bridged names
// the host, its workload, the observers, the derived set and the way out,
// and ha.voter.genesis_pending says a split can stall failover. After the
// heal everything converges to the one original copy.
//
// Mutations: drop the noteBridgedStall call in retryPauseWait — the
// condition wait goes red; drop resolveBridgedSettled — the resolve wait
// after the heal goes red.
func TestFleet_PartitionPause_DerivedSetBridgeStallsVisibly(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 6, IndependentReplicas: true, Relays: 6, RealGossip: true})
	owner, n2, n5 := c.Nodes[0], c.Nodes[2], c.Nodes[5]
	insertVMPolicy(t, owner, "pp-vm", owner.Name, "restart-any")
	c.WaitConverged(t, convergeTimeout)
	owner.Virt.SetState("pp-vm", libvirtfake.StateRunning)
	if err := corrosion.UpdateHostState(ctx, owner.DB, n5.Name, "maintenance"); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "every node's derived voter set to be n0..n4", func() bool {
		for _, n := range c.Nodes {
			cfg, err := corrosion.AdoptedVoterConfig(ctx, n.DB)
			if err != nil || cfg.Explicit() {
				return false
			}
			v, err := corrosion.VoterSet(ctx, n.DB)
			if err != nil || len(v) != 5 || v[n5.Name] {
				return false
			}
		}
		return true
	})
	s := newPPStack(t, c, ppOpts{latched: true, coordinators: map[string]bool{n2.Name: true}})
	rs := sampleRunning(t, c, "pp-vm")
	eventually(t, time.Minute, "the owner's pauser to be healed before the split", func() bool {
		return s.node(owner).pauser.HealedForTests()
	})

	minority, majority := c.Nodes[:2], c.Nodes[2:5]
	c.SplitGossip(minority, majority)

	// The minority pauses; the majority fences, waits, and holds.
	eventually(t, ppRecoverBound, "ha.recovery.bridged for node-0 on node-2", func() bool {
		row, ok, err := corrosion.GetHealthCondition(ctx, n2.DB, failover.RefenceEvaluator,
			failover.CondRecoveryBridged, "host", owner.Name)
		return err == nil && ok && row.Lifecycle == corrosion.ConditionConfirmed
	})
	if _, ok := firstEvent(owner, "suspend", "pp-vm"); !ok {
		t.Fatalf("%s never suspended pp-vm", owner.Name)
	}
	if len(s.fencesOf(owner.Name)) == 0 {
		t.Fatalf("no coordinator fenced %s", owner.Name)
	}
	row, _, _ := corrosion.GetHealthCondition(ctx, n2.DB, failover.RefenceEvaluator,
		failover.CondRecoveryBridged, "host", owner.Name)
	var ev struct {
		Workloads       []string `json:"workloads"`
		Observers       []string `json:"observers"`
		DerivedVoterSet bool     `json:"derived_voter_set"`
		Remedy          string   `json:"remedy"`
	}
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
		t.Fatalf("evidence %q: %v", row.Evidence, err)
	}
	if !slices.Equal(ev.Workloads, []string{"vm/pp-vm"}) || !ev.DerivedVoterSet ||
		!strings.Contains(ev.Remedy, "lv host fence-confirm "+owner.Name) || !slices.Contains(ev.Observers, n5.Name) {
		t.Fatalf("evidence %s: want vm/pp-vm, the bridge %s among the observers, the derived set and the fence-confirm way out",
			row.Evidence, n5.Name)
	}
	for _, o := range ev.Observers {
		if o == n2.Name || o == c.Nodes[3].Name || o == c.Nodes[4].Name {
			t.Fatalf("majority voter %s named as seeing %s answer during the split: %v", o, owner.Name, ev.Observers)
		}
	}

	// Recovery does not proceed while the split is bridged.
	time.Sleep(ppWait(4) + 10*time.Second)
	for _, n := range c.Nodes[1:] {
		if _, ok := firstEvent(n, "start", "pp-vm"); ok {
			t.Fatalf("%s started pp-vm while the split was bridged on a derived voter set", n.Name)
		}
	}
	if st, _ := owner.Virt.RawState("pp-vm"); st != libvirtfake.StatePaused {
		t.Fatalf("%s's copy is %s during the split, want paused", owner.Name, st)
	}
	if row, ok, err := corrosion.GetHealthCondition(ctx, n2.DB, failover.RefenceEvaluator,
		failover.CondRecoveryBridged, "host", owner.Name); err != nil || !ok || row.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("ha.recovery.bridged resolved while the stall lasts: %+v (%v)", row, err)
	}

	// Genesis is pending, and says a split can stall failover; a host in
	// maintenance is a blocker the operator is already ending, so a warning.
	openVoterConfigGates(c)
	n2.Server.VoterGenesisTick(ctx, 0)
	gp, ok, err := corrosion.GetHealthCondition(ctx, n2.DB, "voter_config", "ha.voter.genesis_pending", "cluster", "voters")
	if err != nil || !ok || gp.Lifecycle == corrosion.ConditionResolved || gp.Severity != corrosion.SeverityWarning ||
		!strings.Contains(gp.Evidence, n5.Name+" (in maintenance) can reach both halves") {
		t.Fatalf("ha.voter.genesis_pending %+v (%v): want it open, a warning, naming %s as a bridge", gp, err, n5.Name)
	}

	// The heal: one copy, the original, and the condition resolves.
	c.HealGossip()
	c.WaitGossip(t, remergeBound, "the halves to merge", c.GossipConverged)
	eventually(t, ppRecoverBound, "pp-vm to run again on node-0 alone", func() bool {
		got := runningOn(c, "pp-vm")
		return len(got) == 1 && got[0] == owner.Name
	})
	eventually(t, time.Minute, "ha.recovery.bridged to resolve after the heal", func() bool {
		row, ok, err := corrosion.GetHealthCondition(ctx, n2.DB, failover.RefenceEvaluator,
			failover.CondRecoveryBridged, "host", owner.Name)
		return err == nil && ok && row.Lifecycle == corrosion.ConditionResolved
	})
	rs.mu.Lock()
	maxRun, overlap := rs.max, rs.overlap
	rs.mu.Unlock()
	if maxRun > 1 {
		t.Fatalf("pp-vm ran on more than one host at once: %v", overlap)
	}
	for _, n := range c.Nodes[1:] {
		if _, ok := firstEvent(n, "start", "pp-vm"); ok {
			t.Fatalf("%s started pp-vm; nothing was recovered, so only the original may run", n.Name)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.fence {
		for _, m := range minority {
			if f.by == m.Name {
				t.Fatalf("minority node %s fenced %s", m.Name, f.target)
			}
		}
	}
}

// TestFleet_PartitionPause_DerivedSetWitnessBridgeStallsVisibly: the same
// split on a derived voter set, with n5 a WITNESS reaching both halves. A
// witness votes on a derived set, so there are six voters and a quorum of
// four: the majority side holds it (n2 n3 n4 n5) and the minority pauses
// (n0 n1 n5 is three), but only n2 n3 n4 fail n0 — n5 sees it answer — so n0
// is never a fence candidate. Nothing is fenced and nothing waits; the
// workloads stay paused. ha.recovery.bridged must still say so, in its
// before-any-fence form, and ha.voter.genesis_pending is critical.
//
// After the heal the original runs alone and the condition resolves. (The
// fence-confirm way out is pinned by
// TestBridgedStall_BeforeAnyFenceTheWayOutRecovers.)
//
// Mutation: drop noteBridgedBeforeFence from the cycle — the condition wait
// goes red.
func TestFleet_PartitionPause_DerivedSetWitnessBridgeStallsVisibly(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 6, IndependentReplicas: true, Relays: 6, RealGossip: true})
	owner, n2, n5 := c.Nodes[0], c.Nodes[2], c.Nodes[5]
	insertVMPolicy(t, owner, "pp-vm", owner.Name, "restart-any")
	c.WaitConverged(t, convergeTimeout)
	owner.Virt.SetState("pp-vm", libvirtfake.StateRunning)
	if err := corrosion.UpdateHostRole(ctx, owner.DB, n5.Name, "witness"); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "every node to see the witness in a six-voter derived set", func() bool {
		for _, n := range c.Nodes {
			cfg, err := corrosion.AdoptedVoterConfig(ctx, n.DB)
			if err != nil || cfg.Explicit() {
				return false
			}
			v, err := corrosion.VoterSet(ctx, n.DB)
			h, herr := corrosion.GetHost(ctx, n.DB, n5.Name)
			if err != nil || herr != nil || len(v) != 6 || h == nil || !h.IsWitness() {
				return false
			}
		}
		return true
	})
	s := newPPStack(t, c, ppOpts{latched: true, coordinators: map[string]bool{n2.Name: true}})
	rs := sampleRunning(t, c, "pp-vm")
	eventually(t, time.Minute, "the owner's pauser to be healed before the split", func() bool {
		return s.node(owner).pauser.HealedForTests()
	})

	minority, majority := c.Nodes[:2], c.Nodes[2:5]
	c.SplitGossip(minority, majority)

	cond := func() (corrosion.HealthCondition, bool) {
		row, ok, err := corrosion.GetHealthCondition(ctx, n2.DB, failover.RefenceEvaluator,
			failover.CondRecoveryBridged, "host", owner.Name)
		return row, err == nil && ok
	}
	eventually(t, ppRecoverBound, "ha.recovery.bridged for node-0 on node-2, before any fence", func() bool {
		row, ok := cond()
		return ok && row.Lifecycle == corrosion.ConditionConfirmed
	})
	if _, ok := firstEvent(owner, "suspend", "pp-vm"); !ok {
		t.Fatalf("%s never suspended pp-vm", owner.Name)
	}
	if f := s.fencesOf(owner.Name); len(f) != 0 {
		t.Fatalf("%s was fenced by %s; a witness bridge on a derived set leaves no fence quorum", owner.Name, f[0].by)
	}
	row, _ := cond()
	var ev struct {
		Detail          string   `json:"detail"`
		Workloads       []string `json:"workloads"`
		Observers       []string `json:"observers"`
		DerivedVoterSet bool     `json:"derived_voter_set"`
		Remedy          string   `json:"remedy"`
	}
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
		t.Fatalf("evidence %q: %v", row.Evidence, err)
	}
	if !slices.Equal(ev.Workloads, []string{"vm/pp-vm"}) || !ev.DerivedVoterSet ||
		!slices.Contains(ev.Observers, n5.Name) || !strings.Contains(ev.Detail, "no fence candidate") ||
		!strings.Contains(ev.Remedy, "lv host fence-confirm "+owner.Name) {
		t.Fatalf("evidence %s: want vm/pp-vm, the witness among the observers, the derived set, "+
			"the before-any-fence detail and the fence-confirm way out", row.Evidence)
	}
	openVoterConfigGates(c)
	n2.Server.VoterGenesisTick(ctx, 0)
	gp, ok, err := corrosion.GetHealthCondition(ctx, n2.DB, "voter_config", "ha.voter.genesis_pending", "cluster", "voters")
	if err != nil || !ok || gp.Severity != corrosion.SeverityCritical ||
		!strings.Contains(gp.Evidence, n5.Name+" (witness) can reach both halves") {
		t.Fatalf("ha.voter.genesis_pending %+v (%v): want it critical, naming the witness", gp, err)
	}
	for _, n := range c.Nodes[1:] {
		if _, ok := firstEvent(n, "start", "pp-vm"); ok {
			t.Fatalf("%s started pp-vm while the split was bridged", n.Name)
		}
	}

	time.Sleep(10 * time.Second)
	if row, ok := cond(); !ok || row.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("ha.recovery.bridged resolved while the split lasts: %+v", row)
	}
	c.HealGossip()
	c.WaitGossip(t, remergeBound, "the halves to merge", c.GossipConverged)
	eventually(t, ppRecoverBound, "pp-vm to run again on node-0 alone", func() bool {
		got := runningOn(c, "pp-vm")
		return len(got) == 1 && got[0] == owner.Name
	})
	dest := owner
	eventually(t, time.Minute, "ha.recovery.bridged to resolve", func() bool {
		row, ok := cond()
		return ok && row.Lifecycle == corrosion.ConditionResolved
	})
	rs.mu.Lock()
	maxRun, overlap := rs.max, rs.overlap
	rs.mu.Unlock()
	if maxRun > 1 {
		t.Fatalf("pp-vm ran on more than one host at once: %v", overlap)
	}
	if got := runningOn(c, "pp-vm"); len(got) != 1 || got[0] != dest.Name {
		t.Fatalf("pp-vm runs on %v, want only %s", got, dest.Name)
	}
}
