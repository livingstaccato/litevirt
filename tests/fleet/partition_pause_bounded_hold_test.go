// The bridged hold is bounded (lab 1 at f9bafd75, drills W1 P2 and W5c). A
// self-paused host that a non-voter bridge reached was held at its
// partition-pause deadline while the bridge lasted; once the bridge was cut
// too, the bridge's failing run began after the fence, and that restarted
// run (with, on the explicit set, a pause report dated on a clock 60 s
// behind) held the recovery for as long as the outage lasted, with no way
// out but power-off and `lv host fence-confirm`.
//
// When enough voters have failed the host without a break since before the
// fence that it cannot have regained a majority since, the bridge's answers
// are all it can have seen: the deadline goes ahead
// (docs/design/partition-pause.md §4.2 step 3).
package fleet

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// TestFleet_PartitionPause_DerivedSetBridgeCutRecovers: W1 P2. On the
// derived voter set n0..n4 the bridge n5 holds n0's recovery at the deadline
// (TestFleet_PartitionPause_DerivedSetBridgeStallsVisibly). Then n0 is cut
// from n1 and n5 as well. Their failing runs begin after the fence, but n2,
// n3 and n4 have failed n0 since before it: three of five voters, so n0
// cannot have held a majority since. The deadline goes ahead and pp-vm runs
// once, on the majority.
//
// Mutation: drop the derived exemption (selfPauseStillStands passes
// noRegain=false to quietFallback) — the hold stays under the restarted runs
// and the recovery wait times out.
func TestFleet_PartitionPause_DerivedSetBridgeCutRecovers(t *testing.T) {
	ctx := context.Background()
	c, s, rs := derivedBridgeHeld(t)
	owner, n1, n2, n5 := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[5]
	logs := captureLogs(t)

	c.SplitGossip([]*Node{owner}, []*Node{n1, n5})

	minority := c.Nodes[:2]
	dest := waitRecovered(t, c, minority)
	assertRecoveredOnce(t, c, s, rs, dest, minority)
	eventually(t, time.Minute, "ha.recovery.bridged to resolve on node-2", func() bool {
		row, ok, err := corrosion.GetHealthCondition(ctx, n2.DB, failover.RefenceEvaluator,
			failover.CondRecoveryBridged, "host", owner.Name)
		return err == nil && ok && row.Lifecycle == corrosion.ConditionResolved
	})
	out := logs.String()
	for _, want := range []string{
		"partition-pause deadline passed; recovering the host's workloads",
		"the partition-pause deadline went ahead",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("node-2 never logged %q", want)
		}
	}
}

// TestFleet_PartitionPause_ExplicitSetSkewedPauserBridgeCutRecovers: W5c. On
// the explicit voter set n0..n4, n0 alone is cut from the other voters while
// the non-voter n5 still reaches it, and n0's clock is 60 s behind. Its
// partition_paused condition is stamped on that clock, so it reads as
// raised before this outage and the bridged deadline holds. Then n0 is cut
// from n5 too: n5's failing run begins after the fence, but n1..n4 have
// failed n0 since before it, so it cannot have regained a majority, and the
// deadline goes ahead on that alone.
//
// The control arm has no step: the host's word dates to this outage and the
// deadline goes ahead while the bridge still stands, which shows that the
// skew is what holds the bridged deadline.
//
// Mutation: drop the explicit exemption (the noRegainSinceIn check in
// selfPauseStillStands) — the skewed arm holds under the restarted run and
// "predates this outage", and its recovery wait times out.
func TestFleet_PartitionPause_ExplicitSetSkewedPauserBridgeCutRecovers(t *testing.T) {
	for _, skewed := range []bool{true, false} {
		t.Run(map[bool]string{true: "skewed", false: "control"}[skewed], func(t *testing.T) {
			ctx := context.Background()
			c, s, rs := bridgeFleetWith(t, ppOpts{coordinators: map[string]bool{"node-2": true}, pauserOnNodeClock: true}, Options{ClockSeam: true})
			owner, n2, n5 := c.Nodes[0], c.Nodes[2], c.Nodes[5]
			measureSkews(t, c, s)
			// The step makes node-0's skew 60 s, and every stamp may be
			// node-0's.
			settleVoterHistory(t, c, 45*time.Second+map[bool]time.Duration{true: 70 * time.Second}[skewed])
			if skewed {
				owner.StepClock(-60 * time.Second)
			}
			minority := []*Node{owner}
			c.SplitGossip(minority, c.Nodes[1:5])

			if !skewed {
				dest := waitRecovered(t, c, minority)
				assertRecoveredOnce(t, c, s, rs, dest, minority)
				return
			}
			eventually(t, ppRecoverBound, "node-2's deadline to hold on a pause report that predates the outage", func() bool {
				row, ok, err := corrosion.GetHealthCondition(ctx, n2.DB, failover.RefenceEvaluator,
					failover.CondRecoveryBridged, "host", owner.Name)
				if err != nil || !ok || row.Lifecycle != corrosion.ConditionConfirmed {
					return false
				}
				var ev struct {
					Detail string `json:"detail"`
				}
				return json.Unmarshal([]byte(row.Evidence), &ev) == nil && strings.Contains(ev.Detail, "predates this outage")
			})
			cond, ok, err := corrosion.GetHealthCondition(ctx, n2.DB, corrosion.PartitionPauseEvaluator,
				corrosion.CondPartitionPaused, "host", owner.Name)
			if err != nil || !ok {
				t.Fatalf("setup: node-2 holds no partition_paused for %s (%v)", owner.Name, err)
			}
			raised, ok := corrosion.ParseUpdatedAt(cond.FirstSeen)
			if !ok || n2.Now().Sub(raised) < 55*time.Second {
				t.Fatalf("setup: %s's partition_paused was raised at %s, not 55 s or more behind node-2's clock: the step did not reach the pauser",
					owner.Name, cond.FirstSeen)
			}
			for _, n := range c.Nodes[1:] {
				if _, ok := firstEvent(n, "start", "pp-vm"); ok {
					t.Fatalf("setup: %s started pp-vm while the bridged deadline held", n.Name)
				}
			}

			c.SplitGossip(minority, []*Node{n5})

			dest := waitRecovered(t, c, minority)
			assertRecoveredOnce(t, c, s, rs, dest, minority)
		})
	}
}

// TestFleet_PartitionPause_DerivedSetRegainedMajorityHolds: the bound must
// count as the host counts. Five nodes on the derived voter set n0..n4, pp-vm
// on n0, n3 the only coordinator. n0 is cut from the rest, paused and fenced.
// Then, for a while, it reaches n1 and n2 again: with them it is three of five by its own
// replica's count, which still holds it active, so it may resume. Then it is
// cut from them too. At the deadline n3 and n4 have failed n0 since before
// the fence, and n1's and n2's runs began after it. Two spanning runs are
// n−q+1 of the four voters n3's derived set holds once n0 is fenced, but not
// of n0's five: n0 may hold its majority again, and the deadline must not go
// ahead on the restarted runs (H1).
//
// Mutation: count over this node's derived set in noRegainSinceIn (drop the
// host from derivedRegainCandidate) — n3 recovers pp-vm while n0 may run it.
func TestFleet_PartitionPause_DerivedSetRegainedMajorityHolds(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, Relays: 5, RealGossip: true})
	owner, n1, n2, n3 := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
	insertVMPolicy(t, owner, "pp-vm", owner.Name, "restart-any")
	c.WaitConverged(t, convergeTimeout)
	owner.Virt.SetState("pp-vm", libvirtfake.StateRunning)
	eventually(t, 30*time.Second, "every node's derived voter set to be n0..n4", func() bool {
		for _, n := range c.Nodes {
			cfg, err := corrosion.AdoptedVoterConfig(ctx, n.DB)
			if err != nil || cfg.Explicit() {
				return false
			}
			v, err := corrosion.VoterSet(ctx, n.DB)
			if err != nil || len(v) != 5 {
				return false
			}
		}
		return true
	})
	s := newPPStack(t, c, ppOpts{latched: true, coordinators: map[string]bool{n3.Name: true}})
	eventually(t, time.Minute, "the owner's pauser to be healed before the split", func() bool {
		return s.node(owner).pauser.HealedForTests()
	})
	measureSkews(t, c, s)
	settleMembership(t, c)
	logs := captureLogs(t)

	c.SplitGossip([]*Node{owner}, c.Nodes[1:])
	eventually(t, ppRecoverBound, "node-3 to fence node-0", func() bool {
		h, err := corrosion.GetHost(ctx, n3.DB, owner.Name)
		return err == nil && h != nil && (h.State == "fenced" || h.State == "offline")
	})
	fencedAt := time.Now()

	// n0 reaches n1 and n2 again: three of five by its own count. It stays
	// reachable long enough that their next failing runs begin well after
	// the fence (past fenceSkewMargin), as a restarted run must.
	c.HealGossipBetween([]*Node{owner}, []*Node{n1, n2})
	late := fencedAt.Add(10 * time.Second)
	eventually(t, ppRecoverBound, "node-3 to hold node-1's and node-2's answers from node-0, 10 s after the fence", func() bool {
		return answered(ctx, n3, owner.Name, n1.Name, late) && answered(ctx, n3, owner.Name, n2.Name, late)
	})
	c.SplitGossip([]*Node{owner}, []*Node{n1, n2})
	noStart := func() {
		for _, n := range c.Nodes[1:] {
			if _, ok := firstEvent(n, "start", "pp-vm"); ok {
				t.Fatalf("%s started pp-vm while node-0 may hold its majority again; the failover log:\n%s",
					n.Name, failoverLog(logs.String()))
			}
		}
	}
	eventually(t, ppRecoverBound, "node-3 to hold the deadline on a restarted run", func() bool {
		noStart()
		return strings.Contains(logs.String(), "began after the fence")
	})
	// Several coordinator cycles more on the restarted runs.
	time.Sleep(20 * time.Second)
	noStart()
}

// answered reports whether n holds observer's latest verdict about target as
// an answer written after since.
func answered(ctx context.Context, n *Node, target, observer string, since time.Time) bool {
	rows, err := n.DB.Query(ctx, `SELECT consecutive_failures, updated_at FROM host_health WHERE observer = ? AND target = ?`, observer, target)
	if err != nil || len(rows) != 1 || rows[0].Int("consecutive_failures") != 0 {
		return false
	}
	upd, ok := corrosion.ParseUpdatedAt(rows[0].String("updated_at"))
	return ok && upd.After(since)
}

// failoverLog is the failover and partition-pause lines of a captured log.
func failoverLog(out string) string {
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "msg=\"failover:") || strings.Contains(l, "msg=\"partition-pause:") {
			lines = append(lines, l)
		}
	}
	return strings.Join(lines, "\n")
}

// TestFleet_PartitionPause_TwoVoterChangesSinceTheOutageHold: the bound holds
// only while the voter configuration n0 may count over is pinned. On voter
// generation 2 = n0..n4 (n5 a non-member), n0 is cut from every other node,
// paused and fenced by n3. For a while it reaches n1 and n2 again, three of
// five on generation 2, and is cut from them again, so their runs restart.
// Then the operator replaces the dead voter: `voter rm node-0` (generation
// 3 = n1..n4), then `voter add node-5` (4 = n1..n5). On generation 4, n3, n4
// and n5 span; on 3, n3 and n4 do. n0, which still counts over generation 2,
// may hold its majority there, so two generations decided since the outage
// began keep the hold.
//
// Mutation: allow two generations since the outage in regainCandidates is
// no longer red here: n0 reported generation 2, below the floor (3) the
// waiver would count from, so the evidence gate (hostReportedAdopting) holds
// first. The unit arm "add v6 10 s before the outage, rm down since"
// (TestSelfPauseExplicit_AGenerationJustBeforeTheOutageIsNotSettled) kills
// it.
func TestFleet_PartitionPause_TwoVoterChangesSinceTheOutageHold(t *testing.T) {
	ctx := context.Background()
	// node-0 must not pause before it is healed to node-1 and node-2: a
	// pause it reports there replicates to the majority, and its own word
	// then lets the deadline go ahead (as it should). On ppTPause that
	// ordering is a race the fence decision wins only under light load.
	c, s, rs := bridgeFleet(t, ppOpts{coordinators: map[string]bool{"node-3": true},
		tPause: map[string]time.Duration{"node-0": ppHoldOwnerTPause}})
	owner, n1, n2, n3, n5 := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3], c.Nodes[5]
	measureSkews(t, c, s)
	settleVoterHistory(t, c, 45*time.Second)
	logs := captureLogs(t)
	noStart := func() {
		for _, n := range c.Nodes[1:] {
			if _, ok := firstEvent(n, "start", "pp-vm"); ok {
				t.Fatalf("%s started pp-vm while node-0 may hold its majority on generation 2; the failover log:\n%s",
					n.Name, failoverLog(logs.String()))
			}
		}
	}

	c.SplitGossip([]*Node{owner}, c.Nodes[1:])
	eventually(t, ppRecoverBound, "node-3 to fence node-0", func() bool {
		h, err := corrosion.GetHost(ctx, n3.DB, owner.Name)
		return err == nil && h != nil && (h.State == "fenced" || h.State == "offline")
	})
	fencedAt := time.Now()
	if ev, ok := firstEvent(owner, "suspend", "pp-vm"); ok {
		t.Fatalf("setup: node-0 paused pp-vm at %s, before the heal: its report would reach the majority", ev.When.Format("15:04:05.000"))
	}
	c.HealGossipBetween([]*Node{owner}, []*Node{n1, n2})
	late := fencedAt.Add(10 * time.Second)
	eventually(t, ppRecoverBound, "node-3 to hold node-1's and node-2's answers from node-0, 10 s after the fence", func() bool {
		noStart()
		return answered(ctx, n3, owner.Name, n1.Name, late) && answered(ctx, n3, owner.Name, n2.Name, late)
	})
	c.SplitGossip([]*Node{owner}, []*Node{n1, n2})

	for i, ch := range []*pb.ChangeVoterConfigRequest{{Op: "rm", Host: owner.Name}, {Op: "add", Host: n5.Name}} {
		resp, err := c.SelfClient(n3).ChangeVoterConfig(ctx, ch)
		if err != nil || resp.GetGeneration() != int64(3+i) {
			t.Fatalf("voter %s %s: %+v %v", ch.Op, ch.Host, resp, err)
		}
		adoptAll(t, c, int64(3+i), c.Nodes[1:]...)
	}
	noStart()
	eventually(t, ppRecoverBound, "node-3 to hold the deadline on a restarted run", func() bool {
		noStart()
		return strings.Contains(logs.String(), "began after the fence")
	})
	// Several coordinator cycles on generation 4.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		noStart()
		time.Sleep(time.Second)
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.max > 1 {
		t.Fatalf("pp-vm ran on more than one host at once: %v", rs.overlap)
	}
}

// ppHoldOwnerTPause is node-0's T_pause in TwoVoterChangesSinceTheOutageHold:
// well past the majority's fence decision even under heavy load (about 9 s
// after node-0 loses the majority at 20 tests at once), so node-0 cannot
// pause before the test heals it.
const ppHoldOwnerTPause = 40 * time.Second

// measureSkews has every node's checker Ping every peer, as the daemon's
// capability sweeps do, until each has measured every peer's clock skew and
// holds its report of the voter generation the peer has adopted: a
// coordinator reads an unmeasured observer's skew as unknown, and its run
// then spans only well before the fence, and it counts no generation the
// host did not report.
func measureSkews(t *testing.T, c *Cluster, s *ppStack) {
	t.Helper()
	ctx := context.Background()
	eventually(t, time.Minute, "every node to measure every peer's clock skew and voter generation", func() bool {
		all := true
		for _, n := range c.Nodes {
			chk := s.node(n).chk
			for _, p := range c.Nodes {
				if p == n {
					continue
				}
				adopted, err := corrosion.AdoptedVoterGeneration(ctx, p.DB)
				if err != nil {
					return false
				}
				reported := func() bool {
					g, ok := n.Server.PeerVoterGeneration(p.Name, time.Now().Add(time.Second))
					return adopted == 0 || (ok && g >= adopted)
				}
				if _, ok := chk.MeasuredClockSkew(p.Name); !ok || !reported() {
					chk.PeerSupportsFresh(ctx, p.Name, capabilities.SplitBrainGateV1)
					_, ok = chk.MeasuredClockSkew(p.Name)
					all = all && ok && reported()
				}
			}
		}
		return all
	})
}

// settleVoterHistory waits until the setup's voter generations, proposed and
// written, are older than any outage the scenario starts by more than the
// deadline's window (healthFreshness plus fenceSkewMargin and the largest
// skew of any host, which a host stepped later adds to): a generation decided
// within it is one the host may not have adopted.
func settleVoterHistory(t *testing.T, c *Cluster, age time.Duration) {
	t.Helper()
	for _, n := range c.Nodes {
		cfgs, err := corrosion.ListVoterConfigs(context.Background(), n.DB)
		if err != nil {
			t.Fatal(err)
		}
		for _, cfg := range cfgs {
			for _, ts := range []string{cfg.CreatedAt, cfg.UpdatedAt} {
				if at, ok := corrosion.ParseUpdatedAt(ts); ok {
					if d := time.Until(at.Add(age)); d > 0 {
						time.Sleep(d)
					}
				}
			}
		}
	}
}

// settleMembership waits until no host's membership has changed for longer
// than the deadline's window for a change the host's replica may lack
// (healthFreshness, 30 s, before the outage), so every voter's spanning run
// counts: a cluster just built has every membership freshly written.
func settleMembership(t *testing.T, c *Cluster) {
	t.Helper()
	stamps, err := corrosion.HostMembershipStamps(context.Background(), c.Nodes[1].DB)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range stamps {
		if at, ok := corrosion.ParseUpdatedAt(st.Changed); ok {
			if d := time.Until(at.Add(45 * time.Second)); d > 0 {
				time.Sleep(d)
			}
		}
	}
}
