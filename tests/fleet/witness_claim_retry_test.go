// A recovery-claim retry owed to one outage of a host must not run in the
// next one (witness drill design 2026-10-15, scenario 4b / question Q3).
//
// A coordinator that recovers a fenced host and has a claim refused keeps an
// in-memory retry for the host (claimRetry), retried every tick while the
// host stays a fence candidate. When the host comes back but is not put back
// in service (its fence moved another workload, so recoverHosts leaves it for
// `lv host undrain`), the retry outlives the outage. If the host then drops
// out again, the retry must not run on the first outage's fence: that fence
// says nothing about the second outage, in which the host is up, paused only
// T_pause after it lost the majority, and a replacement started at once would
// run beside it.
package fleet

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// TestFleet_PartitionPause_ClaimRetryOwedToAnEarlierOutageWaitsAgain: two
// outages of node-0, both 1|4 splits, with node-2's coordinator deciding. In
// the first, q3-a is recovered and q3-b's claim is refused (its claim RPCs are
// dropped), so a retry is owed. The split heals; node-0 answers and stays
// offline because q3-a moved, so the retry outlives the outage. The claim
// RPCs are let through and the split is made again, with node-0 pausing on
// losing the majority. q3-b must not start on the majority before the
// partition-pause wait W has passed since the second split, must never run
// on two hosts at once, and must still be recovered.
//
//   - pause-off-then-on: node-0 runs without the pause in the first outage
//     (so q3-b keeps running through it and after the heal, and the first
//     recovery runs only on an operator's mistaken confirmation), and with it in
//     the second (its flag flipped without the restart that would re-admit
//     it, as the scenario's only way to reach this). A retry that runs at
//     once starts q3-b while node-0 still runs it. A retry judged at the
//     heal, on node-0's answer while its pause could not be relied on, is
//     dropped and q3-b waits for an operator; one judged in the second
//     outage waits afresh and is recovered. Either way q3-b never runs twice
//     and never starts before W.
//   - pause-on: node-0 pauses in both outages; q3-b stays paused on node-0
//     after the heal (a voter has it offline). Running the retry at once is
//     harmless here, but the coordinator cannot tell the cases apart.
//
// Mutations: drop claimRetryOutageOver (the code before the fix) — in
// pause-off-then-on the retry starts q3-b on node-2 10.4 s into the second
// split while node-0 still runs it (both sampled running at once), and in
// pause-on it starts before W; always drop the retry rather than wait afresh
// — q3-b is never recovered in the second outage, in either subtest.
func TestFleet_PartitionPause_ClaimRetryOwedToAnEarlierOutageWaitsAgain(t *testing.T) {
	t.Run("pause-off-then-on", func(t *testing.T) { claimRetryAcrossOutages(t, true) })
	t.Run("pause-on", func(t *testing.T) { claimRetryAcrossOutages(t, false) })
}

func claimRetryAcrossOutages(t *testing.T, pauseOffFirst bool) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, Relays: 5, RealGossip: true})
	owner, decider := c.Nodes[0], c.Nodes[2]
	insertVMPolicy(t, owner, "q3-a", owner.Name, "restart-any")
	insertVMPolicy(t, owner, "q3-b", owner.Name, "restart-any")
	c.WaitConverged(t, convergeTimeout)
	owner.Virt.SetState("q3-a", libvirtfake.StateRunning)
	owner.Virt.SetState("q3-b", libvirtfake.StateRunning)
	genesisByTick(t, c, decider)
	enableRecoveryClaims(t, c)

	// q3-b's claim forms no certificate while refuse holds: every remote
	// vote is lost, and the proposer's own is not a majority.
	var refuse atomic.Bool
	refuse.Store(true)
	c.SetClaimScript(func(m ClaimMsg) ClaimFate {
		if m.Target == "q3-b" && refuse.Load() {
			return ClaimDropRequest
		}
		return ClaimDefault
	})

	o := ppOpts{latched: true, coordinators: map[string]bool{decider.Name: true}}
	if pauseOffFirst {
		o.pauseOff = map[string]bool{owner.Name: true}
	}
	s := newPPStack(t, c, o)
	rsB := sampleRunning(t, c, "q3-b")
	// node-0 alone: a 2|3 split would let the first recovery pick node-1,
	// in the minority, before it too is fenced.
	minority, majority := c.Nodes[:1], c.Nodes[1:]
	waitHealed := func(what string) {
		eventually(t, time.Minute, "the owner's pauser to be healed "+what, func() bool {
			return s.node(owner).pauser.HealedForTests()
		})
	}
	runsOnMajority := func(vm string) *Node {
		for _, n := range majority {
			if st, ok := n.Virt.RawState(vm); ok && st == libvirtfake.StateRunning {
				return n
			}
		}
		return nil
	}
	// q3-b only: without the pause (pause-off-then-on's first outage) q3-a
	// legitimately runs twice until Layer 3 settles it, as
	// TestFleet_PartitionSettle_DualRunSettlesToTheCertifiedCopy shows.
	assertOneCopy := func(when string) {
		t.Helper()
		rsB.mu.Lock()
		maxRun, overlap := rsB.max, rsB.overlap
		rsB.mu.Unlock()
		if maxRun > 1 {
			t.Fatalf("%s: q3-b ran on more than one host at once: %v", when, overlap)
		}
	}

	// ── outage 1 ──
	waitHealed("before the first split")
	c.SplitGossip(minority, majority)
	if pauseOffFirst {
		// Without node-0's pause the majority's best-effort fence proves
		// nothing and recovers nothing; an operator confirms node-0 off (by
		// mistake: it still runs q3-b) to start the first recovery.
		eventually(t, ppRecoverBound, "a fence of "+owner.Name+" in "+decider.Name+"'s fencing_log", func() bool {
			rows, err := decider.DB.Query(ctx, `SELECT 1 FROM fencing_log WHERE host_name = ?`, owner.Name)
			return err == nil && len(rows) > 0
		})
		if _, err := c.SelfClient(decider).FenceHost(ctx, &pb.FenceHostRequest{Name: owner.Name, Confirmed: true, ConfirmManualOnly: true}); err != nil {
			t.Fatalf("fence-confirm %s: %v", owner.Name, err)
		}
	}
	var destA *Node
	eventually(t, ppRecoverBound, "the majority to recover q3-a in the first outage", func() bool {
		destA = runsOnMajority("q3-a")
		return destA != nil
	})
	// The retry is owed: q3-b's claim is refused on every tick of the outage.
	time.Sleep(5 * time.Second)
	if n := runsOnMajority("q3-b"); n != nil {
		t.Fatalf("setup: q3-b started on %s while its claim RPCs were dropped", n.Name)
	}
	if row := vmOn(t, decider, "q3-b"); row == nil || row.HostName != owner.Name {
		t.Fatalf("setup: q3-b's row moved in the first outage (%+v); no retry is owed", row)
	}
	assertOneCopy("outage 1")

	// ── heal ──
	c.HealGossip()
	c.WaitGossip(t, remergeBound, "the halves to merge", c.GossipConverged)
	// Unpaused, q3-b ran through the outage; paused, it stays paused while a
	// voter has node-0 offline (health.DecideResume).
	wantB := libvirtfake.StatePaused
	if pauseOffFirst {
		wantB = libvirtfake.StateRunning
	}
	if st, _ := owner.Virt.RawState("q3-b"); st != wantB {
		t.Fatalf("setup: q3-b is %s on %s after the first outage, want %s", st, owner.Name, wantB)
	}
	eventually(t, time.Minute, "every majority voter to see node-0 answer", func() bool {
		rows, err := decider.DB.Query(ctx,
			`SELECT observer FROM host_health WHERE target = ? AND consecutive_failures = 0`, owner.Name)
		if err != nil {
			return false
		}
		seen := map[string]bool{}
		for _, r := range rows {
			seen[r.String("observer")] = true
		}
		for _, n := range majority {
			if !seen[n.Name] {
				return false
			}
		}
		return true
	})
	if pauseOffFirst {
		// The operator turns the pause on. Its restart would re-admit node-0
		// (hostboot's boot write) and drop the retry with it; the scenario
		// flips the flag without one, so the retry survives into an outage in
		// which node-0 pauses.
		s.node(owner).setPartitionPause(true)
		eventually(t, time.Minute, "node-2 to see node-0 say it pauses on losing the majority", func() bool {
			return decider.Server.PeerPausesOnLoss(owner.Name)
		})
	}
	waitHealed("after the heal")
	time.Sleep(3 * time.Second)
	h, err := corrosion.GetHost(ctx, decider.DB, owner.Name)
	if err != nil || h == nil {
		t.Fatalf("read %s on %s: %v", owner.Name, decider.Name, err)
	}
	if h.State == "active" {
		t.Fatalf("setup: %s was put back in service after the heal; the retry was forgotten with it and the scenario is not exercised", owner.Name)
	}
	assertOneCopy("after the heal")

	// ── outage 2 ──
	refuse.Store(false)
	rsB.markNow()
	split2 := time.Now()
	c.SplitGossip(minority, majority)
	w := ppWait(len(c.Nodes) - 1)
	watch := w + 45*time.Second
	var destB *Node
	for end := time.Now().Add(watch); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		assertOneCopy("outage 2")
		if destB = runsOnMajority("q3-b"); destB != nil {
			break
		}
	}
	assertOneCopy("outage 2")
	if destB == nil && pauseOffFirst {
		// node-0 answered at the heal while it ran q3-b unpaused. When the
		// coordinator judged the retry then, on that answer, node-0's
		// pause could not be relied on, so the retry was dropped and the
		// unverified fence declined: it waits for an operator
		// (claimRetryOutageOver). That is the outcome when the heal is
		// seen while node-0 is still a fence candidate; otherwise the
		// retry is judged in the second outage and waits afresh.
		t.Logf("q3-b was not recovered within %v of the second split: the retry was dropped at the heal", watch)
		return
	}
	if destB == nil {
		t.Fatalf("q3-b was not recovered within %v of the second split (node-0 has it %s)", watch,
			func() libvirtfake.State { st, _ := owner.Virt.RawState("q3-b"); return st }())
	}
	start, ok := firstEvent(destB, "start", "q3-b")
	if !ok {
		t.Fatalf("%s runs q3-b with no start event", destB.Name)
	}
	if d := start.When.Sub(split2); d < w {
		t.Fatalf("q3-b started on %s %v after the second split, before the partition-pause wait %v: "+
			"a claim retry owed to the first outage ran on its fence", destB.Name, d.Round(time.Millisecond), w)
	}
	if pauseOffFirst {
		susp, ok := lastEvent(owner, "suspend", "q3-b")
		if !ok || !susp.When.After(split2) || !susp.When.Before(start.When) {
			t.Fatalf("the replacement started on %s at %s, and %s did not pause q3-b in the second outage before it (%+v, %v)",
				destB.Name, start.When.Format("15:04:05.000"), owner.Name, susp, ok)
		}
	}
}

// lastEvent is n's newest op event for vm.
func lastEvent(n *Node, op, vm string) (libvirtfake.Event, bool) {
	var out libvirtfake.Event
	found := false
	for _, ev := range n.Virt.EventLog() {
		if ev.Op == op && ev.Domain == vm {
			out, found = ev, true
		}
	}
	return out, found
}
