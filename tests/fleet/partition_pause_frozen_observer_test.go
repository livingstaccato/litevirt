// A health observer that stops running across a fence (lab 1 Drill2,
// 2026-10-16). The drill freezes the failover lease holder with SIGSTOP while
// another host dies. The frozen node is also a health observer. Thawed after
// the majority has fenced the dead host, its checker discards the gap and
// starts a new failing run at its first counted probe — after the fence. At
// the partition-pause deadline the coordinator read that run as "this observer
// saw the host answer after the fence" (restartedSinceObserversIn) and refused
// the recovery, re-checked every cycle and never passing: the VM stayed down
// until an operator confirmed the host off. It happened whenever the thawed
// observer's first failing row replicated before the deadline check, 1 run
// in 3.
package fleet

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// frozenClock is a node's health-checker clock that blocks while the node is
// frozen: every path of the checker — the probe loop, the heartbeat, a gate
// read — halts at its next clock reading and resumes, on thaw, at the real
// time, so the checker sees the gap as a stalled process does.
type frozenClock struct {
	mu     sync.Mutex
	thawed chan struct{} // non-nil while frozen
}

func (f *frozenClock) now() time.Time {
	f.mu.Lock()
	ch := f.thawed
	f.mu.Unlock()
	if ch != nil {
		<-ch
	}
	return time.Now()
}

func (f *frozenClock) freeze() {
	f.mu.Lock()
	if f.thawed == nil {
		f.thawed = make(chan struct{})
	}
	f.mu.Unlock()
}

func (f *frozenClock) thaw() {
	f.mu.Lock()
	if f.thawed != nil {
		close(f.thawed)
		f.thawed = nil
	}
	f.mu.Unlock()
}

// frozenObserverWait is the coordinator's pause wait in these scenarios. The
// thawed observer's first counted failure comes StallGrace after the thaw;
// the wait is long enough that it has always replicated to the coordinator
// by the deadline, which is the order that stalled the drill.
const frozenObserverWait = 30 * time.Second

// frozenObserverFleet is five voters, pp-vm on node-0, node-2 the only
// coordinator (pause wait frozenObserverWait), and node-1's checker on a
// frozenClock.
func frozenObserverFleet(t *testing.T) (c *Cluster, s *ppStack, rs *runSampler, frz *frozenClock) {
	t.Helper()
	c = New(t, Options{Nodes: 5, IndependentReplicas: true, Relays: 5, RealGossip: true})
	owner, obs, coord := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	insertVMPolicy(t, owner, "pp-vm", owner.Name, "restart-any")
	c.WaitConverged(t, convergeTimeout)
	owner.Virt.SetState("pp-vm", libvirtfake.StateRunning)
	genesisByTick(t, c, coord)
	enableRecoveryClaims(t, c)
	frz = &frozenClock{}
	t.Cleanup(frz.thaw)
	s = newPPStack(t, c, ppOpts{latched: true,
		coordinators:     map[string]bool{coord.Name: true},
		lateCoordinators: map[string]bool{coord.Name: true},
		clocks:           map[string]func() time.Time{obs.Name: frz.now},
	})
	s.node(coord).coord.PauseWaitFor = func(int) time.Duration { return frozenObserverWait }
	s.startCoordinator(s.node(coord), 0)
	rs = sampleRunning(t, c, "pp-vm")
	eventually(t, time.Minute, "the owner's pauser to be healed before the split", func() bool {
		return s.node(owner).pauser.HealedForTests()
	})
	return c, s, rs, frz
}

// observerRow is obs's host_health verdict about target as reader holds it.
type observerRow struct {
	failures int
	lastSeen time.Time
	rawSeen  string
	updated  time.Time
}

func readObserverRow(reader, obs, target *Node) (observerRow, bool) {
	rows, err := reader.DB.Query(context.Background(),
		`SELECT consecutive_failures, last_seen, updated_at FROM host_health WHERE observer = ? AND target = ?`,
		obs.Name, target.Name)
	if err != nil || len(rows) == 0 {
		return observerRow{}, false
	}
	r := rows[0]
	ls, _ := corrosion.ParseUpdatedAt(r.String("last_seen"))
	upd, _ := corrosion.ParseUpdatedAt(r.String("updated_at"))
	return observerRow{failures: int(r.Int("consecutive_failures")), lastSeen: ls, rawSeen: r.String("last_seen"), updated: upd}, true
}

// silentRecord is what obs's observer_stalled condition, as reader holds it,
// records for obs's failing run about target that began at run.
func silentRecord(reader, obs, target *Node, run observerRow) (time.Time, bool) {
	row, ok, err := corrosion.GetHealthCondition(context.Background(), reader.DB, health.StallEvaluator,
		health.CondObserverStalled, "host", obs.Name)
	if err != nil || !ok {
		return time.Time{}, false
	}
	return health.SilentSince(row.Evidence, target.Name, run.rawSeen)
}

// TestFleet_PartitionPause_AFrozenObserverDoesNotStallRecovery is Drill2:
// node-1 stops running, node-0 is cut off and fenced, and node-1 resumes after
// the fence and before the deadline. Its first failing run about node-0 begins
// after the fence, but node-1 records it as silent through its stall — it
// never saw node-0 answer since before it stopped — and the recovery must go
// ahead at the deadline, exactly once.
//
// Mutations: drop the noteSilentRun call in checkHost, or the silentThroughStall
// excuse in restartedSinceObserversIn — the deadline refuses for good and the
// recovery wait goes red.
func TestFleet_PartitionPause_AFrozenObserverDoesNotStallRecovery(t *testing.T) {
	frozenObserverRecovers(t, false)
}

// TestFleet_PartitionPause_AFrozenObserverThatCatchesUpDoesNotStallRecovery
// is the same with the catch-up a resumed process commonly has: moments after
// the thaw node-1 stops again, for 3 s (8.0 s then 2.2 s on the lab). Its run
// is silent since the FIRST stop, before the fence.
//
// Mutation: record the latest stall's start (drop silentFrom's carry-over in
// checkHost) — silent_since is after the fence, the deadline refuses for good
// and the recovery wait goes red.
func TestFleet_PartitionPause_AFrozenObserverThatCatchesUpDoesNotStallRecovery(t *testing.T) {
	frozenObserverRecovers(t, true)
}

func frozenObserverRecovers(t *testing.T, catchUp bool) {
	c, s, rs, frz := frozenObserverFleet(t)
	owner, obs, coord := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	frz.freeze()
	frozeAt := time.Now()
	c.SplitGossip([]*Node{owner}, c.Nodes[1:])
	eventually(t, ppRecoverBound, "node-2 to fence node-0", func() bool { return len(s.fencesOf(owner.Name)) > 0 })
	fenceAt := s.fencesOf(owner.Name)[0].at
	frz.thaw()
	if catchUp {
		time.Sleep(600 * time.Millisecond) // the heartbeat beats once or twice
		frz.freeze()
		time.Sleep(3 * time.Second)
		frz.thaw()
	}
	thawAt := time.Now()

	// When node-1's first failing verdict after the thaw reached the
	// coordinator, and what it said.
	var (
		mu     sync.Mutex
		seenAt time.Time
		seen   observerRow
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for ctx.Err() == nil {
			if r, ok := readObserverRow(coord, obs, owner); ok && r.failures > 0 && r.updated.After(thawAt) {
				mu.Lock()
				seenAt, seen = time.Now(), r
				mu.Unlock()
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	dest := waitRecovered(t, c, []*Node{owner})
	assertRecoveredOnce(t, c, s, rs, dest, []*Node{owner})

	start, _ := firstEvent(dest, "start", "pp-vm")
	mu.Lock()
	defer mu.Unlock()
	if seenAt.IsZero() || !seenAt.Before(start.When) {
		t.Fatalf("setup: node-1's failing verdict after the thaw reached node-2 at %v, not before the replacement "+
			"started at %s; the deadline was not checked against it", seenAt, start.When.Format("15:04:05.000"))
	}
	if !seen.lastSeen.After(fenceAt.Add(5 * time.Second)) {
		t.Fatalf("setup: node-1's failing run about node-0 began at %v, not after the fence at %s: the run that "+
			"refused the recovery was not exercised", seen.lastSeen, fenceAt.Format("15:04:05.000"))
	}
	since, ok := silentRecord(coord, obs, owner, seen)
	if !ok || since.After(frozeAt) {
		t.Fatalf("node-2 holds node-1's run as silent since %v (%v); node-1 stopped at %s (fence %s, thaw %s) and saw no answer since",
			since, ok, frozeAt.Format("15:04:05.000"), fenceAt.Format("15:04:05.000"), thawAt.Format("15:04:05.000"))
	}
}

// TestFleet_PartitionPause_AThawedObserverThatSawTheHostAnswerStillRefuses is
// the safety half: node-1 resumes after the fence and, before cutting off
// again, does reach node-0 and sees it answer. Its next failing run begins
// after that answer, after the fence, and the deadline must keep refusing the
// recovery: a host an observer saw answer after its fence may still run its
// workloads. Replication from node-0 stays cut, so its own word that it paused
// never reaches the majority.
//
// Mutation: record every first run after a stall as silent through it,
// whatever was answered since — node-1's run is excused, the deadline goes
// ahead and pp-vm starts on the majority.
func TestFleet_PartitionPause_AThawedObserverThatSawTheHostAnswerStillRefuses(t *testing.T) {
	c, s, _, frz := frozenObserverFleet(t)
	owner, obs, coord := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	frz.freeze()
	c.SplitGossip([]*Node{owner}, c.Nodes[1:])
	eventually(t, ppRecoverBound, "node-2 to fence node-0", func() bool { return len(s.fencesOf(owner.Name)) > 0 })
	fenceAt := s.fencesOf(owner.Name)[0].at
	frz.thaw()
	thawAt := time.Now()

	// node-1's probes reach node-0 again; replication between them stays cut.
	c.SetLinkFault(obs, owner, LinkFault{Block: true})
	eventually(t, 20*time.Second, "node-1 to see node-0 answer after the thaw", func() bool {
		at, ok := s.node(obs).chk.LastContact(owner.Name)
		return ok && at.After(thawAt)
	})
	c.SetLinkFault(obs, owner, LinkFault{Block: true, BlockAll: true})

	eventually(t, time.Minute, "node-1's failing verdict about node-0 to reach node-2", func() bool {
		r, ok := readObserverRow(coord, obs, owner)
		return ok && r.failures > 0 && r.updated.After(thawAt)
	})
	r, _ := readObserverRow(coord, obs, owner)
	if !r.lastSeen.After(fenceAt) {
		t.Fatalf("node-1's failing run about node-0 is dated %v, before the fence at %s; it saw node-0 answer after the thaw",
			r.lastSeen, fenceAt.Format("15:04:05.000"))
	}

	// Well past the deadline, nothing has started pp-vm on the majority.
	for time.Since(fenceAt) < frozenObserverWait+30*time.Second {
		for _, n := range c.Nodes[1:] {
			if ev, ok := firstEvent(n, "start", "pp-vm"); ok {
				t.Fatalf("%s started pp-vm at %s; node-1 saw node-0 answer after the fence at %s",
					n.Name, ev.When.Format("15:04:05.000"), fenceAt.Format("15:04:05.000"))
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if since, ok := silentRecord(coord, obs, owner, r); ok {
		t.Fatalf("node-1's run about node-0 is recorded silent since %v; it saw node-0 answer after the thaw", since)
	}
}
