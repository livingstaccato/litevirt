package health_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
)

// These scenarios run the real health checker of every node against one shared
// database (replication is instantaneous, which only makes a false quorum EASIER
// to reach) and the real failover coordinator on top of it. Probes are the
// injected readiness prober; time is a per-node clock the scenario advances.
//
// What they model is the one thing a failure detector cannot see from the
// inside: an OBSERVER that stopped running. A qemu guest whose host suspends,
// swaps or is starved of CPU is descheduled wholesale; its clocks keep moving
// (kvmclock tracks the host), so every probe it had in flight runs out its
// deadline without the observer ever having waited for an answer. The probe
// reports "unreachable". The peer was fine.

// stallClock is one node's local clock: real time plus an offset the scenario
// advances. time.Now().Add keeps the monotonic reading, so it behaves like the
// production clock in every comparison the checker makes.
type stallClock struct{ off atomic.Int64 }

func (c *stallClock) Now() time.Time          { return time.Now().Add(time.Duration(c.off.Load())) }
func (c *stallClock) advance(d time.Duration) { c.off.Add(int64(d)) }

type stallNode struct {
	name    string
	checker *health.Checker
	clock   *stallClock
}

type stallCluster struct {
	t     *testing.T
	db    *corrosion.Client
	nodes []*stallNode
	coord *failover.Coordinator

	mu sync.Mutex
	// dead: probes of this target fail at once — a host that is really gone.
	dead map[string]bool
	// stallOn[observer][target]: the observer is descheduled while probing the
	// target; its clock jumps by stallFor and the probe returns a deadline error.
	stallOn  map[string]map[string]bool
	stallFor time.Duration
	fenced   []string
}

func newStallCluster(t *testing.T, names ...string) *stallCluster {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	sc := &stallCluster{t: t, db: db, dead: map[string]bool{}, stallOn: map[string]map[string]bool{}}
	for i, name := range names {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: name, Address: "10.77.0." + string(rune('1'+i)), SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "ssh",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", name, err)
		}
		n := &stallNode{name: name, checker: health.NewChecker(name, t.TempDir(), db), clock: &stallClock{}}
		n.checker.SetClockForTest(n.clock.Now)
		observer := n
		n.checker.SetPeerReadiness(func(ctx context.Context, host string) (bool, string, error) {
			return sc.probe(observer, host)
		})
		sc.nodes = append(sc.nodes, n)
	}
	sc.coord = failover.NewCoordinator(names[0], db)
	sc.coord.LocalStall = sc.nodes[0].checker.InStallGrace // as the daemon wires it
	sc.coord.SetFencer(func(_ context.Context, h fence.HostConfig) fence.Result {
		sc.mu.Lock()
		sc.fenced = append(sc.fenced, h.Name)
		sc.mu.Unlock()
		return fence.Result{Method: "ssh", Success: true, Detail: "test"}
	})
	return sc
}

func (sc *stallCluster) probe(observer *stallNode, target string) (bool, string, error) {
	sc.mu.Lock()
	dead := sc.dead[target]
	stall := sc.stallOn[observer.name][target]
	stallFor := sc.stallFor
	sc.mu.Unlock()
	if stall {
		observer.clock.advance(stallFor)
		return false, "", context.DeadlineExceeded
	}
	if dead {
		return false, "", context.DeadlineExceeded
	}
	return true, "", nil
}

func (sc *stallCluster) node(name string) *stallNode {
	for _, n := range sc.nodes {
		if n.name == name {
			return n
		}
	}
	sc.t.Fatalf("no node %s", name)
	return nil
}

func (sc *stallCluster) setStall(observer, target string, on bool) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.stallOn[observer] == nil {
		sc.stallOn[observer] = map[string]bool{}
	}
	sc.stallOn[observer][target] = on
}

func (sc *stallCluster) setDead(target string, dead bool) {
	sc.mu.Lock()
	sc.dead[target] = dead
	sc.mu.Unlock()
}

// tick lets checkInterval pass normally on every node, then runs one probe
// cycle on each, then one coordinator cycle.
func (sc *stallCluster) tick() {
	ctx := context.Background()
	for _, n := range sc.nodes {
		stepNormally(n, 2*time.Second)
	}
	for _, n := range sc.nodes {
		n.checker.ProbeAllForTest(ctx)
	}
	sc.coord.RunOnce(ctx)
}

// stepNormally advances a node's clock by d the way a RUNNING node experiences
// it: in small steps, with the checker's liveness heartbeat beating at each.
func stepNormally(n *stallNode, d time.Duration) {
	const step = 250 * time.Millisecond
	for moved := time.Duration(0); moved < d; moved += step {
		n.clock.advance(step)
		health.BeatForTest(n.checker)
	}
}

func (sc *stallCluster) fencedHosts() []string {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return append([]string(nil), sc.fenced...)
}

// A cluster whose observers are all being descheduled — the lab's laptop,
// out of memory and swapping its qemu processes — must not agree that a
// healthy peer died. Each observer's probe of node-4 runs out its deadline
// while the OBSERVER is not running; node-4 answers every probe it receives.
// Before the fix every one of those timeouts counted, three observers reached
// offlineThreshold together, and the coordinator fenced a live host.
func TestStall_StalledObserversDoNotFenceAHealthyPeer(t *testing.T) {
	sc := newStallCluster(t, "node-1", "node-2", "node-3", "node-4")
	sc.tick() // one clean cycle: every observer has seen node-4 healthy

	sc.stallFor = 4 * time.Second
	for _, obs := range []string{"node-1", "node-2", "node-3"} {
		sc.setStall(obs, "node-4", true)
	}
	for i := 0; i < 8; i++ {
		sc.tick()
	}
	if got := sc.fencedHosts(); len(got) != 0 {
		t.Fatalf("fenced %v: every failed probe of node-4 was an observer that had stopped running, not a peer that stopped answering", got)
	}
}

// The whole cluster is paused at once (a hypervisor suspend) at a moment when
// every observer already had failure debt against node-4 from a genuine blip —
// one probe short of offlineThreshold. The probe each observer had in flight
// straddles the pause and times out on resume. Before the fix that one
// timeout was the fifth consecutive failure on three observers at once, and
// the coordinator's first post-resume cycle fenced node-4, which answers every
// probe from then on. A failure counted after a pause must come from a probe
// attempted after it.
func TestStall_ResumedClusterDoesNotFenceOnAStraddlingProbe(t *testing.T) {
	sc := newStallCluster(t, "node-1", "node-2", "node-3", "node-4")
	sc.tick()

	// A genuine blip: node-4 misses four probes on every observer.
	sc.setDead("node-4", true)
	for i := 0; i < 4; i++ {
		sc.tick()
	}
	if got := sc.fencedHosts(); len(got) != 0 {
		t.Fatalf("precondition: four failures must stay below offlineThreshold, fenced %v", got)
	}
	sc.setDead("node-4", false)

	// The pause: every node's clock jumps ten minutes. The probe in flight on
	// each observer is the one that sees it.
	sc.stallFor = 10 * time.Minute
	for _, obs := range []string{"node-1", "node-2", "node-3"} {
		sc.setStall(obs, "node-4", true)
	}
	ctx := context.Background()
	for _, n := range sc.nodes {
		n.checker.ProbeAllForTest(ctx)
	}
	for _, obs := range []string{"node-1", "node-2", "node-3"} {
		sc.setStall(obs, "node-4", false)
	}
	sc.node("node-4").clock.advance(10 * time.Minute) // node-4 was paused too
	sc.coord.RunOnce(ctx)
	if got := sc.fencedHosts(); len(got) != 0 {
		t.Fatalf("fenced %v on the first cycle after a cluster-wide pause, on the strength of probes that straddled it", got)
	}

	// And the resumed cluster settles: node-4 is answering, nobody fences it.
	for i := 0; i < 10; i++ {
		sc.tick()
	}
	if got := sc.fencedHosts(); len(got) != 0 {
		t.Fatalf("fenced %v after the cluster resumed and node-4 answered every probe", got)
	}
}

// The plain form of the hypothesis — every node paused at once, every clock
// jumps forward, every peer healthy, no probe in flight — does NOT fence, and
// did not before the stall guard either: consecutive_failures only counts
// probes that were attempted and failed, the ticker drops the ticks it missed,
// and rows written before the pause are stale against the resumed clock. It is
// pinned so a future change that makes elapsed time count as failure is caught.
func TestStall_ClusterWidePauseAloneDoesNotFence(t *testing.T) {
	sc := newStallCluster(t, "node-1", "node-2", "node-3", "node-4")
	for i := 0; i < 3; i++ {
		sc.tick()
	}
	for _, n := range sc.nodes {
		n.clock.advance(10 * time.Minute)
	}
	for i := 0; i < 10; i++ {
		sc.tick()
	}
	if got := sc.fencedHosts(); len(got) != 0 {
		t.Fatalf("fenced %v after a pause in which no probe failed", got)
	}
}

// The guard must not cost the cluster its failure detection. node-4 dies,
// the observers build up four failures, and then the whole cluster pauses.
// node-4 never answers again. It is fenced within StallGrace plus the usual
// offlineThreshold probes of resume — and every one of those probes is made
// after the grace window: the four failures from before the pause are
// discarded, not topped up.
func TestStall_ADeadHostIsStillFencedWithinTheBound(t *testing.T) {
	sc := newStallCluster(t, "node-1", "node-2", "node-3", "node-4")
	sc.tick()

	sc.setDead("node-4", true)
	for i := 0; i < 4; i++ {
		sc.tick()
	}
	if got := sc.fencedHosts(); len(got) != 0 {
		t.Fatalf("precondition: fenced %v before offlineThreshold", got)
	}
	for _, n := range sc.nodes {
		n.clock.advance(10 * time.Minute)
	}
	resumed := sc.node("node-1").clock.Now()

	const (
		probeTick      = 2 * time.Second // tick's normal step (checkInterval)
		failuresNeeded = 5               // failover.offlineThreshold
	)
	bound := health.StallGrace + failuresNeeded*probeTick + probeTick
	var fencedAfter time.Duration
	for i := 0; i < 40 && fencedAfter == 0; i++ {
		sc.tick()
		if len(sc.fencedHosts()) > 0 {
			fencedAfter = sc.node("node-1").clock.Now().Sub(resumed)
		}
	}
	if fencedAfter == 0 {
		t.Fatalf("a host that never answered again was never fenced — the stall guard withheld its failures forever")
	}
	if got := sc.fencedHosts(); len(got) != 1 || got[0] != "node-4" {
		t.Fatalf("fenced %v, want exactly [node-4]", got)
	}
	if fencedAfter > bound {
		t.Fatalf("dead host fenced %v after resume, want within %v (StallGrace + %d probes)", fencedAfter, bound, failuresNeeded)
	}
	if earliest := health.StallGrace + (failuresNeeded-1)*probeTick; fencedAfter < earliest {
		t.Fatalf("dead host fenced %v after resume; a verdict made only of probes after the %v grace window needs at least %v",
			fencedAfter, health.StallGrace, earliest)
	}
}

// Observers on one hypervisor that suspends, a coordinator elsewhere that
// keeps running. node-2..4 each have four failures against node-5 from a real
// blip, pause together, and the probe each had in flight straddles the pause.
// The coordinator never stopped, so its own guard does not apply: only the
// observers' refusal to count a straddling probe keeps node-5 alive.
func TestStall_ObserversPausedTogetherDoNotFence(t *testing.T) {
	sc := newStallCluster(t, "node-1", "node-2", "node-3", "node-4", "node-5")
	sc.tick()
	sc.setDead("node-5", true)
	for i := 0; i < 4; i++ {
		sc.tick()
	}
	sc.setDead("node-5", false)

	paused := []string{"node-2", "node-3", "node-4"}
	sc.stallFor = 90 * time.Second
	for _, obs := range paused {
		sc.setStall(obs, "node-5", true)
	}
	ctx := context.Background()
	for _, name := range paused {
		sc.node(name).checker.ProbeAllForTest(ctx)
		sc.setStall(name, "node-5", false)
	}
	stepNormally(sc.node("node-1"), 2*time.Second) // the coordinator ran throughout
	sc.coord.RunOnce(ctx)
	if got := sc.fencedHosts(); len(got) != 0 {
		t.Fatalf("fenced %v on probes that straddled the observers' pause", got)
	}
}

// Peers resuming together get the grace window to answer. After a
// cluster-wide pause node-4 does not answer for the first ~10s (its daemon,
// its dialers and the network are resuming too — the lab saw dial timeouts
// and wedged replication right after a host suspend), then does. Five
// unanswered probes inside the window must not become a fence.
func TestStall_PeersGetAGraceWindowToAnswerAfterAClusterWidePause(t *testing.T) {
	sc := newStallCluster(t, "node-1", "node-2", "node-3", "node-4")
	sc.tick()
	for _, n := range sc.nodes {
		n.clock.advance(10 * time.Minute)
	}
	sc.setDead("node-4", true)
	for i := 0; i < 5; i++ { // probes at +2s … +10s
		sc.tick()
	}
	sc.setDead("node-4", false)
	for i := 0; i < 10; i++ {
		sc.tick()
	}
	if got := sc.fencedHosts(); len(got) != 0 {
		t.Fatalf("fenced %v for not answering in the first 10s after a cluster-wide resume", got)
	}
}

// The coordinator's own guard. Three observers kept running and agree node-5
// is down (quorum is 3 of 5); the coordinator node, node-1, was itself stopped
// a moment ago. It defers the fence for the grace window, then makes it on the
// same evidence.
func TestStall_ACoordinatorThatStalledDefersTheFence(t *testing.T) {
	sc := newStallCluster(t, "node-1", "node-2", "node-3", "node-4", "node-5")
	sc.tick()

	sc.setDead("node-5", true)
	for i := 0; i < 4; i++ {
		sc.tick()
	}
	if got := sc.fencedHosts(); len(got) != 0 {
		t.Fatalf("precondition: fenced %v before offlineThreshold", got)
	}

	// node-1 stops for 3s. The others run and take the fifth failure.
	ctx := context.Background()
	sc.node("node-1").clock.advance(3 * time.Second)
	for _, n := range sc.nodes[1:] {
		stepNormally(n, 2*time.Second)
		n.checker.ProbeAllForTest(ctx)
	}
	sc.coord.RunOnce(ctx)
	if got := sc.fencedHosts(); len(got) != 0 {
		t.Fatalf("fenced %v from a coordinator that was not running 3s ago", got)
	}

	// After the grace window, the same evidence (kept fresh) fences.
	stepNormally(sc.node("node-1"), health.StallGrace)
	for _, n := range sc.nodes[1:] {
		stepNormally(n, 2*time.Second)
		n.checker.ProbeAllForTest(ctx)
	}
	sc.coord.RunOnce(ctx)
	if got := sc.fencedHosts(); len(got) != 1 || got[0] != "node-5" {
		t.Fatalf("after the grace window: fenced %v, want [node-5]", got)
	}
}
