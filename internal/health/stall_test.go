package health

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Start must run the liveness heartbeat. Without it the only beats are probe
// results, a full probe tick apart, and every gap between them is as long as
// stallThreshold: each failed probe would read as observed across a stall, and
// a dead peer would never be fenced.
func TestStart_RunsTheStallHeartbeat(t *testing.T) {
	c := NewChecker("host-a", t.TempDir(), testCheckerDB(t)) // no PKI: Start parks in its TLS retry loop
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go c.Start(ctx)

	lastBeat := func() time.Time {
		c.stall.mu.Lock()
		defer c.stall.mu.Unlock()
		return c.stall.lastBeat
	}
	deadline := time.Now().Add(3 * time.Second)
	for lastBeat().IsZero() {
		if time.Now().After(deadline) {
			t.Fatal("Start did not start the stall heartbeat")
		}
		time.Sleep(20 * time.Millisecond)
	}
	first := lastBeat()
	time.Sleep(3 * stallBeat)
	if !lastBeat().After(first) {
		t.Fatalf("the heartbeat beat once and stopped (last beat %v)", first)
	}
	if c.InStallGrace() {
		t.Fatal("a checker whose heartbeat is running normally reports a stall")
	}
}

// A heartbeat gap longer than stallThreshold opens the grace window; one that
// is not, does not; and the window closes after StallGrace.
func TestBeat_GapOpensAndClosesTheGraceWindow(t *testing.T) {
	c := NewChecker("host-a", t.TempDir(), testCheckerDB(t))
	now := time.Now()
	c.clock = func() time.Time { return now }

	c.beat(now)
	now = now.Add(stallThreshold - 100*time.Millisecond)
	if c.InStallGrace() {
		t.Fatalf("a %v gap is not a stall", stallThreshold-100*time.Millisecond)
	}
	now = now.Add(stallThreshold + time.Second)
	if !c.InStallGrace() {
		t.Fatalf("a %v gap is a stall", stallThreshold+time.Second)
	}
	// From here the process runs normally: the heartbeat beats every stallBeat.
	run := func(d time.Duration) {
		for moved := time.Duration(0); moved < d; moved += stallBeat {
			now = now.Add(stallBeat)
			c.beat(now)
		}
	}
	run(StallGrace - time.Second)
	if !c.InStallGrace() {
		t.Fatal("the grace window closed early")
	}
	run(2 * time.Second)
	if c.InStallGrace() {
		t.Fatal("the grace window did not close after StallGrace")
	}
}

// The fail-closed half of the guard. Withholding failures after a stall must
// not leave this node crediting peers it has not heard from since: a peer seen
// healthy only BEFORE the stall does not count toward quorum until a probe sent
// after it succeeds — and a probe that straddled the stall, even a successful
// one, is not such a probe.
func TestQuorumProof_PeersMustBeReprovenAfterAStall(t *testing.T) {
	db := testCheckerDB(t)
	ctx := context.Background()
	for _, n := range []string{"host-a", "host-b", "host-c"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: n, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", n, err)
		}
	}
	c := NewChecker("host-a", t.TempDir(), db)
	var mu sync.Mutex
	now := time.Now()
	c.clock = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	var stallDuringProbe atomic.Bool
	c.SetPeerReadiness(func(context.Context, string) (bool, string, error) {
		if stallDuringProbe.Load() {
			advance(5 * time.Second)
		}
		return true, "", nil
	})
	c.startedAt = time.Now().Add(-time.Minute)
	c.probedOnce = true
	quorum := func() QuorumState { s, _, _ := c.QuorumProof(ctx); return s }

	c.checkAllPeers(ctx)
	if got := quorum(); got != QuorumYes {
		t.Fatalf("precondition: both peers just probed healthy, quorum=%v", got)
	}

	advance(5 * time.Second) // stopped between probe cycles
	if got := quorum(); got != QuorumNo {
		t.Fatalf("after a stall, peers last seen before it still count toward quorum (state %v)", got)
	}
	c.checkAllPeers(ctx)
	if got := quorum(); got != QuorumYes {
		t.Fatalf("a successful probe sent after the stall must re-prove the peer, quorum=%v", got)
	}

	stallDuringProbe.Store(true) // stopped while the probes were in flight
	c.checkAllPeers(ctx)
	stallDuringProbe.Store(false)
	if got := quorum(); got != QuorumNo {
		t.Fatalf("a probe that straddled a stall re-proved a peer (state %v)", got)
	}
}
